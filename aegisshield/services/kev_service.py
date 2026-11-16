"""CISA Known Exploited Vulnerabilities (KEV) catalog adapter.

CISA publishes a free, keyless JSON catalog of CVEs confirmed exploited in
the wild. A CVE on KEV is the strongest "patch this now" signal a lookup can
show: an attacker can already use the flaw, so the lookup raises the
finding's severity.

The catalog is public data, so one process-wide index serves every visitor.
It is downloaded at most every ``CACHE_TTL_SECONDS``; a failed refresh keeps
the previous index. A vulnerability lookup takes one ``catalog_snapshot`` per
job and answers every CVE from it.

Switched off by ``Settings.offline`` or ``AEGIS_DISABLE_KEV`` /
``AEGIS_OFFLINE`` (see ``lookup_switches``). Mock LLM mode does not switch it
off: that mode stands in for the paid model only.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

import requests
from requests.exceptions import RequestException

from aegisshield.config import Settings
from aegisshield.core.errors import IntelLookupError
from aegisshield.core.retry import retry_call
from aegisshield.services.lookup_switches import source_disabled

logger = logging.getLogger(__name__)

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
CACHE_TTL_SECONDS = 6 * 60 * 60
# Oldest catalog a lookup may still answer from when a refresh fails. Past it,
# known-exploited status is unknown, never "not exploited".
MAX_STALE_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class KevConfig:
    """Retry and timeout settings for one catalog download."""

    max_retries: int = 3
    base_delay_seconds: float = 1.0
    timeout_seconds: float = 30.0


@dataclass(frozen=True)
class KevRecord:
    """A single CISA KEV catalog entry (subset of the published fields)."""

    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_campaign_use: str

    def to_dict(self) -> dict:
        """The record as a JSON-ready dict."""
        return {
            "cve_id": self.cve_id,
            "vendor_project": self.vendor_project,
            "product": self.product,
            "vulnerability_name": self.vulnerability_name,
            "date_added": self.date_added,
            "short_description": self.short_description,
            "required_action": self.required_action,
            "due_date": self.due_date,
            "known_ransomware_campaign_use": self.known_ransomware_campaign_use,
        }


_lock = threading.Lock()
_cache_built_at: float = 0.0
_cache_index: dict[str, KevRecord] = {}


def _offline(settings: Settings | None) -> bool:
    return source_disabled("kev", settings)


def _parse_catalog(payload: object) -> dict[str, KevRecord]:
    """The CVE index from a catalog download.

    A catalog with no entries (no ``vulnerabilities`` list, an empty one, or
    none with a CVE id) is a failed download, never "nothing is known
    exploited".
    """
    entries = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError("CISA KEV catalog has no vulnerabilities list")
    index: dict[str, KevRecord] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cve_id = str(entry.get("cveID") or "").strip().upper()
        if not cve_id:
            continue
        index[cve_id] = KevRecord(
            cve_id=cve_id,
            vendor_project=str(entry.get("vendorProject") or ""),
            product=str(entry.get("product") or ""),
            vulnerability_name=str(entry.get("vulnerabilityName") or ""),
            date_added=str(entry.get("dateAdded") or ""),
            short_description=str(entry.get("shortDescription") or ""),
            required_action=str(entry.get("requiredAction") or ""),
            due_date=str(entry.get("dueDate") or ""),
            known_ransomware_campaign_use=str(entry.get("knownRansomwareCampaignUse") or ""),
        )
    if not index:
        raise ValueError("CISA KEV catalog has no usable entries")
    return index


def _refresh(config: KevConfig, force: bool = False) -> None:
    """Download the catalog unless the cached one is fresh.

    The download runs outside the lock, so a slow feed never blocks a reader
    of the cached index. Raises ``IntelLookupError`` when it fails.
    """
    global _cache_built_at, _cache_index

    with _lock:
        if not force and _cache_index and (time.time() - _cache_built_at) < CACHE_TTL_SECONDS:
            return

    def _fetch() -> object:
        response = requests.get(KEV_CATALOG_URL, timeout=config.timeout_seconds)
        response.raise_for_status()
        return response.json()

    try:
        payload = retry_call(
            _fetch,
            max_retries=config.max_retries,
            base_delay_seconds=config.base_delay_seconds,
            retry_exceptions=(RequestException,),
        )
        index = _parse_catalog(payload)
    except (RequestException, ValueError) as exc:
        logger.warning("kev_cache_refresh_failed error_type=%s", type(exc).__name__)
        raise IntelLookupError("The CISA KEV catalog could not be downloaded.") from exc

    with _lock:
        _cache_index = index
        _cache_built_at = time.time()
    logger.info("kev_cache_refreshed entries=%d", len(index))


def lookup(
    cve_id: str, config: KevConfig | None = None, *, settings: Settings | None = None
) -> KevRecord | None:
    """The KEV record for ``cve_id`` (case-insensitive), or None.

    Best effort: a failed download answers from the cached index.
    """
    if not cve_id or _offline(settings):
        return None
    try:
        _refresh(config or KevConfig())
    except IntelLookupError:
        pass  # answer from whatever index is cached
    with _lock:
        return _cache_index.get(cve_id.strip().upper())


def catalog_snapshot(
    config: KevConfig | None = None,
    *,
    max_age_seconds: float = MAX_STALE_SECONDS,
    settings: Settings | None = None,
) -> dict[str, KevRecord] | None:
    """The catalog to answer one whole lookup from, or None when unknown.

    No download when the cache is fresh (under ``CACHE_TTL_SECONDS``).
    Otherwise one refresh with ``config``; if that fails, a cache younger than
    ``max_age_seconds`` is still used. None when the feed is switched off or
    nothing usable could be loaded: the caller must then report
    known-exploited status as unknown, never as "not exploited". Reading the
    returned dict never downloads anything.
    """
    if _offline(settings):
        return None
    try:
        _refresh(config or KevConfig())
    except IntelLookupError:
        pass  # a young cache may still answer; checked below
    with _lock:
        if _cache_built_at <= 0 or (time.time() - _cache_built_at) >= max_age_seconds:
            return None
        return dict(_cache_index)


def is_known_exploited(
    cve_id: str, config: KevConfig | None = None, *, settings: Settings | None = None
) -> bool:
    """True when ``cve_id`` is on the CISA KEV catalog."""
    return lookup(cve_id, config, settings=settings) is not None


def refresh_catalog(config: KevConfig | None = None, *, settings: Settings | None = None) -> int:
    """Force a catalog refresh and return the entry count (raises on failure)."""
    if _offline(settings):
        return 0
    _refresh(config or KevConfig(), force=True)
    with _lock:
        return len(_cache_index)


def reset_cache_for_tests() -> None:
    """Forget the cached catalog."""
    global _cache_built_at, _cache_index
    with _lock:
        _cache_built_at = 0.0
        _cache_index = {}


def seed_cache_for_tests(records: dict[str, KevRecord]) -> None:
    """Load a catalog without the network."""
    global _cache_built_at, _cache_index
    with _lock:
        _cache_index = {k.upper(): v for k, v in records.items()}
        _cache_built_at = time.time()
