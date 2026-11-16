"""endoflife.date adapter.

A free, keyless API at ``https://endoflife.date/api/{product}.json`` returns a
product's release cycles. A lookup matches the version to its cycle and shows
whether that release is past end of life.

Answers are public data, cached process-wide for an hour per product, for at
most ``MAX_CACHE_ENTRIES`` products (the oldest is dropped first). A failure
is soft: ``check_eol`` returns None (unknown) and the rest of the lookup still
runs. A failure is not cached, so the next lookup asks again; a 404 is an
answer (no such product) and is cached. Switched off by ``Settings.offline`` or
``AEGIS_DISABLE_EOL`` / ``AEGIS_OFFLINE``.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass
from datetime import date

import requests
from requests.exceptions import RequestException

from aegisshield.config import Settings
from aegisshield.services.lookup_switches import source_disabled

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10.0
CACHE_TTL_SECONDS = 60 * 60
# Products cached at once. A visitor's typed name becomes a slug, so the set
# of products is not fixed; this bounds the memory it can take.
MAX_CACHE_ENTRIES = 512
# What a product slug may hold before it goes into the request path. A
# visitor's typed name becomes the slug for an unmapped technology, so
# anything else (``/``, ``?``, ``#``, ``..``) is never requested or cached.
_SLUG_RE = re.compile(r"[a-z0-9][a-z0-9.+-]{0,63}")


@dataclass(frozen=True)
class EolStatus:
    """One product release cycle's support status."""

    product: str
    cycle: str
    eol: str | None  # ISO date string, "true", or None when not set
    is_eol: bool
    support_until: str | None
    latest: str | None
    url: str

    def to_dict(self) -> dict:
        """The status as a JSON-ready dict."""
        return {
            "product": self.product,
            "cycle": self.cycle,
            "eol": self.eol,
            "is_eol": self.is_eol,
            "support_until": self.support_until,
            "latest": self.latest,
            "url": self.url,
        }


_lock = threading.Lock()
_cache: dict[str, tuple[float, list[dict] | None]] = {}


def _slug(name: str) -> str:
    return name.strip().lower().replace(" ", "-")


def _fetch_cycles(product_slug: str) -> list[dict] | None:
    """The product's cycles from the cache or one request; None when unknown.

    The request runs outside the lock so one slow answer does not hold up
    other visitors' lookups. Only an answer is cached (the cycles, or None
    for a 404); a failure returns None and is asked again next time.
    """
    now = time.time()
    with _lock:
        cached = _cache.get(product_slug)
        if cached and (now - cached[0]) >= CACHE_TTL_SECONDS:
            del _cache[product_slug]
            cached = None
    if cached:
        return cached[1]

    url = f"https://endoflife.date/api/{product_slug}.json"
    cycles: list[dict] | None
    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 404:
            cycles = None
        else:
            response.raise_for_status()
            body = response.json()
            if not isinstance(body, list):
                raise ValueError("the answer is not a list")
            cycles = [c for c in body if isinstance(c, dict)]
    except (RequestException, ValueError) as exc:
        logger.warning("eol_fetch_failed product=%s error_type=%s", product_slug, type(exc).__name__)
        return None

    with _lock:
        _cache.pop(product_slug, None)
        while len(_cache) >= MAX_CACHE_ENTRIES:
            _cache.pop(next(iter(_cache)))
        _cache[product_slug] = (now, cycles)
    return cycles


def _parse_eol(eol_value: object) -> tuple[str | None, bool]:
    """Normalize the ``eol`` field, which can be False, True, or a date string."""
    if eol_value is False or eol_value is None:
        return (None, False)
    if eol_value is True:
        return ("true", True)
    text = str(eol_value)
    try:
        eol_date = date.fromisoformat(text)
    except ValueError:
        return (text, False)
    return (text, eol_date <= date.today())


def _in_cycle(version: str, cycle: str) -> bool:
    if not version.startswith(cycle):
        return False
    rest = version[len(cycle) :]
    return not rest or not rest[0].isdigit()


def check_eol(
    product: str, version: str | None = None, *, settings: Settings | None = None
) -> EolStatus | None:
    """The endoflife.date cycle for ``product`` at ``version``, or None.

    The cycle matches on a version boundary: what follows the cycle is the
    end or a non-digit (``1.18.0`` is cycle ``1.18``, ``1.1.1w`` is cycle
    ``1.1.1``, ``10.2`` is not cycle ``1``), and the longest match wins. A
    version outside every listed cycle is unknown (None); guessing the newest
    cycle would call it supported. With no version, the first cycle that is
    not past end of life is used.
    """
    if not product or source_disabled("eol", settings):
        return None
    product_slug = _slug(product)
    if not _SLUG_RE.fullmatch(product_slug) or ".." in product_slug:
        return None
    cycles = _fetch_cycles(product_slug)
    if not cycles:
        return None

    target_version = (version or "").strip()
    matched: dict | None = None
    if target_version:
        best = -1
        for entry in cycles:
            cycle = str(entry.get("cycle") or "")
            if cycle and _in_cycle(target_version, cycle) and len(cycle) > best:
                matched, best = entry, len(cycle)
        if matched is None:
            return None
    else:
        matched = next((e for e in cycles if not _parse_eol(e.get("eol"))[1]), cycles[0])

    eol_str, is_eol = _parse_eol(matched.get("eol"))
    support_until = matched.get("support")
    if support_until is False:
        support_until = None
    elif support_until is not None:
        support_until = str(support_until)

    return EolStatus(
        product=product,
        cycle=str(matched.get("cycle") or ""),
        eol=eol_str,
        is_eol=is_eol,
        support_until=support_until,
        latest=str(matched.get("latest")) if matched.get("latest") is not None else None,
        url=f"https://endoflife.date/{product_slug}",
    )


def reset_cache_for_tests() -> None:
    """Forget every cached answer."""
    with _lock:
        _cache.clear()


def seed_cache_for_tests(product: str, cycles: list[dict] | None) -> None:
    """Cache an answer for ``product`` without the network."""
    with _lock:
        _cache[_slug(product)] = (time.time(), cycles)
