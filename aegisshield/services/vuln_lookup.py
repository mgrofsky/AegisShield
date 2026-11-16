"""Passive vulnerability lookup for technologies a visitor names.

The visitor types, pastes, or selects technologies and versions. For each
one this module asks public databases what is known about that product at
that version. Nothing here contacts a system the visitor runs.

Call path (``run_lookup``):

1. ``_normalize_technologies`` cleans and de-duplicates the input (the
   ``parse_*`` helpers turn a pasted list, JSON, or banner text into that
   input first).
2. ``lookup`` gives every technology exactly one state. Only a technology
   with a usable release version and a product in ``tech_cpe_map.json`` is
   looked up, at most ``MAX_LOOKUPS`` per job, within one time budget. The
   CISA KEV snapshot and the ExploitDB index are loaded once per job, before
   the first lookup.
3. ``enrich_tech`` asks NVD for CVEs where the product itself is vulnerable,
   marks known-exploited CVEs from the KEV snapshot (raising them to at
   least high), attaches ExploitDB references, endoflife.date status, and,
   with a key, AlienVault OTX pulses. One source failing never loses the
   others' answers.
4. ``lookup`` asks EPSS once for the whole job, then ``describe`` words each
   technology's state.
5. ``run_lookup`` adds the overall summary and the finding rows.

Accuracy rules: "checked, none found" is said only when NVD's dictionary
lists that exact version; a pre-release or bracketed pre-release version is
never looked up as the release; a version with fewer than
``MIN_VERSION_PARTS`` parts is never looked up; a count that is unknown is
None, never zero.

Every source answers to ``Settings.offline`` and its own disable flag (see
``lookup_switches``). API keys are passed by value and never logged, stored
in a result, or put in an error message.

``prefill_from_lookup`` turns a finished lookup into the selections and
description text a threat-model form starts from.
"""

from __future__ import annotations

import logging
import re
import threading
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import Timeout as RequestsTimeout

from aegisshield.config import Settings
from aegisshield.core.errors import IntelLookupError, ValidationError
from aegisshield.core.text import redact_keys
from aegisshield.services import eol_service, epss_service, exploitdb_service, kev_service
from aegisshield.services.lookup_switches import source_disabled
from aegisshield.services.tech_products import ProductRef, product_by_pair, product_for

logger = logging.getLogger(__name__)

# Most CVEs ``enrich_tech`` keeps per technology by default. Counts cover
# every CVE NVD returned; only the detail rows are cut, known exploited first.
MAX_CVES_PER_TECH = 25
# CVE rows a job keeps per technology.
MAX_CVE_ROWS = 10
# CVEs asked of NVD per technology: one page, the most nvdlib asks for at
# once. A product with more is marked ``nvd_truncated`` and its counts cover
# only this page.
MAX_NVD_RESULTS = 2000
# A version with fewer dotted parts than this (``2``, ``8.2``) is too vague
# to look up.
MIN_VERSION_PARTS = 3
# Technologies one job accepts, and how many of them are looked up.
MAX_TECHNOLOGIES = 30
MAX_LOOKUPS = 15
# One job's time budget; a lookup is not started with less than
# ``MIN_LOOKUP_SECONDS`` left.
LOOKUP_BUDGET_SECONDS = 300.0
MIN_LOOKUP_SECONDS = 20.0
# EPSS is asked once per job for at most this many CVE ids (the API's default
# page size). Feed loads get at most these many seconds.
MAX_EPSS_IDS = 100
FEED_TIMEOUT_SECONDS = 12.0
EXPLOITDB_TIMEOUT_SECONDS = 30.0
MAX_FIELD_LENGTH = 200

# NVD status of one technology (``TechFinding.nvd_status``).
NVD_CHECKED = "checked"
NVD_NO_VERSION = "no_version"
NVD_PRODUCT_NOT_RECOGNIZED = "product_not_recognized"
NVD_LOOKUP_FAILED = "lookup_failed"
NVD_OVER_BUDGET = "over_budget"
NVD_VERSION_NOT_RECOGNIZED = "version_not_recognized"

# Lookup states (one per technology in the result).
STATE_VULNERABILITIES_FOUND = "vulnerabilities_found"
STATE_CHECKED_NONE_FOUND = "checked_none_found"
STATE_NOT_CHECKED = "not_checked"

REASON_NO_VERSION = NVD_NO_VERSION
REASON_PRODUCT_NOT_RECOGNIZED = NVD_PRODUCT_NOT_RECOGNIZED
REASON_LOOKUP_FAILED = NVD_LOOKUP_FAILED
REASON_OVER_BUDGET = NVD_OVER_BUDGET
REASON_VERSION_NOT_RECOGNIZED = NVD_VERSION_NOT_RECOGNIZED
REASON_CANCELLED = "cancelled"

LOOKUP_COMPLETE = "complete"
LOOKUP_CANCELLED = "cancelled"

DISTRO_NOTE = (
    "This is a distribution build whose fixes may be backported without a "
    "version change, so some listed vulnerabilities may not apply."
)

KEV_MARKER = "Known Exploited (CISA KEV)"

# The only characters a version may carry into a CPE name or a query.
_CPE_VERSION_RE = re.compile(r"^[0-9A-Za-z._-]{1,64}$")
# Ordered low to high so a severity can be raised by taking the max of two.
_SEVERITY_ORDER = ["", "low", "medium", "high", "critical"]

# A version starts with digits and dots, optionally a letter suffix that is
# part of the release name (OpenSSL ``1.1.1w``).
_UPSTREAM_RE = re.compile(r"^\d+(?:\.\d+)*(?:[A-Za-z]+\d*)?")
# A pre-release marker anywhere after the numbers, not inside a longer word:
# no letter right before or after it (``6.4.2~beta1``, ``10.0.0-M1``,
# ``1.2.3-0.rc1.el9``, ``6.4.2 (beta1)``, ``6.4.2 [rc1]``), so ``precise``
# does not count.
_PRERELEASE_RE = re.compile(
    r"(?<![A-Za-z])(?:alpha|beta|rc|pre|preview|dev|snapshot|m(?=\d))(?![A-Za-z])",
    re.IGNORECASE,
)
_NUMERIC_RE = re.compile(r"^\d+(?:\.\d+)*")
_DISTRO_RE = re.compile(
    r"\b(debian|ubuntu|red ?hat|rhel|centos|fedora|amazon linux|amzn|suse|opensuse|"
    r"alpine|rocky|almalinux|alma linux|oracle linux|raspbian)\b",
    re.IGNORECASE,
)
MAX_VERSION_LENGTH = 64


# -- Versions ----------------------------------------------------------------


def _clean(value: object) -> str | None:
    """A printable string capped at ``MAX_FIELD_LENGTH``, or None.

    Anything that is not a string, is empty, or carries a control or format
    character (including bidi overrides) is dropped.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or any(unicodedata.category(ch).startswith("C") for ch in text):
        return None
    return text[:MAX_FIELD_LENGTH]


@dataclass(frozen=True)
class VersionInfo:
    """A version as given, and what is looked up.

    ``lookup`` is the upstream version (distribution and build suffixes
    removed), or None when the text cannot be matched to a release (a
    pre-release, or an unexpected tail). ``distro_build`` is True when the
    version carries a distribution or build suffix, or names a distribution.
    """

    display: str
    lookup: str | None
    distro_build: bool


def parse_version(value: object) -> VersionInfo | None:
    """``2.4.69 (Debian)``, ``1.18.0-0ubuntu1``, ``1.2.3+deb12u1`` to the
    upstream version to look up; None when it is not a version at all."""
    text = _clean(value)
    if text is None or len(text) > MAX_VERSION_LENGTH:
        return None
    bare = text[1:] if text[:1] in {"v", "V"} else text
    match = _UPSTREAM_RE.match(bare)
    if match is None:
        return None
    token, rest = match.group(0), bare[match.end() :]
    numeric = _NUMERIC_RE.match(bare)
    if numeric is not None and _PRERELEASE_RE.search(bare, numeric.end()):
        return VersionInfo(bare, None, False)
    if not rest:
        return VersionInfo(bare, token, False)
    if rest[0] in "-+~":
        return VersionInfo(bare, token, True)
    if rest[0].isspace():
        return VersionInfo(bare, token, bool(_DISTRO_RE.search(rest)))
    return VersionInfo(bare, None, False)


def version_parts(version: str) -> int:
    """Dotted numeric parts at the start of ``version`` (``8.2`` is 2)."""
    match = re.match(r"^\d+(?:\.\d+)*", version or "")
    return len(match.group(0).split(".")) if match else 0


# -- Time budget ---------------------------------------------------------------


class _Deadline:
    """A ``time.monotonic`` deadline."""

    def __init__(self, seconds: float, *, cap: _Deadline | None = None) -> None:
        at = time.monotonic() + seconds
        self.at = min(at, cap.at) if cap is not None else at

    def remaining(self) -> float:
        """Seconds left, never negative."""
        return max(0.0, self.at - time.monotonic())


def call_within(fn: Callable[[], object], seconds: float) -> tuple[bool, object]:
    """Run ``fn`` on a daemon thread and wait at most ``seconds``.

    Returns ``(True, value)``, or ``(False, None)`` when it did not finish in
    time. An exception from ``fn`` is raised here. The thread is abandoned on
    a timeout (it cannot be cancelled) and ends when its own requests give
    up: every outside call made under it has a socket timeout (NVD through
    nvdlib, OTX through ``BoundedOTXv2``, and the KEV, EPSS, ExploitDB, and
    endoflife.date downloads). A socket timeout bounds each wait for bytes,
    so a server that keeps sending slowly can hold the thread longer.
    """
    outcome: dict[str, object] = {}
    finished = threading.Event()

    def run() -> None:
        try:
            outcome["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - handed to the caller below
            outcome["error"] = exc
        finally:
            finished.set()

    threading.Thread(target=run, name="vuln-lookup-call", daemon=True).start()
    if not finished.wait(max(0.0, seconds)):
        return False, None
    error = outcome.get("error")
    if isinstance(error, BaseException):
        raise error
    return True, outcome.get("value")


# -- Input -------------------------------------------------------------------


@dataclass(frozen=True)
class DetectedTech:
    """One technology to look up, as given."""

    name: str
    version: str | None
    source: str  # "selected" | "tech_list" | "json" | "text"
    raw: str

    def key(self) -> str:
        """The de-duplication key: name and version, case-insensitive."""
        return f"{self.name.lower()}|{(self.version or '').lower()}"


# A technology name starts with a letter.
_NAME_START_RE = re.compile(r"^[A-Za-z]")
# A word that may start a version (``2.4.69``, ``v1.18.0``).
_VERSION_START_RE = re.compile(r"^[vV]?\d")
# The name is at most 64 characters, so each start position scans a bounded
# distance: with an open-ended name, a long run such as "-A-A-A..." made
# every position scan to the end of the run (35 s for 200,000 characters).
_BANNER_RE = re.compile(r"\b(?P<name>[A-Za-z][A-Za-z0-9._\-]{0,63})/(?P<version>\d+(?:\.\d+){0,3})\b")


def _split_line(line: str) -> tuple[str, str | None]:
    """``name version`` to ``(name, version)``; ``(line, None)`` with no version.

    The version starts at the first word after the name that begins with a
    digit and runs to the end of the line, and ``parse_version`` decides
    whether that text is a version (``1.1.1w``, ``7.4.3-1+deb11u5``,
    ``2.4.69 (Debian)``, and pre-releases such as ``6.4.2 beta1``, which are
    then reported as not recognized instead of being folded into the name).
    """
    words = line.split()
    for index in range(1, len(words)):
        if not _VERSION_START_RE.match(words[index]):
            continue
        name = " ".join(words[:index])
        version = " ".join(words[index:])
        if _NAME_START_RE.match(name) and parse_version(version) is not None:
            return name, version.removeprefix("v").removeprefix("V")
        break
    return line, None


def parse_tech_list(raw: str) -> list[DetectedTech]:
    """One technology per non-empty line: ``name version`` or just ``name``.

    A line with no version keeps its whole text as the name (keeping only
    the first word would turn ``Microsoft IIS`` into ``Microsoft``, which maps
    to nothing), and versions such as ``1.1.1w`` are kept.
    Lines starting with ``#`` are comments.
    """
    out: list[DetectedTech] = []
    for line in (raw or "").splitlines():
        line = " ".join(line.split())
        if not line or line.startswith("#"):
            continue
        name, version = _split_line(line)
        out.append(DetectedTech(name=name, version=version, source="tech_list", raw=line))
    return out


def parse_json_input(payload: Any) -> list[DetectedTech]:
    """Accept ``[{name, version}]``, ``{technologies: [...]}``, one object, or
    a flat ``{name: version}`` mapping."""
    items: list[Any] = []
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        for key in ("technologies", "tech", "components", "stack"):
            value = payload.get(key)
            if isinstance(value, list):
                items = value
                break
        else:
            if "name" in payload:
                items = [payload]
            else:
                items = [{"name": k, "version": v} for k, v in payload.items() if isinstance(k, str)]
    out: list[DetectedTech] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("product") or "").strip()
        if not name:
            continue
        version = item.get("version") or item.get("ver")
        out.append(
            DetectedTech(
                name=name,
                version=str(version) if version is not None else None,
                source="json",
                raw=str(item),
            )
        )
    return out


def parse_text(raw: str) -> list[DetectedTech]:
    """``Name/X.Y.Z`` banners in free text (``nginx/1.18.0``, ``OpenSSH/8.9``).

    Deterministic, so it needs no model and tests stay hermetic.
    """
    if not raw:
        return []
    seen: set[str] = set()
    out: list[DetectedTech] = []
    for match in _BANNER_RE.finditer(raw):
        name, version = match.group("name"), match.group("version")
        if name.lower() in {"http", "https"}:
            continue
        key = f"{name.lower()}|{version.lower()}"
        if key in seen:
            continue
        seen.add(key)
        out.append(DetectedTech(name=name, version=version, source="text", raw=match.group(0)))
    return out


def _normalize_technologies(technologies: Sequence[DetectedTech | Mapping[str, Any]]) -> list[dict]:
    """``{name, version, source, distro}`` per usable, distinct technology.

    Names and versions with control characters are dropped (a name) or
    treated as missing (a version). Raises ``ValidationError`` above
    ``MAX_TECHNOLOGIES``.
    """
    out: list[dict] = []
    seen: set[str] = set()
    for item in technologies or []:
        if isinstance(item, DetectedTech):
            name, version, source, distro = item.name, item.version, item.source, False
        elif isinstance(item, Mapping):
            name, version = item.get("name"), item.get("version")
            source = item.get("source") if isinstance(item.get("source"), str) else "selected"
            distro = bool(item.get("distro"))
        else:
            continue
        name = _clean(name)
        if name is None:
            continue
        version = _clean(version) if version is not None else None
        key = f"{name.lower()}|{(version or '').lower()}"
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "version": version, "source": source, "distro": distro})
    if len(out) > MAX_TECHNOLOGIES:
        raise ValidationError(f"A lookup takes at most {MAX_TECHNOLOGIES} technologies.")
    return out


# -- NVD ---------------------------------------------------------------------


class NvdLookupError(IntelLookupError):
    """The NVD lookup did not produce an answer.

    ``source`` says what failed: ``nvd`` (NVD answered with an error, or the
    client library is missing), ``network`` (no connection or a timeout), or
    ``disabled`` (lookups are switched off on this deployment).
    """

    def __init__(self, source: str, message: str) -> None:
        super().__init__(message)
        self.source = source


def _nvd_kwargs(api_key: str) -> dict:
    # nvdlib sleeps 6 seconds after every request unless a key AND a delay
    # are passed (0.6 is the shortest it accepts). Without a key the lookup
    # still works, just slower.
    return {"key": api_key, "delay": 0.6} if api_key else {}


def _default_nvd_search_cpe(match_string: str, api_key: str) -> list:
    import nvdlib  # noqa: PLC0415 - heavy import, only when a lookup runs

    return nvdlib.searchCPE(cpeMatchString=match_string, **_nvd_kwargs(api_key))


def _default_nvd_search_cve(cpe_name: str, api_key: str) -> list:
    import nvdlib  # noqa: PLC0415 - heavy import, only when a lookup runs

    # isVulnerable: a CVE record can name a product only as the platform
    # another, vulnerable product runs on. Without this filter NVD returns
    # those too, and they would be reported against the wrong software.
    return nvdlib.searchCVE(cpeName=cpe_name, isVulnerable=True, **_nvd_kwargs(api_key),
                            limit=MAX_NVD_RESULTS)


# The two calls that reach NVD. Tests replace these names.
_nvd_search_cpe = _default_nvd_search_cpe
_nvd_search_cve = _default_nvd_search_cve

_CPE_FIELD_SPLIT = re.compile(r"(?<!\\):")


def _cpe_fields(cpe_name: str) -> list[str]:
    return _CPE_FIELD_SPLIT.split(cpe_name or "")


def _cpe_vendor_product(cpe_name: str) -> tuple[str, str] | None:
    parts = _cpe_fields(cpe_name)
    if len(parts) < 5:
        return None
    return parts[3].lower(), parts[4].lower()


def _pick_cpe_name(cpe_results: list, ref: ProductRef, version: str) -> tuple[str, bool]:
    """``(cpe_name, exact)``: the CPE name to search CVEs with, and whether
    NVD's dictionary has a release entry for this product at exactly this
    version.

    An entry counts only when its vendor and product are one of the mapped
    product's accepted pairs and its version field equals ``version``. A
    deprecated entry is followed to its replacement only when the
    replacement is an accepted pair too. Only a release entry (update ``*``
    or ``-``) is exact: a version listed only as a variant such as ``beta1``
    is not. With no release entry, the name is built from the main pair and
    the version: NVD still matches it against the version ranges in its CVE
    records, but the dictionary does not vouch for the version.
    """
    accepted = {(v.lower(), p.lower()) for v, p in (ref.accepted or ((ref.vendor, ref.product),))}
    candidates: list[str] = []
    for cpe in cpe_results or []:
        name = getattr(cpe, "cpeName", "") or ""
        fields = _cpe_fields(name)
        if len(fields) < 6 or _cpe_vendor_product(name) not in accepted:
            continue
        if fields[5].lower() != version.lower():
            continue
        if getattr(cpe, "deprecated", False):
            replacements = [
                r.cpeName
                for r in getattr(cpe, "deprecatedBy", None) or []
                if _cpe_vendor_product(getattr(r, "cpeName", "")) in accepted
            ]
            if not replacements:
                continue
            name = replacements[0]
        candidates.append(name)
    for name in candidates:
        fields = _cpe_fields(name)
        if (fields[6] if len(fields) > 6 else "*") in {"*", "-"}:
            return name, True
    return f"cpe:2.3:a:{ref.vendor}:{ref.product}:{version}:*:*:*:*:*:*:*", False


def _cvss_v4(cve: Any) -> tuple[float | None, str | None]:
    """Base score and severity from a CVSS 4.0 metric (nvdlib's ``score``
    covers CVSS 3.1, 3.0, and 2 only)."""
    metrics = getattr(getattr(cve, "metrics", None), "cvssMetricV40", None) or []
    data = getattr(metrics[0], "cvssData", None) if metrics else None
    return getattr(data, "baseScore", None), getattr(data, "baseSeverity", None)


# nvdlib names the CVSS version of ``score`` as V31, V30, or V2.
_CVSS_VERSIONS = {"V40": "4.0", "V31": "3.1", "V30": "3.0", "V2": "2.0"}


def _cve_row(cve: Any) -> dict:
    score = getattr(cve, "score", None) or [None, None, None]
    severity = score[2] if isinstance(score, list) and len(score) >= 3 else None
    cvss = score[1] if isinstance(score, list) and len(score) >= 2 else None
    label = score[0] if isinstance(score, list) and score else None
    cvss_version = _CVSS_VERSIONS.get(label) if cvss is not None and isinstance(label, str) else None
    if cvss is None:
        cvss, severity = _cvss_v4(cve)
        cvss_version = "4.0" if cvss is not None else None
    descriptions = getattr(cve, "descriptions", []) or []
    description = descriptions[0].value if descriptions else ""
    references = [r.url for r in getattr(cve, "references", []) or []][:5]
    return {
        "cve_id": getattr(cve, "id", None),
        "cvss_score": cvss,
        "cvss_version": cvss_version,
        "severity": severity,
        "published": (getattr(cve, "published", "") or "").split("T", 1)[0],
        "description": description,
        "references": references,
        "url": f"https://nvd.nist.gov/vuln/detail/{getattr(cve, 'id', '')}",
    }


@dataclass(frozen=True)
class NvdAnswer:
    """What NVD said about one product at one version.

    ``exact_version`` is True when NVD's CPE dictionary lists the product at
    exactly that version; only then may an empty ``cves`` be reported as
    "checked, none found".
    ``truncated`` is True when NVD returned a full page
    (``MAX_NVD_RESULTS``), so it may list more than ``cves`` holds.
    """

    cves: list[dict]
    exact_version: bool
    truncated: bool = False


def sort_cves(rows: list[dict]) -> list[dict]:
    """Highest CVSS score first, missing scores last, newest first on a tie."""
    by_date = sorted(rows, key=lambda r: r.get("published") or "", reverse=True)
    return sorted(
        by_date, key=lambda r: (r.get("cvss_score") is None, -(r.get("cvss_score") or 0.0))
    )


def prioritize_cves(rows: list[dict]) -> list[dict]:
    """Known exploited (CISA KEV) first, then ``sort_cves`` order."""
    return sorted(sort_cves(rows), key=lambda r: r.get("known_exploited") is not True)


def _default_nvd_lookup(tech_name: str, version: str | None, api_key: str) -> NvdAnswer:
    """Every CVE NVD lists for the mapped product at this version, and
    whether its dictionary has that exact version.

    Asks nothing and returns an empty, not-exact answer when the technology
    has no version, no mapped product, or a version that is not safe to put
    in a CPE name. Raises ``NvdLookupError`` when the lookup could not be
    made, so a caller never mistakes a failure for "none found". Works
    without an API key.
    """
    ref = product_for(tech_name)
    if not version or ref is None or not _CPE_VERSION_RE.match(version):
        return NvdAnswer([], exact_version=False)
    if source_disabled("nvd"):
        raise NvdLookupError("disabled", "NVD lookups are switched off on this deployment.")

    match_string = f"cpe:2.3:a:{ref.vendor}:{ref.product}:{version}:*"
    try:
        cpe_results = _nvd_search_cpe(match_string, api_key)
        cpe_name, exact = _pick_cpe_name(cpe_results, ref, version)
        cve_rows = _nvd_search_cve(cpe_name, api_key)
    except (RequestsConnectionError, RequestsTimeout) as exc:
        logger.warning("nvd_lookup_network_failed product=%s:%s", ref.vendor, ref.product)
        raise NvdLookupError("network", f"Could not reach NVD ({type(exc).__name__}).") from None
    except Exception as exc:
        # nvdlib raises many types (HTTP errors, LookupError, JSON errors).
        # Any of them means NVD gave no answer; the text is not kept because
        # it can quote the request.
        logger.warning(
            "nvd_lookup_failed product=%s:%s error_type=%s",
            ref.vendor,
            ref.product,
            type(exc).__name__,
        )
        raise NvdLookupError("nvd", f"NVD lookup failed ({type(exc).__name__}).") from None

    rows = list(cve_rows or [])
    return NvdAnswer(sort_cves([_cve_row(cve) for cve in rows]), exact_version=exact,
                     truncated=len(rows) >= MAX_NVD_RESULTS)


def _default_otx_lookup(tech_name: str, api_key: str) -> list[dict]:
    """Up to ten OTX pulses that mention the technology (needs a key)."""
    if not api_key or not tech_name:
        return []
    from aegisshield.core.otx import BoundedOTXv2  # noqa: PLC0415 - only with a key

    result = BoundedOTXv2(api_key).search_pulses(tech_name, max_results=10)
    pulses = result.get("results", []) if isinstance(result, dict) else []
    out: list[dict] = []
    for pulse in pulses[:10]:
        if not isinstance(pulse, dict):
            continue
        pulse_id = pulse.get("id")
        out.append(
            {
                "id": pulse_id,
                "name": pulse.get("name"),
                "tlp": pulse.get("TLP"),
                "modified": pulse.get("modified"),
                "tags": pulse.get("tags", []),
                "url": f"https://otx.alienvault.com/pulse/{pulse_id}" if pulse_id else None,
            }
        )
    return out


# Tests replace these names.
nvd_lookup = _default_nvd_lookup
otx_lookup = _default_otx_lookup


# -- Feeds ---------------------------------------------------------------------

# One short attempt per feed: a feed that is down must not eat the job's
# time budget once per CVE.
_KEV_PROBE_CONFIG = kev_service.KevConfig(max_retries=1, timeout_seconds=10.0)
_EPSS_CONFIG = epss_service.EpssConfig(max_retries=1, timeout_seconds=10.0)


@dataclass
class FeedAvailability:
    """What the secondary feeds can answer during one job.

    ``kev`` is a snapshot of the CISA KEV catalog taken once per job, or None
    when it is unknown. ``exploitdb`` and ``epss``: True to use, False when
    unavailable (recorded as an error), None when the caller does not use
    them in ``enrich_tech`` (``lookup`` fetches EPSS once per job itself).
    EPSS is switched off for the rest of the job after a failure.
    """

    kev: dict[str, kev_service.KevRecord] | None = None
    exploitdb: bool | None = True
    epss: bool | None = True


def probe_feeds(settings: Settings | None = None) -> FeedAvailability:
    """One KEV snapshot and the ExploitDB index (one attempt each)."""
    return FeedAvailability(
        kev=kev_service.catalog_snapshot(_KEV_PROBE_CONFIG, settings=settings),
        exploitdb=exploitdb_service.index_available(settings=settings),
    )


def fetch_epss_once(
    cve_ids: list[str], settings: Settings | None = None
) -> dict[str, epss_service.EpssScore]:
    """One EPSS request for a whole job (one attempt). Raises on failure."""
    return epss_service.fetch_scores(cve_ids, _EPSS_CONFIG, settings=settings)


def _severity_is(cve: dict, level: str) -> bool:
    return (cve.get("severity") or "").lower() == level


def _escalate_severity(current: str | None) -> str:
    """A CVE confirmed exploited in the wild is at least high; critical stays."""
    value = (current or "").strip().lower()
    cur_rank = _SEVERITY_ORDER.index(value) if value in _SEVERITY_ORDER else 0
    return _SEVERITY_ORDER[max(cur_rank, _SEVERITY_ORDER.index("high"))]


# -- One technology --------------------------------------------------------------


@dataclass
class TechFinding:
    """Everything the sources said about one technology."""

    tech: dict[str, Any]
    cves: list[dict] = field(default_factory=list)
    exploits: list[dict] = field(default_factory=list)
    eol: dict | None = None
    otx_pulses: list[dict] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    # Whether NVD was actually asked, and if not, why (an ``NVD_*`` value).
    # Only ``checked`` means an empty ``cves`` list is a real "none found".
    nvd_status: str = NVD_CHECKED
    # ``nvd``, ``network``, or ``disabled`` when ``nvd_status`` is lookup_failed.
    nvd_failed_source: str | None = None
    # NVD returned a full page (``MAX_NVD_RESULTS``) and may list more.
    nvd_truncated: bool = False
    # Counts over every CVE NVD returned. ``kev_total`` is None when the KEV
    # catalog was unavailable: unknown, not zero.
    cve_total: int = 0
    critical_total: int = 0
    high_total: int = 0
    kev_total: int | None = 0

    def to_dict(self) -> dict:
        """The finding as a JSON-ready dict."""
        return {
            "tech": self.tech,
            "cves": self.cves,
            "exploits": self.exploits,
            "eol": self.eol,
            "otx_pulses": self.otx_pulses,
            "errors": self.errors,
            "nvd_status": self.nvd_status,
            "nvd_failed_source": self.nvd_failed_source,
            "summary": {
                "cve_count": self.cve_total,
                "critical_count": self.critical_total,
                "high_count": self.high_total,
                "exploit_count": len(self.exploits),
                "kev_count": self.kev_total,
                "is_eol": bool(self.eol and self.eol.get("is_eol")),
                "otx_count": len(self.otx_pulses),
            },
        }


def _ask_nvd(finding: TechFinding, tech: DetectedTech, nvd_api_key: str, settings: Settings | None) -> list[dict]:
    """The CVE rows for an eligible technology; records failures on ``finding``."""
    try:
        if source_disabled("nvd", settings):
            raise NvdLookupError("disabled", "NVD lookups are switched off on this deployment.")
        answer = nvd_lookup(tech.name, tech.version, nvd_api_key)
    except NvdLookupError as exc:
        finding.nvd_status = NVD_LOOKUP_FAILED
        finding.nvd_failed_source = exc.source
        finding.errors["nvd"] = redact_keys(str(exc), nvd_api_key)
        return []
    except Exception as exc:
        # A replaced ``nvd_lookup`` may raise anything; it is still a failed
        # lookup, never "none found". Logged by type only.
        logger.warning("nvd_lookup_crashed error_type=%s", type(exc).__name__)
        finding.nvd_status = NVD_LOOKUP_FAILED
        finding.nvd_failed_source = "nvd"
        finding.errors["nvd"] = "NVD lookup failed."
        return []
    finding.nvd_truncated = bool(getattr(answer, "truncated", False))
    if answer.exact_version or answer.cves:
        return sort_cves(list(answer.cves))
    finding.nvd_status = NVD_VERSION_NOT_RECOGNIZED
    return []


def _mark_known_exploited(finding: TechFinding, cves: list[dict], feeds: FeedAvailability) -> None:
    """Mark every CVE from the job's KEV snapshot (never a download here).

    A known-exploited CVE is raised to at least high and carries the KEV
    marker. Without a snapshot the answer is unknown (None), never "not
    exploited".
    """
    if not cves:
        return
    if feeds.kev is None:
        for cve in cves:
            cve["known_exploited"] = None
        finding.errors["kev"] = "CISA KEV catalog unavailable."
        return
    for cve in cves:
        cve_id = (cve.get("cve_id") or "").strip().upper()
        record = feeds.kev.get(cve_id) if cve_id else None
        if record is not None:
            cve["known_exploited"] = True
            cve["kev_marker"] = KEV_MARKER
            cve["kev"] = record.to_dict()
            cve["severity"] = _escalate_severity(cve.get("severity"))
        else:
            cve["known_exploited"] = False


def enrich_tech(
    tech: DetectedTech,
    *,
    nvd_api_key: str | None = None,
    otx_api_key: str | None = None,
    feeds: FeedAvailability | None = None,
    deadline: float | None = None,
    max_cves: int = MAX_CVES_PER_TECH,
    settings: Settings | None = None,
) -> TechFinding:
    """Look one technology up in NVD, KEV, EPSS, ExploitDB, endoflife.date, and OTX.

    Never raises: each source records its own failure in ``errors`` and
    ``nvd_status`` says whether NVD was actually asked and could answer.
    "Checked" with no CVEs requires NVD's dictionary to list this exact
    version; CVEs matched through a version range count without it. A
    version with fewer than ``MIN_VERSION_PARTS`` parts is never looked up.
    ``deadline`` is a ``time.monotonic()`` value; a source that would start
    after it is skipped (NVD as ``over_budget``). OTX is asked only with a key
    and when it is not switched off.
    """
    if feeds is None:
        feeds = probe_feeds(settings)
    nvd_key = nvd_api_key or ""

    def past_deadline() -> bool:
        return deadline is not None and time.monotonic() >= deadline

    finding = TechFinding(
        tech={"name": tech.name, "version": tech.version, "source": tech.source, "raw": tech.raw}
    )
    ref = product_for(tech.name)

    all_cves: list[dict] = []
    if not tech.version:
        finding.nvd_status = NVD_NO_VERSION
    elif ref is None:
        finding.nvd_status = NVD_PRODUCT_NOT_RECOGNIZED
    elif not _CPE_VERSION_RE.match(tech.version) or version_parts(tech.version) < MIN_VERSION_PARTS:
        finding.nvd_status = NVD_VERSION_NOT_RECOGNIZED
    elif past_deadline():
        finding.nvd_status = NVD_OVER_BUDGET
    else:
        all_cves = _ask_nvd(finding, tech, nvd_key, settings)

    _mark_known_exploited(finding, all_cves, feeds)
    all_cves = prioritize_cves(all_cves)
    finding.cve_total = len(all_cves)
    finding.critical_total = sum(1 for c in all_cves if _severity_is(c, "critical"))
    finding.high_total = sum(1 for c in all_cves if _severity_is(c, "high"))
    finding.kev_total = (
        None if "kev" in finding.errors else sum(1 for c in all_cves if c.get("known_exploited"))
    )
    cves = all_cves[:max_cves]
    finding.cves = cves

    if feeds.exploitdb is None:
        pass  # not used by this caller
    elif cves and feeds.exploitdb and not past_deadline():
        try:
            for cve in cves:
                cve_id = cve.get("cve_id")
                for exploit in exploitdb_service.find_for_cve(cve_id, settings=settings) if cve_id else []:
                    finding.exploits.append({**exploit.to_dict(), "cve_id": cve_id})
        except Exception as exc:
            # Best effort: an ExploitDB failure must not lose NVD's answer.
            logger.warning("exploitdb_lookup_failed error_type=%s", type(exc).__name__)
            finding.errors["exploitdb"] = "ExploitDB lookup failed."
    elif cves:
        finding.errors["exploitdb"] = "ExploitDB index unavailable."

    cve_ids = [c.get("cve_id") for c in cves if c.get("cve_id")]
    if feeds.epss is None:
        pass  # the caller fetches EPSS itself
    elif cve_ids and feeds.epss and not past_deadline():
        try:
            scores = epss_service.fetch_scores(cve_ids, _EPSS_CONFIG, settings=settings)
            for cve in cves:
                score = scores.get((cve.get("cve_id") or "").strip().upper())
                if score is not None:
                    cve["epss"] = score.epss
                    cve["epss_percentile"] = score.percentile
        except Exception as exc:
            # Best effort, and not retried for the rest of the job.
            logger.warning("epss_lookup_failed error_type=%s", type(exc).__name__)
            finding.errors["epss"] = "EPSS scores unavailable."
            feeds.epss = False
    elif cve_ids:
        finding.errors["epss"] = "EPSS scores unavailable."

    if not past_deadline():
        try:
            eol = eol_service.check_eol(
                ref.eol if ref and ref.eol else tech.name, tech.version, settings=settings
            )
            finding.eol = eol.to_dict() if eol else None
        except Exception as exc:
            # Best effort: end-of-life status is extra context.
            logger.warning("eol_lookup_failed error_type=%s", type(exc).__name__)
            finding.errors["eol"] = "endoflife.date lookup failed."

    if otx_api_key:
        if source_disabled("otx", settings):
            finding.errors["otx"] = "OTX lookups are switched off on this deployment."
        else:
            try:
                finding.otx_pulses = otx_lookup(tech.name, otx_api_key)
            except Exception as exc:
                # The OTX client raises its own types; the text is not kept
                # because it can quote the request.
                logger.warning("otx_lookup_failed error_type=%s", type(exc).__name__)
                finding.errors["otx"] = "OTX lookup failed."

    return finding


# -- The job -----------------------------------------------------------------

_ANSWERED_STATES = (STATE_VULNERABILITIES_FOUND, STATE_CHECKED_NONE_FOUND)


def _entry(tech: dict, *, state: str, reason: str | None = None) -> dict:
    """One technology in the result contract.

    Counts are None unless NVD was actually asked: unknown is not zero.
    ``product`` and ``product_name`` come from the mapping file (never the
    name as typed), so a form can match the technology exactly and name it
    safely. ``description`` is filled in once the state is final.
    """
    info = parse_version(tech["version"]) if tech["version"] else None
    distro = bool(tech.get("distro")) or bool(info and info.distro_build)
    ref = product_for(tech["name"])
    return {
        "name": tech["name"],
        "version": tech["version"],
        "lookup_version": info.lookup if info else None,
        "product": f"{ref.vendor}:{ref.product}" if ref else None,
        "product_name": ref.name if ref else None,
        "source": tech["source"],
        "state": state,
        "reason": reason,
        "failed_source": None,
        "cve_count": None,
        "critical_count": None,
        "high_count": None,
        "kev_count": None,
        "nvd_truncated": False,
        "eol": None,
        # The note is about listed vulnerabilities, so only an answer
        # (found, or none found) carries it.
        "note": DISTRO_NOTE if distro and tech["version"] and state in _ANSWERED_STATES else None,
        "description": None,
    }


class LookupProgress(Protocol):
    """Where a job reports progress (``aegisshield.jobs.ProgressSink`` fits)."""

    def set(self, record: dict[str, Any]) -> None:
        """Replace the progress record."""


@dataclass
class LookupOutcome:
    """What ``lookup`` found.

    ``entries`` is the result contract, in input order. ``cves`` maps an
    entry's index to its CVE rows (at most ``MAX_CVE_ROWS``, known exploited
    first, then by score). ``extras`` maps an index to its ``exploits``,
    ``otx_pulses``, and ``errors``.
    """

    entries: list[dict]
    cves: dict[int, list[dict]]
    extras: dict[int, dict]
    cancelled: bool = False


def _label(entry: Mapping[str, Any]) -> str:
    return f"{entry['name']} {entry['version']}" if entry.get("version") else str(entry["name"])


def _report(progress: LookupProgress | None, done: int, total: int, message: str) -> None:
    if progress is not None:
        progress.set({"stage": "lookup", "done": done, "total": total, "message": message})


def _is_cancelled(progress: LookupProgress | None) -> bool:
    check = getattr(progress, "cancelled", None)
    return bool(check()) if callable(check) else False


def _load_feeds(deadline: _Deadline, settings: Settings | None) -> FeedAvailability:
    """The job's KEV snapshot and ExploitDB index, each within its timeout.

    A load that does not finish in time is unknown (KEV) or unavailable
    (ExploitDB). EPSS is fetched once per job by ``lookup`` instead.
    """
    finished, kev = call_within(
        lambda: kev_service.catalog_snapshot(_KEV_PROBE_CONFIG, settings=settings),
        min(FEED_TIMEOUT_SECONDS, deadline.remaining()),
    )
    if not finished:
        logger.warning("vuln_lookup_kev_load_abandoned")
    finished_edb, exploitdb = call_within(
        lambda: exploitdb_service.index_available(settings=settings),
        min(EXPLOITDB_TIMEOUT_SECONDS, deadline.remaining()),
    )
    if not finished_edb:
        logger.warning("vuln_lookup_exploitdb_load_abandoned")
    return FeedAvailability(
        kev=kev if finished and isinstance(kev, dict) else None,
        exploitdb=bool(exploitdb) if finished_edb else False,
        epss=None,
    )


def _attach_epss(cves: dict[int, list[dict]], deadline: _Deadline, settings: Settings | None) -> None:
    """One EPSS request for the job's rows (known exploited first, at most
    ``MAX_EPSS_IDS``). On any failure no row gets a score: absent, not zero."""
    ids: list[str] = []
    for rows in cves.values():
        for cve in rows:
            cve_id = (cve.get("cve_id") or "").strip().upper()
            if cve_id and cve_id not in ids:
                ids.append(cve_id)
    ids = ids[:MAX_EPSS_IDS]
    seconds = min(FEED_TIMEOUT_SECONDS, deadline.remaining())
    if not ids or seconds < 1.0:
        return
    try:
        finished, scores = call_within(lambda: fetch_epss_once(ids, settings), seconds)
    except Exception as exc:
        # Best effort: EPSS only ranks rows; their counts stand without it.
        logger.warning("vuln_lookup_epss_failed error_type=%s", type(exc).__name__)
        return
    if not finished or not isinstance(scores, dict):
        return
    for rows in cves.values():
        for cve in rows:
            score = scores.get((cve.get("cve_id") or "").strip().upper())
            if score is not None:
                cve["epss"] = score.epss
                cve["epss_percentile"] = score.percentile


def _entry_from_finding(tech: dict, finding: TechFinding) -> dict:
    if finding.nvd_status == NVD_CHECKED:
        state = STATE_VULNERABILITIES_FOUND if finding.cve_total else STATE_CHECKED_NONE_FOUND
        entry = _entry(tech, state=state)
        entry["cve_count"] = finding.cve_total
        entry["critical_count"] = finding.critical_total
        entry["high_count"] = finding.high_total
        entry["kev_count"] = finding.kev_total
        entry["nvd_truncated"] = finding.nvd_truncated
    elif finding.nvd_status == NVD_LOOKUP_FAILED:
        entry = _entry(tech, state=STATE_NOT_CHECKED, reason=REASON_LOOKUP_FAILED)
        entry["failed_source"] = finding.nvd_failed_source
    else:
        # Every other status is one of the not-checked reasons.
        entry = _entry(tech, state=STATE_NOT_CHECKED, reason=finding.nvd_status)
    if finding.eol:
        entry["eol"] = {
            "is_eol": bool(finding.eol.get("is_eol")),
            "cycle": finding.eol.get("cycle"),
            "eol": finding.eol.get("eol"),
            "url": finding.eol.get("url"),
        }
    return entry


def lookup(
    technologies: list[dict],
    *,
    nvd_api_key: str | None = None,
    otx_api_key: str | None = None,
    settings: Settings | None = None,
    deadline: _Deadline | None = None,
    progress: LookupProgress | None = None,
) -> LookupOutcome:
    """Look up each technology and give it exactly one state.

    ``technologies`` are ``{name, version, source, distro}`` dicts. Only a
    technology with a usable version and a recognized product is looked up,
    by its upstream version, at most ``MAX_LOOKUPS`` of them, each started
    only with at least ``MIN_LOOKUP_SECONDS`` left on ``deadline`` and
    abandoned when it runs past it (``over_budget``). KEV and ExploitDB are
    loaded once and EPSS is asked once, for the whole job. A cancel seen on
    ``progress`` stops the job; the rest are not checked (``cancelled``).
    """
    deadline = deadline or _Deadline(LOOKUP_BUDGET_SECONDS)
    outcome = LookupOutcome(entries=[], cves={}, extras={})
    feeds: FeedAvailability | None = None
    looked_up = 0
    total = len(technologies)

    for index, tech in enumerate(technologies):
        if outcome.cancelled or _is_cancelled(progress):
            outcome.cancelled = True
            outcome.entries.append(_entry(tech, state=STATE_NOT_CHECKED, reason=REASON_CANCELLED))
            continue
        _report(progress, index, total, f"Looking up {_label(tech)} ({index + 1} of {total})")
        info = parse_version(tech["version"]) if tech["version"] else None
        if not tech["version"]:
            reason: str | None = REASON_NO_VERSION
        elif product_for(tech["name"]) is None:
            reason = REASON_PRODUCT_NOT_RECOGNIZED
        elif info is None or info.lookup is None:
            reason = REASON_VERSION_NOT_RECOGNIZED
        elif looked_up >= MAX_LOOKUPS or deadline.remaining() < MIN_LOOKUP_SECONDS:
            reason = REASON_OVER_BUDGET
        else:
            reason = None
        if reason is not None:
            outcome.entries.append(_entry(tech, state=STATE_NOT_CHECKED, reason=reason))
            continue

        looked_up += 1
        if feeds is None:
            feeds = _load_feeds(deadline, settings)
        finished, finding = call_within(
            lambda tech=tech, feeds=feeds, version=info.lookup: enrich_tech(
                DetectedTech(name=tech["name"], version=version, source=tech["source"], raw=tech["name"]),
                nvd_api_key=nvd_api_key,
                otx_api_key=otx_api_key,
                feeds=feeds,
                deadline=deadline.at,
                max_cves=MAX_CVE_ROWS,
                settings=settings,
            ),
            deadline.remaining(),
        )
        if not finished or not isinstance(finding, TechFinding):
            logger.warning("vuln_lookup_abandoned index=%d", index)
            outcome.entries.append(_entry(tech, state=STATE_NOT_CHECKED, reason=REASON_OVER_BUDGET))
            continue
        outcome.entries.append(_entry_from_finding(tech, finding))
        if finding.nvd_status == NVD_CHECKED and finding.cves:
            outcome.cves[index] = finding.cves[:MAX_CVE_ROWS]
        outcome.extras[index] = {
            "exploits": finding.exploits,
            "otx_pulses": finding.otx_pulses,
            "errors": {
                k: redact_keys(v, nvd_api_key or "", otx_api_key or "")
                for k, v in finding.errors.items()
            },
        }

    if not outcome.cancelled:
        _attach_epss(outcome.cves, deadline, settings)
    for entry in outcome.entries:
        entry["description"] = describe(entry)
    return outcome


# -- Plain-language wording ----------------------------------------------------

_FAILED_SOURCE_TEXT = {
    "nvd": "NVD returned an error",
    "network": "the network request to NVD failed",
    "disabled": "vulnerability lookups are switched off on this deployment",
}

_NOT_CHECKED_TEXT = {
    REASON_NO_VERSION: "no version was given, so it was not checked",
    REASON_PRODUCT_NOT_RECOGNIZED: "not checked; this product is not in the lookup catalog",
    REASON_OVER_BUDGET: "not checked; this lookup reached its limit",
    REASON_VERSION_NOT_RECOGNIZED: (
        "not checked; NVD does not recognize this version, so no answer could be trusted"
    ),
    REASON_CANCELLED: "not checked; the lookup was cancelled",
}


def describe(entry: Mapping[str, Any]) -> str:
    """One technology's state in plain words."""
    label = _label(entry)
    if entry["state"] == STATE_VULNERABILITIES_FOUND:
        count = entry["cve_count"]
        parts = [f"{entry['critical_count']} critical", f"{entry['high_count']} high"]
        if entry["kev_count"] is None:
            parts.append("known-exploited status unknown")
        else:
            parts.append(f"{entry['kev_count']} known exploited")
        noun = "vulnerability" if count == 1 else "vulnerabilities"
        text = f"{label}: {count} known {noun} in NVD ({', '.join(parts)})"
    elif entry["state"] == STATE_CHECKED_NONE_FOUND:
        text = f"{label}: checked against NVD, no known vulnerabilities listed for this version"
    elif entry["reason"] == REASON_LOOKUP_FAILED:
        why = _FAILED_SOURCE_TEXT.get(entry.get("failed_source") or "", "the lookup failed")
        text = f"{label}: not checked; {why}"
    else:
        text = f"{label}: {_NOT_CHECKED_TEXT.get(entry['reason'], 'not checked')}"
    eol = entry.get("eol")
    if eol and eol.get("is_eol"):
        text += "; this release is past end of life"
    text += "."
    if entry.get("note"):
        text += f" {entry['note']}"
    return text


def _cve_severity(cve: Mapping[str, Any]) -> str:
    severity = (cve.get("severity") or "").strip().lower()
    return severity if severity in {"critical", "high", "medium", "low"} else "info"


def describe_cve(entry: Mapping[str, Any], cve: Mapping[str, Any]) -> str:
    """One CVE row in plain words."""
    score = cve.get("cvss_score")
    parts = [
        f"{cve.get('cve_id')} in {_label(entry)}",
        f"CVSS {score}" if score is not None else "no CVSS score yet",
    ]
    if cve.get("known_exploited"):
        parts.append("known exploited (CISA KEV)")
    elif cve.get("known_exploited") is None:
        parts.append("known-exploited status unknown")
    if cve.get("epss") is not None:
        parts.append(f"EPSS {float(cve['epss']) * 100:.1f}%")
    parts.append(str(cve.get("url") or ""))
    return "; ".join(part for part in parts if part)


def build_rows(entries: list[dict], cves: Mapping[int, list[dict]]) -> list[dict]:
    """Finding rows: one ``info`` row per technology (source ``lookup``) and
    one row per kept CVE (source ``nvd``, known exploited first)."""
    rows: list[dict] = []
    for index, entry in enumerate(entries):
        rows.append(
            {"severity": "info", "source": "lookup", "technology": _label(entry), "finding": describe(entry)}
        )
        for cve in cves.get(index, []):
            rows.append(
                {
                    "severity": _cve_severity(cve),
                    "source": "nvd",
                    "technology": _label(entry),
                    "finding": describe_cve(entry, cve),
                }
            )
    return rows


def _summarize(technologies: list[dict]) -> dict:
    """The overall counts. A count no technology could answer is None.

    An unknown KEV count is not summed as zero: one unknown makes the total
    unknown, and with nothing checked every CVE count is unknown.
    """
    checked = [t for t in technologies if t["state"] in _ANSWERED_STATES]
    found = [t for t in checked if t["state"] == STATE_VULNERABILITIES_FOUND]

    def total(key: str) -> int | None:
        if not checked or any(t.get(key) is None for t in checked):
            return None
        return sum(t[key] for t in checked)

    exploit_unknown = any("exploitdb" in t.get("errors", {}) for t in found)
    return {
        "tech_count": len(technologies),
        "checked_count": len(checked),
        "not_checked_count": len(technologies) - len(checked),
        "cve_count": total("cve_count"),
        "critical_count": total("critical_count"),
        "high_count": total("high_count"),
        "kev_count": total("kev_count"),
        "exploit_count": (
            None if exploit_unknown or not checked else sum(len(t.get("exploits", [])) for t in checked)
        ),
        "eol_count": sum(1 for t in technologies if t.get("eol") and t["eol"].get("is_eol")),
    }


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def run_lookup(
    technologies: Sequence[DetectedTech | Mapping[str, Any]],
    *,
    nvd_api_key: str | None = None,
    otx_api_key: str | None = None,
    settings: Settings,
    progress: LookupProgress | None = None,
) -> dict:
    """Look up the given technologies and return the result document.

    ``technologies`` are ``DetectedTech`` records or ``{name, version}``
    mappings (see the ``parse_*`` helpers for pasted input). Returns::

        {"status": "complete" | "cancelled", "started_at", "finished_at",
         "technologies": [entry + cves, exploits, otx_pulses, errors],
         "rows": [...], "summary": {...}}

    Raises ``ValidationError`` for more than ``MAX_TECHNOLOGIES``. Keys are
    used for the calls only and never appear in the result.
    """
    started_at = _now()
    cleaned = _normalize_technologies(technologies)
    outcome = lookup(
        cleaned,
        nvd_api_key=nvd_api_key,
        otx_api_key=otx_api_key,
        settings=settings,
        progress=progress,
    )
    merged: list[dict] = []
    for index, entry in enumerate(outcome.entries):
        extras = outcome.extras.get(index, {})
        merged.append(
            {
                **entry,
                "cves": outcome.cves.get(index, []),
                "exploits": extras.get("exploits", []),
                "otx_pulses": extras.get("otx_pulses", []),
                "errors": extras.get("errors", {}),
            }
        )
    status = LOOKUP_CANCELLED if outcome.cancelled else LOOKUP_COMPLETE
    _report(progress, len(merged), len(merged), "Lookup cancelled" if outcome.cancelled else "Lookup finished")
    return {
        "status": status,
        "started_at": started_at,
        "finished_at": _now(),
        "technologies": merged,
        "rows": build_rows(outcome.entries, outcome.cves),
        "summary": _summarize(merged),
    }


# -- Threat-model form prefill -------------------------------------------------

# The same rule the mapping file's canonical names are held to.
_PRODUCT_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9 .]{0,39}")
# Numbers and dots, at most five parts, one optional trailing letter
# (``1.1.1w``). No other letters: a version is the last stored text that
# could reach the description, so it must not be able to carry words.
_SAFE_VERSION_RE = re.compile(r"[0-9]{1,6}(?:\.[0-9]{1,6}){0,4}[a-z]?")
# The threat-model form's own version check (numbers or ``*``, at most four parts).
_FORM_VERSION_RE = re.compile(r"(?:\d+|\*)(?:\.(?:\d+|\*)){0,3}")
_PRODUCT_RE = re.compile(r"[^:\s]+:[^:\s]+")

# At most this many technologies are named in the description sentence.
MAX_LISTED = 15
PREFILL_FAILED = "That lookup's technologies could not be loaded."


def safe_product_name(value: object) -> str | None:
    """A canonical product name that may be named in the description, or None."""
    return value if isinstance(value, str) and _PRODUCT_NAME_RE.fullmatch(value) else None


def safe_version(value: object) -> str | None:
    """A version that may be named in the description, or None."""
    return value if isinstance(value, str) and _SAFE_VERSION_RE.fullmatch(value) else None


def form_version(value: object) -> str:
    """A version the form can take as is, or "".

    It passes the safety pattern and the form's own check, so a prefilled
    field never blocks the visitor, and it has the parts a lookup needs.
    """
    version = safe_version(value)
    if not version or not _FORM_VERSION_RE.fullmatch(version):
        return ""
    return version if len(version.split(".")) >= MIN_VERSION_PARTS else ""


def catalog_entries(catalog: Mapping[str, Any] | None) -> list[dict]:
    """The form's technology catalog as one list of ``{name, cpe, category}``.

    Accepts ``category -> name -> cpe`` (the Streamlit form) or ``category ->
    name -> {cpe, libraries}`` (a catalog that also lists libraries). Top-level entries come
    before libraries, so when two share a product the visible one is chosen.
    """
    top: list[dict] = []
    libs: list[dict] = []
    for category, options in (catalog or {}).items():
        if not isinstance(options, Mapping):
            continue
        for name, entry in options.items():
            cpe = entry if isinstance(entry, str) else entry.get("cpe") if isinstance(entry, Mapping) else None
            if not isinstance(cpe, str):
                continue
            top.append({"name": name, "cpe": cpe, "category": category})
            libraries = entry.get("libraries") if isinstance(entry, Mapping) else None
            for lib_name, lib in (libraries or {}).items():
                if isinstance(lib, Mapping) and isinstance(lib.get("cpe"), str):
                    libs.append({"name": lib_name, "cpe": lib["cpe"], "category": f"{category} > {name}"})
    return [*top, *libs]


def _catalog_pairs(product: str | None) -> list[str]:
    """The ``vendor:product`` pairs a catalog entry may use for ``product``.

    The product itself first, then the other pairs the mapping file says NVD
    files it under (a catalog may list MySQL as ``mysql:mysql`` while the
    mapping's main pair is ``oracle:mysql``). Only the mapping file supplies
    the extra pairs, never the lookup result.
    """
    if not product:
        return []
    ref = product_by_pair(product)
    others = [f"{v}:{p}" for v, p in ref.accepted] if ref else []
    return [product, *(pair for pair in others if pair != product)]


def match_technologies(technologies: object, catalog: Mapping[str, Any] | None) -> dict:
    """Split lookup technologies into selected, listed, and not recognized.

    Matched by product only, never by name: a catalog entry matches when its
    CPE prefix is exactly ``cpe:2.3:a:<vendor>:<product>:`` for the product
    or one of the pairs the mapping file accepts for it. Selected ones
    take ``lookup_version`` (never the version as typed). A mapped product
    not in the catalog is listed by its canonical name. Anything else is
    counted only.
    """
    entries = catalog_entries(catalog)
    selected: list[dict] = []
    unmatched: list[dict] = []
    unrecognized = 0
    if not isinstance(technologies, list):
        return {"selected": selected, "unmatched": unmatched, "unrecognized": unrecognized}
    for tech in technologies:
        if not isinstance(tech, Mapping):
            continue
        product = tech.get("product")
        product = product if isinstance(product, str) and _PRODUCT_RE.fullmatch(product) else None
        entry = None
        for pair in _catalog_pairs(product):
            entry = next((e for e in entries if e["cpe"] == f"cpe:2.3:a:{pair}:"), None)
            if entry is not None:
                break
        if entry is not None:
            if any(s["cpe"] == entry["cpe"] for s in selected):
                continue
            selected.append({**entry, "version": form_version(tech.get("lookup_version"))})
        elif product and safe_product_name(tech.get("product_name")):
            unmatched.append(
                {"product_name": tech["product_name"], "version": tech.get("lookup_version") or None}
            )
        else:
            unrecognized += 1
    return {"selected": selected, "unmatched": unmatched, "unrecognized": unrecognized}


def listed_technologies(unmatched: object) -> list[str]:
    """The unmatched technologies that may be named: canonical names only, a
    version only when it is safe, duplicates once."""
    items: list[str] = []
    for tech in unmatched if isinstance(unmatched, list) else []:
        name = safe_product_name(tech.get("product_name")) if isinstance(tech, Mapping) else None
        if not name:
            continue
        version = safe_version(tech.get("version"))
        item = f"{name} {version}" if version else name
        if item not in items:
            items.append(item)
    return items


def description_sentence(unmatched: object) -> str:
    """One sentence for the description field, or "" when nothing can be named."""
    items = listed_technologies(unmatched)
    if not items:
        return ""
    named = items[:MAX_LISTED]
    rest = len(items) - len(named)
    names = f"{', '.join(named)}, and {rest} more" if rest > 0 else ", ".join(named)
    return f"Technologies from your vulnerability lookup: {names}."


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def prefill_notice(selected_count: object, listed_count: object, unrecognized_count: object = 0) -> str:
    """What was filled in, as counts only: no technology name appears."""
    n, m, k = _count(selected_count), _count(listed_count), _count(unrecognized_count)
    left_out = f" {k} not recognized {'was' if k == 1 else 'were'} left out." if k else ""
    return (
        f"Filled in from your vulnerability lookup: {n} {'technology' if n == 1 else 'technologies'} "
        f"selected, {m} listed in the description.{left_out} Review before generating."
    )


def prefill_from_lookup(lookup_result: object, catalog: Mapping[str, Any] | None = None) -> dict:
    """The threat-model form's starting values from a finished lookup.

    ``catalog`` is the form's technology catalog (see ``catalog_entries``);
    without one nothing is selected and every mapped technology is listed in
    the description. The lookup result may come from an uploaded workspace,
    so it is treated as untrusted: only canonical product names from the
    mapping file and versions of digits and dots can reach the description,
    which is sent to the model. Returns::

        {"selected": [{name, cpe, category, version}],
         "selected_technologies": {name: cpe}, "selected_versions": {name: version},
         "description": str, "notice": str, "listed": [str], "unrecognized": int}
    """
    technologies = lookup_result.get("technologies") if isinstance(lookup_result, Mapping) else None
    matched = match_technologies(technologies, catalog)
    listed = listed_technologies(matched["unmatched"])
    selected = matched["selected"]
    return {
        "selected": selected,
        "selected_technologies": {s["name"]: s["cpe"] for s in selected},
        "selected_versions": {s["name"]: s["version"] for s in selected},
        "description": description_sentence(matched["unmatched"]),
        "notice": prefill_notice(len(selected), len(listed), matched["unrecognized"]),
        "listed": listed,
        "unrecognized": matched["unrecognized"],
    }
