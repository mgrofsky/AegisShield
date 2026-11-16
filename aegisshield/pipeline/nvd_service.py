"""NVD lookups for the selected technologies (passive, public database only).

``lookup_nvd`` returns what NVD gave for one product and version as a
structured ``NvdLookup`` (the live view shows it) and ``nvd_text`` turns it
into the prompt text. Errors carry fixed sentences: the visitor's key is
passed to nvdlib and must never reach a message or a log line.
"""

from __future__ import annotations

import logging
import math
import numbers
from dataclasses import dataclass, field
from typing import Any

import nvdlib
from requests.exceptions import RequestException, Timeout

from aegisshield.core.errors import IntelLookupError
from aegisshield.core.retry import retry_call

logger = logging.getLogger(__name__)


# CVEs asked of NVD per product: one page, the most nvdlib asks for at once.
MAX_NVD_RESULTS = 2000


@dataclass(frozen=True)
class NvdSearchConfig:
    """Retry and size settings for one NVD lookup."""

    max_retries: int = 3
    base_delay_seconds: float = 1.0
    top_n: int = 10


class NoCpeMatch(IntelLookupError):
    """NVD has no entry (no CPE) for the product and version: an answer, not a
    failure. A subclass, so callers that catch the lookup error are unchanged."""


def fetch_cpe_name(api_key: str, cpe_prefix: str, version: str, config: NvdSearchConfig) -> str:
    """The CPE name NVD uses for a product prefix and version (its replacement if deprecated).

    Raises ``NoCpeMatch`` when NVD has none and ``IntelLookupError`` when the
    lookup fails.
    """
    cpe_match_string = f"{cpe_prefix}{version}:*"

    def _fetch() -> str:
        cpe_results = nvdlib.searchCPE(cpeMatchString=cpe_match_string, key=api_key)
        if not cpe_results:
            raise NoCpeMatch("NVD has no entry for this product and version.")

        cpe = cpe_results[0]
        if getattr(cpe, "deprecated", False) and getattr(cpe, "deprecatedBy", None):
            return cpe.deprecatedBy[0].cpeName
        return cpe.cpeName

    try:
        return retry_call(
            _fetch,
            max_retries=config.max_retries,
            base_delay_seconds=config.base_delay_seconds,
            retry_exceptions=(RequestException, Timeout),
        )
    except IntelLookupError:
        raise
    # nvdlib can fail in many ways (HTTP, JSON, its own checks). The cause is
    # kept for the log; the message never quotes it, since it may hold the key.
    except Exception as exc:
        raise IntelLookupError("The NVD product lookup failed.") from exc


@dataclass(frozen=True)
class NvdItem:
    """One kept NVD entry, with each value as the prompt text uses it."""

    id: Any
    score: Any
    published: Any
    description: Any


@dataclass(frozen=True)
class NvdLookup:
    """What NVD returned for one product and version.

    ``returned`` is how many entries the query matched; ``items`` are the
    ones kept for the threat writer (the ``top_n`` highest-scored), in the
    order the prompt text lists them. ``truncated`` is True when NVD
    returned a full page (``MAX_NVD_RESULTS``) and may list more.
    """

    returned: int
    items: list[NvdItem] = field(default_factory=list)
    truncated: bool = False


def _item(entry: Any) -> NvdItem:
    description = "No description available"
    descriptions = getattr(entry, "descriptions", None)
    if descriptions:
        try:
            description = descriptions[0].value
        except (AttributeError, IndexError, KeyError, TypeError):
            description = "No description available"

    published = getattr(entry, "published", "")
    if published and "T" in published:
        published = published.split("T", 1)[0]

    return NvdItem(
        id=getattr(entry, "id", "N/A"),
        score=_score_of(entry, "N/A"),
        published=published,
        description=description,
    )


def score_number(score: Any) -> numbers.Real | None:
    """The number in a score as nvdlib gives it (``['V31', 8.8, 'HIGH']``, a
    tuple, or a bare number), or None when there is no usable one. Never
    converts to float, so an integer too large for a float is still a number."""
    if isinstance(score, (list, tuple)):
        score = next((v for v in score if isinstance(v, numbers.Real) and not isinstance(v, bool)), None)
    if not isinstance(score, numbers.Real) or isinstance(score, bool):
        return None
    if isinstance(score, numbers.Integral):
        return score
    try:
        return score if math.isfinite(score) else None
    except (OverflowError, TypeError, ValueError):
        return None


def _score_of(entry: Any, default: Any) -> Any:
    """The entry's score as nvdlib gives it, or, when that holds no number,
    its CVSS 4.0 base score in the same list shape.

    nvdlib fills ``score`` from CVSS 3.1, 3.0, or 2 only, so an entry scored
    only under CVSS 4.0 arrives as ``[None, None, None]``. Without this it
    would rank as unscored however severe it is."""
    score = getattr(entry, "score", default)
    if score_number(score) is not None:
        return score
    try:
        metrics = getattr(getattr(entry, "metrics", None), "cvssMetricV40", None) or []
        data = getattr(metrics[0], "cvssData", None) if metrics else None
        base = getattr(data, "baseScore", None)
        if score_number(base) is not None:
            return ["V40", base, getattr(data, "baseSeverity", None)]
    # An odd metrics shape must never lose the technology.
    except Exception as exc:
        logger.debug("nvd_cvss40_unreadable kind=%s", type(exc).__name__)
        return score
    return score


def _sort_key(entry: Any) -> tuple[int, Any, str]:
    """Highest score number first, then newest published; no number sorts last."""
    number = score_number(_score_of(entry, None))
    published = getattr(entry, "published", "")
    when = published if isinstance(published, str) else ""
    return (0, 0, when) if number is None else (1, number, when)


def lookup_nvd(api_key: str, cpe_prefix: str, version: str, config: NvdSearchConfig) -> NvdLookup:
    """Query NVD for one product and version and keep the highest-scored."""
    cpe_name = fetch_cpe_name(api_key, cpe_prefix, version, config)

    def _search():
        return nvdlib.searchCVE(cpeName=cpe_name, key=api_key, limit=MAX_NVD_RESULTS)

    try:
        cve_results = retry_call(
            _search,
            max_retries=config.max_retries,
            base_delay_seconds=config.base_delay_seconds,
            retry_exceptions=(RequestException, Timeout),
        )
    # As in fetch_cpe_name: keep the cause, never quote it.
    except Exception as exc:
        raise IntelLookupError("The NVD search failed.") from exc

    if not cve_results:
        return NvdLookup(returned=0)

    sorted_results = sorted(cve_results, key=_sort_key, reverse=True)[: config.top_n]
    return NvdLookup(returned=len(cve_results), items=[_item(entry) for entry in sorted_results],
                     truncated=len(cve_results) >= MAX_NVD_RESULTS)


def nvd_text(lookup: NvdLookup, *, tech: str, category: str, version: str) -> str:
    """The prompt text for one lookup."""
    if not lookup.returned:
        return "No vulnerabilities found"

    entries: list[str] = []
    for idx, item in enumerate(lookup.items, start=1):
        entries.append(
            f"""{tech} NVD {idx}
CVE ID: {item.id}
Technology: {tech}
Category: {category}
Version: {version}
CVSS Score: {item.score}
Published Date: {item.published or 'Unknown date'}
Description: {str(item.description).replace(chr(10), ' ').replace('/', '-')}|"""
        )

    result = "".join(entries)
    result += f"\n\nTotal vulnerabilities found: {len(entries)}"
    if lookup.truncated:
        result += (f"\nNVD lists more than {MAX_NVD_RESULTS:,} CVEs for this version; these were "
                   f"chosen from the first {MAX_NVD_RESULTS:,} it returned.")
    logger.info("NVD results generated for %s (%s)", tech, version)
    return result


