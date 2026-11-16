"""AlienVault OTX lookups for the visitor's industry sector (passive feed only).

``lookup_otx`` returns the matching community reports as a structured
``OtxLookup`` and ``otx_text`` turns it into the prompt text. Errors carry
fixed sentences, never the visitor's key or the client's exception text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from requests.exceptions import RequestException, Timeout

from aegisshield.core.errors import IntelLookupError
from aegisshield.core.otx import BoundedOTXv2
from aegisshield.core.retry import retry_call

# The most results one search asks OTX for. A search that returns this many
# may have matched more, so the matched count is a floor.
SEARCH_LIMIT = 100


@dataclass(frozen=True)
class OtxLookup:
    """What the OTX search gave for one sector.

    ``state`` is ``off`` (offline mode), ``none``, or ``found``.
    ``returned`` is how many reports passed the filter (public and modified in
    the window); ``pulses`` are the ones kept (the newest ``max_results``), in
    the order the prompt text lists them. ``capped`` is true when the search
    returned its limit, so more may have matched than ``returned`` counts.
    """

    state: str
    returned: int = 0
    pulses: list[dict[str, Any]] = field(default_factory=list)
    capped: bool = False


def lookup_otx(
    api_key: str,
    industry: str,
    days: int,
    max_results: int,
    max_retries: int,
    base_delay_seconds: float,
    *,
    offline: bool = False,
) -> OtxLookup:
    """Search OTX for ``industry`` and keep the newest public reports from the last ``days``.

    ``offline`` (``Settings.offline``) answers ``off`` without a call.
    Raises ``IntelLookupError`` when the search fails.
    """
    if offline:
        return OtxLookup(state="off")
    otx = BoundedOTXv2(api_key)
    modified_since = (datetime.now() - timedelta(days=days)).isoformat()

    def _search():
        pulses = otx.search_pulses(industry.strip(), max_results=SEARCH_LIMIT)
        if not pulses:
            raise IntelLookupError("OTX did not answer.")
        return pulses

    try:
        pulses = retry_call(
            _search,
            max_retries=max_retries,
            base_delay_seconds=base_delay_seconds,
            retry_exceptions=(RequestException, Timeout),
        )
    # The OTX client can fail in many ways. The cause is kept for the log;
    # the message never quotes it, since it may hold the key.
    except Exception as exc:
        raise IntelLookupError("The OTX search failed.") from exc

    results = pulses.get("results", [])
    capped = isinstance(results, list) and len(results) >= SEARCH_LIMIT
    filtered_pulses = [
        pulse
        for pulse in results
        if pulse.get("modified", "") >= modified_since and pulse.get("public", 1) == 1
    ]

    sorted_pulses = sorted(
        filtered_pulses,
        key=lambda x: x.get("modified", ""),
        reverse=True,
    )[:max_results]
    if not sorted_pulses:
        return OtxLookup(state="none", returned=len(filtered_pulses), capped=capped)
    return OtxLookup(state="found", returned=len(filtered_pulses), pulses=sorted_pulses, capped=capped)


def otx_text(lookup: OtxLookup, industry: str) -> str:
    """The prompt text for one lookup."""
    if lookup.state == "off":
        return "OTX threat intelligence disabled (offline mode)"

    cti_blocks: list[str] = []
    for idx, pulse in enumerate(lookup.pulses, start=1):
        name = pulse.get("name", "N/A")
        description = pulse.get("description") or "No description available"
        modified = pulse.get("modified", "N/A")
        tlp = pulse.get("TLP", "N/A")
        adversary = pulse.get("adversary") or "N/A"
        families = ", ".join(pulse.get("malware_families", [])) or "N/A"

        block = (
            f"### Pulse {idx}: {name}\n\n"
            f"- **Industry**: {industry or 'N/A'}\n"
            f"- **Modified**: {modified}\n"
            f"- **TLP**: {tlp}\n"
            f"- **Adversary**: {adversary}\n"
            f"- **Malware Families**: {families}\n\n"
            f"**Description**\n\n{description}"
        )
        cti_blocks.append(block)

    if not cti_blocks:
        return "No threat intelligence data found"

    body = "\n\n---\n\n".join(cti_blocks)
    return body + f"\n\n*Total pulses found: {len(cti_blocks)}*\n"


