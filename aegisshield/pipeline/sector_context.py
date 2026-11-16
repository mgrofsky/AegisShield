"""Neutral organization context for the threat-model prompts.

The STRIDE, MITRE, and specialist prompts get no fixed block of sector priors,
which would describe the same organization whatever the visitor's was. The
context is built only from what the request says: industry sector, data
sensitivity, the compliance requirements the visitor selected, authentication
methods, and internet exposure. Nothing is assumed: a sector is never mapped
to a regulation, and a field the visitor left empty is left out.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from aegisshield.core.text import single_line

SECTOR_CONTEXT_HEADER = "ORGANIZATION CONTEXT"

# Bounds on what one value may add to a prompt.
_CAP_VALUE = 120
_MAX_LIST = 12

# Answers that say nothing about the organization.
_EMPTY = {"", "unknown", "none", "n/a", "not specified", "not sure"}


def _value(raw: object) -> str:
    text = single_line(raw, _CAP_VALUE)
    return "" if text.lower() in _EMPTY else text


def _values(raw: object) -> list[str]:
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, Iterable):
        return []
    out: list[str] = []
    for item in raw:
        text = _value(item)
        if text and text not in out:
            out.append(text)
        if len(out) >= _MAX_LIST:
            break
    return out


def context_lines(app_details: Mapping[str, Any]) -> list[str]:
    """One ``label: value`` line per field the request filled in."""
    lines: list[str] = []
    sector = _value(app_details.get("industry_sector"))
    if sector:
        lines.append(f"Industry sector: {sector}")
    sensitive = _value(app_details.get("sensitive_data"))
    if sensitive:
        lines.append(f"Data sensitivity: {sensitive}")
    frameworks = _values(app_details.get("compliance_requirements"))
    if frameworks:
        lines.append(f"Compliance requirements selected: {', '.join(frameworks)}")
    auth = _values(app_details.get("authentication"))
    if auth:
        lines.append(f"Authentication methods: {', '.join(auth)}")
    exposure = _value(app_details.get("internet_facing"))
    if exposure:
        lines.append(f"Internet facing: {exposure}")
    return lines


def context_block(app_details: Mapping[str, Any]) -> str:
    """The full block for the STRIDE prompt, or "" when the request gave nothing.

    When the visitor selected compliance requirements, the block asks the
    model to weigh threats against them; it never names one they did not pick.
    """
    lines = context_lines(app_details)
    if not lines:
        return ""
    body = "\n".join(f"- {line}" for line in lines)
    guidance = (
        "Ground threats and impact ratings in this context."
        " Where compliance requirements are listed, note which threats would put them at risk."
        if _values(app_details.get("compliance_requirements"))
        else "Ground threats and impact ratings in this context."
    )
    return f"{SECTOR_CONTEXT_HEADER} (from the request; use alongside STRIDE):\n{body}\n{guidance}"


def compact_context(app_details: Mapping[str, Any]) -> str:
    """One line of the same context, for prompts that run once per threat."""
    lines = context_lines(app_details)
    if not lines:
        return ""
    return f"{SECTOR_CONTEXT_HEADER}: " + "; ".join(lines) + "."


def focus_block(focus: str | None, *, heading: str = "LEAD FOCUS FOR THIS SECTION") -> str:
    """The Lead's focus note for one specialist, appended to its prompt; "" when empty."""
    text = single_line(focus, 600)
    if not text:
        return ""
    return f"\n\n{heading}:\n{text}\n"


__all__ = [
    "SECTOR_CONTEXT_HEADER",
    "compact_context",
    "context_block",
    "context_lines",
    "focus_block",
]
