"""The "Safeguards" and "Review flags" blocks of the results views, and the
Settings page's safeguards status.

The words come from ``aegisshield.safeguards.summary``, so a results view
and every export say the same thing. When nothing was found the Safeguards
block is one quiet line; anything changed, withheld, or not checked is
listed with its reason. Every value from a record is escaped.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping, Sequence
from typing import Any

import streamlit as st

from aegisshield.config import Settings
from aegisshield.safeguards import safeguards_status
from aegisshield.safeguards import summary as words
from aegisshield.ui import kit
from aegisshield.ui.theme import Tone

_TONES = {"ok": Tone.OK, "warn": Tone.WARN, "neutral": Tone.NEUTRAL}
_ANCHOR_RE = re.compile(r"[^A-Za-z0-9-]")


def threat_anchor(threat_id: str) -> str:
    """The element id a threat's finding card carries, for links to it."""
    return "tm-threat-" + _ANCHOR_RE.sub("", threat_id)


def _quiet(text: str) -> None:
    st.html(f'<p class="sg-quiet">{html.escape(text)}</p>')


def _list(title: str, items: Sequence[str]) -> str:
    rows = "".join(f"<li>{html.escape(i)}</li>" for i in items)
    return f'<div class="sg-label">{html.escape(title)}</div><ul class="sg-list">{rows}</ul>'


def render_safeguards(report: Mapping[str, Any] | None, *, key: str, edited: bool = False) -> None:
    """The compact Safeguards block for one record's report (``edited``: the
    text was changed after the checks)."""
    summary = words.summarize(report, edited=edited)
    if summary.quiet:
        _quiet(summary.headline)
        return
    with kit.card(f"{key}_safeguards"):
        kit.notice(summary.headline, tone=_TONES[summary.tone], label="Safeguards")
        parts = []
        for title, items in (("Changed", summary.changed), ("Withheld", summary.withheld),
                             ("Not checked", summary.not_checked), ("Notes", summary.notes)):
            if items:
                parts.append(_list(title, items))
        st.html("".join(parts))
        _quiet(words.WHAT_THEY_CHECK)


def render_review_flags(flags: Sequence[Mapping[str, Any]] | None, *, key: str,
                        threat_titles: Mapping[str, str] | None = None) -> None:
    """The Review flags block, each flag linked to the threat it concerns."""
    items = words.flag_items(flags)
    if not items:
        _quiet(f"{words.flags_headline(flags)} {words.FLAGS_NOTE}")
        return
    titles = threat_titles or {}
    with kit.card(f"{key}_review_flags"):
        kit.section("Review flags", words.FLAGS_NOTE)
        rows = []
        for tid, field, sentence in items:
            place = ""
            if tid:
                title = titles.get(tid)
                place = f'<a href="#{threat_anchor(tid)}" class="sg-id">{html.escape(tid)}</a> '
                if title:
                    short = title if len(title) <= 48 else title[:45].rstrip() + "..."
                    place += f'<span class="sg-title">{html.escape(short)}</span> '
            if field:
                place += f'<span class="sg-field">{html.escape(field)}</span> '
            rows.append(f"<li>{place}{html.escape(sentence)}</li>")
        st.html(f'<ul class="sg-list">{"".join(rows)}</ul>')


def render_status(settings: Settings) -> None:
    """The Settings page's line: on, off, or unavailable, and the version."""
    status = safeguards_status(settings)
    word = {"on": ("On", Tone.OK), "off": ("Off", Tone.WARN),
            "unavailable": ("Unavailable", Tone.WARN)}[status["status"]]
    version = status["engine_version"] or "not installed"
    st.html(f'<div class="ax-key-head"><strong>Safeguards</strong> {kit.badge_html(word[0], tone=word[1])}</div>')
    kit.key_value_list({status["engine"]: version,
                        "Strict mode": "On" if status["strict"] else "Off"}, mono=True)
    if status["status"] == "off":
        st.caption("The operator turned the safeguards off for this server (AEGIS_SAFEGUARDS).")
    elif status["status"] == "unavailable":
        st.caption("NeMo Guardrails is not installed here, so model calls run unchecked and every "
                   "result says so.")
    st.caption(f"{words.WHAT_THEY_CHECK} An AI answer the safeguards could not check is always "
               "withheld. Strict mode also stops a step when a check of its input could not run; "
               "otherwise the result is marked as not fully checked.")


__all__ = ["render_review_flags", "render_safeguards", "render_status", "threat_anchor"]
