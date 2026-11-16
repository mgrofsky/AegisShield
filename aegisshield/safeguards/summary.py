"""The safeguards record and the review flags as words, for the results views
and every export.

``summarize(report)`` turns a ``Safeguards.report()`` into a headline and
the lists of what was changed, withheld, and not checked; ``as_markdown``
and ``as_html`` render that summary and the review flags the same way in
every format. Everything taken from a record is escaped by the renderer
that shows it; excerpts are stored already HTML-escaped and are shown as
plain text.
"""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

WHAT_THEY_CHECK = (
    "The safeguards look for instructions addressed to the AI in content where none belong, "
    "and for the AI's answers repeating its instructions, carrying a key, or carrying markup "
    "that sends data elsewhere. They do not make a result safe or correct."
)
SIMULATED_NOTE = (
    "These answers came from a simulated model that is built to follow injected instructions. "
    "They say nothing about any real model."
)
EDITED_NOTE = (
    "This record describes the checks on the generated text. It was edited afterward, and the "
    "edits were not checked."
)
NO_RECORD = "No safeguards record: this result was made before the checks existed or was imported without one."
FLAGS_NOTE = (
    "Checks of form and of references: they look at the shape of the result and whether what it "
    "cites was supplied to the run. They do not judge whether a finding is right."
)

_RAIL_SET_WORDS = {"input": "input check", "retrieved": "retrieved-content check",
                   "output": "answer check"}
_SOURCE_WORDS = {
    "description": "Description", "diagram": "Diagram description", "capture": "Capture text",
    "lookup": "Lookup results", "threat_intel": "Threat intelligence", "profile": "Profile",
    "import": "Imported record", "policy": "Policy text",
}


@dataclass(frozen=True)
class Summary:
    """What a results view or export says about one record's checks."""

    headline: str
    tone: str  # "ok", "warn", or "neutral"
    changed: list[str] = field(default_factory=list)
    withheld: list[str] = field(default_factory=list)
    not_checked: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def quiet(self) -> bool:
        """True when the summary is one line with nothing to list."""
        return not (self.changed or self.withheld or self.not_checked or self.notes)


def _plain(value: Any) -> str:
    """Stored text as plain text (excerpts are stored HTML-escaped)."""
    return html.unescape(str(value or "")).strip()


def _where(check: Mapping[str, Any]) -> str:
    rail_set = str(check.get("rail_set") or "")
    kind = _RAIL_SET_WORDS.get(rail_set, "check")
    if rail_set == "output":
        step = str(check.get("step") or "a model answer")
        return f"{step[:1].upper()}{step[1:]} ({kind})"
    source = _SOURCE_WORDS.get(str(check.get("source") or ""), "Input")
    return f"{source} ({kind})"


def _line(check: Mapping[str, Any]) -> str:
    reason = _plain(check.get("reason")) or "No reason was recorded."
    excerpt = _plain(check.get("excerpt"))
    quote = f' Excerpt: "{excerpt}"' if excerpt else ""
    return f"{_where(check)}: {reason}{quote}"


def _checks(count: int) -> str:
    return "1 check" if count == 1 else f"{count} checks"


def _grouped(checks: list[Mapping[str, Any]]) -> list[str]:
    """One line per distinct finding; answer checks that found the same
    thing are counted on one line instead of listed one by one."""
    lines: list[str] = []
    answers: dict[tuple[str, str], int] = {}
    for check in checks:
        if check.get("rail_set") == "output":
            key = (_plain(check.get("reason")), _plain(check.get("excerpt")))
            answers[key] = answers.get(key, 0) + 1
        else:
            lines.append(_line(check))
    for (reason, excerpt), count in answers.items():
        quote = f' Excerpt: "{excerpt}"' if excerpt else ""
        where = "1 model answer" if count == 1 else f"{count} model answers"
        lines.append(f"{where} (answer check): {reason or 'No reason was recorded.'}{quote}")
    return lines


def summarize(report: Mapping[str, Any] | None, *, edited: bool = False) -> Summary:
    """The words for one record's safeguards report (``NO_RECORD`` without one).

    ``edited`` adds a note that the text was changed after the checks ran.
    """
    if not isinstance(report, Mapping):
        return Summary(NO_RECORD, "neutral")
    status = str(report.get("status") or "")
    raw = report.get("checks")
    checks = [c for c in raw if isinstance(c, Mapping)] if isinstance(raw, list) else []
    notes = [SIMULATED_NOTE] if report.get("simulated_model") else []
    if edited:
        notes.append(EDITED_NOTE)
    if status == "off":
        return Summary("Safeguards were off for this run: nothing was checked.", "warn", notes=notes)
    changed = _grouped([c for c in checks if c.get("status") == "modified"])
    withheld = _grouped([c for c in checks if c.get("status") == "blocked"])
    unchecked = [c for c in checks if c.get("status") == "not_checked"]
    not_checked = []
    if unchecked:
        reasons = sorted({_plain(c.get("reason")) or "No reason was recorded." for c in unchecked})
        not_checked.append(f"{len(unchecked)} of {len(checks)} checks could not run: "
                           f"{' '.join(reasons)} This result is not fully checked.")
    notes += [_line(c) for c in checks if c.get("status") == "passed" and c.get("excerpt")]
    if status == "unavailable" and len(unchecked) == len(checks):
        headline = "Safeguards were unavailable for this run: nothing was checked."
        tone = "warn"
    elif changed or withheld or unchecked:
        parts = []
        n_changed = sum(1 for c in checks if c.get("status") == "modified")
        n_withheld = sum(1 for c in checks if c.get("status") == "blocked")
        if n_changed:
            parts.append(f"{n_changed} changed")
        if n_withheld:
            parts.append(f"{n_withheld} withheld")
        if unchecked:
            parts.append(f"{len(unchecked)} not checked")
        headline = f"Safeguards ran {_checks(len(checks))}: {', '.join(parts)}."
        tone = "warn"
    else:
        headline = f"Safeguards ran {_checks(len(checks))}; nothing was changed or withheld."
        tone = "ok"
    return Summary(headline, tone, changed, withheld, not_checked, notes)


def flag_items(flags: Sequence[Mapping[str, Any]] | None) -> list[tuple[str | None, str | None, str]]:
    """``(threat id, field, sentence)`` for each review flag in a record."""
    items = []
    for flag in flags if isinstance(flags, list | tuple) else []:
        if isinstance(flag, Mapping) and flag.get("sentence"):
            tid = str(flag.get("threat_id") or "") or None
            where = str(flag.get("field") or "") or None
            items.append((tid, where, str(flag["sentence"])))
    return items


def flags_headline(flags: Sequence[Mapping[str, Any]] | None) -> str:
    count = len(flag_items(flags))
    if not count:
        return "Review flags: none."
    return f"Review flags: {count} {'item needs' if count == 1 else 'items need'} review."


def _flag_place(tid: str | None, where: str | None) -> str:
    return ", ".join(p for p in (tid, where) if p)


def as_markdown(report: Mapping[str, Any] | None, flags: Sequence[Mapping[str, Any]] | None = None,
                *, with_flags: bool = True, edited: bool = False) -> str:
    """The summary (and the review flags) as Markdown, every value escaped."""
    summary = summarize(report, edited=edited)
    lines = ["## Safeguards", "", _md(summary.headline), "", _md(WHAT_THEY_CHECK)]
    for title, items in (("Changed", summary.changed), ("Withheld", summary.withheld),
                         ("Not checked", summary.not_checked), ("Notes", summary.notes)):
        if items:
            lines += ["", f"{title}:", ""] + [f"- {_md(i)}" for i in items]
    if with_flags:
        lines += ["", "## Review flags", "", _md(flags_headline(flags)), "", _md(FLAGS_NOTE)]
        items = flag_items(flags)
        if items:
            lines += [""] + [f"- {_md(_flag_place(t, w))}: {_md(s)}" if _flag_place(t, w)
                             else f"- {_md(s)}" for t, w, s in items]
    return "\n".join(lines) + "\n"


_MD_SPECIAL = str.maketrans({c: f"\\{c}" for c in "\\`*_{}[]()<>#+!|~"})


def _md(text: str) -> str:
    return " ".join(text.split()).translate(_MD_SPECIAL)


def as_html(report: Mapping[str, Any] | None, flags: Sequence[Mapping[str, Any]] | None = None,
            *, with_flags: bool = True, edited: bool = False) -> str:
    """The summary (and the review flags) as an HTML fragment, every value escaped."""
    esc = html.escape
    summary = summarize(report, edited=edited)
    parts = [f"<p><strong>{esc(summary.headline)}</strong></p>", f"<p class=\"meta\">{esc(WHAT_THEY_CHECK)}</p>"]
    for title, items in (("Changed", summary.changed), ("Withheld", summary.withheld),
                         ("Not checked", summary.not_checked), ("Notes", summary.notes)):
        if items:
            parts.append(f"<h4>{esc(title)}</h4><ul>" + "".join(f"<li>{esc(i)}</li>" for i in items) + "</ul>")
    out = "".join(parts)
    if with_flags:
        flag_html = [f"<p><strong>{esc(flags_headline(flags))}</strong></p>",
                     f"<p class=\"meta\">{esc(FLAGS_NOTE)}</p>"]
        items = flag_items(flags)
        if items:
            flag_html.append("<ul>" + "".join(
                f"<li>{esc(_flag_place(t, w)) + ': ' if _flag_place(t, w) else ''}{esc(s)}</li>"
                for t, w, s in items) + "</ul>")
        out += "<h3>Review flags</h3>" + "".join(flag_html)
    return out


__all__ = [
    "EDITED_NOTE",
    "FLAGS_NOTE",
    "NO_RECORD",
    "SIMULATED_NOTE",
    "WHAT_THEY_CHECK",
    "Summary",
    "as_html",
    "as_markdown",
    "flag_items",
    "flags_headline",
    "summarize",
]
