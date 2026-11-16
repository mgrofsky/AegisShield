"""Small building blocks that pages compose, so every page looks the same.

Every helper that writes HTML escapes the text it places there with
``html.escape``; enum values pick CSS classes, so no caller text ever becomes
markup or a class name. ``st.html`` also runs DOMPurify on the result, as a
second layer. Model output goes through :func:`model_markdown`, which never
renders raw HTML or remote images and shows links as text when the text
names a script, ``data``, or ``file`` scheme.
"""

from __future__ import annotations

import hashlib
import html
import math
import re
from collections import deque
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass

import streamlit as st
from streamlit.delta_generator import DeltaGenerator

from aegisshield.core.text import clip_words, sanitize_user_markdown
from aegisshield.llm.providers import answered_by_words
from aegisshield.services.markdown_render import CUT_NOTE, MAX_RENDER_CHARS
from aegisshield.ui import routes
from aegisshield.ui.state import DEEP_LINK_PARAM
from aegisshield.ui.theme import Area, Tone, area_class

__all__ = [
    "MAX_TILES_PER_ROW",
    "Tile",
    "badge",
    "badge_html",
    "card",
    "empty_state",
    "key_value_list",
    "model_markdown",
    "notice",
    "open_record",
    "page_header",
    "record_link",
    "section",
    "severity_badge_html",
    "stat_row",
    "tile_columns",
    "wide_canvas",
]

_AREA_LABELS = {Area.DEFENSE: "Defense", Area.COMPLIANCE: "Compliance", Area.NEUTRAL: ""}

# Severity words, their tone, and a text glyph so the level never rests on
# color alone.
_SEVERITY: dict[str, tuple[str, Tone]] = {
    "critical": ("Critical", Tone.CRIT),
    "high": ("High", Tone.CRIT),
    "medium": ("Medium", Tone.WARN),
    "low": ("Low", Tone.OK),
    "info": ("Info", Tone.INFO),
    "informational": ("Info", Tone.INFO),
    "none": ("None", Tone.NEUTRAL),
}

_NOTICE_LABELS = {
    Tone.NEUTRAL: "Note",
    Tone.ACCENT: "Note",
    Tone.INFO: "Note",
    Tone.OK: "Done",
    Tone.WARN: "Warning",
    Tone.CRIT: "Error",
}


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _tone(tone: Tone | str) -> str:
    return f"ax-tone-{Tone(tone).value}"


def _key_part(text: str) -> str:
    """A short, stable widget-key fragment derived from ``text``."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


# ------------------------------------------------------------ page parts


def page_header(title: str, subtitle: str | None = None, *, area: Area | str) -> None:
    """The page title block. ``area`` sets the accent color of the whole page."""
    area = Area(area)
    eyebrow = ""
    if _AREA_LABELS[area]:
        eyebrow = (
            '<div class="ax-eyebrow"><span class="ax-dot" aria-hidden="true"></span>'
            f"{_AREA_LABELS[area]}</div>"
        )
    sub = f'<p class="ax-subtitle">{_esc(subtitle)}</p>' if subtitle else ""
    st.html(
        f'<header class="ax-header {area_class(area)}">'
        '<span class="ax-header-rail" aria-hidden="true"></span>'
        f'<div>{eyebrow}<h1 class="ax-title">{_esc(title)}</h1>{sub}</div>'
        "</header>"
    )


def section(title: str, description: str | None = None) -> None:
    """A small uppercase section heading with an optional one-line description."""
    desc = f"<p>{_esc(description)}</p>" if description else ""
    st.html(f'<div class="ax-section"><h2 class="ax-section-title">{_esc(title)}</h2>{desc}</div>')


@contextmanager
def card(key: str) -> Iterator[DeltaGenerator]:
    """A raised, bordered surface; use as ``with card("summary"):``.

    ``key`` must be unique on the page. It becomes the widget key
    ``ax_card_<key>``, which the stylesheet targets.
    """
    with st.container(border=True, key=f"ax_card_{key}") as box:
        yield box


# ---------------------------------------------------------- stats, badges


@dataclass(frozen=True)
class Tile:
    """One stat tile for :func:`stat_row`."""

    label: str
    value: str | int | float
    hint: str | None = None
    tone: Tone | str = Tone.NEUTRAL


def _tile_html(tile: Tile) -> str:
    hint = f'<div class="ax-tile-hint">{_esc(tile.hint)}</div>' if tile.hint else ""
    return (
        f'<div class="ax-tile {_tone(tile.tone)}">'
        f'<div class="ax-tile-label">{_esc(tile.label)}</div>'
        f'<div class="ax-tile-value">{_esc(tile.value)}</div>{hint}</div>'
    )


# The most tiles one row holds; more go onto balanced rows.
MAX_TILES_PER_ROW = 4


def tile_columns(count: int) -> int:
    """Columns for ``count`` tiles so every row is full or the rows are
    balanced: 7 tiles are 4 and 3, 5 are 3 and 2, 6 are 3 and 3."""
    if count <= 0:
        return 1
    rows = math.ceil(count / MAX_TILES_PER_ROW)
    return math.ceil(count / rows)


def stat_row(tiles: Sequence[Tile]) -> None:
    """Tiles side by side, on balanced rows (two columns on a narrow screen)."""
    columns = tile_columns(len(tiles))
    st.html(f'<div class="ax-tiles" style="--ax-cols: {columns}">'
            f'{"".join(_tile_html(t) for t in tiles)}</div>')


def badge_html(text: str, *, tone: Tone | str = Tone.NEUTRAL) -> str:
    """A pill as an HTML string, for composing into other kit markup."""
    return f'<span class="ax-badge {_tone(tone)}">{_esc(text)}</span>'


def badge(text: str, *, tone: Tone | str = Tone.NEUTRAL) -> None:
    """A small pill with a word in it."""
    st.html(badge_html(text, tone=tone))


def severity_badge_html(level: str | None) -> str:
    """A severity pill as an HTML string. Unknown levels show as "Unknown"."""
    word, tone = _SEVERITY.get(str(level or "").strip().lower(), ("Unknown", Tone.NEUTRAL))
    return badge_html(word, tone=tone)


def key_value_list(items: Mapping[str, object] | Iterable[tuple[str, object]], *,
                   mono: bool = False) -> None:
    """Label and value pairs in two aligned columns. ``mono`` sets values in
    the code font (ids, hashes, versions)."""
    pairs = items.items() if isinstance(items, Mapping) else items
    cls = ' class="ax-mono"' if mono else ""
    rows = "".join(f"<dt>{_esc(k)}</dt><dd{cls}>{_esc(v)}</dd>" for k, v in pairs)
    st.html(f'<dl class="ax-kv">{rows}</dl>')


# ------------------------------------------------------------ messages


def empty_state(title: str, body: str, *, action_label: str | None = None,
                action_page: routes.PageName | None = None) -> None:
    """What a page shows before there is anything in it, with one next step."""
    with st.container(key=f"ax_empty_{_key_part(title)}"):
        st.html(
            '<div class="ax-empty">'
            '<div class="ax-empty-icon" aria-hidden="true"></div>'
            f'<h3 class="ax-empty-title">{_esc(title)}</h3><p>{_esc(body)}</p></div>'
        )
        if action_label and action_page:
            st.page_link(routes.page(action_page), label=action_label,
                         icon=":material/arrow_forward:")


def notice(text: str, *, tone: Tone | str = Tone.INFO, label: str | None = None) -> None:
    """An inline message. It starts with a word (Note, Done, Warning, Error),
    so the meaning does not rest on its color."""
    tone = Tone(tone)
    word = label or _NOTICE_LABELS[tone]
    st.html(
        f'<div class="ax-notice {_tone(tone)}" role="status">'
        f'<span class="ax-notice-label">{_esc(word)}</span><span>{_esc(text)}</span></div>'
    )


NOT_RECORDED = "Provider and model: not recorded for this item."


def answered_by(record: object) -> None:
    """One muted line naming the provider and model that answered, from a
    stored ``answered_by`` record; older items say it was not recorded."""
    words = answered_by_words(record)
    text = f"Answered by {words}." if words else NOT_RECORDED
    st.html(f'<p class="tx-muted ax-answered-by">{_esc(text)}</p>')


# -------------------------------------------------------------- layout


def wide_canvas() -> None:
    """Give this page the full width, for the live deck.

    The deck switches to its narrow layout when its board columns are under
    168 px, which takes about 1400 px of deck. So this trims the side
    padding and collapses the sidebar. Call it at the top of the page's
    render on every run, not only once a job starts: Streamlit applies the
    sidebar state only when the page is entered. If the visitor opens the
    sidebar again, their choice stands and the deck uses its narrow layout.
    """
    st.set_page_config(initial_sidebar_state="collapsed")
    st.html('<div class="ax-wide" hidden></div>')


# ------------------------------------------------------------- model text

# Link schemes that can run script or read data when a link is followed.
# Streamlit's own frontend already refuses javascript: and vbscript: links;
# this filter is a second layer. Before scanning, a copy of the text has HTML
# entities decoded and backslashes, controls, tabs, and newlines removed,
# the way a browser or a markdown parser would read a link target, so
# ``&#106;avascript:``, ``javascript&colon;``, ``javascript\:``, and
# ``java<tab>script:`` all count. ``data`` and ``file`` count only when
# something other than a space follows the colon, so prose such as
# "Sensitive data: none" does not.
_DANGEROUS_SCHEME_RE = re.compile(
    r"(?<![a-z0-9+.\-])(?:(?:java|vb|live)script\s*:|(?:data|file)\s*:(?=\S))"
)
_SCAN_NOISE_RE = re.compile(r"[\\\x00-\x1f\x7f-\x9f]+")
# What opens a link: ``[`` (inline, reference, and definition) and ``<``
# (autolink).
_LINK_OPENERS = frozenset("[<")
_CUT_NOTE = f"\n\n*{CUT_NOTE}*"


def _has_dangerous_scheme(text: str) -> bool:
    probe = _SCAN_NOISE_RE.sub("", html.unescape(text)).lower()
    return _DANGEROUS_SCHEME_RE.search(probe) is not None


# What counts as code is kept narrower than CommonMark's, so that text the
# browser treats as prose is never skipped: a fence opens only at the start
# of a line (an indented one may belong to a list item that ends before the
# link), a backtick fence's info string holds no backtick, a fence closes at
# up to three spaces of indent, and a code span stays on one line.


def _fence_open(line: str) -> str | None:
    """The fence a line opens, or None."""
    for mark in ("`", "~"):
        if line.startswith(mark * 3):
            run = mark * (len(line) - len(line.lstrip(mark)))
            if mark == "`" and "`" in line[len(run):]:
                return None
            return run
    return None


def _fence_closes(line: str, fence: str) -> bool:
    stripped = line.lstrip(" ")
    if len(line) - len(stripped) > 3 or not stripped.startswith(fence):
        return False
    return not stripped.strip().strip(fence[0])


def _code_spans(text: str) -> list[tuple[int, int]]:
    """``(start, end)`` of each inline code span in one line: a run of
    backticks up to the next run of the same length. An unclosed run, and a
    backtick after an odd number of backslashes, is plain text. Each run's
    partner comes from a per-length index, so this is linear."""
    runs: list[tuple[int, int]] = []
    index = 0
    while (index := text.find("`", index)) != -1:
        end = index
        while end < len(text) and text[end] == "`":
            end += 1
        before = index
        while before > 0 and text[before - 1] == "\\":
            before -= 1
        start = index + (index - before) % 2  # an escaped backtick opens nothing
        if end > start:
            runs.append((start, end - start))
        index = end
    by_length: dict[int, deque[int]] = {}
    for position, (_start, length) in enumerate(runs):
        by_length.setdefault(length, deque()).append(position)
    spans: list[tuple[int, int]] = []
    position = 0
    while position < len(runs):
        start, length = runs[position]
        queue = by_length[length]
        while queue and queue[0] <= position:
            queue.popleft()
        if not queue:
            position += 1
            continue
        partner = queue.popleft()
        spans.append((start, runs[partner][0] + length))
        position = partner + 1
    return spans


def _escape_openers(text: str) -> str:
    """``text`` with each unescaped ``[`` and ``<`` escaped, so it opens no
    link, autolink, or reference definition. An opener after an odd number
    of backslashes is already escaped and is left alone."""
    out: list[str] = []
    backslashes = 0
    for char in text:
        if char in _LINK_OPENERS and backslashes % 2 == 0:
            out.append("\\")
        backslashes = backslashes + 1 if char == "\\" else 0
        out.append(char)
    return "".join(out)


def _escape_prose(text: str) -> str:
    """``_escape_openers`` on everything but inline code spans."""
    parts: list[str] = []
    last = 0
    for start, end in _code_spans(text):
        parts.append(_escape_openers(text[last:start]))
        parts.append(text[start:end])
        last = end
    parts.append(_escape_openers(text[last:]))
    return "".join(parts)


def _links_as_text(text: str) -> str:
    """Every link construct outside fenced and inline code made literal."""
    out: list[str] = []
    fence: str | None = None
    for line in text.split("\n"):
        if fence is not None:
            if _fence_closes(line, fence):
                fence = None
            out.append(line)
        elif (mark := _fence_open(line)) is not None:
            fence = mark
            out.append(line)
        else:
            out.append(_escape_prose(line))
    return "\n".join(out)


def _safe_markdown(text: str | None) -> str:
    """Model text ready for ``st.markdown``.

    Control and bidi characters are removed; every ``![`` is escaped, so no
    image syntax (inline, reference, or shortcut, over any number of lines)
    can make the browser load a remote URL; and when the text names a
    script, ``data``, or ``file`` scheme anywhere (see
    ``_DANGEROUS_SCHEME_RE``), every link, autolink, and reference
    definition outside code is made literal text. Otherwise links are left
    as written. Text over ``MAX_RENDER_CHARS`` is cut with a note. Linear in
    the length of the text.
    """
    text = sanitize_user_markdown(text)
    cut = len(text) > MAX_RENDER_CHARS
    if cut:
        text = clip_words(text, MAX_RENDER_CHARS)
    text = text.replace("![", "!\\[")
    if _has_dangerous_scheme(text):
        text = _links_as_text(text)
    return text + _CUT_NOTE if cut else text


def model_markdown(text: str | None) -> None:
    """Render model output as markdown.

    Raw HTML is never rendered (``unsafe_allow_html`` stays off), image
    syntax is shown as text instead of loading, text that names a script,
    ``data``, or ``file`` scheme has all its links shown as text, control
    and bidi characters are removed, and at most ``MAX_RENDER_CHARS`` are
    shown.
    """
    st.markdown(_safe_markdown(text), unsafe_allow_html=False)


# ---------------------------------------------------------- deep links


def record_link(page_name: routes.PageName, record_id: str, label: str) -> None:
    """A link that opens one record on ``page_name`` (``?id=<record_id>``)."""
    st.page_link(routes.page(page_name), label=label, query_params={DEEP_LINK_PARAM: record_id})


def open_record(page_name: routes.PageName, record_id: str) -> None:
    """Go to ``page_name`` showing one record. Does not return."""
    st.switch_page(routes.page(page_name), query_params={DEEP_LINK_PARAM: record_id})
