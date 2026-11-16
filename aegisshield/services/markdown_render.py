"""Untrusted markdown to HTML in bounded time, for the PDF and HTML exports.

The app is one Streamlit process shared by every visitor. markdown2 is pure
Python between its own pattern calls, but some of its passes cost the
square of the text they see: every list or indented code block rescans the
rest of the document, and every unclosed ``[`` scans ahead for its ``]``.
One very long line makes a single pattern call slow, which holds the
interpreter lock and freezes every session, and deep nesting or a run of
about a thousand tabs raises ``RecursionError``.

So the text is bounded before markdown2 sees it:

- At most ``MAX_RENDER_CHARS`` are rendered; the rest is cut with a note.
- The text is rendered in chunks of about ``CHUNK_CHARS``, split only where
  one top-level block ends and the next begins (a blank line, then a line
  that cannot continue a list, quote, table, or code block), outside fenced
  code. Each chunk renders as it would inside the whole document, and the
  total cost grows with the length instead of its square. Reference link
  definitions are copied into every chunk, so ``[text][ref]`` resolves
  across a split.
- A chunk is passed to markdown2 only when a linear check finds no line
  over ``MAX_LINE_CHARS``, no more ``[`` than its bracket budget, few
  enough fence lines for its length (``MAX_FENCE_SCAN``), quotes
  nested at most ``MAX_QUOTE_DEPTH`` deep, and list items indented at most
  ``MAX_LIST_INDENT`` columns. Otherwise, or if markdown2 raises anyway, the
  chunk is shown as escaped plain text in a ``<pre>`` block with a note.
- Tabs are expanded first, and fence language tags are dropped, so no
  syntax highlighter (pygments, when installed) runs on the text.

The numbers below were measured on an Apple M-series machine with the
second-thread stall test in ``tests/aegisshield/services/test_markdown_render.py``.
"""

from __future__ import annotations

import html
import logging
import re

import markdown2

from aegisshield.core.text import clip_words, sanitize_user_markdown

logger = logging.getLogger(__name__)

# Three times the longest answer a model gives in this app (an 8,192-token
# answer is about 33,000 characters) and the policy body limit.
MAX_RENDER_CHARS = 100_000
# The target size of one chunk; a single block longer than this is one chunk.
CHUNK_CHARS = 4_000
# A line this long makes one markdown2 pattern call take about 0.05 s (a
# line of 20,000 backticks or pipes took 1.1 s, growing with the square).
MAX_LINE_CHARS = 4_000
# ``[`` allowed in a chunk: this many, or one per BRACKET_SPACING characters
# when the chunk is longer (a table of links has one about every 60).
MIN_BRACKET_BUDGET = 200
BRACKET_SPACING = 20
# markdown2 finds fenced code with one pattern call per chunk, and each
# backtick fence line with no closing fence after it makes that call scan to
# the end of the chunk. A chunk passes when its backtick fence lines times
# its length stay under this (about 0.06 s at 16 ns a character; a chunk of
# 100,000 characters made of such lines took 13 s).
MAX_FENCE_SCAN = 4_000_000
# markdown2 recurses once per level; it raised RecursionError at about 150
# levels of quotes or nested lists with Python's default limit.
MAX_QUOTE_DEPTH = 16
MAX_LIST_INDENT = 64
# Reference definitions copied into each chunk, in characters.
MAX_SHARED_DEFINITIONS_CHARS = 4_000

MARKDOWN_EXTRAS = ("fenced-code-blocks", "tables", "strike", "cuddled-lists")

CUT_NOTE = f"The text is cut here: only the first {MAX_RENDER_CHARS:,} characters are shown."
PLAIN_NOTE = ("Part of this text is shown as plain text: it has longer lines, deeper nesting, "
              "or more brackets than the formatter handles quickly.")

_LIST_MARKERS = ("- ", "* ", "+ ", "-\t", "*\t", "+\t")


def _fence(line: str) -> str | None:
    """The fence a line opens or closes (``\\`\\`\\``` or ``~~~`` run), or None."""
    stripped = line.lstrip(" ")
    if len(line) - len(stripped) > 3:
        return None
    for mark in ("`", "~"):
        if stripped.startswith(mark * 3):
            run = mark * (len(stripped) - len(stripped.lstrip(mark)))
            # A backtick fence's info string holds no backtick (CommonMark).
            return None if mark == "`" and "`" in stripped[len(run):] else run
    return None


def _is_list_item(stripped: str) -> bool:
    if stripped.startswith(_LIST_MARKERS):
        return True
    digits = len(stripped) - len(stripped.lstrip("0123456789"))
    return 0 < digits <= 9 and stripped[digits : digits + 2] in {". ", ") ", ".\t", ")\t"}


def _starts_block(line: str) -> bool:
    """True when a line after a blank line cannot continue the block before it."""
    if not line or line[0] in " \t>|-*+" or _is_list_item(line):
        return False
    return True


def _is_definition(line: str) -> bool:
    stripped = line.lstrip(" ")
    return len(line) - len(stripped) <= 3 and stripped.startswith("[") and "]:" in stripped


def _split(text: str) -> tuple[list[str], str]:
    """The text in chunks at top-level block boundaries, and the reference
    definitions to share between chunks ("" when there are none or too many)."""
    chunks: list[str] = []
    current: list[str] = []
    size = 0
    fence: str | None = None
    previous_blank = False
    definitions: list[str] = []
    definitions_size = 0
    for line in text.split("\n"):
        mark = _fence(line)
        if fence is None and size >= CHUNK_CHARS and previous_blank and (mark is not None or _starts_block(line)):
            chunks.append("\n".join(current))
            current, size = [], 0
        if fence is None and mark is not None:
            fence = mark
            # Drop the language tag, so no syntax highlighter runs on the text.
            line = line[: len(line) - len(line.lstrip(" "))] + mark
        elif fence is not None and mark is not None and mark[0] == fence[0] and len(mark) >= len(fence) \
                and not line.strip().strip(mark[0]):
            fence = None
        if fence is None and _is_definition(line):
            definitions.append(line)
            definitions_size += len(line) + 1
        current.append(line)
        size += len(line) + 1
        previous_blank = fence is None and not line.strip()
    chunks.append("\n".join(current))
    shared = "\n".join(definitions) if len(chunks) > 1 and definitions_size <= MAX_SHARED_DEFINITIONS_CHARS else ""
    return chunks, shared


def _renderable(chunk: str) -> bool:
    """A linear check that markdown2 renders ``chunk`` quickly and without
    running out of stack."""
    if chunk.count("[") > max(MIN_BRACKET_BUDGET, len(chunk) // BRACKET_SPACING):
        return False
    fence_lines = 0
    for line in chunk.split("\n"):
        if len(line) > MAX_LINE_CHARS:
            return False
        if line.lstrip(" \t").startswith("```"):
            fence_lines += 1
            if fence_lines * len(chunk) > MAX_FENCE_SCAN:
                return False
        stripped = line.lstrip(" ")
        if stripped.startswith(">"):
            lead = len(stripped) - len(stripped.lstrip("> "))
            if stripped[:lead].count(">") > MAX_QUOTE_DEPTH:
                return False
            stripped = stripped[lead:]
        if len(line) - len(stripped) > MAX_LIST_INDENT and _is_list_item(stripped):
            return False
    return True


def _plain(chunk: str) -> str:
    return f'<pre class="md-plain">{html.escape(chunk, quote=False)}</pre>'


def _markdown2(chunk: str) -> str | None:
    """markdown2's HTML for ``chunk``, or None when it fails."""
    try:
        return str(markdown2.markdown(chunk, extras=list(MARKDOWN_EXTRAS), safe_mode="escape"))
    # RecursionError on deep nesting is the known case; markdown2 is a large
    # pure-Python parser, so any exception it raises on hostile text means
    # the same thing here: show the chunk as plain text. Only the class is
    # logged: the message or traceback can quote the document.
    except Exception as exc:
        logger.warning("markdown2 raised %s on a chunk of %d characters; shown as plain text",
                       type(exc).__name__, len(chunk))
        return None


# markdown2's safe mode escapes every complete tag, and every unclosed one
# that carries attributes, but it leaves a bare "<word" at the end of a block
# as written ("<p>text<word</p>"). A browser reads that as an unknown element
# with no attributes of the writer's choosing, so it is not a way in, but the
# rule is simpler to state and to test without it: after rendering, a "<"
# that does not open or close one of the tags markdown2 itself writes is
# escaped. Each "<" looks ahead only as far as the next "<" or ">", so the
# pass is linear.
_OWN_TAGS = "p|pre|code|em|strong|ul|ol|li|h[1-6]|blockquote|a|img|hr|br|table|thead|tbody|tr|th|td|s|del"
_STRAY_LT_RE = re.compile(rf"<(?!/?(?:{_OWN_TAGS})(?:\s[^<>]*)?/?>)")


def render_markdown(text: str | None) -> str:
    """Untrusted markdown as HTML, in time that grows with its length.

    Control and invisible characters are removed (``sanitize_user_markdown``)
    and raw HTML is escaped (markdown2 ``safe_mode``, then any ``<`` that
    does not belong to a tag markdown2 wrote). Images and link targets are
    left to the caller. Never raises.
    """
    source = sanitize_user_markdown(text if isinstance(text, str) else "")
    if not source:
        return ""
    notes: list[str] = []
    if len(source) > MAX_RENDER_CHARS:
        source = clip_words(source, MAX_RENDER_CHARS)
        notes.append(CUT_NOTE)
    chunks, shared = _split(source.expandtabs(4))
    parts: list[str] = []
    plain = False
    for chunk in chunks:
        rendered = None
        if _renderable(chunk):
            rendered = _markdown2(f"{chunk}\n\n{shared}" if shared else chunk)
        if rendered is None:
            rendered, plain = _plain(chunk), True
        parts.append(rendered)
    if plain:
        notes.insert(0, PLAIN_NOTE)
    parts.extend(f'<p class="md-note"><em>{html.escape(note)}</em></p>' for note in notes)
    return _STRAY_LT_RE.sub("&lt;", "\n".join(parts))


__all__ = [
    "BRACKET_SPACING",
    "CHUNK_CHARS",
    "CUT_NOTE",
    "MAX_FENCE_SCAN",
    "MAX_LINE_CHARS",
    "MAX_LIST_INDENT",
    "MAX_QUOTE_DEPTH",
    "MAX_RENDER_CHARS",
    "MIN_BRACKET_BUDGET",
    "PLAIN_NOTE",
    "render_markdown",
]
