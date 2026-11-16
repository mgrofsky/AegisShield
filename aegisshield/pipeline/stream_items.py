"""Incremental parsers for streamed model text.

Each parser takes the text deltas of one model answer, in order, and reports
the items each delta completes: objects of a named top-level JSON array,
markdown table rows, ``## `` heading sections, or plain lines. ``close()``
flushes what the end of the stream completes, and ``tail(n)`` returns the last
``n`` characters of the item still being written.

These parsers feed display data only (the live "agents at work" view). The
job's result is always parsed from the full text by the existing services, so
nothing here can change what a run produces.

Pure standard library. The text helpers (``clean_text``, ``clip_words``,
``clip_tail``) live in ``aegisshield.core.text``.
"""

from __future__ import annotations

import json
import re
from typing import Any

_SEPARATOR_CELL_RE = re.compile(r"^:?-+:?$")


class JsonArrayItems:
    """Completed objects of one named top-level array in a streamed JSON object.

    Scans only for structure (strings, escapes, nesting depth, and the key at
    depth one) and decodes each completed object with ``json.loads``, so any
    chunking of the text gives the same items. Text before the first ``{``
    (prose, a code fence) is ignored.

    Optionally it also follows the string being written, for display:
    ``fields`` names top-level string fields of an item (for example
    ``Scenario``) and ``list_key`` a top-level array of strings (for example
    ``improvement_suggestions``). ``field`` is the one being written now (the
    field name, ``list_label`` inside the list, or None between values) and
    ``field_text`` is the decoded value so far (escapes decoded, no quotes),
    kept after the value closes until the next one starts. ``field_ordinal``
    is the index of the item that text belongs to (None for the list). None
    of this changes which items ``feed`` returns.
    """

    def __init__(
        self,
        key: str,
        *,
        fields: tuple[str, ...] = (),
        list_key: str | None = None,
        list_label: str | None = None,
    ) -> None:
        self._key = key
        self._fields = fields
        self._list_key = list_key
        self._list_label = list_label
        self._in_list = False
        self._items_started = 0
        # Array position of each item the last ``feed`` returned, in order.
        self.last_ordinals: list[int] = []
        # Item-level key and value tracking (depth 3: inside one item).
        self._ikey_chars: list[str] | None = None
        self._ikey: str | None = None
        self._value_next = False
        # The value being decoded, and what the panel shows.
        self._decoder: _StringTail | None = None
        self.field: str | None = None
        self.field_ordinal: int | None = None
        self._field_text = ""
        self.has_field = False
        self._depth = 0
        self._in_str = False
        self._esc = False
        self._key_chars: list[str] | None = None
        self._last_key: str | None = None
        self._colon = False
        self._in_array = False
        self._item: list[str] | None = None

    def feed(self, delta: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        self.last_ordinals = []
        for c in delta or "":
            self._step(c, out)
        return out

    def close(self) -> list[dict[str, Any]]:
        return []

    def tail(self, n: int) -> str:
        if self._item is None:
            return ""
        return "".join(self._item)[-n:]

    @property
    def in_item(self) -> bool:
        return self._item is not None

    @property
    def items_started(self) -> int:
        """How many array items have opened so far."""
        return self._items_started

    @property
    def field_text(self) -> str:
        """Decoded text of the current or last followed value."""
        if self._decoder is not None:
            return self._decoder.text()
        return self._field_text

    def _string_char(self, c: str) -> None:
        if self._decoder is not None:
            self._decoder.feed(c)
        if self._ikey_chars is not None:
            self._ikey_chars.append(c)

    def _string_start(self) -> None:
        """A string opens at the current depth: decide what to follow."""
        if self._depth == 3 and self._item is not None:
            if not self._value_next:
                self._ikey_chars = []
            elif self._ikey in self._fields:
                self._follow(self._ikey, self._items_started - 1)
            else:
                self.field = None
            self._value_next = False
        elif self._depth == 2 and self._in_list and self._list_label:
            self._follow(self._list_label, None)

    def _follow(self, name: str | None, ordinal: int | None) -> None:
        self.field = name
        self.field_ordinal = ordinal
        self.has_field = True
        self._decoder = _StringTail()

    def _string_end(self) -> None:
        if self._ikey_chars is not None:
            self._ikey = _decode_key("".join(self._ikey_chars))
            self._ikey_chars = None
        if self._decoder is not None:
            self._field_text = self._decoder.text()
            self._decoder = None
            if self.field != self._list_label:
                self.field = None

    def _step(self, c: str, out: list[dict[str, Any]]) -> None:
        if self._in_str:
            if self._item is not None:
                self._item.append(c)
            if self._esc:
                self._esc = False
            elif c == "\\":
                self._esc = True
            elif c == '"':
                self._in_str = False
                if self._key_chars is not None:
                    self._last_key = _decode_key("".join(self._key_chars))
                    self._key_chars = None
                    self._colon = False
                self._string_end()
                return
            if self._key_chars is not None:
                self._key_chars.append(c)
            self._string_char(c)
            return

        if self._depth == 0:
            if c == "{":
                self._depth = 1
            return

        if self._item is not None:
            self._item.append(c)

        if c == '"':
            self._in_str = True
            self._key_chars = [] if self._depth == 1 else None
            self._string_start()
        elif c in "{[":
            if (
                c == "["
                and self._depth == 1
                and self._colon
                and self._last_key == self._key
            ):
                self._in_array = True
            elif (
                c == "["
                and self._depth == 1
                and self._colon
                and self._list_key is not None
                and self._last_key == self._list_key
            ):
                self._in_list = True
            elif c == "{" and self._in_array and self._depth == 2 and self._item is None:
                self._item = ["{"]
                self._items_started += 1
                self._ikey = None
                self._value_next = False
            if self._depth == 3:
                self._value_next = False
            self._depth += 1
        elif c in "}]":
            self._depth -= 1
            if c == "}" and self._in_array and self._depth == 2 and self._item is not None:
                raw = "".join(self._item)
                self._item = None
                try:
                    parsed = json.loads(raw)
                except ValueError:
                    parsed = None
                if isinstance(parsed, dict):
                    out.append(parsed)
                    self.last_ordinals.append(self._items_started - 1)
            elif c == "]" and self._in_array and self._depth == 1:
                self._in_array = False
            elif c == "]" and self._in_list and self._depth == 1:
                self._in_list = False
        elif c == ":":
            if self._depth == 1:
                self._colon = self._last_key is not None
            elif self._depth == 3:
                self._value_next = True
        elif c == "," and self._depth == 1:
            self._last_key = None
            self._colon = False
        elif c == "," and self._depth == 3:
            self._value_next = False


_ESCAPES = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
_TAIL_KEEP = 4000


class _StringTail:
    """Decodes the inside of a JSON string one character at a time.

    Keeps the last few thousand decoded characters. An escape that has not
    finished (a lone backslash, a partial ``\\uXXXX``, or a high surrogate
    waiting for its pair) is held back, so ``text()`` never shows a backslash
    or half a character.
    """

    def __init__(self) -> None:
        self._out: list[str] = []
        self._size = 0
        self._escape = False
        self._hex: str | None = None
        self._high: int | None = None

    def _put(self, ch: str) -> None:
        self._out.append(ch)
        self._size += 1
        if self._size > 2 * _TAIL_KEEP:
            kept = "".join(self._out)[-_TAIL_KEEP:]
            self._out = [kept]
            self._size = len(kept)

    def _code_point(self, cp: int) -> None:
        if 0xD800 <= cp <= 0xDBFF:
            self._high = cp
            return
        high, self._high = self._high, None
        if 0xDC00 <= cp <= 0xDFFF:
            if high is not None:
                self._put(chr(0x10000 + ((high - 0xD800) << 10) + (cp - 0xDC00)))
            return
        self._put(chr(cp))

    def feed(self, c: str) -> None:
        if self._hex is not None:
            self._hex += c
            if len(self._hex) == 4:
                digits, self._hex = self._hex, None
                try:
                    self._code_point(int(digits, 16))
                except ValueError:
                    self._high = None
            return
        if self._escape:
            self._escape = False
            if c == "u":
                self._hex = ""
                return
            self._high = None
            self._put(_ESCAPES.get(c, c))
            return
        if c == "\\":
            self._escape = True
            return
        self._high = None
        self._put(c)

    def text(self) -> str:
        return "".join(self._out)


def _decode_key(raw: str) -> str:
    try:
        value = json.loads(f'"{raw}"')
    except ValueError:
        return raw
    return value if isinstance(value, str) else raw


class _LineParser:
    """Shared line splitting: subclasses handle one complete line at a time."""

    def __init__(self) -> None:
        self._partial = ""

    def feed(self, delta: str) -> list[Any]:
        out: list[Any] = []
        self._partial += delta or ""
        while "\n" in self._partial:
            line, self._partial = self._partial.split("\n", 1)
            out.extend(self._on_line(line.rstrip("\r")))
        return out

    def close(self) -> list[Any]:
        out: list[Any] = []
        if self._partial:
            line, self._partial = self._partial, ""
            out.extend(self._on_line(line.rstrip("\r")))
        out.extend(self._on_end())
        return out

    def _on_line(self, line: str) -> list[Any]:  # pragma: no cover - abstract
        raise NotImplementedError

    def _on_end(self) -> list[Any]:
        return []


class Lines(_LineParser):
    """Each complete line (used for the Mermaid attack tree)."""

    def tail(self, n: int) -> str:
        return self._partial[-n:]

    def _on_line(self, line: str) -> list[str]:
        return [line]


def table_cells(line: str) -> list[str] | None:
    """Cells of one markdown table row, or None when the line is not a row.

    Same split rule as the existing table readers (``export_service`` and
    ``tm_detail.js``): strip the outer pipes and split on ``|``. There is no
    escaped-pipe rule there, so there is none here.
    """
    s = line.strip()
    if not s.startswith("|"):
        return None
    return [c.strip() for c in s.strip("|").split("|")]


def _is_separator(cells: list[str]) -> bool:
    return bool(cells) and all(
        _SEPARATOR_CELL_RE.match(c.replace(" ", "")) for c in cells
    )


class TableRows(_LineParser):
    """Data rows of markdown tables, as lists of cells.

    A table's first row is held until the next line shows whether it is a
    header (followed by a separator row, then dropped) or data.
    """

    def __init__(self) -> None:
        super().__init__()
        self._in_table = False
        self._pending: list[str] | None = None

    def tail(self, n: int) -> str:
        if self._partial.lstrip().startswith("|"):
            return self._partial[-n:]
        return ""

    def _on_line(self, line: str) -> list[list[str]]:
        cells = table_cells(line)
        if cells is None:
            out = [self._pending] if self._pending is not None else []
            self._pending = None
            self._in_table = False
            return out
        if _is_separator(cells):
            self._pending = None
            self._in_table = True
            return []
        if self._in_table:
            return [cells]
        if self._pending is None:
            self._pending = cells
            return []
        out = [self._pending, cells]
        self._pending = None
        self._in_table = True
        return out

    def _on_end(self) -> list[list[str]]:
        out = [self._pending] if self._pending is not None else []
        self._pending = None
        return out


class Sections(_LineParser):
    """``## `` heading sections as ``{"heading", "body"}``.

    A section completes when the next ``## `` heading starts or the stream
    ends. A ``## `` line inside a fenced code block (opened by three
    backticks or three tildes) is body text; a fence closes only on the same
    character that opened it.
    """

    def __init__(self) -> None:
        super().__init__()
        self._heading: str | None = None
        self._body: list[str] = []
        self._fence: str | None = None

    @property
    def heading(self) -> str | None:
        return self._heading

    def body_so_far(self) -> str:
        parts = [*self._body, self._partial] if self._partial else list(self._body)
        return "\n".join(parts)

    def tail(self, n: int) -> str:
        if self._heading is None:
            return ""
        return f"## {self._heading}\n{self.body_so_far()}"[-n:]

    def _finish(self) -> list[dict[str, str]]:
        if self._heading is None:
            return []
        item = {"heading": self._heading, "body": "\n".join(self._body).strip()}
        self._heading = None
        self._body = []
        return [item]

    def _on_line(self, line: str) -> list[dict[str, str]]:
        marker = line.lstrip()[:3]
        if marker in ("```", "~~~") and self._fence in (None, marker):
            self._fence = None if self._fence else marker
        elif self._fence is None and line.startswith("## "):
            out = self._finish()
            self._heading = line[3:].strip()
            return out
        if self._heading is not None:
            self._body.append(line)
        return []

    def _on_end(self) -> list[dict[str, str]]:
        return self._finish()
