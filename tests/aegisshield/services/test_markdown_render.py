"""The bounded markdown renderer: same output as markdown2 on real text,
plain text instead of a stall or a crash on hostile text."""

from __future__ import annotations

import json
import logging
import re
from html.parser import HTMLParser
from pathlib import Path

import markdown2
import pytest

from aegisshield.services import markdown_render as mr
from tests.aegisshield.stall import STALL_LIMIT_S, least_stall

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
N = mr.MAX_RENDER_CHARS


def _whole(text: str) -> str:
    """markdown2 on the whole text at once, as the app rendered it before,
    with fence language tags dropped (no stylesheet styled the highlighter's
    spans, so dropping them changes nothing a reader sees)."""
    text = re.sub(r"(?m)^( {0,3})(`{3,}|~{3,})[^`~\n]*$", r"\1\2", text)
    return str(markdown2.markdown(text, extras=list(mr.MARKDOWN_EXTRAS), safe_mode="escape"))


def _same(html_text: str) -> str:
    return re.sub(r">\s+<", "><", html_text).strip()


def _real_markdown() -> list[str]:
    from tests.aegisshield.ui.tm_records import mock_payload

    recorded = json.loads((FIXTURES / "stream_capture.json").read_text())["expected"]
    texts = [v for k, v in recorded.items() if k.endswith("_markdown") and isinstance(v, str)]
    texts += [v for k, v in mock_payload().items() if k.endswith("_markdown") and isinstance(v, str) and v]
    return texts


def _rep(unit: str, size: int) -> str:
    return (unit * (size // len(unit) + 1))[:size]


# ------------------------------------------------------------ fidelity


@pytest.mark.parametrize("chunk", [mr.CHUNK_CHARS, 200])
def test_real_text_renders_as_markdown2_renders_it_whole(monkeypatch, chunk):
    """Splitting into chunks changes nothing on real model output, even
    when the chunks are made tiny to force a split at every block."""
    monkeypatch.setattr(mr, "CHUNK_CHARS", chunk)
    texts = _real_markdown()
    assert len(texts) >= 6 and max(map(len, texts)) > 10_000
    for text in texts:
        source = text.strip()
        assert _same(mr.render_markdown(text)) == _same(_whole(source))


def test_real_text_never_falls_back_to_plain_text():
    for text in _real_markdown():
        rendered = mr.render_markdown(text)
        assert mr.PLAIN_NOTE not in rendered and "md-plain" not in rendered


def test_a_long_policy_is_split_and_still_matches(monkeypatch):
    para = "The service must log every access to customer records and review logs weekly. " * 3
    text = "".join(
        f"## Section {i}\n\n{para}\n\n- item one\n- item two\n\n  continued item\n\n"
        f"1. first\n2. second\n\n> quoted {i}\n> more\n\n| a | b |\n|---|---|\n| {i} | y |\n\n"
        f"```\ncode {i}\n\n  still code\n```\n\n    indented code\n\nafter\n\n"
        for i in range(60)
    )
    chunks, _shared = mr._split(text)
    assert len(chunks) > 5
    assert "".join(chunks).replace("\n", "") == text.replace("\n", "")
    assert _same(mr.render_markdown(text)) == _same(_whole(text.strip()))


def test_reference_definitions_resolve_across_chunks(monkeypatch):
    monkeypatch.setattr(mr, "CHUNK_CHARS", 50)
    text = "[guide]: https://example.com/guide\n\n" + "Filler paragraph text.\n\n" * 10 + "See [the guide][guide].\n"
    assert '<a href="https://example.com/guide">the guide</a>' in mr.render_markdown(text)


def test_too_many_definitions_are_not_copied(monkeypatch):
    monkeypatch.setattr(mr, "CHUNK_CHARS", 50)
    monkeypatch.setattr(mr, "MAX_SHARED_DEFINITIONS_CHARS", 10)
    text = "[guide]: https://example.com/guide\n\n" + "Filler paragraph text.\n\n" * 10 + "See [the guide][guide].\n"
    assert "href" not in mr.render_markdown(text)


def test_fence_language_tags_are_dropped_so_no_highlighter_runs():
    rendered = mr.render_markdown("```python\nx = 1\n```\n\n~~~~js\ny\n~~~~\n")
    assert "codehilite" not in rendered and "<span" not in rendered
    assert "<pre><code>x = 1" in rendered


def test_a_fence_is_never_split(monkeypatch):
    monkeypatch.setattr(mr, "CHUNK_CHARS", 10)
    text = "intro\n\n```\nline one\n\nplain after blank\n\n# not a heading\n```\n\nafter\n"
    chunks, _ = mr._split(text)
    assert any("line one" in c and "# not a heading" in c for c in chunks)
    assert "<h1>" not in mr.render_markdown(text)


# --------------------------------------------------------- the limits


def test_text_over_the_cap_is_cut_with_a_note():
    rendered = mr.render_markdown("word " * (N // 4))
    assert mr.CUT_NOTE in rendered
    assert mr.render_markdown("word " * 10).count("<p") == 1


@pytest.mark.parametrize(
    "text",
    [
        "a" * (mr.MAX_LINE_CHARS + 1),
        "[" * (mr.MIN_BRACKET_BUDGET + 1),
        "> " * (mr.MAX_QUOTE_DEPTH + 1) + "deep",
        " " * (mr.MAX_LIST_INDENT + 1) + "- deep item",
        " " * (mr.MAX_LIST_INDENT + 1) + "12. deep item",
    ],
    ids=["long line", "brackets", "quotes", "list indent", "ordered list indent"],
)
def test_text_past_a_limit_is_escaped_plain_text_with_a_note(text):
    rendered = mr.render_markdown("intro\n\n" + text + "\n\n<b>raw</b>")
    assert mr.PLAIN_NOTE in rendered and '<pre class="md-plain">' in rendered
    assert "<b>" not in rendered and "&lt;b&gt;raw&lt;/b&gt;" in rendered


def test_text_inside_the_limits_renders():
    text = "\n".join(
        ["a" * mr.MAX_LINE_CHARS, "[x]" * 10, "> " * mr.MAX_QUOTE_DEPTH + "q", " " * mr.MAX_LIST_INDENT + "- item",
         " " * (mr.MAX_LIST_INDENT + 10) + "indented text that is not a list item"]
    )
    assert mr.PLAIN_NOTE not in mr.render_markdown(text)


def test_a_dense_table_of_links_is_within_the_bracket_budget():
    rows = "".join(f"| [CVE-2024-{i:05d}](https://nvd.nist.gov/vuln/detail/CVE-2024-{i:05d}) | high |\n"
                   for i in range(600))
    rendered = mr.render_markdown("| CVE | Severity |\n|---|---|\n" + rows)
    assert mr.PLAIN_NOTE not in rendered and rendered.count("<a href") == 600


@pytest.mark.parametrize("exc", [RecursionError, ValueError, IndexError])
def test_any_markdown2_failure_becomes_plain_text_and_is_logged(monkeypatch, caplog, exc):
    def boom(*_a, **_k):
        raise exc("quoted document text")

    monkeypatch.setattr(mr.markdown2, "markdown", boom)
    with caplog.at_level(logging.WARNING, logger=mr.__name__):
        rendered = mr.render_markdown("# Title\n\n<i>x</i>")
    assert mr.PLAIN_NOTE in rendered and "&lt;i&gt;x&lt;/i&gt;" in rendered
    assert "shown as plain text" in caplog.text and exc.__name__ in caplog.text
    # only the class: a parser's message or traceback can quote the document
    assert "quoted document text" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.parametrize("value", [None, "", "   \n\t ", 42])
def test_empty_or_non_text_is_empty(value):
    assert mr.render_markdown(value) == ""


# ------------------------------------------------- hostile text at the cap

HOSTILE = {
    "kit pattern input": "[](" + " " * (N - 4) + "x",
    "backticks": "x " + "`" * N,
    "[a](": "x " + _rep("[a](", N),
    "[": "x " + "[" * N,
    "1,000 tabs": "x\n" + "\t" * 1000 + "y",
    "500 nested quotes": "x\n" + "> " * 500 + "y",
    "deep list": "x\n" + "".join("  " * i + "- a\n" for i in range(300)),
    # Repeated tokens and blocks, the slowest found for each pass.
    "pipes": "x " + "|" * N,
    "wrapped [": "x " + "\n".join(_rep("[", N)[i : i + 70] for i in range(0, N, 70)),
    "lists between paragraphs": "x\n\n" + _rep("- a\n\nb\n\n", N),
    "indented code between paragraphs": "x\n\n" + _rep("    code\n\nb\n\n", N),
    "nested lists": "x\n\n" + _rep("* a\n  * b\n\n", N),
    "brackets at the budget": _rep("[a]( " + "z" * 15, N),
    "a line at the length limit": _rep("`|", mr.MAX_LINE_CHARS - 1) + "\n\n" + _rep("x ", N - mr.MAX_LINE_CHARS),
}


@pytest.mark.parametrize("name", list(HOSTILE))
def test_hostile_text_at_the_cap_neither_stalls_nor_raises(name):
    """At ``MAX_RENDER_CHARS``, no input blocks a second thread for long,
    the whole call stays bounded, and nothing raises."""
    run = least_stall(mr.render_markdown, HOSTILE[name], repeats=2)
    assert run.result.startswith("<")
    assert run.stall < STALL_LIMIT_S * 0.6, run
    # Measured at most 1.3 s on an Apple M-series machine; generous for a
    # slower machine running under coverage.
    assert run.total < 15, run


def test_a_chunk_of_unclosed_fence_lines_is_plain_text():
    """markdown2 rescans to the end of a chunk for each backtick fence line
    that never closes; past ``MAX_FENCE_SCAN`` the chunk is plain text."""
    text = "x\n\n" + _rep("```gherkin\n\n", N)
    run = least_stall(mr.render_markdown, text, repeats=1)
    assert mr.PLAIN_NOTE in run.result
    assert run.stall < STALL_LIMIT_S * 0.6, run


def test_real_fenced_blocks_stay_within_the_fence_budget():
    blocks = "".join(f"Scenario {i}\n\n```gherkin\nGiven a\nWhen b\nThen c\n```\n\n" for i in range(400))
    rendered = mr.render_markdown(blocks)
    assert mr.PLAIN_NOTE not in rendered and rendered.count("<pre><code>") == 400


_WRITTEN_TAGS = {
    "p", "pre", "code", "em", "strong", "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6",
    "blockquote", "a", "img", "hr", "br", "table", "thead", "tbody", "tr", "th", "td", "s", "del",
}
_UNCLOSED = [
    "text<script",
    "text<style",
    "text<script\nalert(1)",
    "<img\nsrc=x\nonerror=alert(1)\n",
    "x<svg/onload=alert(1)",
    "<img/src=x/onerror=alert(1)",
    "<a\nhref=javascript:alert(1)\n",
    "- item<img\n  src=x\n  onerror=alert(1)",
    "# head<svg\nonload=alert(1)",
    "| a | b |\n|---|---|\n| <img | src=x onerror=alert(1) |",
    "</pre><script>x</script>",
    "</code></pre><img src=x>",
]


class _Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.seen: list[tuple[str, list[str]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.seen.append((tag, [name for name, _ in attrs]))


def _elements(rendered: str) -> list[tuple[str, list[str]]]:
    parser = _Tags()
    parser.feed(rendered)
    return parser.seen


@pytest.mark.parametrize("text", _UNCLOSED)
def test_an_unclosed_or_raw_tag_never_becomes_an_element(text):
    # A browser's view of the output: only tags markdown2 writes, and no
    # attribute that came from the text. Checked whole, and with the tag
    # split by a blank line at every position (the chunk boundary case).
    variants = [text] + [f"{text[:cut]}\n\n{text[cut:]}" for cut in range(1, len(text))]
    for variant in variants:
        for tag, attrs in _elements(mr.render_markdown(variant)):
            assert tag in _WRITTEN_TAGS, (variant, tag)
            assert not [name for name in attrs if name.startswith("on") or name in {"src", "href", "style"}], (
                variant, tag, attrs)


def test_a_bare_unclosed_tag_is_escaped():
    assert mr.render_markdown("text<script") == "<p>text&lt;script</p>\n"


def test_the_stray_bracket_pass_is_linear():
    text = "<p " + "a" * 100_000 + "\n\n" + "<" * 50_000
    run = least_stall(mr._STRAY_LT_RE.sub, "&lt;", text)
    assert run.stall < STALL_LIMIT_S * 0.4, run
