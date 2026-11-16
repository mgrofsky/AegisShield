"""Links in rendered model and visitor text keep their target only for
http, https, mailto, or a fragment; anything else is reduced to its text.
Covers the shared check and the two HTML renderers (export HTML and policy
HTML). The kit's on-page markdown, which the browser renders, makes every
link literal when the text names a script, data, or file scheme."""

from __future__ import annotations

import pytest

from aegisshield.core.text import is_safe_link
from aegisshield.services import policy_service
from aegisshield.services.export_service import markdown_html
from aegisshield.ui import kit

ALLOWED = ["https://ok.example/a", "http://ok.example", "mailto:a@b.example", "#section",
           "HTTPS://OK.EXAMPLE", " https://ok.example"]
REFUSED = ["vbscript:msgbox(1)", "javascript:alert(1)", "JaVa&#115;cript:alert(1)",
           "java\tscript:alert(1)", "java​script:x", "data:text/html,hi", "file:///etc/passwd",
           "//evil.example/a", "rel/path", "", "#", "ftp://files.example", None]


@pytest.mark.parametrize("href", ALLOWED)
def test_allowed_targets(href: str) -> None:
    assert is_safe_link(href)


@pytest.mark.parametrize("href", REFUSED)
def test_refused_targets(href: str | None) -> None:
    assert not is_safe_link(href)


HOSTILE = ("[a](vbscript:1) [b](//evil.example/x) [c](rel/path) [d](javascript:alert(1)) "
           "[e](file:///etc/passwd) [ok](https://ok.example/p) [m](mailto:a@b.example) [f](#top)")


@pytest.mark.parametrize("render", [markdown_html, policy_service.markdown_to_html])
def test_html_renderers_keep_only_allowed_links(render) -> None:
    out = render(HOSTILE)
    for bad in ("vbscript", "evil.example", "rel/path", "javascript", "file:", 'href="#"'):
        assert bad not in out, bad
    for word in ("a", "b", "c", "d", "e"):
        assert f">{word}<" not in out and f" {word} " in f" {out} ".replace("<p>", " ")
    assert '<a href="https://ok.example/p">ok</a>' in out
    assert '<a href="mailto:a@b.example">m</a>' in out
    assert '<a href="#top">f</a>' in out


def test_html_renderer_refuses_reference_links() -> None:
    out = markdown_html("[r][1] and [s][2]\n\n[1]: vbscript:x\n[2]: https://ok.example")
    assert "vbscript" not in out and '<a href="https://ok.example">s</a>' in out


# ------------------------------------------------- the kit's on-page filter
#
# ``st.markdown`` renders in the browser, so the kit cannot see link
# targets the way the HTML renderers do. When the text names a script,
# data, or file scheme anywhere, every link construct outside code becomes
# literal text; otherwise the text is left as written.


def _live_openers(text: str) -> list[int]:
    """Positions of ``[`` and ``<`` outside code that are not escaped."""
    found: list[int] = []
    fence = None
    offset = 0
    for line in text.split("\n"):
        if fence is not None:
            if kit._fence_closes(line, fence):
                fence = None
        elif (mark := kit._fence_open(line)) is not None:
            fence = mark
        else:
            backslashes = 0
            spans = kit._code_spans(line)
            for index, char in enumerate(line):
                inside = any(start <= index < end for start, end in spans)
                if char in "[<" and backslashes % 2 == 0 and not inside:
                    found.append(offset + index)
                backslashes = backslashes + 1 if char == "\\" else 0
        offset += len(line) + 1
    return found


def _no_live_link(out: str, *, parse: bool = True) -> None:
    """No opener outside code is unescaped, and a markdown parser finds no link."""
    assert _live_openers(out) == [], out
    if parse:
        import markdown2

        html_out = markdown2.markdown(out, extras=["fenced-code-blocks"], safe_mode="escape")
        assert "<a " not in html_out, html_out


BYPASS_FORMS = {
    "nested brackets in the text": "[a [b] c](javascript:alert(1))",
    "a line break in the text": "[first\nsecond](javascript:alert(1))",
    "an angle-bracket target with a space": "[a](<javascript:alert(1) x>)",
    "nested parentheses in the target": "[a](javascript:f((1)))",
    "an escaped quote in a title": '[a](javascript:alert(1) "t\\"q")',
    "an escaped ] in a reference label": "[a][b\\]c]\n\n[b\\]c]: javascript:alert(1)",
    "a definition inside a blockquote": "> [r]: javascript:alert(1)\n\n[a][r]",
}


@pytest.mark.parametrize("text", list(BYPASS_FORMS.values()), ids=list(BYPASS_FORMS))
def test_kit_bypass_forms_leave_no_link(text: str) -> None:
    _no_live_link(kit._safe_markdown(text))


@pytest.mark.parametrize("scheme", [
    "javascript:", "JavaScript:", "javascript :", "java\tscript:", "java\nscript:", "javascript\\:",
    "&#106;avascript:", "&#x6A;avascript:", "javascript&colon;", "javascript&#58;", "vbscript:",
    "livescript:", "data:text/html,hi", "file:///etc/passwd", "\x01javascript:",
])
def test_kit_obfuscated_schemes_count(scheme: str) -> None:
    out = kit._safe_markdown(f"see [a]({scheme}alert(1)) and <{scheme}x> and [r]\n\n[r]: {scheme}x")
    _no_live_link(out)


def test_kit_existing_hostile_cases_leave_no_link() -> None:
    out = kit._safe_markdown(HOSTILE + "\n\n[r][1]\n\n[1]: data:text/html,hi\n\n<vbscript:x> <https://a.example>")
    _no_live_link(out)
    # The words stay readable.
    for word in ("[a]", "[ok]", "(https://ok.example/p)", "[1]: data:text/html,hi", "vbscript:x>"):
        assert word in out.replace("\\", "")


@pytest.mark.parametrize("text", [
    "[ok](https://ok.example/p) [m](mailto:a@b.example) [f](#top) <https://a.example>",
    "[w](https://ok.example/a_(b)) [r][1]\n\n[1]: https://ok.example",
    "Sensitive data: none. Config file: app.yaml. [ok](https://ok.example)",
    "metadata:x and [ok](https://ok.example)",
])
def test_kit_text_without_a_dangerous_scheme_is_left_as_written(text: str) -> None:
    assert kit._safe_markdown(text) == text


def test_kit_backslash_parity_is_respected() -> None:
    # An escaped backslash before "[" leaves the bracket live, so it is escaped.
    out = kit._safe_markdown("\\\\[x](javascript:alert(1))")
    _no_live_link(out)
    assert out.startswith("\\\\\\[x]")
    # An escaped bracket stays as it is, not doubly escaped.
    assert kit._safe_markdown("\\[x] javascript:1") == "\\[x] javascript:1"


def test_kit_code_is_never_rewritten() -> None:
    text = ("`[a](javascript:x)` and ``[b](c) ` d`` then [e](javascript:y)\n\n"
            "```js\n[f](javascript:z) <g:h>\n```\n~~~\n[i](j)\n~~~\n")
    out = kit._safe_markdown(text)
    assert "`[a](javascript:x)`" in out and "``[b](c) ` d``" in out
    assert "```js\n[f](javascript:z) <g:h>\n```" in out and "~~~\n[i](j)\n~~~" in out
    assert "\\[e](javascript:y)" in out
    _no_live_link(out, parse=False)  # markdown2 does not read ~~~ fences; CommonMark does


def test_kit_an_unclosed_backtick_is_not_code() -> None:
    out = kit._safe_markdown("`` open [a](javascript:x) ` and more")
    assert "\\[a](javascript:x)" in out
    _no_live_link(out)


def test_kit_an_unclosed_fence_runs_to_the_end() -> None:
    text = "intro javascript:\n```\n[a](b)"
    assert kit._safe_markdown(text) == text


def test_kit_images_never_load() -> None:
    out = kit._safe_markdown("![x](https://evil.example/p.png) ![y][r]\n\n[r]: https://evil.example/q.png")
    assert "![" not in out.replace("!\\[", "")


def test_kit_text_over_the_cap_is_cut_with_a_note() -> None:
    from aegisshield.services.markdown_render import CUT_NOTE, MAX_RENDER_CHARS

    out = kit._safe_markdown("word " * (MAX_RENDER_CHARS // 4))
    assert out.endswith(f"*{CUT_NOTE}*") and len(out) < MAX_RENDER_CHARS + 200
    assert CUT_NOTE not in kit._safe_markdown("word " * 10)


def _rep(unit: str, size: int) -> str:
    return (unit * (size // len(unit) + 1))[:size]


@pytest.mark.parametrize("hostile", [
    "[](" + " " * 199_990 + "x",  # an empty link with a long space run, past the cap
    "javascript: " + _rep("[", 200_000),
    "javascript: " + _rep("\\[", 200_000),
    "javascript: " + _rep("`", 200_000),
    "javascript: " + _rep("`x``", 200_000),
    "javascript: " + "".join("`" * n + "a" for n in range(1, 600)),
    "javascript: " + _rep("&#106;", 200_000),
    "javascript: " + _rep("```\n", 200_000),
    _rep("javascript", 200_000),
    _rep("data ", 200_000) + ":",
    _rep("<a", 200_000),
], ids=["space run", "brackets", "escaped brackets", "backticks", "backtick runs", "growing runs",
        "entities", "fences", "scheme words", "spaces before colon", "angles"])
def test_kit_filter_neither_stalls_nor_raises_at_the_cap(hostile: str) -> None:
    from tests.aegisshield.stall import STALL_LIMIT_S, least_stall

    run = least_stall(kit._safe_markdown, hostile, repeats=2)
    assert isinstance(run.result, str)
    assert run.stall < STALL_LIMIT_S * 0.4, run
    assert run.total < 5, run


# Literal expectations, independent of the kit's own code detection: text
# CommonMark reads as prose must be escaped even where it looks like code.
@pytest.mark.parametrize(("text", "expected"), [
    ("\\`[x](javascript:alert(1))\\`", "\\`\\[x](javascript:alert(1))\\`"),
    ("`a\n\n[x](javascript:alert(1))\n\n`b", "`a\n\n\\[x](javascript:alert(1))\n\n`b"),
    ("```x`\n[x](javascript:alert(1))", "```x`\n\\[x](javascript:alert(1))"),
    ("- a\n\n  ```\n\n[x](javascript:alert(1))\n\n```", "- a\n\n  ```\n\n\\[x](javascript:alert(1))\n\n```"),
    ("```\n[a](javascript:x)\n   ```\n[b](c)", "```\n[a](javascript:x)\n   ```\n\\[b](c)"),
    ("`[a](javascript:x)` and [b](c)", "`[a](javascript:x)` and \\[b](c)"),
], ids=["escaped backticks", "span across a blank line", "backtick in fence info",
        "indented fence in a list item", "closing fence indented", "real code span"])
def test_kit_code_detection_never_hides_a_link(text: str, expected: str) -> None:
    assert kit._safe_markdown(text) == expected
