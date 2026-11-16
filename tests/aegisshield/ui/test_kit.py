"""The kit escapes every piece of caller text it puts into HTML."""

from __future__ import annotations

import html

import pytest
import streamlit as st

from aegisshield.ui import kit
from aegisshield.ui.theme import Area, Tone

HOSTILE = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "' onmouseover='alert(1)",
    "</div></header><style>body{display:none}</style>",
    "&lt;already&gt; & <b>bold</b>",
    "javascript:alert(1)",
]


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    out: list[str] = []
    monkeypatch.setattr(st, "html", lambda body, **_: out.append(body))
    return out


def _assert_inert(markup: str, text: str) -> None:
    """The text is present only in escaped form, and adds no tags."""
    assert html.escape(text, quote=True) in markup, markup
    if any(ch in text for ch in "<>\"'&"):
        assert text not in markup
    for tag in ("<script", "<img", "<style", "<b>"):
        assert tag not in markup


@pytest.mark.parametrize("text", HOSTILE)
def test_page_header_escapes(captured: list[str], text: str) -> None:
    kit.page_header(text, text, area=Area.DEFENSE)
    _assert_inert(captured[0], text)
    assert "ax-area-defense" in captured[0]


@pytest.mark.parametrize("text", HOSTILE)
def test_section_badge_notice_escape(captured: list[str], text: str) -> None:
    kit.section(text, text)
    kit.badge(text, tone=Tone.WARN)
    kit.notice(text, tone=Tone.CRIT, label=text)
    for markup in captured:
        _assert_inert(markup, text)


@pytest.mark.parametrize("text", HOSTILE)
def test_stat_tiles_and_key_values_escape(captured: list[str], text: str) -> None:
    kit.stat_row([kit.Tile(text, text, text, Tone.OK)])
    kit.key_value_list({text: text})
    kit.key_value_list([(text, text)], mono=True)
    for markup in captured:
        _assert_inert(markup, text)


def test_severity_badge_words_and_unknowns() -> None:
    assert "Critical" in kit.severity_badge_html("CRITICAL ")
    assert "ax-tone-crit" in kit.severity_badge_html("high")
    assert "Medium" in kit.severity_badge_html("medium")
    assert "Info" in kit.severity_badge_html("informational")
    assert "Unknown" in kit.severity_badge_html(None)
    hostile = kit.severity_badge_html("<script>x</script>")
    assert "Unknown" in hostile and "<script" not in hostile




def test_area_and_tone_must_be_known_values(captured: list[str]) -> None:
    with pytest.raises(ValueError):
        kit.page_header("t", area="offense")
    with pytest.raises(ValueError):
        kit.badge("t", tone='x" onclick="y')
    assert captured == []


def test_neutral_area_has_no_eyebrow(captured: list[str]) -> None:
    kit.page_header("Settings", area=Area.NEUTRAL)
    assert "ax-eyebrow" not in captured[0] and "ax-subtitle" not in captured[0]


@pytest.mark.parametrize("sample", [
    "![leak](https://evil.example/x.png?d=secret)",
    "![ref][r]\n\n[r]: https://evil.example/y.png",
    "![r]\n\n[r]: https://evil.example/z.png",
    "![a [nested] alt](https://evil.example/n.png)",
    "![multi\nline alt](https://evil.example/m.png \"t\nitle\")",
])
def test_model_markdown_escapes_every_image_opener(monkeypatch: pytest.MonkeyPatch,
                                                   sample: str) -> None:
    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(st, "markdown", lambda body, **kw: calls.append((body, kw)))
    kit.model_markdown(sample)
    body, kw = calls[0]
    assert kw == {"unsafe_allow_html": False}
    assert body.count("![") == 0
    assert body.count("!\\[") == sample.count("![")


def test_model_markdown_drops_controls_and_keeps_formatting(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(st, "markdown", lambda body, **kw: calls.append(body))
    kit.model_markdown("**bold** \u202eflip\u200b and `code`")
    assert calls[0] == "**bold** flip and `code`"


def test_model_markdown_handles_none(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(st, "markdown", lambda body, **kw: calls.append(body))
    kit.model_markdown(None)
    assert calls == [""]


def test_wide_canvas_marks_the_page(captured: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    configs: list[dict] = []
    monkeypatch.setattr(st, "set_page_config", lambda **kw: configs.append(kw))
    kit.wide_canvas()
    assert captured == ['<div class="ax-wide" hidden></div>']
    assert configs == [{"initial_sidebar_state": "collapsed"}]


def test_deep_link_helpers_put_the_id_in_the_query(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisshield.ui import routes

    sentinel = object()
    monkeypatch.setattr(routes, "page", lambda name: (sentinel, name))
    links: list[tuple] = []
    switches: list[tuple] = []
    monkeypatch.setattr(st, "page_link", lambda page, **kw: links.append((page, kw)))
    monkeypatch.setattr(st, "switch_page", lambda page, **kw: switches.append((page, kw)))
    kit.record_link("threat_model_detail", "abc_123", "Open")
    kit.open_record("threat_model_detail", "abc_123")
    assert links == [((sentinel, "threat_model_detail"),
                      {"label": "Open", "query_params": {"id": "abc_123"}})]
    assert switches == [((sentinel, "threat_model_detail"), {"query_params": {"id": "abc_123"}})]


@pytest.mark.parametrize(("count", "columns"), [
    (0, 1), (1, 1), (3, 3), (4, 4), (5, 3), (6, 3), (7, 4), (8, 4), (9, 3),
])
def test_tile_rows_are_full_or_balanced(count: int, columns: int) -> None:
    assert kit.tile_columns(count) == columns
    if count:
        rows = -(-count // columns)
        last = count - (rows - 1) * columns
        assert columns <= kit.MAX_TILES_PER_ROW and columns - last <= 1 or last == columns


def test_stat_row_sets_its_column_count(captured: list[str]) -> None:
    kit.stat_row([kit.Tile(str(i), i) for i in range(7)])
    assert '<div class="ax-tiles" style="--ax-cols: 4">' in captured[-1]
