"""Incremental parsers for streamed model text.

The reference for every assertion is an independent parse of the full text
(``json.loads``, ``splitlines``), never the parser under test fed all at once.
The fixture is a recording of one real streamed run.
"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path

import pytest

from aegisshield.core.text import clip_tail, clip_words
from aegisshield.pipeline.stream_items import (
    JsonArrayItems,
    Lines,
    Sections,
    TableRows,
    table_cells,
)

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "stream_capture.json"


def _capture() -> dict:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _call(stage: str) -> dict:
    return next(c for c in _capture()["calls"] if c["stage"] == stage)


def _deltas(stage: str) -> list[str]:
    return [d[1] for d in _call(stage)["deltas"]]


def _full(stage: str) -> str:
    return "".join(_deltas(stage))


def _run(parser, chunks: list[str]) -> list:
    out: list = []
    for chunk in chunks:
        out.extend(parser.feed(chunk))
    out.extend(parser.close())
    return out


def _rechunk(text: str, mode: str) -> list[str]:
    if mode == "one":
        return list(text)
    rng = random.Random(24)  # noqa: S311 - fixed-seed test chunking, not crypto
    out, i = [], 0
    while i < len(text):
        step = rng.randint(1, 40)
        out.append(text[i : i + step])
        i += step
    return out


# Independent references


def _ref_table_rows(text: str) -> list[list[str]]:
    rows = [ln for ln in text.splitlines() if ln.strip().startswith("|")]
    return [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows[2:]]


def _ref_sections(text: str) -> list[dict[str, str]]:
    parts = re.split(r"^## (.*)$", text, flags=re.MULTILINE)
    return [
        {"heading": parts[i].strip(), "body": parts[i + 1].strip()}
        for i in range(1, len(parts), 2)
    ]


# Fixture replays


@pytest.mark.parametrize("mode", ["real", "one", "random"])
def test_threat_model_items_match_full_parse(mode: str) -> None:
    full = _full("stride")
    chunks = _deltas("stride") if mode == "real" else _rechunk(full, mode)
    items = _run(JsonArrayItems("threat_model"), chunks)
    assert items == json.loads(full)["threat_model"]
    assert len(items) == 18


def test_threat_model_items_arrive_one_at_a_time_in_order() -> None:
    parser = JsonArrayItems("threat_model")
    seen = []
    for delta in _deltas("stride"):
        got = parser.feed(delta)
        assert len(got) <= 1
        seen.extend(got)
    assert [t["Scenario"] for t in seen] == [
        t["Scenario"] for t in _capture()["expected"]["threat_model"]
    ]


@pytest.mark.parametrize("mode", ["real", "one", "random"])
def test_dread_items_match_full_parse(mode: str) -> None:
    full = _full("dread")
    chunks = _deltas("dread") if mode == "real" else _rechunk(full, mode)
    items = _run(JsonArrayItems("Risk Assessment"), chunks)
    assert items == _capture()["expected"]["dread_assessment"]["Risk Assessment"]


@pytest.mark.parametrize("mode", ["real", "one", "random"])
def test_mitigation_rows_match_full_parse(mode: str) -> None:
    full = _full("mitigations")
    chunks = _deltas("mitigations") if mode == "real" else _rechunk(full, mode)
    rows = _run(TableRows(), chunks)
    assert rows == _ref_table_rows(full)
    assert [r[0] for r in rows][:3] == ["TC-S01", "TC-S02", "TC-S03"]
    assert len(rows) == 18


@pytest.mark.parametrize("mode", ["real", "one", "random"])
def test_test_case_sections_match_full_parse(mode: str) -> None:
    full = _full("test_cases")
    chunks = _deltas("test_cases") if mode == "real" else _rechunk(full, mode)
    sections = _run(Sections(), chunks)
    assert sections == _ref_sections(full)
    assert len(sections) == 18
    assert sections[0]["heading"] == "TC-S01"


@pytest.mark.parametrize("mode", ["real", "one", "random"])
def test_attack_tree_lines_match_full_parse(mode: str) -> None:
    full = _full("attack_tree")
    chunks = _deltas("attack_tree") if mode == "real" else _rechunk(full, mode)
    assert _run(Lines(), chunks) == full.split("\n")


def test_last_item_without_trailing_newline_is_flushed_by_close() -> None:
    # The recorded mitigations table ends on a row with no newline after it.
    parser = TableRows()
    fed = []
    for delta in _deltas("mitigations"):
        fed.extend(parser.feed(delta))
    assert len(fed) == 17
    assert len(parser.close()) == 1


# Hostile JSON

_HOSTILE = (
    "Here you go:\n```json\n"
    '{"note": "a { [ \\" } ] threat_model", '
    '"nested": {"threat_model": [{"wrong": 1}]}, '
    '"threat_model": ['
    '{"s": "back\\\\slash", "t": "}{][", "q": "say \\"hi\\""}, '
    '{"u": "caf\\u00e9 \u00e9 \U0001f600 \u4e2d\u6587", "n": [1, {"a": [2, "]"]}]}, '
    '"not an object", '
    '{"last": true}'
    '], "other": [{"z": 1}]}\n```'
)


def test_hostile_json_every_split_point() -> None:
    body = _HOSTILE.split("```json\n", 1)[1].rsplit("\n```", 1)[0]
    expected = [x for x in json.loads(body)["threat_model"] if isinstance(x, dict)]
    assert len(expected) == 3
    for cut in range(len(_HOSTILE) + 1):
        parser = JsonArrayItems("threat_model")
        got = _run(parser, [_HOSTILE[:cut], _HOSTILE[cut:]])
        assert got == expected, f"split at {cut}"
    assert _run(JsonArrayItems("threat_model"), list(_HOSTILE)) == expected


def test_split_escape_sequence_and_unicode_escape() -> None:
    text = '{"threat_model": [{"a": "x\\"y\\\\", "b": "\\u00e9\\ud83d\\ude00"}]}'
    expected = json.loads(text)["threat_model"]
    for cut in range(len(text) + 1):
        assert _run(JsonArrayItems("threat_model"), [text[:cut], text[cut:]]) == expected


def test_key_must_be_top_level_and_followed_by_array() -> None:
    text = '{"label": "threat_model", "x": ["threat_model"], "threat_model": []}'
    assert _run(JsonArrayItems("threat_model"), list(text)) == []


def test_json_tail_reports_item_in_progress() -> None:
    parser = JsonArrayItems("threat_model")
    parser.feed('{"threat_model": [{"Threat Type": "Spoof')
    assert parser.in_item
    assert parser.tail(5) == "Spoof"
    parser.feed('ing"}')
    assert not parser.in_item
    assert parser.tail(5) == ""


def test_malformed_item_is_skipped() -> None:
    text = '{"threat_model": [{"a": 1, }, {"b": 2}]}'
    assert _run(JsonArrayItems("threat_model"), [text]) == [{"b": 2}]


# Hostile markdown


def test_table_header_and_separator_skipped_with_alignment() -> None:
    text = "intro\n| ID | Fix |\n|:---|---:|\n| TC-S01 | a |\n\n| TC-X | no header |\n| TC-Y | z |\n"
    assert _run(TableRows(), list(text)) == [
        ["TC-S01", "a"],
        ["TC-X", "no header"],
        ["TC-Y", "z"],
    ]


def test_table_single_row_before_prose_is_data() -> None:
    assert _run(TableRows(), ["| TC-S01 | a |\nprose\n"]) == [["TC-S01", "a"]]


def test_table_cells_has_no_escaped_pipe_rule_like_existing_readers() -> None:
    # The existing table readers split on every pipe; so does this.
    assert table_cells("| TC-S01 | a \\| b |") == ["TC-S01", "a \\", "b"]
    assert table_cells("not a row") is None


def test_table_tail_only_for_row_in_progress() -> None:
    parser = TableRows()
    parser.feed("| TC-S01 | partial fi")
    assert parser.tail(10) == "partial fi"
    parser = TableRows()
    parser.feed("prose")
    assert parser.tail(10) == ""


def test_sections_ignore_heading_inside_fence_and_report_progress() -> None:
    text = "preamble\n## TC-S01\n```\n## not a heading\n```\nbody\n### sub\n## TC-S02\nx"
    parser = Sections()
    got = parser.feed(text)
    assert got == [
        {"heading": "TC-S01", "body": "```\n## not a heading\n```\nbody\n### sub"}
    ]
    assert parser.heading == "TC-S02"
    assert parser.body_so_far() == "x"
    assert parser.tail(4) == "02\nx"
    assert parser.close() == [{"heading": "TC-S02", "body": "x"}]
    assert Sections().tail(5) == ""


def test_lines_tail_and_crlf() -> None:
    parser = Lines()
    assert parser.feed("a\r\nb") == ["a"]
    assert parser.tail(3) == "b"
    assert parser.close() == ["b"]
    assert parser.close() == []


# Clipping


def test_clip_words() -> None:
    assert clip_words("  short  ", 10) == "short"
    clipped = clip_words("alpha beta gamma delta", 15)
    assert clipped == "alpha beta..."
    assert len(clipped) <= 15
    assert clip_words("abcdefghij", 6) == "abc..."
    assert clip_words("abcdef", 2) == "ab"
    assert clip_words(None, 5) == ""  # type: ignore[arg-type]


def test_clip_tail() -> None:
    assert clip_tail("short", 10) == "short"
    clipped = clip_tail("alpha beta gamma delta", 14)
    assert clipped == "...gamma delta"
    assert len(clipped) <= 14
    assert clip_tail("abcdefghij", 6) == "...hij"
    assert clip_tail("abcdef", 2) == "ef"
    assert clip_tail("abc defghij ", 8) == "...ghij "


def test_sections_treat_tilde_fence_like_backtick_fence() -> None:
    text = (
        "## TC-S01\n~~~gherkin\n## not a heading\n```\n## still body\n~~~\n"
        "## TC-S02\n```\n~~~\n## body too\n```\nend"
    )
    parser = Sections()
    items = [*parser.feed(text), *parser.close()]
    assert [s["heading"] for s in items] == ["TC-S01", "TC-S02"]
    assert "## not a heading" in items[0]["body"] and "## still body" in items[0]["body"]
    assert "## body too" in items[1]["body"]
