"""Every function that applies a pattern to text a visitor can influence
(imported records, model output, a pasted list) finishes quickly on hostile
text at the import limit, without stalling other threads or raising.

The inputs are the slowest found for each function by timing it on runs of
each character its patterns mention and on pairs of them (the audit table
is in the report of the change). Several took seconds before."""

from __future__ import annotations

import re

import pytest

from aegisshield.pipeline import attack_tree_service
from aegisshield.services import report_service, vuln_lookup
from aegisshield.storage.workspace import MAX_STRING_CHARS
from aegisshield.ui import lookup_data, pcap_data, threat_model_view, tm_detail
from tests.aegisshield.stall import STALL_LIMIT_S, least_stall

N = MAX_STRING_CHARS


def _rep(unit: str, size: int = N) -> str:
    return (unit * (size // len(unit) + 1))[:size]


CHAIN = "graph TD\n" + "".join(f"N{i}[step {i}] --> N{i + 1}[step {i + 1}]\n" for i in range(5000))

CASES = {
    # (function, hostile input); the time each took before this change.
    "Mermaid node labels (9 s at 50k)": (report_service.render_attack_tree, _rep("(0")),
    "Mermaid edges over blank lines (6 s at 50k)": (report_service.render_attack_tree, "A" + "\n" * N),
    "a Mermaid chain 5,000 deep (RecursionError)": (report_service.render_attack_tree, CHAIN),
    "the tree drawing of that chain (RecursionError)": (tm_detail.attack_tree_svg, CHAIN),
    "gherkin fence before whitespace (4.8 s at 50k)": (threat_model_view.gherkin_text, "```" + "\n" * N),
    "gherkin fences": (threat_model_view.gherkin_text, _rep("```gherkin\n\n")),
    "PCAP conversation with trailing spaces (3.9 s at 50k)":
        (lambda s: pcap_data.conversation_rows([s]), "a <-> b x" + " " * N + "y"),
    "banner names (35 s at 200k)": (vuln_lookup.parse_text, _rep("-A")),
    "a pasted banner run": (lookup_data.parse_pasted, _rep("A")),
    "Mermaid fence cleanup (1.3 s at 50k)": (attack_tree_service.strip_code_fences, "a" + "\t" * N + "b"),
    "test cases": (report_service.render_test_cases, _rep("```gherkin\n\n")),
    "DREAD table": (tm_detail.parse_dread_table, _rep("| TC-S01 | 1 | 2 | 3 | 4 | 5 | 6 |\n")),
    "first mitigation": (tm_detail.first_mitigation_text, _rep("\n(")),
    "markdown table": (threat_model_view.markdown_table, _rep("| a |\n")),
}


@pytest.mark.parametrize("name", list(CASES))
def test_hostile_text_neither_stalls_nor_raises(name: str) -> None:
    fn, text = CASES[name]
    run = least_stall(fn, text, repeats=2)
    assert run.stall < STALL_LIMIT_S * 0.6, run
    assert run.total < 5, run


# ------------------------------------------------- same answers as before


def _old_gherkin(markdown: str) -> str:
    blocks = re.findall(r"```(?:gherkin|cucumber)?\s*\n(.*?)```", markdown, flags=re.S)
    return "\n\n".join(b.strip() for b in blocks if b.strip()) + ("\n" if blocks else "")


@pytest.mark.parametrize("text", [
    "```gherkin\nFeature: a\n```\nprose\n```cucumber  \n\nScenario: b\n```",
    "```\nplain\n```",
    "```gherkinx\nnot a block\n```\n```gherkin\nyes\n```",
    "``` no newline ``` then\n```\nnext\n```",
    "````\nfour\n````",
    "```gherkin\nunclosed",
    "text only",
    "```\n\n\n   \nspaced\n```",
])
def test_gherkin_text_finds_what_the_pattern_found(text: str) -> None:
    assert threat_model_view.gherkin_text(text) == _old_gherkin(text)


_OLD_FENCES = r"^```mermaid\s*|\s*```$"


@pytest.mark.parametrize("text", [
    "```mermaid\ngraph TD\nA-->B\n```",
    "```\ngraph TD\n  A-->B  \n```\n",
    "graph TD\nA-->B",
    "```mermaid graph TD\nA-->B ```",
    "  ```mermaid\nA-->B\n```",
])
def test_fence_cleanup_matches_the_pattern_it_replaces(text: str) -> None:
    expected = re.sub(_OLD_FENCES, "", text, flags=re.MULTILINE).strip()
    assert attack_tree_service.strip_code_fences(text) == expected


@pytest.mark.parametrize("tail", ["", "   ", "\t "])
def test_conversation_rows_read_the_same_with_or_without_trailing_space(tail: str) -> None:
    (row,) = pcap_data.conversation_rows(["10.0.0.1:5060 <-> 10.0.0.2:5060   12 3456 7 890 19 4346" + tail])
    assert (row["Address A"], row["Address B"], row["Details"]) == (
        "10.0.0.1:5060", "10.0.0.2:5060", "12 3456 7 890 19 4346")


def test_banners_with_names_over_64_characters_are_not_read() -> None:
    assert [t.name for t in vuln_lookup.parse_text("nginx/1.25.3 and OpenSSL/3.0.13")] == ["nginx", "OpenSSL"]
    assert vuln_lookup.parse_text("x" * 65 + "/1.2") == []
    assert [t.name for t in vuln_lookup.parse_text("y" * 64 + "/1.2")] == ["y" * 64]


def test_a_paste_is_read_up_to_its_limits() -> None:
    line = "nginx 1.25.3"
    found = lookup_data.parse_pasted(line + "\n" + "z" * 50_000)
    assert found[0].name == "nginx"
    assert all(len(t.name) <= lookup_data.MAX_PASTE_LINE_CHARS for t in found)
    far = "\n" * lookup_data.MAX_PASTE_CHARS + "OpenSSL/3.0.13"
    assert lookup_data.parse_pasted(far) == []
    # A line is read up to MAX_PASTE_LINE_CHARS, so a banner past that point is not seen.
    clipped = "A" * (lookup_data.MAX_PASTE_LINE_CHARS - 5) + " OpenSSL/3.0.13"
    assert all(t.name != "OpenSSL" for t in lookup_data.parse_pasted(clipped))


def test_a_long_mermaid_line_is_skipped_not_parsed() -> None:
    code = "graph TD\nA[Goal] --> B[Step]\n" + "C" * (report_service.MAX_MERMAID_LINE_CHARS + 1) + " --> D\n"
    labels, children, _roots = report_service._parse_mermaid_graph(code)
    assert children == {"A": ["B"]} and labels["A"] == "Goal"


def test_a_deep_tree_is_cut_at_the_depth_limit() -> None:
    html_out = report_service.render_attack_tree(CHAIN)
    assert f"steps below level {report_service.MAX_TREE_DEPTH} not shown" in html_out
    assert html_out.count('class="tree-node') == report_service.MAX_TREE_DEPTH
    svg = tm_detail.attack_tree_svg(CHAIN)
    assert svg is not None and svg.count('class="node') <= report_service.MAX_TREE_DEPTH + 1
