"""The threat model detail helpers, the generalized attack chain, and the SVG
diagrams."""

from __future__ import annotations

import base64
import re

import pytest

from aegisshield.llm.mock import MOCK_ATTACK_TREE
from aegisshield.ui import tm_detail as d

DREAD_MD = "\n".join([
    "| ID | Damage Potential | Reproducibility | Exploitability | Affected Users | Discoverability | Risk Score |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    "| TC-S01 | 10 | 9 | 9 | 10 | 8 | 9.2 |",
    "| TC-I02 | 8 | 7 | 8 | 9 | 6 | 7.6 |",
    "| TC-D03 | 6 | 5 | 5 | 4 | 7 | 5.4 |",
])


def test_stride_letter_maps_each_name_by_substring() -> None:
    assert [d.stride_letter(n) for n in ("Spoofing", "Tampering", "Repudiation",
            "Information Disclosure", "Denial of Service", "Elevation of Privilege")] == list("STRIDE")
    assert d.stride_letter("Information Disclosure on $export") == "I"


@pytest.mark.parametrize("value", ["", None, "Nonsense"])
def test_stride_letter_unknown_is_empty(value: object) -> None:
    assert d.stride_letter(value) == ""


def test_parse_dread_table_skips_header_and_separator() -> None:
    rows, by_id = d.parse_dread_table(DREAD_MD)
    assert len(rows) == 3
    assert by_id["TC-S01"].risk == 9.2 and by_id["TC-S01"].damage == 10
    assert by_id["TC-I02"].discoverability == 6


@pytest.mark.parametrize("value", [None, "", 42])
def test_parse_dread_table_empty_for_missing_input(value: object) -> None:
    assert d.parse_dread_table(value) == ([], {})


def test_parse_dread_table_skips_rows_without_a_numeric_risk() -> None:
    md = "| ID | a | b | c | d | e | Risk Score |\n| X1 | 1 | 1 | 1 | 1 | 1 | n/a |"
    assert d.parse_dread_table(md)[0] == []


def test_parse_dread_table_reads_the_pipelines_table() -> None:
    md = ("| ID | Damage Potential | Reproducibility | Exploitability | Affected Users | "
          "Discoverability | Risk Score |\n|----|---|---|---|---|---|----|\n| TC-S01 | 8 | 6 | 6 | 7 | 5 | 6.40 |")
    assert d.parse_dread_table(md)[1]["TC-S01"].risk == 6.4


def test_dread_composite_is_the_rounded_mean() -> None:
    assert d.dread_composite(d.parse_dread_table(DREAD_MD)[0]) == 7.4
    assert d.dread_composite([]) is None
    assert d.dread_composite(None) is None


def test_top_threat_row_and_axes() -> None:
    top = d.top_threat_row(d.parse_dread_table(DREAD_MD)[0])
    assert top is not None and top.id == "TC-S01" and top.risk == 9.2
    axes = d.top_threat_axes(top)
    assert [a[2] for a in axes] == [10, 9, 9, 10, 8]
    assert [a[1] for a in axes] == ["Damage", "Reproducible", "Exploitable", "Affected", "Discoverable"]
    assert d.top_threat_row([]) is None


def test_top_threat_axes_drops_missing_values() -> None:
    assert d.top_threat_axes(None) == []
    partial = d.DreadRow("X", 5, None, 3, None, 2, risk=4)
    assert [a[0] for a in d.top_threat_axes(partial)] == ["damage", "exploitability", "discoverability"]


THREATS = [
    {"ID": "TC-S01", "Threat Type": "Spoofing", "Scenario": "Unauthenticated token refresh grants scope"},
    {"ID": "TC-I02", "Threat Type": "Information Disclosure", "Scenario": "Over-broad scope on export"},
    {"ID": "TC-D03", "Threat Type": "Denial of Service", "Scenario": "Missing rate limit on auth"},
]


def test_attack_chain_runs_entry_surface_top_two_then_data() -> None:
    _, by_id = d.parse_dread_table(DREAD_MD)
    nodes, edges = d.derive_attack_chain(
        {"app_type": "Partner portal", "industry_sector": "Retail", "sensitive_data": "High"}, THREATS, by_id)
    ids = [n.id for n in nodes]
    assert ids == ["entry", "surface", "crit-TC-S01", "crit-TC-I02", "sink"]
    assert nodes[-1].label == "Sensitive data"
    assert any(e.attack for e in edges) and not edges[0].attack


@pytest.mark.parametrize("sector", ["Healthcare", "Pharmaceuticals", "Financial", "Retail"])
def test_the_sink_does_not_depend_on_the_sector(sector: str) -> None:
    nodes, _ = d.derive_attack_chain({"industry_sector": sector, "sensitive_data": "Medium"}, THREATS, {})
    assert nodes[-1].label == "Sensitive data"


def test_no_sink_without_sensitive_data() -> None:
    for sensitive in ("", "None"):
        nodes, _ = d.derive_attack_chain({"sensitive_data": sensitive}, [], {})
        assert [n.id for n in nodes] == ["entry"]


def test_unscored_threats_rank_last() -> None:
    _, by_id = d.parse_dread_table("| ID | a | b | c | d | e | R |\n| TC-D03 | 1 | 1 | 1 | 1 | 1 | 3 |")
    nodes, _ = d.derive_attack_chain({}, THREATS, by_id)
    assert nodes[1].id == "crit-TC-D03"


def test_short_label_cuts_to_the_first_clause() -> None:
    assert d.short_label("Bots flood the endpoint, then stop") == "Bots flood the endpoint"
    assert d.short_label("x" * 40) == "x" * 27 + "..."


def test_mitre_url() -> None:
    assert d.mitre_url("T1078") == "https://attack.mitre.org/techniques/T1078/"
    assert d.mitre_url("T1078.004") == "https://attack.mitre.org/techniques/T1078/004/"
    for bad in ("", "1078", "TXYZ", None, "T1078/../x"):
        assert d.mitre_url(bad) is None


def test_first_mitigation_text_paragraph() -> None:
    md = "# Mitigations\n\n- **Bind** refresh tokens to the `session`.\n\nSecond paragraph."
    assert d.first_mitigation_text(md) == "Bind refresh tokens to the session."
    assert d.first_mitigation_text(None) == ""
    assert d.first_mitigation_text("") == ""


def test_first_mitigation_text_reads_the_table_the_pipeline_writes() -> None:
    md = ("| Threat ID | Threat Type | Mitigation |\n|---|---|---|\n"
          "| TC-S01 | Spoofing | Bind sessions to the device. |\n| TC-T01 | Tampering | Other. |")
    assert d.first_mitigation_text(md) == "Bind sessions to the device."


def _svg(image: str) -> str:
    match = re.search(r'src="data:image/svg\+xml;base64,([^"]+)"', image)
    assert match
    return base64.b64decode(match.group(1)).decode()


def test_chain_svg_escapes_labels_and_draws_every_node() -> None:
    nodes = [d.Node("entry", "Internet", "entry"), d.Node("crit-X", "<script>alert(1)</script>", "crit", "X")]
    svg = d.chain_svg(nodes, [d.Edge("entry", "crit-X", attack=True)])
    assert "<script>" not in svg and "&lt;script&gt;" in svg
    assert svg.count("<circle") == 2 and 'class="edge attack"' in svg


def test_svg_image_is_a_data_uri_with_alt_text() -> None:
    image = d.svg_image('<svg xmlns="http://www.w3.org/2000/svg"></svg>', 'Tree "x"')
    assert image.startswith('<img class="tm-svg" alt="Tree &quot;x&quot;"')
    assert _svg(image) == '<svg xmlns="http://www.w3.org/2000/svg"></svg>'


def test_attack_tree_svg_draws_the_mock_tree() -> None:
    svg = d.attack_tree_svg(MOCK_ATTACK_TREE)
    assert svg is not None
    assert svg.count("<rect") == MOCK_ATTACK_TREE.count("[")
    assert "TC-S01" in svg and 'class="node goal"' in svg and 'class="node leaf"' in svg


def test_attack_tree_svg_escapes_and_survives_cycles() -> None:
    code = 'graph TD\n A["<b>goal</b>"] --> B["step"]\n B --> A\n B --> C["x & y"]'
    svg = d.attack_tree_svg(code)
    assert svg is not None and "<b>" not in svg and "&lt;b&gt;" in svg and "x &amp; y" in svg


@pytest.mark.parametrize("code", [None, "", "   ", "graph TD\n A[only a node]"])
def test_attack_tree_svg_none_without_edges(code: object) -> None:
    assert d.attack_tree_svg(code) is None
