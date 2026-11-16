"""Tests for the NIST CSF 2.0 mapper."""

from __future__ import annotations

from aegisshield.services.nist_csf_service import (
    EMPTY_CELL,
    CsfCategory,
    ThreatCsfMapping,
    _category_index,
    category_index,
    coverage_summary,
    csf_report,
    map_threats,
    to_markdown,
)


def _threat(threat_type: str, scenario: str, **extra) -> dict:
    return {
        "Threat Type": threat_type,
        "Scenario": scenario,
        "Assumptions": [],
        "Potential Impact": "High",
        "MITRE ATT&CK Keywords": [],
        **extra,
    }


def _mitre(threat: dict, tactic: object, technique_id: str = "T1041") -> dict:
    return {
        "threat": {**threat},
        "mitre_techniques": [{"technique_id": technique_id, "tactic": tactic, "name": "x"}],
    }


# Mapping and coverage -------------------------------------------------------


def test_stride_baseline_maps_to_csf() -> None:
    threats = [_threat("Information Disclosure", "secrets leak through API")]
    mappings = map_threats(threats, mitre_data=[])
    assert mappings
    cat_ids = {c.id for c in mappings[0].categories}
    assert "PR.DS" in cat_ids
    assert "PR.AA" in cat_ids


def test_tactic_signal_unions_with_stride_signal() -> None:
    threats = [_threat("Information Disclosure", "exfiltration via vector store", ID="T-1")]
    mitre = [_mitre(threats[0], "Exfiltration")]
    mappings = map_threats(threats, mitre_data=mitre)
    cat_ids = {c.id for c in mappings[0].categories}
    assert "RS.MI" in cat_ids
    assert mappings[0].technique_id == "T1041"
    assert mappings[0].threat_id == "T-1"


def test_unknown_stride_yields_empty_mapping() -> None:
    threats = [_threat("NotARealStrideCategory", "weird threat")]
    mappings = map_threats(threats, mitre_data=[])
    assert mappings[0].categories == []


def test_coverage_summary_counts_per_function() -> None:
    threats = [
        _threat("Spoofing", "credential reuse"),
        _threat("Denial of Service", "flood the API"),
    ]
    coverage = coverage_summary(map_threats(threats, mitre_data=[]))
    assert coverage["PR"]["threat_count"] == 2
    assert "PR.AA" in coverage["PR"]["categories"]
    # Only the denial of service threat touches Respond (RS.MI).
    assert coverage["RS"]["threat_count"] == 1
    assert coverage["RS"]["categories"] == ["RS.MI"]


def test_markdown_renders_table() -> None:
    md = to_markdown(map_threats([_threat("Spoofing", "credential reuse")], mitre_data=[]))
    assert "| Threat |" in md
    assert "Spoofing" in md
    assert "PR.AA" in md


def test_markdown_handles_empty() -> None:
    assert "No threats" in to_markdown([])


# Shape the exporters rely on ------------------------------------------------


def test_output_shape_is_faithful() -> None:
    mappings = map_threats([_threat("Spoofing", "credential reuse")])
    m = mappings[0]
    assert isinstance(m, ThreatCsfMapping)
    assert m.threat_id is None
    assert m.technique_id is None
    assert m.categories[0] == CsfCategory(
        id="PR.AA",
        name=m.categories[0].name,
        function_id="PR",
        function_name="Protect",
    )
    # STRIDE order is kept: PR.AA, DE.CM, GV.PO.
    assert [c.id for c in m.categories] == ["PR.AA", "DE.CM", "GV.PO"]
    coverage = coverage_summary(mappings)
    assert list(coverage) == ["GV", "ID", "PR", "DE", "RS", "RC"]
    assert set(coverage["GV"]) == {"name", "summary", "threat_count", "categories"}


def test_tactic_categories_are_not_duplicated() -> None:
    threats = [_threat("Information Disclosure", "leak", ID="T-1")]
    mappings = map_threats(threats, [_mitre(threats[0], "Exfiltration")])
    ids = [c.id for c in mappings[0].categories]
    assert ids == ["PR.DS", "PR.AA", "DE.CM", "RS.MI"]


def test_mitre_entry_matches_by_scenario_without_id() -> None:
    threats = [_threat("Tampering", "edit the cart total")]
    mappings = map_threats(threats, [_mitre(threats[0], "Impact", "T1565")])
    assert mappings[0].technique_id == "T1565"
    assert "RC.RP" in {c.id for c in mappings[0].categories}


def test_malformed_mitre_entries_are_skipped() -> None:
    threats = [_threat("Spoofing", "credential reuse")]
    mitre = [
        "not a dict",
        {"threat": "not a dict"},
        {"threat": threats[0], "mitre_techniques": []},
        {"threat": threats[0], "mitre_techniques": ["not a dict"]},
    ]
    mappings = map_threats(threats, mitre)
    assert mappings[0].technique_id is None
    assert [c.id for c in mappings[0].categories] == ["PR.AA", "DE.CM", "GV.PO"]


# Matching edge cases ------------------------------------------------------------


def test_title_cased_tactic_still_matches() -> None:
    """The catalog title-cases tactics ("Command And Control"); the map says "and"."""
    threats = [_threat("Repudiation", "c2 over https", ID="T-9")]
    for tactic in ("Command And Control", "command-and-control", "Ml Attack Staging"):
        mappings = map_threats(threats, [_mitre(threats[0], tactic)])
        ids = {c.id for c in mappings[0].categories}
        assert {"PR.IR"} <= ids or {"GV.SC", "PR.PS"} <= ids, tactic


def test_non_string_tactic_is_ignored() -> None:
    threats = [_threat("Spoofing", "x", ID="T-1")]
    mappings = map_threats(threats, [_mitre(threats[0], None)])
    assert [c.id for c in mappings[0].categories] == ["PR.AA", "DE.CM", "GV.PO"]


def test_markdown_escapes_every_model_cell() -> None:
    mapping = ThreatCsfMapping(
        threat_id="T-1",
        threat_type="Spoof|ing",
        scenario="line one\nline | two",
        technique_id="T1|059",
        categories=[],
    )
    md = to_markdown([mapping])
    row = md.splitlines()[2]
    assert "Spoof\\|ing" in row
    assert "line one line \\| two" in row
    assert "T1\\|059" in row
    # One row per threat even when the scenario has a newline.
    assert len(md.splitlines()) == 3


def test_markdown_empty_cells_use_plain_hyphen() -> None:
    mapping = ThreatCsfMapping(
        threat_id=None, threat_type="", scenario="", technique_id=None, categories=[]
    )
    row = to_markdown([mapping]).splitlines()[2]
    assert row == f"| {EMPTY_CELL} | {EMPTY_CELL} | {EMPTY_CELL} | {EMPTY_CELL} |"
    assert "\u2014" not in row


def test_coverage_ignores_category_from_unknown_function() -> None:
    stray = CsfCategory(id="ZZ.XX", name="Stray", function_id="ZZ", function_name="Unknown")
    mapping = ThreatCsfMapping(
        threat_id=None, threat_type="", scenario="", technique_id=None, categories=[stray]
    )
    coverage = coverage_summary([mapping])
    assert "ZZ" not in coverage
    assert all(v["threat_count"] == 0 for v in coverage.values())


# Helpers other services and the exporters use ----------------------------------


def test_category_index_tuple_matches_source_signature() -> None:
    by_id, functions = _category_index()
    assert by_id == category_index()
    assert by_id["RS.MI"].function_name == "Respond"
    assert functions["PR"]["name"] == "Protect"
    # The raw functions are copies, so a caller cannot change the cached data.
    functions["PR"]["name"] = "changed"
    assert _category_index()[1]["PR"]["name"] == "Protect"


def test_csf_report_shape_matches_the_route() -> None:
    threats = [_threat("Spoofing", "credential reuse", ID="TC-S01")]
    report = csf_report(threats, [_mitre(threats[0], "Credential Access", "T1539")])
    assert set(report) == {"mappings", "coverage", "markdown"}
    row = report["mappings"][0]
    assert set(row) == {"threat_id", "threat_type", "scenario", "technique_id", "categories"}
    assert row["threat_id"] == "TC-S01"
    assert row["technique_id"] == "T1539"
    assert row["categories"][0] == {
        "id": "PR.AA",
        "name": row["categories"][0]["name"],
        "function_id": "PR",
        "function_name": "Protect",
    }
    assert report["coverage"]["PR"]["threat_count"] == 1
    assert report["markdown"].startswith("| Threat |")
