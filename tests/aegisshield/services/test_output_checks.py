"""The application checks: form and references, never correctness."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from aegisshield.services import output_checks
from aegisshield.services.output_checks import review_flags
from tests.aegisshield.safeguards import harness

PROFILE = harness.PROFILE


@pytest.fixture(scope="module")
def linear() -> dict[str, Any]:
    mp = pytest.MonkeyPatch()
    harness.Lookups().install(mp)
    try:
        return harness.run(harness.request())
    finally:
        mp.undo()


@pytest.fixture(scope="module")
def agentic() -> dict[str, Any]:
    mp = pytest.MonkeyPatch()
    harness.Lookups().install(mp)
    try:
        return harness.run(harness.request(agentic=True))
    finally:
        mp.undo()


def _codes(result: dict[str, Any], addons: list[str] | None = harness.ADDONS) -> list[tuple[str, Any, Any]]:
    return [(f["code"], f["threat_id"], f["field"]) for f in review_flags(result, profile=PROFILE, addons=addons)]


def test_mock_runs_carry_zero_flags(linear: dict[str, Any], agentic: dict[str, Any]) -> None:
    assert linear["review_flags"] == [] and agentic["review_flags"] == []
    assert _codes(linear) == [] and _codes(agentic) == []


def test_a_missing_field_and_a_bad_category(linear: dict[str, Any]) -> None:
    result = copy.deepcopy(linear)
    result["threat_model"][0]["Scenario"] = "  "
    result["threat_model"][1]["Threat Type"] = "Phishing"
    result["threat_model"][2]["MITRE ATT&CK Keywords"] = []
    result["threat_model"][3]["Assumptions"] = "none"
    codes = _codes(result)
    assert ("missing_field", "TC-S01", "Scenario") in codes
    assert ("stride_category", "TC-T01", "Threat Type") in codes
    assert ("missing_field", "TC-R01", "MITRE ATT&CK Keywords") in codes
    assert ("structure", "TC-I01", "Assumptions") in codes


def test_shapes(linear: dict[str, Any]) -> None:
    result = copy.deepcopy(linear)
    result["threat_model"].append("not an object")
    result["improvement_suggestions"] = [1, 2]
    result["mitre_data"] = [{"threat": {}}]
    codes = {c[0] for c in _codes(result)}
    assert codes == {"structure"}
    assert _codes({**linear, "threat_model": "x"})[0] == ("structure", None, "threat_model")
    assert ("missing_section", None, "threat_model") in _codes({**linear, "threat_model": []})


def test_a_requested_section_that_is_missing(linear: dict[str, Any], agentic: dict[str, Any]) -> None:
    result = {k: v for k, v in linear.items() if k != "test_cases_markdown"}
    assert ("missing_section", None, "test_cases_markdown") in _codes(result)
    assert _codes(result, addons=["mitigations", "dread"]) == []
    plan_result = {k: v for k, v in agentic.items() if k != "rebuttal_review"}
    assert ("missing_section", None, "rebuttal_review") in _codes(plan_result, addons=None)


def test_dread_ranges_and_scores(linear: dict[str, Any]) -> None:
    result = copy.deepcopy(linear)
    rows = result["dread_assessment"]["Risk Assessment"]
    rows[0]["Damage Potential"] = 11
    rows[1]["Risk Score"] = 9.9
    rows[2]["Exploitability"] = 0
    result["dread_assessment_markdown"] = result["dread_assessment_markdown"].replace(
        "| 5.60 |", "| 7.00 |", 1)
    codes = _codes(result)
    assert ("dread_range", rows[0]["ID"], "Damage Potential") in codes
    assert ("dread_score", rows[1]["ID"], "Risk Score") in codes
    assert ("dread_range", rows[2]["ID"], "Exploitability") in codes
    assert sum(1 for c in codes if c[0] == "dread_score") == 2
    bad = {**linear, "dread_assessment": {"Risk Assessment": [{"Damage Potential": "high"}]}}
    assert ("structure", None, "dread_assessment") in _codes(bad)
    assert ("structure", None, "dread_assessment") in _codes({**linear, "dread_assessment": []})


def test_references_that_resolve_to_nothing_supplied(linear: dict[str, Any]) -> None:
    result = copy.deepcopy(linear)
    result["threat_model"][0]["Scenario"] += " See CVE-2021-44228 and technique T9999."
    result["threat_model"][1]["Scenario"] += " Uses CVE-2024-10979 and T1078."
    result["mitigations_markdown"] += "\n| TC-Z09 | Spoofing | Patch nginx 1.25.3 and Redis 7.2.4. |"
    result["mitre_data"][0]["mitre_techniques"][0]["technique_id"] = "AML.T9999"
    result["dread_assessment"]["Risk Assessment"][0]["ID"] = "TC-Q01"
    flags = review_flags(result, profile=PROFILE, addons=harness.ADDONS)
    codes = [(f["code"], f["threat_id"], f["field"]) for f in flags]
    assert ("unsupported_cve", "TC-S01", "Scenario") in codes
    assert ("unsupported_technique", "TC-S01", "Scenario") in codes
    assert ("unknown_threat_id", None, "mitigations_markdown") in codes
    assert ("unknown_threat_id", None, "dread_assessment") in codes
    assert ("unsupported_technique", "TC-S01", "mitre_data") in codes
    named = [f["sentence"] for f in flags if f["code"] == "unsupported_technology"]
    assert any("nginx 1.25.3" in s for s in named) and any("Redis 7.2.4" in s for s in named)
    # Supplied ones resolve: CVE-2024-10979 came from the NVD stub, T1078 is in the catalog.
    assert not any("CVE-2024-10979" in f["sentence"] or "T1078" in f["sentence"] for f in flags)
    assert all(f["sentence"].startswith("Unsupported reference, review: ")
               for f in flags if f["code"].startswith(("unsupported", "unknown")))
    # Flags never change the result.
    assert result["threat_model"][0]["Scenario"].endswith("T9999.")


def test_a_requested_version_resolves(linear: dict[str, Any]) -> None:
    result = copy.deepcopy(linear)
    result["mitigations_markdown"] += "\nUpgrade nginx 1.24.0 and PostgreSQL 15.4."
    assert _codes(result) == []


def test_the_note_says_what_the_checks_are() -> None:
    assert "form and of references" in output_checks.CHECKS_NOTE
    assert "do not judge whether a finding is right" in output_checks.CHECKS_NOTE
