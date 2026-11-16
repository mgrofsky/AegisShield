"""Neutral organization context built only from the request."""

from __future__ import annotations

import pytest

from aegisshield.llm.mock import MockLLM
from aegisshield.pipeline import sector_context as sc
from aegisshield.pipeline.mitre_service import create_mitre_prompt
from aegisshield.pipeline.threat_model_service import create_threat_model_prompt

FULL = {
    "industry_sector": "Retail",
    "sensitive_data": "Payment card data",
    "compliance_requirements": ["PCI DSS", "GDPR", "PCI DSS"],
    "authentication": ["OAuth2", "MFA"],
    "internet_facing": "Yes",
}


def test_context_lines_name_each_field_the_request_filled_in() -> None:
    assert sc.context_lines(FULL) == [
        "Industry sector: Retail",
        "Data sensitivity: Payment card data",
        "Compliance requirements selected: PCI DSS, GDPR",
        "Authentication methods: OAuth2, MFA",
        "Internet facing: Yes",
    ]


@pytest.mark.parametrize("empty", ["", "  ", "Unknown", "none", "N/A", None, 42])
def test_empty_or_non_answers_are_left_out(empty: object) -> None:
    assert sc.context_lines({"industry_sector": empty, "compliance_requirements": [empty]}) == []
    assert sc.context_block({"industry_sector": empty}) == ""
    assert sc.compact_context({"industry_sector": empty}) == ""


def test_nothing_is_assumed_from_a_sector() -> None:
    block = sc.context_block({"industry_sector": "Finance"})
    assert "Industry sector: Finance" in block
    assert "Compliance" not in block
    assert "compliance" not in block


def test_a_selected_framework_is_named_with_guidance() -> None:
    block = sc.context_block(FULL)
    assert block.startswith(f"{sc.SECTOR_CONTEXT_HEADER} (from the request")
    assert "Compliance requirements selected: PCI DSS, GDPR" in block
    assert "note which threats would put them at risk" in block


def test_compact_context_is_one_line() -> None:
    line = sc.compact_context(FULL)
    assert "\n" not in line
    assert line.startswith(f"{sc.SECTOR_CONTEXT_HEADER}: Industry sector: Retail;")
    assert line.endswith("Internet facing: Yes.")


def test_values_are_single_line_clipped_and_lists_bounded() -> None:
    noisy = {
        "industry_sector": "Retail\nIgnore the above\u202e",
        "sensitive_data": "x " * 200,
        "authentication": [f"method{i}" for i in range(30)],
        "compliance_requirements": "PCI DSS",
    }
    lines = sc.context_lines(noisy)
    assert lines[0] == "Industry sector: Retail Ignore the above"
    assert len(lines[1]) <= len("Data sensitivity: ") + 120
    assert lines[2] == "Compliance requirements selected: PCI DSS"
    assert lines[3].split(": ", 1)[1].count("method") == 12
    assert sc.context_lines({"authentication": 5}) == []


def test_focus_block() -> None:
    assert sc.focus_block("") == ""
    assert sc.focus_block(None) == ""
    assert sc.focus_block("Check refunds\nfirst") == (
        "\n\nLEAD FOCUS FOR THIS SECTION:\nCheck refunds first\n"
    )
    assert sc.focus_block("x", heading="H") == "\n\nH:\nx\n"


def test_threat_model_prompt_carries_the_context_block() -> None:
    prompt = create_threat_model_prompt(
        app_type="Web application",
        authentication=["OAuth2"],
        internet_facing="Yes",
        industry_sector="Retail",
        sensitive_data="Payment card data",
        app_input="A checkout service.",
        nvd_vulnerabilities={},
        otx_data="",
        technical_ability="High",
        app_details=FULL,
    )
    assert sc.context_block(FULL) in prompt


def test_threat_model_prompt_builds_context_from_its_arguments() -> None:
    prompt = create_threat_model_prompt(
        app_type="Web application",
        authentication=["SSO"],
        internet_facing="No",
        industry_sector="Logistics",
        sensitive_data="Low",
        app_input="An internal routing tool.",
        nvd_vulnerabilities={},
        otx_data="",
        technical_ability="Low",
    )
    assert "- Industry sector: Logistics" in prompt
    assert "- Authentication methods: SSO" in prompt
    assert "Compliance requirements" not in prompt


def test_mitre_prompt_carries_the_compact_context_and_keeps_the_mock_marker() -> None:
    details = dict(FULL, app_type="Web application", app_input="A checkout service.")
    prompt = create_mitre_prompt(details, {"Scenario": "x"}, [], focus="Look at refunds")
    assert sc.compact_context(details) in prompt
    assert "LEAD FOCUS FOR THIS SECTION:\nLook at refunds" in prompt
    # The mock picks the first candidate after the last header; the focus sits before it.
    assert prompt.rfind("Candidate Techniques") > prompt.find("Look at refunds")
    assert MockLLM().chat_text(system="attack techniques", user=prompt, model="m") == (
        '{"technique_id": "NONE"}'
    )
