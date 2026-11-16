"""The MITRE ATT&CK mapping service.

The service takes an ``llm`` object, so these tests pass a fake one.
"""

from __future__ import annotations

import json

import pytest

from aegisshield.core.errors import ConfigurationError
from aegisshield.pipeline import mitre_service
from aegisshield.pipeline.catalog_service import CatalogEntry

SAMPLE_CATALOG = [
    CatalogEntry(
        framework="ATT&CK",
        domain="enterprise",
        technique_id="T1059",
        stix_id="attack-pattern--cmd",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        description="Adversaries use command-line interfaces to execute commands.",
    ),
    CatalogEntry(
        framework="ATT&CK",
        domain="enterprise",
        technique_id="T1078",
        stix_id="attack-pattern--valid-acct",
        name="Valid Accounts",
        tactic="Initial Access",
        description="Use of compromised credentials.",
    ),
    CatalogEntry(
        framework="ATLAS",
        domain="atlas",
        technique_id="AML.T0051",
        stix_id=None,
        name="LLM Prompt Injection",
        tactic="Initial Access",
        description="Adversaries supply input that overrides the system prompt.",
    ),
]

APP_DETAILS = {
    "app_type": "Web application",
    "industry_sector": "Information Technology",
    "authentication": ["MFA"],
    "internet_facing": "Yes",
    "sensitive_data": "High",
    "app_input": "An online banking app.",
}


class _TextLLM:
    """A fake LLM whose chat_text gives a fixed answer (or calls ``answer``)."""

    def __init__(self, answer):
        self.answer = answer
        self.calls = 0

    def chat_text(self, *, system, user, model, max_tokens=8192, on_text=None):
        self.calls += 1
        return self.answer() if callable(self.answer) else self.answer


def _threat(keywords: list[str]) -> dict:
    return {
        "Threat Type": "Spoofing",
        "Scenario": "An attacker impersonates a user.",
        "Assumptions": [],
        "Potential Impact": "High",
        "MITRE ATT&CK Keywords": keywords,
    }


def test_create_mitre_prompt_includes_all_candidates() -> None:
    prompt = mitre_service.create_mitre_prompt(APP_DETAILS, _threat(["any"]), SAMPLE_CATALOG)
    assert "T1059" in prompt
    assert "AML.T0051" in prompt
    assert "do not invent a technique ID" in prompt
    assert '"technique_id": "T1059"' in prompt  # response shape example


def test_select_best_technique_id_parses_object() -> None:
    llm = _TextLLM(json.dumps({"technique_id": "T1059"}))
    assert mitre_service._select_best_technique_id("p", llm, "m") == "T1059"


def test_select_best_technique_id_parses_list() -> None:
    llm = _TextLLM('["T1078"]')
    assert mitre_service._select_best_technique_id("p", llm, "m") == "T1078"


def test_select_best_technique_id_handles_fenced_code() -> None:
    llm = _TextLLM('```json\n{"technique_id": "AML.T0051"}\n```')
    assert mitre_service._select_best_technique_id("p", llm, "m") == "AML.T0051"


def test_select_best_technique_id_returns_none_on_garbage() -> None:
    llm = _TextLLM("definitely not json")
    assert mitre_service._select_best_technique_id("p", llm, "m") == "NONE"


def test_candidates_from_keywords_filters_by_overlap() -> None:
    matches = mitre_service._candidates_from_keywords(
        SAMPLE_CATALOG, ["prompt"], max_candidates=10
    )
    assert [m.technique_id for m in matches] == ["AML.T0051"]


def test_candidates_from_keywords_returns_full_list_when_no_keywords() -> None:
    matches = mitre_service._candidates_from_keywords(SAMPLE_CATALOG, [], max_candidates=2)
    assert len(matches) == 2


def test_process_picks_valid_id_from_model() -> None:
    llm = _TextLLM('{"technique_id": "T1078"}')
    threat_model = [_threat(["credentials"])]
    result = mitre_service.process_mitre_attack_data(
        threat_model, APP_DETAILS, llm, "test-model", catalog=SAMPLE_CATALOG
    )
    techniques = result[0]["mitre_techniques"]
    assert techniques and techniques[0]["technique_id"] == "T1078"
    assert techniques[0]["framework"] == "ATT&CK"


def test_process_falls_back_when_model_hallucinates() -> None:
    llm = _TextLLM('{"technique_id": "T9999-fake"}')
    threat_model = [_threat(["command"])]  # matches T1059
    result = mitre_service.process_mitre_attack_data(
        threat_model, APP_DETAILS, llm, "test-model", catalog=SAMPLE_CATALOG
    )
    techniques = result[0]["mitre_techniques"]
    # Hallucinated T9999-fake must NOT leak through; we fall back to top match.
    assert techniques and techniques[0]["technique_id"] == "T1059"


def test_process_emits_empty_when_no_keyword_match() -> None:
    # If chat_text were called the test would fail.
    llm = _TextLLM(lambda: pytest.fail("model should not be called when there are no candidates"))
    threat_model = [_threat(["totally-unrelated-keyword-xyz"])]
    result = mitre_service.process_mitre_attack_data(
        threat_model, APP_DETAILS, llm, "test-model", catalog=SAMPLE_CATALOG
    )
    assert result[0]["mitre_techniques"] == []
    assert llm.calls == 0


def test_process_raises_when_catalog_is_empty() -> None:
    with pytest.raises(ConfigurationError):
        mitre_service.process_mitre_attack_data(
            [_threat([])], APP_DETAILS, _TextLLM("{}"), "test-model", catalog=[]
        )
