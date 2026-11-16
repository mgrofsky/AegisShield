"""The threat model prompt (with and without threat cards) and answer normalizing."""

from __future__ import annotations

from aegisshield.pipeline.threat_card_service import ThreatCard
from aegisshield.pipeline.threat_model_service import (
    create_threat_model_prompt,
    generate_threat_model,
)


def _prompt_kwargs(**overrides):
    base = {
        "app_type": "Web application",
        "authentication": ["MFA"],
        "internet_facing": "Yes",
        "industry_sector": "Information Technology",
        "sensitive_data": "High",
        "app_input": "An online banking app.",
        "nvd_vulnerabilities": {},
        "otx_data": "",
        "technical_ability": "Medium",
    }
    base.update(overrides)
    return base


class _FakeLLM:
    """Answers chat_json with a fixed payload and records the calls."""

    def __init__(self, payload):
        self.payload = payload
        self.calls: list[dict] = []

    def chat_json(self, *, system, user, model, max_tokens=16000, on_text=None):
        self.calls.append({"system": system, "user": user, "model": model})
        return self.payload


def test_create_threat_model_prompt_omits_card_block_when_no_cards() -> None:
    prompt = create_threat_model_prompt(**_prompt_kwargs())
    assert "ADDITIONAL THREAT REFERENCE CARDS" not in prompt


def test_create_threat_model_prompt_appends_cards_when_supplied() -> None:
    cards = [ThreatCard(name="Test Card", body="- Item one\n- Item two")]
    prompt = create_threat_model_prompt(**_prompt_kwargs(extra_cards=cards))
    assert "ADDITIONAL THREAT REFERENCE CARDS" in prompt
    assert "Threat Card: Test Card" in prompt
    assert "Item one" in prompt


def test_generate_threat_model_normalizes_non_string_suggestions() -> None:
    llm = _FakeLLM(
        {
            "threat_model": [
                {
                    "Threat Type": "Spoofing",
                    "Scenario": "An attacker reuses credentials",
                    "Assumptions": [],
                    "Potential Impact": "Unauthorized access",
                    "MITRE ATT&CK Keywords": ["credential abuse"],
                }
            ],
            "improvement_suggestions": [
                {"suggestion": "Add stronger MFA checks"},
                {"description": "Document trust boundaries"},
                {"other": "value"},
                "Validate session expiration",
            ],
        }
    )

    _threat_model, suggestions = generate_threat_model(llm, "test-model", "test prompt")

    assert suggestions[0] == "Add stronger MFA checks"
    assert suggestions[1] == "Document trust boundaries"
    assert suggestions[2] == '{"other": "value"}'
    assert suggestions[3] == "Validate session expiration"
    assert llm.calls[0]["model"] == "test-model"
