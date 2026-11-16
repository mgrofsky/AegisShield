"""Tests for the regulation matcher (pinned frameworks, keyword overlap)."""

from __future__ import annotations

import pytest

from aegisshield.services import regulation_service


def test_match_threats_returns_obligations() -> None:
    threats = [
        {
            "ID": "T-1",
            "Threat Type": "Information Disclosure",
            "Scenario": "Adversarial inputs cause model evasion",
            "Potential Impact": "Wrong outputs",
            "MITRE ATT&CK Keywords": ["adversarial", "evasion"],
        },
        {
            "ID": "T-2",
            "Threat Type": "Tampering",
            "Scenario": "Data poisoning of the training set",
            "Potential Impact": "Compromised model",
            "MITRE ATT&CK Keywords": ["data poisoning"],
        },
    ]
    matches = regulation_service.match_threats_to_framework(threats, "eu-ai-act")
    assert "T-1" in matches and "T-2" in matches
    assert "EUAIA-15" in [m.obligation_id for m in matches["T-1"]]
    assert "EUAIA-10" in [m.obligation_id for m in matches["T-2"]]


def test_match_threats_unknown_framework_raises() -> None:
    with pytest.raises(ValueError):
        regulation_service.match_threats_to_framework([], "not-a-framework")


def test_match_keys_by_scenario_without_id_and_respects_top_n() -> None:
    threats = [
        {
            "Threat Type": "Tampering",
            "Scenario": "Data poisoning and adversarial evasion with model tampering",
            "MITRE ATT&CK Keywords": "not a list",
        }
    ]
    matches = regulation_service.match_threats_to_framework(threats, "eu-ai-act", top_n=2)
    key = threats[0]["Scenario"]
    assert list(matches) == [key]
    assert 1 <= len(matches[key]) <= 2
    scores = [m.score for m in matches[key]]
    assert scores == sorted(scores, reverse=True)


def test_load_framework_returns_a_copy() -> None:
    data = regulation_service.load_framework("eu-ai-act")
    data["obligations"].clear()
    assert len(regulation_service.load_framework("eu-ai-act")["obligations"]) == 10


def test_match_with_no_overlap_is_empty() -> None:
    threats = [{"ID": "T-1", "Scenario": "zzz qqq"}]
    assert regulation_service.match_threats_to_framework(threats, "eu-ai-act") == {"T-1": []}


def test_match_against_a_framework_record_skips_bad_obligations() -> None:
    framework = {
        "obligations": [
            "not a dict",
            {"name": "No id here", "threat_keywords": ["refund"]},
            {"id": "CS-1", "name": "Refund approval", "threat_keywords": ["refund", "approval"]},
            {"id": "CS-2", "name": "Empty", "threat_keywords": "not a list"},
        ]
    }
    threats = [{"ID": "T-1", "Scenario": "A support agent issues a refund without approval"}]
    matches = regulation_service.match_threats_to_obligations(threats, framework)
    assert [m.obligation_id for m in matches["T-1"]] == ["CS-1"]


def test_tokenise_adds_bigrams_and_handles_empty() -> None:
    assert regulation_service._tokenise("") == set()
    tokens = regulation_service._tokenise("Data Poisoning")
    assert {"data", "poisoning", "data poisoning"} <= tokens


def test_score_without_keywords_is_zero() -> None:
    assert regulation_service._score({"a"}, set()) == 0.0
