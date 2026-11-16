"""Edge cases of the per-section services that the per-service tests do not reach."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from aegisshield.core.errors import LLMResponseError, ValidationError
from aegisshield.pipeline import formatting_service as fmt
from aegisshield.pipeline import mitre_service, threat_model_service
from aegisshield.pipeline.attack_tree_service import get_attack_tree
from aegisshield.pipeline.catalog_service import CatalogEntry
from aegisshield.pipeline.dread_service import _extract_id, dread_json_to_markdown
from aegisshield.pipeline.pattern_detection_service import detect_patterns_llm

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 16


class TextLLM:
    def __init__(self, text: str = "", payload: dict | None = None) -> None:
        self.text = text
        self.payload = payload or {}

    def chat_text(self, **_kw: Any) -> str:
        return self.text

    def chat_json(self, **_kw: Any) -> dict:
        return self.payload


# DREAD ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("item", "expected"),
    [
        ({"ID": "TC-S01"}, "TC-S01"),
        ({"ID": "row 3", "Threat ID": "see TC-T02"}, "TC-T02"),
        ({"Scenario": "As in TC-I01, the order page leaks"}, "TC-I01"),
        ({"ID": "", "Threat Type": 7}, "-"),
        ({"ID": "custom"}, "custom"),
    ],
)
def test_extract_id(item: dict, expected: str) -> None:
    assert _extract_id(item) == expected


def test_dread_markdown_rejects_bad_shapes() -> None:
    with pytest.raises(LLMResponseError):
        dread_json_to_markdown({"Risk Assessment": "nope"})
    with pytest.raises(LLMResponseError):
        dread_json_to_markdown({"Risk Assessment": ["nope"]})


def test_dread_markdown_scores_the_mean() -> None:
    row = {"ID": "TC-S01", "Damage Potential": 8, "Reproducibility": 6, "Exploitability": 6,
           "Affected Users": 7, "Discoverability": 5}
    assert "| TC-S01 | 8 | 6 | 6 | 7 | 5 | 6.40 |" in dread_json_to_markdown({"Risk Assessment": [row]})


# Formatting -------------------------------------------------------------------


def test_stride_letter_and_ids() -> None:
    assert fmt._stride_letter("") == "X"
    assert fmt._stride_letter("Something else") == "X"
    threats: list[Any] = [{"Threat Type": "DoS"}, "skip", {"Threat Type": "dos attack"}]
    fmt.assign_threat_ids(threats)
    assert threats[0]["ID"] == "TC-D01" and threats[2]["ID"] == "TC-D02"


def test_threat_markdown_handles_assumptions_and_pipes() -> None:
    md = fmt.threat_model_to_markdown(
        [
            {"ID": "TC-S01", "Threat Type": "Spoofing", "Scenario": "a|b",
             "Assumptions": [{"Assumption": "A", "Role": "R", "Condition": "C"}, "x"]},
            {"Threat Type": "Tampering"},
        ],
        ["Add logging"],
    )
    assert "a/b" in md and "**A** (Role: R, Condition: C)" in md
    assert "| - | Tampering |" in md and "No assumptions provided" in md
    assert md.rstrip().endswith("- Add logging")


def test_mitre_markdown_with_and_without_techniques() -> None:
    assert fmt.mitre_data_to_markdown([]) == "No MITRE ATT&CK data found.\n"
    md = fmt.mitre_data_to_markdown(
        [
            {"threat": {"ID": "TC-S01", "Threat Type": "Spoofing"}, "mitre_techniques": []},
            {"threat": {}, "mitre_techniques": [{"name": "N", "technique_id": "N/A"}]},
            {"threat": {"ID": "TC-T01"}, "mitre_techniques": [
                {"name": "Sub", "technique_id": "T1059.001", "id": "attack-pattern--1",
                 "description": "Runs code."}]},
        ]
    )
    assert "### TC-S01 - Spoofing" in md and "*No relevant MITRE ATT&CK techniques found.*" in md
    assert "#### N/A - N" in md and "View on ATT&CK" in md
    assert "https://attack.mitre.org/techniques/T1059/001/" in md


def test_nvd_markdown() -> None:
    assert fmt.nvd_to_markdown({}) == "No NVD vulnerabilities found.\n"
    md = fmt.nvd_to_markdown({"nginx 1.24.0": "one|two| ", "bad": 3})  # type: ignore[dict-item]
    assert "#### nginx 1.24.0\none\n---\ntwo\n---" in md
    assert "Unexpected data type for bad" in md


# Attack tree, pattern detection ------------------------------------------------


def test_attack_tree_requires_a_prompt_and_strips_fences() -> None:
    with pytest.raises(ValidationError):
        get_attack_tree(TextLLM(), "m", "  ")
    assert get_attack_tree(TextLLM("```mermaid\ngraph TD\nA-->B\n```"), "m", "p") == "graph TD\nA-->B"


@pytest.mark.parametrize(
    ("answer", "tags"),
    [
        ('```json\n["RAG", "Nope"]\n```', ["RAG"]),
        ("```\n[\"ML\"]\n```", ["ML"]),
        ("not json", []),
        ('{"tags": ["RAG"]}', []),
    ],
)
def test_pattern_llm_answers(answer: str, tags: list[str]) -> None:
    assert detect_patterns_llm("desc", TextLLM(answer), "m") == tags


# MITRE ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("answer", "chosen"),
    [
        ('```json\n{"technique_id": " T1059 "}\n```', "T1059"),
        ('["T1078"]', "T1078"),
        ("[]", "NONE"),
        ('{"technique_id": ""}', "NONE"),
        ("no", "NONE"),
    ],
)
def test_select_best_technique_id(answer: str, chosen: str) -> None:
    assert mitre_service._select_best_technique_id("p", TextLLM(answer), "m") == chosen


def test_mapping_falls_back_and_survives_a_failing_callback() -> None:
    entry = CatalogEntry("ATT&CK", "enterprise", "T1110", "attack-pattern--x", "Brute Force",
                         "Credential Access", "Guess passwords.")
    details = {"app_type": "Web application", "industry_sector": "Retail",
               "sensitive_data": "High", "authentication": [], "internet_facing": "Yes",
               "app_input": "A checkout."}

    def boom(*_a: Any) -> None:
        raise RuntimeError("display")

    out = mitre_service.process_mitre_attack_data(
        [{"MITRE ATT&CK Keywords": ["password"]}, {"MITRE ATT&CK Keywords": ["zzz-none"]}],
        details, TextLLM('{"technique_id": "T9999"}'), "m", catalog=[entry], on_mapped=boom,
    )
    assert out[0]["mitre_techniques"][0]["technique_id"] == "T1110"
    assert out[1]["mitre_techniques"] == []


# Images and the threat model answer -------------------------------------------


@pytest.mark.parametrize("raw", [PNG, JPEG])
def test_decode_image_reads_the_type_from_the_bytes(raw: bytes) -> None:
    b64 = base64.b64encode(raw).decode()
    media, data = threat_model_service.decode_image(f"data:image/png;base64,{b64}")
    assert data == raw and media == ("image/png" if raw is PNG else "image/jpeg")


@pytest.mark.parametrize(
    "value",
    [
        "data:image/gif;base64,AAAA",
        "data:image/png;base64",
        "not base64!",
        "",
        base64.b64encode(b"GIF89a....").decode(),
    ],
)
def test_decode_image_rejects(value: str) -> None:
    with pytest.raises(ValidationError):
        threat_model_service.decode_image(value)


def test_decode_image_size_caps() -> None:
    big = base64.b64encode(PNG + b"\x00" * 100).decode()
    with pytest.raises(ValidationError):
        threat_model_service.decode_image(big, max_bytes=50)
    with pytest.raises(ValidationError):
        threat_model_service.decode_image("A" * 1000, max_bytes=10)
    exact = base64.b64encode(PNG + b"\x00" * 30).decode()
    with pytest.raises(ValidationError):
        threat_model_service.decode_image(exact, max_bytes=len(PNG) + 20)


@pytest.mark.parametrize(
    "payload",
    [
        {"threat_model": {}, "improvement_suggestions": []},
        {"threat_model": [], "improvement_suggestions": "x"},
        {"threat_model": ["x"], "improvement_suggestions": []},
    ],
)
def test_threat_model_answer_shape_errors(payload: dict) -> None:
    with pytest.raises(LLMResponseError):
        threat_model_service.generate_threat_model(TextLLM(payload=payload), "m", "p")


def test_threat_model_suggestions_are_normalized() -> None:
    payload = {
        "threat_model": [{"Scenario": "s", "Potential Impact": "i"}],
        "improvement_suggestions": [" a ", {"text": "b"}, {"other": 1}, 5, "  "],
    }
    threats, suggestions = threat_model_service.generate_threat_model(
        TextLLM(payload=payload), "m", "p"
    )
    assert threats[0]["MITRE ATT&CK Keywords"] == ["s Potential impact: i"]
    assert suggestions == ["a", "b", json.dumps({"other": 1}), "5"]
