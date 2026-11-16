"""ATLAS through a whole run, on both paths, in mock mode; and a non-AI run
left exactly as it was."""

from __future__ import annotations

from typing import Any

import pytest

from aegisshield.config import Settings
from aegisshield.pipeline import atlas_service, catalog_service
from aegisshield.pipeline.run import run_threat_model
from aegisshield.pipeline.schemas import ThreatModelRequest
from aegisshield.pipeline.workflow_service import AI_STAGE_TEXT, THREAT_MODEL_STAGES
from aegisshield.services.output_checks import review_flags
from tests.aegisshield.pipeline import non_ai_pin

# Computed by ``non_ai_pin.digests`` at the commit before ATLAS mapping
# (4ce2324), with the canned mock. A non-AI system's prompts, stored result,
# and exports must stay byte-for-byte the same. "pdf_html" is digested
# without the logo since the logo set changed; with the old logo file
# (aegisshield-bw.png) the same HTML gave 9597f559..., the value pinned
# at that commit.
BEFORE = {
    False: {
        "markdown": "0c982dd248a87f1d91d2dd608d216edd778220d6124c04281792b7e91f077c9c",
        "prompts": "d2ed7c20616f360a4f77471f0cf90853d9942259bdaada36055d602f4c55bed5",
        "result": "998f05ada94d6e4cb0469045e67e5bc9bc2fa051922b95f5567d4f969730fd45",
        "json": "911538e5c6db33c61e00bac38d3949ab1478f82277d4393193df0d11e4ea0fa3",
        "html": "6cb7bd31ecd1d8e80d3da2c2caea7c8b070fad586bdb8b25b0db5812d42a358a",
        "pdf_html": "d28de7ca637b68028d3f19c107273abd4e347f8f388057645abf5dd366b0ffba",
        "sarif": "b559afd7e61044263fa0cd3327919930c3e48b9ddb27b7dea240701c50105882",
    },
    True: {
        "markdown": "0c982dd248a87f1d91d2dd608d216edd778220d6124c04281792b7e91f077c9c",
        "prompts": "27394cd809a4c7b5d18811e12bb58ea622d94d0304876e749e032fbd9b5b4132",
        "result": "d9c44c1d4fdb277fc8d00e02ec5ec9c251c2b74eced0db784610ee654748b434",
        "json": "911538e5c6db33c61e00bac38d3949ab1478f82277d4393193df0d11e4ea0fa3",
        "html": "6cb7bd31ecd1d8e80d3da2c2caea7c8b070fad586bdb8b25b0db5812d42a358a",
        "pdf_html": "d28de7ca637b68028d3f19c107273abd4e347f8f388057645abf5dd366b0ffba",
        "sarif": "b559afd7e61044263fa0cd3327919930c3e48b9ddb27b7dea240701c50105882",
    },
}

AI_PROFILE = {**non_ai_pin.PROFILE, "app_pattern": ["GenAI"]}


class Sink:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def set(self, record: dict[str, Any]) -> None:
        self.records.append(record)

    def cancelled(self) -> bool:
        return False


def _run(profile: dict[str, Any], *, agentic: bool) -> tuple[non_ai_pin.Recorder, dict[str, Any], Sink]:
    llm, sink = non_ai_pin.Recorder(), Sink()
    request = ThreatModelRequest.model_validate({
        "app_profile": profile, "app_description": non_ai_pin.DESCRIPTION,
        "addons": ["mitigations", "dread", "test_cases"], "agentic": agentic,
    })
    result = run_threat_model(request, llm=llm, settings=Settings(), progress=sink)
    return llm, result, sink


@pytest.mark.parametrize("agentic", [False, True])
def test_a_non_ai_system_is_byte_for_byte_what_it_was(agentic: bool) -> None:
    assert non_ai_pin.digests(agentic) == BEFORE[agentic]


@pytest.mark.parametrize("agentic", [False, True])
def test_a_genai_web_app_gets_atlas_candidates_and_one_more_call(agentic: bool) -> None:
    plain_llm, plain, _ = _run(non_ai_pin.PROFILE, agentic=agentic)
    llm, result, _ = _run(AI_PROFILE, agentic=agentic)
    assert atlas_service.ATLAS_RESULT_KEY not in plain
    # Exactly one more model call, and it is the ATLAS request.
    assert len(llm.prompts) == len(plain_llm.prompts) + 1
    atlas_prompts = [p for p in llm.prompts if atlas_service.CANDIDATES_HEADER in p]
    assert len(atlas_prompts) == 1 and atlas_prompts[0].startswith("json\n" + atlas_service.ATLAS_SYSTEM)
    # The ATT&CK pick still sees ATT&CK candidates only.
    attack_picks = [p for p in llm.prompts if "Candidate Techniques (ATT&CK + ATLAS)" in p]
    assert attack_picks and not any('"framework": "ATLAS"' in p for p in attack_picks)
    assert [e["mitre_techniques"] for e in result["mitre_data"]] == \
           [e["mitre_techniques"] for e in plain["mitre_data"]]
    mapping = result[atlas_service.ATLAS_RESULT_KEY]
    assert mapping["call"] == "answered"
    assert mapping["atlas_version"] == catalog_service.atlas_version()
    rows = mapping["threats"]
    assert [r["threat_id"] for r in rows] == [t["ID"] for t in result["threat_model"]]
    index = catalog_service.atlas_index()
    for row in rows:
        assert row["status"] == atlas_service.STATUS_MAPPED
        assert row["technique"]["technique_id"] in index
        assert row["mitigations_total"] >= len(row["mitigations"])
    assert review_flags(result, profile=AI_PROFILE, addons=["mitigations", "dread", "test_cases"]) == \
           result["review_flags"]
    assert not [f for f in result["review_flags"] if f["code"] == "unsupported_technique"]


@pytest.mark.parametrize("agentic", [False, True])
def test_no_case_study_reaches_a_prompt_and_the_mitigations_step_gets_the_reference(agentic: bool) -> None:
    llm, result, _ = _run(AI_PROFILE, agentic=agentic)
    everything = "\n".join(llm.prompts)
    assert "AML.CS" not in everything
    for study in catalog_service.atlas_case_studies():
        assert study.summary[:60] not in everything
    reference = atlas_service.mitigation_reference(result[atlas_service.ATLAS_RESULT_KEY])
    assert reference
    mitigation_prompts = [p for p in llm.prompts if "Provide mitigations for the identified threats" in p]
    assert len(mitigation_prompts) == 1
    assert f"MITRE ATLAS mapping (reference data from the bundled catalog):\n{reference}\n" in mitigation_prompts[0]
    assert "MITRE ATLAS mapping" not in "\n".join(p for p in llm.prompts if p not in mitigation_prompts)


def test_the_atlas_request_is_small_enough_to_state() -> None:
    llm, _result, _ = _run(AI_PROFILE, agentic=False)
    (prompt,) = [p for p in llm.prompts if atlas_service.CANDIDATES_HEADER in p]
    # Six mock threats: about 12,700 characters, near 3,200 tokens at four
    # characters a token. The ATLAS card adds about 8,000 characters to the
    # STRIDE prompt of a system that did not get it before.
    assert 6_000 < len(prompt) < 14_000


def test_the_linear_stages_say_atlas_for_an_ai_system_only() -> None:
    _llm, _result, sink = _run(AI_PROFILE, agentic=False)
    last = sink.records[-1]["stages"]
    by_id = {s["id"]: s for s in last}
    for stage_id, text in AI_STAGE_TEXT.items():
        assert by_id[stage_id]["label"] == text["label"] and by_id[stage_id]["term"] == text["term"]
    details = [s["detail"] for r in sink.records for s in r.get("stages", []) if s["id"] == "mitre_map" and s["detail"]]
    assert any("ATLAS" in d for d in details)
    _llm, _plain, plain_sink = _run(non_ai_pin.PROFILE, agentic=False)
    canonical = {s["id"]: s for s in THREAT_MODEL_STAGES}
    for stage in plain_sink.records[-1]["stages"]:
        assert stage["label"] == canonical[stage["id"]]["label"]
        assert stage["term"] == canonical[stage["id"]]["term"]
    assert not any("ATLAS" in str(s.get("detail")) for r in plain_sink.records for s in r.get("stages", []))


def test_the_agentic_roster_says_atlas_for_an_ai_system_only() -> None:
    _llm, _result, sink = _run(AI_PROFILE, agentic=True)
    mitre = [a for r in sink.records for a in r.get("agents", []) if a["id"] == "mitre"]
    assert any("ATLAS" in a["activity"] for a in mitre)
    _llm, _plain, plain_sink = _run(non_ai_pin.PROFILE, agentic=True)
    assert not any("ATLAS" in a["activity"] for r in plain_sink.records for a in r.get("agents", []))


def test_a_failed_atlas_call_leaves_the_run_and_its_attack_mapping_whole(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisshield.llm import mock

    def broken(user: str) -> dict[str, Any]:
        raise RuntimeError("no answer")

    monkeypatch.setattr(mock, "_atlas_choice", broken)
    _llm, result, _ = _run(AI_PROFILE, agentic=False)
    mapping = result[atlas_service.ATLAS_RESULT_KEY]
    assert mapping["call"] == "failed"
    assert all(r["technique"] is None for r in mapping["threats"])
    assert all(e["mitre_techniques"] for e in result["mitre_data"])
    assert result["mitigations_markdown"]
