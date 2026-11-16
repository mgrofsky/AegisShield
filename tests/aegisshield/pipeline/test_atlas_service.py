"""The ATLAS pick: candidates, the one request, checking, and catalog links."""

from __future__ import annotations

import json
from typing import Any

import pytest

from aegisshield.pipeline import atlas_service as atlas
from aegisshield.pipeline import catalog_service
from aegisshield.pipeline.mitre_service import _candidates_from_keywords
from tests.aegisshield.stall import STALL_LIMIT_S, least_stall

APP = {"app_type": "Web application"}


def _threat(threat_id: str, scenario: str, impact: str = "", keywords: list[str] | None = None,
            threat_type: str = "Tampering") -> dict[str, Any]:
    return {"ID": threat_id, "Threat Type": threat_type, "Scenario": scenario, "Potential Impact": impact,
            "MITRE ATT&CK Keywords": keywords or []}


INJECTION = _threat("TC-T01", "A user types instructions into the chat that override the assistant's "
                    "system prompt and make it issue refunds.", "Unauthorized refunds.", ["prompt injection"])


class Answer:
    """A fake model whose chat_json gives a fixed answer and records the request."""

    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.calls: list[dict[str, Any]] = []

    def chat_json(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


# ------------------------------------------------------------- candidates

# Sixteen AI threats, each with the ATLAS ids a reviewer would accept. The
# labels were chosen by reading the technique names; they are a check on the
# candidate method, not ground truth.
LABELED = [
    (INJECTION, {"AML.T0051", "AML.T0051.000"}),
    (_threat("TC-T02", "A help-center article retrieved by the RAG pipeline carries hidden instructions "
             "that the model follows.", "The bot gives wrong answers.", ["indirect prompt injection"]),
     {"AML.T0051.001", "AML.T0070", "AML.T0066"}),
    (_threat("TC-T03", "An attacker uploads poisoned documents to the vector store so retrieval returns "
             "false answers.", "Users act on false information.", ["data poisoning"]),
     {"AML.T0070", "AML.T0071", "AML.T0059"}),
    (_threat("TC-I01", "An attacker asks the chatbot to reveal its hidden system prompt and configuration.",
             "Exposure of business logic.", ["system prompt extraction"], "Information Disclosure"),
     {"AML.T0069.002", "AML.T0085.003", "AML.T0069", "AML.T0084"}),
    (_threat("TC-I02", "An attacker queries the inference API many times to train a copy of the model.",
             "Loss of model intellectual property.", ["model extraction"], "Information Disclosure"),
     {"AML.T0024", "AML.T0005", "AML.T0005.001", "AML.T0048.004"}),
    (_threat("TC-I03", "The model reproduces personal data memorized from its training set when prompted.",
             "Privacy breach.", ["training data leakage"], "Information Disclosure"),
     {"AML.T0137", "AML.T0137.003", "AML.T0024"}),
    (_threat("TC-E01", "A jailbreak prompt makes the model drop its safety guardrails and produce "
             "prohibited content.", "Policy violations.", ["jailbreak"], "Elevation of Privilege"),
     {"AML.T0054"}),
    (_threat("TC-E02", "The agent is tricked into calling its shell tool to run attacker commands on the host.",
             "Remote code execution.", ["command execution"], "Elevation of Privilege"),
     {"AML.T0053", "AML.T0050", "AML.T0105"}),
    (_threat("TC-D01", "Bots send very long prompts that consume tokens and run up the inference bill.",
             "High cost and outages.", ["resource exhaustion"], "Denial of Service"),
     {"AML.T0034", "AML.T0034.001", "AML.T0029", "AML.T0034.000"}),
    (_threat("TC-T04", "A malicious model file from a public model hub runs code when it is loaded.",
             "Compromise of the training server.", ["supply chain"]),
     {"AML.T0010.003", "AML.T0011.000", "AML.T0010", "AML.T0018.002"}),
    (_threat("TC-S01", "An attacker uses a cloned voice deepfake to impersonate the CFO in a call.",
             "Fraudulent payments.", ["impersonation"], "Spoofing"),
     {"AML.T0088", "AML.T0052.001", "AML.T0073"}),
    (_threat("TC-I04", "The model's answer contains a markdown image whose URL carries conversation data "
             "to an attacker server.", "Data exfiltration.", ["exfiltration"], "Information Disclosure"),
     {"AML.T0077", "AML.T0086", "AML.T0136"}),
    (_threat("TC-T05", "An attacker adds crafted adversarial noise to images so the classifier mislabels them.",
             "Wrong decisions.", ["evasion"]), {"AML.T0015", "AML.T0043"}),
    (_threat("TC-T06", "Poisoned samples injected into the training data plant a backdoor in the model.",
             "Hidden misbehavior.", ["training data poisoning"]),
     {"AML.T0020", "AML.T0018.000", "AML.T0043.004"}),
    (_threat("TC-T07", "A third-party MCP tool definition is changed to include instructions that redirect "
             "the agent.", "Agent misuse.", ["tool poisoning"]),
     {"AML.T0110", "AML.T0110.000", "AML.T0099", "AML.T0011.002"}),
    (_threat("TC-I05", "API keys for the LLM provider are stored in the agent's configuration file and can "
             "be read.", "Key theft and cost.", ["unsecured credentials"], "Information Disclosure"),
     {"AML.T0083", "AML.T0055"}),
]


def _recall(pick: Any) -> int:
    return sum(1 for threat, accepted in LABELED if accepted & {e.technique_id for e in pick(threat)})


def test_scored_candidates_hold_an_accepted_technique_far_more_often_than_the_attack_method() -> None:
    entries = catalog_service.load_atlas_entries()
    scored = _recall(lambda t: atlas.candidates(t, ["GenAI"]))
    keyword_any = _recall(lambda t: _candidates_from_keywords(entries, t["MITRE ATT&CK Keywords"], 25))
    # Measured: 16 of 16 for the scored method at 10 candidates, 10 of 16
    # for the ATT&CK step's keyword filter even at 25.
    assert scored >= 15
    assert keyword_any <= 11 < scored


def test_candidates_are_capped_ranked_and_include_sub_techniques() -> None:
    found = atlas.candidates(INJECTION, ["GenAI"])
    ids = [e.technique_id for e in found]
    assert len(ids) == atlas.MAX_CANDIDATES and len(set(ids)) == len(ids)
    assert "AML.T0051" in ids[:3] and "AML.T0051.000" in ids
    assert all(e.framework == "ATLAS" for e in found)
    assert len(atlas.candidates(INJECTION, limit=3)) == 3


def test_patterns_supply_hint_words_for_a_threat_that_names_no_ai_term() -> None:
    plain = _threat("TC-S01", "Somebody replays a cookie at checkout.", threat_type="Spoofing")
    assert atlas.candidates(_threat("TC-X01", "zzz qqq")) == []
    with_hints = atlas.candidates(_threat("TC-X01", "zzz qqq"), ["RAG"])
    assert with_hints and any("RAG" in catalog_service.atlas_display_name(e) for e in with_hints)
    assert atlas.candidates(plain, ["ML"])


def test_the_word_pattern_is_linear_on_hostile_text() -> None:
    for text in ("a" * 200_000, "a1 " * 70_000, "é" * 200_000, "-" * 200_000):
        assert least_stall(atlas.words, text).stall < STALL_LIMIT_S / 4
    assert atlas.words("The Poisoned poisoning, Agents") == {"poison", "agent"}


def test_first_sentence_keeps_prompts_short() -> None:
    assert atlas.first_sentence("One two.  Three\nfour.") == "One two."
    assert atlas.first_sentence("No full stop") == "No full stop"
    long = atlas.first_sentence("x " * 200)
    assert len(long) == atlas.DESCRIPTION_CHARS and long.endswith("...")


# ------------------------------------------------------------- the request


def test_one_request_for_every_threat_with_each_candidate_once() -> None:
    threats = [INJECTION, LABELED[1][0], LABELED[2][0]]
    llm = Answer({"atlas": []})
    atlas.map_threats_to_atlas(threats, APP, ["GenAI", "RAG"], llm, "worker")
    assert len(llm.calls) == 1
    call = llm.calls[0]
    assert call["model"] == "worker" and call["system"] == atlas.ATLAS_SYSTEM
    user = call["user"]
    per_threat = json.loads(user[user.rindex(atlas.CANDIDATES_HEADER) + len(atlas.CANDIDATES_HEADER) + 1:]
                            .strip().split("\n")[0])
    assert set(per_threat) == {"TC-T01", "TC-T02", "TC-T03"}
    pooled = {json.loads(line)["id"] for line in user.splitlines() if line.startswith('{"id": ')}
    assert pooled == {i for ids in per_threat.values() for i in ids}
    for technique_id in pooled:
        assert user.count(f'"id": "{technique_id}"') == 1
    assert "AI PATTERNS: GenAI, RAG" in user


def test_none_fits_is_stored_as_no_technique_and_never_replaced() -> None:
    mapping = atlas.map_threats_to_atlas([INJECTION], APP, ["GenAI"], Answer(
        {"atlas": [{"threat_id": "TC-T01", "technique_id": "NONE"}]}), "m")
    row = mapping["threats"][0]
    assert row["status"] == atlas.STATUS_NONE_FITS and row["technique"] is None
    assert "mitigations" not in row and mapping["call"] == "answered"


@pytest.mark.parametrize("bad", ["AML.T9999", "T1059", "AML.T0020", "aml.t0051", ""])
def test_an_id_outside_the_catalog_or_the_threats_candidates_is_rejected(bad: str) -> None:
    mapping = atlas.map_threats_to_atlas([INJECTION], APP, ["GenAI"], Answer(
        {"atlas": [{"threat_id": "TC-T01", "technique_id": bad}]}), "m")
    row = mapping["threats"][0]
    assert row["technique"] is None
    assert row["status"] == (atlas.STATUS_NOT_ANSWERED if not bad else atlas.STATUS_REJECTED)


def test_a_sub_technique_is_accepted_and_named_after_its_parent() -> None:
    mapping = atlas.map_threats_to_atlas([INJECTION], APP, ["GenAI"], Answer(
        {"atlas": [{"threat_id": "TC-T01", "technique_id": "AML.T0051.000"}]}), "m")
    row = mapping["threats"][0]
    assert row["status"] == atlas.STATUS_MAPPED
    assert row["technique"] == {"technique_id": "AML.T0051.000", "name": "LLM Prompt Injection: Direct",
                                "tactic": "Execution"}


@pytest.mark.parametrize("answer", [None, [], {"atlas": "x"}, {"atlas": [1, {"threat_id": 3}]}, {}])
def test_an_unreadable_answer_maps_nothing(answer: Any) -> None:
    mapping = atlas.map_threats_to_atlas([INJECTION], APP, ["GenAI"], Answer(answer), "m")
    assert mapping["threats"][0]["status"] == atlas.STATUS_NOT_ANSWERED


def test_no_candidates_means_no_call() -> None:
    llm = Answer(AssertionError("no call expected"))
    mapping = atlas.map_threats_to_atlas([_threat("TC-X01", "zzz qqq")], APP, [], llm, "m")
    assert llm.calls == [] and mapping["call"] == "none"
    assert mapping["threats"][0]["status"] == atlas.STATUS_NO_CANDIDATES


def test_a_failed_call_is_stored_as_failed_and_does_not_raise() -> None:
    mapping = atlas.atlas_step([INJECTION, _threat("TC-X01", "zzz qqq")], APP, [], Answer(RuntimeError("down")), "m")
    assert mapping["call"] == "failed"
    assert [r["status"] for r in mapping["threats"]] == [atlas.STATUS_NOT_ANSWERED, atlas.STATUS_NO_CANDIDATES]
    assert mapping["atlas_version"] == catalog_service.atlas_version()
    assert mapping["attack_version"] == catalog_service.attack_version()


# ------------------------------------------------------------ catalog links


def test_mitigations_and_case_studies_come_from_the_catalog_with_caps_and_totals() -> None:
    links = atlas.technique_links("AML.T0051")
    expected_m = catalog_service.atlas_mitigations_for("AML.T0051")
    expected_c = catalog_service.atlas_case_studies_for("AML.T0051")
    assert links["mitigations"] == [{"id": m.id, "name": m.name} for m in expected_m[:atlas.MAX_SHOWN]]
    assert links["mitigations_total"] == len(expected_m) > atlas.MAX_SHOWN
    assert links["case_studies"] == [{"id": c.id, "name": c.name} for c in expected_c[:atlas.MAX_SHOWN]]
    assert links["case_studies_total"] == len(expected_c)
    assert links["mitigations_from"] == links["case_studies_from"] == "AML.T0051"


def test_a_sub_technique_without_links_of_its_own_shows_its_parents() -> None:
    sub = next(e.technique_id for e in catalog_service.load_atlas_entries()
               if e.technique_id.count(".") == 2 and not catalog_service.atlas_mitigations_for(e.technique_id)
               and catalog_service.atlas_mitigations_for(e.technique_id.rsplit(".", 1)[0]))
    links = atlas.technique_links(sub)
    parent = sub.rsplit(".", 1)[0]
    assert links["mitigations_from"] == parent
    assert links["mitigations_total"] == len(catalog_service.atlas_mitigations_for(parent))
    own = atlas.technique_links("AML.T0051.000")
    assert own["case_studies_from"] == "AML.T0051.000"


def test_the_mitigations_reference_is_small_and_lists_catalog_names_only() -> None:
    mapping = atlas.map_threats_to_atlas([INJECTION, _threat("TC-X01", "zzz qqq")], APP, ["GenAI"], Answer(
        {"atlas": [{"threat_id": "TC-T01", "technique_id": "AML.T0051"}]}), "m")
    reference = atlas.mitigation_reference(mapping)
    names = [m.name for m in catalog_service.atlas_mitigations_for("AML.T0051")]
    assert reference.startswith("- TC-T01: AML.T0051 LLM Prompt Injection. ATLAS mitigations: ")
    assert reference.count(";") == atlas.MAX_REFERENCE_MITIGATIONS - 1
    assert all(name in reference for name in names[:atlas.MAX_REFERENCE_MITIGATIONS])
    assert "TC-X01" not in reference and "AML.CS" not in reference
    assert len(reference) < 400
    assert atlas.mitigation_reference(None) == "" == atlas.mitigation_reference({"threats": "x"})
    bare = {"threats": [{"threat_id": "TC-A01", "technique": {"technique_id": "AML.T0001", "name": "N"}}]}
    assert atlas.mitigation_reference(bare) == "- TC-A01: AML.T0001 N"


def test_every_new_pattern_is_linear_on_hostile_text() -> None:
    """The stall audit of the patterns this change added, on the inputs that
    would stress each: long runs of the characters they match."""
    from aegisshield.llm import mock
    from aegisshield.pipeline import formatting_service as fmt
    from aegisshield.pipeline import mitre_links

    n = 200_000
    cases = [
        (mitre_links.technique_url, "AML.T" + "1" * n),
        (mitre_links.technique_url, "T" + "1" * n),
        (mitre_links.atlas_mitigation_url, "AML.M" + "0" * n),
        (mitre_links.atlas_case_study_url, "AML.CS" + "0" * n),
        (mitre_links.attack_url, "T1078." + "0" * n),
        (fmt._version, "1." * (n // 2)),
        (lambda s: fmt._THREAT_ID.fullmatch(s), "TC-A" + "1" * n),
        (lambda s: mock._ATLAS_RE.search(s), '{"atlas"' + " " * n),
        (fmt._md_text, "[](" * (n // 3)),
    ]
    for fn, text in cases:
        assert least_stall(fn, text).stall < STALL_LIMIT_S / 4, fn
