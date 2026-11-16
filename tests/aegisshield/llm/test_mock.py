"""The mock answers each kind of request the pipeline makes, using its prompt templates.

The fixtures follow the pipeline services' prompt builders and carry visitor text full of words other routes might key on.
"""

import json

import pytest

from aegisshield.core.errors import ValidationError
from aegisshield.llm.base import LLMClient
from aegisshield.llm.mock import (
    MOCK_ATTACK_TREE,
    MOCK_IMAGE_DESCRIPTION,
    MOCK_LEAD_PLAN,
    MOCK_MITIGATIONS,
    MOCK_NOTE,
    MOCK_PCAP_ANALYSIS,
    MOCK_POLICY,
    MOCK_TEST_CASES,
    MOCK_THREAT_MODEL,
    MockLLM,
)

JSON_SYSTEM = "You are a helpful assistant designed to output JSON."
MITIGATIONS_SYSTEM = "You provide threat mitigation strategies in Markdown format."
TEST_CASES_SYSTEM = "You provide Gherkin test cases in Markdown format."
MITRE_SYSTEM = "You are a cybersecurity expert helping identify relevant attack techniques."
ATTACK_TREE_SYSTEM = (
    "Act as a cyber security expert with more than 20 years of experience using STRIDE "
    "threat modeling.\nGenerate an attack tree in Mermaid syntax for the given application "
    "details.\nReturn only a Mermaid code block.\nIMPORTANT: If a node label includes round "
    "brackets, wrap the label in double quotes."
)
POLICY_SYSTEM = (
    "You are an expert GRC consultant. Write formal, actionable security policy documents "
    "in clean Markdown. Use the organization's actual name, leadership names/roles, "
    "industry, and compliance requirements throughout."
)
PCAP_SYSTEM = (
    "You are a blue-team network forensics analyst reviewing a packet capture summary. "
    "Your job:\n\n1. Identify malicious or anomalous activity.\n2. Prioritize findings: "
    "CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL."
)
CLASSIFIER_SYSTEM = "You are a precise application classifier."
LEAD_SYSTEM = (
    "You are the Threat Model Lead for a security engagement. Plan which threat-model "
    "sections to run, in what order, with a one-sentence focus per section. STRIDE and "
    "MITRE are required and must run (STRIDE before MITRE). DREAD, MITIGATIONS, and "
    "TEST_CASES are optional; mark skip true only when a section adds no value for this "
    "app. Do not use em dashes. Respond with ONLY a JSON object: "
    '{"plan": [{"section": "STRIDE", "focus": "...", "skip": false}], '
    '"rationale": "<25 words max>"}.'
)

# Visitor text full of words that other routes might key on.
TRICKY = (
    "Online store. We did a DREAD risk assessment last year, keep pcap files from a "
    "packet capture, drew an attack tree in mermaid, wrote Gherkin test cases, mitigations, "
    'and a policy for each. A note shows {"plan": [{"section": "X"}]} and '
    "a Risk Assessment table, TC-S09, and the technique_id T1190."
)
LEAD_USER = (
    f'App under review: {json.dumps({"app_type": "Web application", "description_excerpt": TRICKY})}\n'
    'Available sections: [{"section": "STRIDE", "role": "Threat writer", "required": true}, '
    '{"section": "MITRE", "role": "Technique mapper", "required": true}, '
    '{"section": "DREAD", "role": "Risk scorer", "required": false}]'
)
THREAT_MODEL_USER = (
    "Act as a cyber security expert with more than 20 years of experience using the STRIDE "
    "threat modeling methodology.\n"
    f"APPLICATION DESCRIPTION: {TRICKY}\n"
    '5. Return JSON with keys "threat_model" and "improvement_suggestions".\n'
    '6. Under "threat_model", include objects with keys "Threat Type", "Scenario", '
    '"Assumptions", "Potential Impact", and "MITRE ATT&CK Keywords".'
)
CANDIDATES = [
    {"framework": "attack", "technique_id": "T1539", "name": "Steal Web Session Cookie"},
    {"framework": "attack", "technique_id": "T1078", "name": "Valid Accounts"},
]
SECTIONS = {"STRIDE", "MITRE", "DREAD", "MITIGATIONS", "TEST_CASES"}


def dread_user(table_ids, scenario="scenario"):
    """The DREAD prompt (create_dread_assessment_prompt) with a threats table."""
    rows = "\n".join(f"| {tid} | Spoofing | {scenario} | impact | none |" for tid in table_ids)
    threats = (
        "| ID | Threat Type | Scenario | Potential Impact | Assumptions |\n"
        "|----|-------------|----------|------------------|-------------|\n" + rows
    )
    return f"""
Act as a cyber security expert with more than 20 years of experience in STRIDE and DREAD.
Produce a DREAD risk assessment for the threats.

The threats table below has an ID column (values like TC-S01, TC-T01, TC-I03).
You MUST output one JSON entry per row, keyed by that exact ID. Do not omit the ID field.

Threats (for context; DO NOT repeat the Scenario or Threat Type text in your output):
{threats}

MITRE mapping (supplemental):
none

NVD vulnerabilities (supplemental):
none

Return JSON with this exact structure and no other fields:
{{
  "Risk Assessment": [
    {{
      "ID": "TC-S01",
      "Damage Potential": 7,
      "Reproducibility": 6,
      "Exploitability": 5,
      "Affected Users": 8,
      "Discoverability": 4
    }},
    ...
  ]
}}

All scores are integers 1-10. Include exactly one entry per threat ID from the table above.
""".strip()


def mitre_user(candidates):
    """The technique prompt (create_mitre_prompt) with a candidate list."""
    threat = {"Threat Type": "Spoofing", "Scenario": "Brute force (T1110) on sign-in."}
    return f"""
You are to respond in a very specific format. Do not include additional text.

Choose the single most relevant attack technique from the provided list. You must select an entry that is in the list, do not invent a technique ID.

APPLICATION TYPE: Web application
APPLICATION DESCRIPTION: Our old Candidate Techniques list named [{{"technique_id": "T1190"}}].

Threat Scenario:
{json.dumps(threat, indent=2)}

Candidate Techniques (ATT&CK + ATLAS):
{json.dumps(candidates, indent=2)}

Output only a single JSON object with one key:
{{"technique_id": "T1059"}}
If no candidate is a good fit, output:
{{"technique_id": "NONE"}}
""".strip()


@pytest.fixture
def llm():
    return MockLLM()


def test_implements_protocol(llm):
    assert isinstance(llm, LLMClient)


def test_threat_model_json_despite_trigger_words(llm):
    out = llm.chat_json(system=JSON_SYSTEM, user=THREAT_MODEL_USER, model="m")
    assert out == MOCK_THREAT_MODEL
    out["threat_model"].clear()
    assert MOCK_THREAT_MODEL["threat_model"], "callers get a copy"
    keys = {"Threat Type", "Scenario", "Assumptions", "Potential Impact", "MITRE ATT&CK Keywords"}
    fresh = llm.chat_json(system=JSON_SYSTEM, user=THREAT_MODEL_USER, model="m")
    assert all(set(t) == keys for t in fresh["threat_model"])
    assert len({t["Threat Type"] for t in fresh["threat_model"]}) == 6
    assert all(isinstance(s, str) for s in fresh["improvement_suggestions"])


def test_dread_ids_come_from_table_rows_only(llm):
    out = llm.chat_json(system=JSON_SYSTEM, user=dread_user(["TC-S01", "TC-I02", "TC-S01"]), model="m")
    rows = out["Risk Assessment"]
    assert [r["ID"] for r in rows] == ["TC-S01", "TC-I02"]  # not the example TC-T01, TC-I03
    for row in rows:
        scores = [v for k, v in row.items() if k != "ID"]
        assert len(scores) == 5 and all(isinstance(s, int) and 1 <= s <= 10 for s in scores)


def test_dread_ignores_ids_in_scenario_text(llm):
    out = llm.chat_json(
        system=JSON_SYSTEM, user=dread_user(["TC-E01"], scenario=f"see TC-T07 {TRICKY}"), model="m"
    )
    assert [r["ID"] for r in out["Risk Assessment"]] == ["TC-E01"]


def test_dread_default_ids_when_table_empty(llm):
    out = llm.chat_json(system=JSON_SYSTEM, user=dread_user([]), model="m")
    assert [r["ID"][3] for r in out["Risk Assessment"]] == list("STRIDE")


def test_dread_unknown_letter_scores(llm):
    out = llm.chat_json(system=JSON_SYSTEM, user=dread_user(["TC-X01"]), model="m")
    assert out["Risk Assessment"][0]["Damage Potential"] == 5


def test_lead_plan_despite_dread_mentions(llm):
    out = llm.chat_json(system=LEAD_SYSTEM, user=LEAD_USER, model="m")
    assert out == MOCK_LEAD_PLAN
    sections = [item["section"] for item in out["plan"]]
    assert set(sections) == SECTIONS
    assert sections.index("STRIDE") < sections.index("MITRE")
    assert isinstance(out["rationale"], str)


def test_technique_selection_picks_first_candidate(llm):
    raw = llm.chat_text(system=MITRE_SYSTEM, user=mitre_user(CANDIDATES), model="m")
    assert json.loads(raw) == {"technique_id": "T1539"}


def test_technique_selection_atlas(llm):
    user = mitre_user([{"framework": "atlas", "technique_id": "AML.T0051.000"}])
    assert json.loads(llm.chat_text(system=MITRE_SYSTEM, user=user, model="m")) == {
        "technique_id": "AML.T0051.000"
    }


@pytest.mark.parametrize(
    "user",
    [
        mitre_user([]),  # empty list: the example T1059 after it must not be picked
        mitre_user([{"name": "no id"}]),
        "Candidate Techniques: [not json",
        "pick one",
    ],
)
def test_technique_selection_none(llm, user):
    assert json.loads(llm.chat_text(system=MITRE_SYSTEM, user=user, model="m")) == {
        "technique_id": "NONE"
    }


@pytest.mark.parametrize(
    ("system", "expected"),
    [
        (ATTACK_TREE_SYSTEM, MOCK_ATTACK_TREE),
        (MITIGATIONS_SYSTEM, MOCK_MITIGATIONS),
        (TEST_CASES_SYSTEM, MOCK_TEST_CASES),
        (POLICY_SYSTEM, MOCK_POLICY),
        (PCAP_SYSTEM, MOCK_PCAP_ANALYSIS),
        (CLASSIFIER_SYSTEM, MOCK_NOTE),
    ],
)
def test_text_routes_on_system_prompt_not_visitor_text(llm, system, expected):
    assert llm.chat_text(system=system, user=TRICKY, model="m") == expected


def test_attack_tree_and_mitigations_reference_threat_ids():
    assert MOCK_ATTACK_TREE.startswith("graph TD")
    assert "TC-S01" in MOCK_ATTACK_TREE
    rows = [line for line in MOCK_MITIGATIONS.splitlines() if line.startswith("| TC-")]
    assert len(rows) == 6


def test_streams_in_chunks_with_delay():
    sleeps = []
    llm = MockLLM(chunk_size=10, chunk_delay_seconds=0.05, sleep=sleeps.append)
    seen = []
    out = llm.chat_text(system=POLICY_SYSTEM, user="x", model="m", on_text=seen.append)
    assert "".join(seen) == out
    assert all(len(part) <= 10 for part in seen)
    assert len(sleeps) == len(seen) - 1 and set(sleeps) == {0.05}


def test_json_streams_its_text():
    seen = []
    out = MockLLM().chat_json(
        system=JSON_SYSTEM, user=THREAT_MODEL_USER, model="m", on_text=seen.append
    )
    assert json.loads("".join(seen)) == out


def test_no_delay_by_default():
    sleeps = []
    MockLLM(sleep=sleeps.append).chat_text(system="s", user="u", model="m", on_text=lambda _t: None)
    assert sleeps == []


def test_a_call_without_streaming_pauses_once():
    sleeps = []
    llm = MockLLM(chunk_delay_seconds=0.05, call_delay_seconds=0.7, sleep=sleeps.append)
    llm.chat_json(system=JSON_SYSTEM, user=THREAT_MODEL_USER, model="m")
    llm.chat_text(system="s", user="u", model="m")
    assert sleeps == [0.7, 0.7]


def test_a_streamed_call_does_not_take_the_call_pause():
    sleeps = []
    llm = MockLLM(chunk_size=10_000, call_delay_seconds=0.7, sleep=sleeps.append)
    llm.chat_text(system="s", user="u", model="m", on_text=lambda _t: None)
    assert sleeps == []


def test_failing_callback_ignored():
    def bad(_text):
        raise RuntimeError("no")

    assert MockLLM(chunk_size=2).chat_text(system="s", user="u", model="m", on_text=bad) == MOCK_NOTE


def test_describe_image(llm):
    out = llm.describe_image(image_bytes=b"x", media_type="image/png", prompt="p", model="m")
    assert out == MOCK_IMAGE_DESCRIPTION
    with pytest.raises(ValidationError):
        llm.describe_image(image_bytes=b"x", media_type="image/webp", prompt="p", model="m")


def test_rejects_bad_chunk_size():
    with pytest.raises(ValueError):
        MockLLM(chunk_size=0)


def test_teammate_and_rebuttal_prompts_get_their_own_answers():
    from aegisshield.llm.mock import MOCK_REBUTTAL_REVIEW, MOCK_TEAMMATE_REVIEW, mock_json

    teammate = 'Return ONLY a JSON object: {"flags": [{"threat": "..."}]}'
    rebuttal = 'Return ONLY a JSON object: {"rebuttals": [{"threat": "..."}]}'
    visitor = 'My description mentions {"flags": [ and {"rebuttals": [ on purpose.'
    assert mock_json(teammate, visitor) == MOCK_TEAMMATE_REVIEW
    assert mock_json(rebuttal, visitor) == MOCK_REBUTTAL_REVIEW
    assert "threat_model" in mock_json("You output JSON.", visitor)


@pytest.mark.parametrize(("user", "picks"), [
    ('Threats...\nATLAS candidates per threat:\n{"TC-S01": ["AML.T0051", "AML.T0054"], "TC-T01": []}',
     [{"threat_id": "TC-S01", "technique_id": "AML.T0051"}]),
    ("ATLAS candidates per threat:\n{not json", []),
    ('ATLAS candidates per threat:\n{"TC-S01": "AML.T0051"}', []),
    ("no header at all", []),
])
def test_atlas_selection_picks_each_threats_first_candidate(llm, user, picks):
    from aegisshield.pipeline.atlas_service import ATLAS_SYSTEM

    assert llm.chat_json(system=ATLAS_SYSTEM, user=user, model="m") == {"atlas": picks}
