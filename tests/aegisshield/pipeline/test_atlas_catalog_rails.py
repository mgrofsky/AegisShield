"""The whole bundled ATLAS catalog against the safeguards' detectors.

ATLAS text is bundled reference data, not visitor or lookup text, so it is
not screened when it enters a prompt. These tests are what stands in for
that screening: every string in the catalog is run through the detectors the
rails use (``safeguards.detect``: instructions, demands, exfiltration
markup, and key shapes), the hits are pinned so a data refresh that adds one
fails here, and every string that can reach a prompt must have none, and
must not set off the simulated stand-in model used by the evaluation.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from aegisshield.llm.susceptible import SusceptibleLLM
from aegisshield.pipeline import atlas_service, catalog_service
from aegisshield.pipeline.catalog_service import _atlas_data
from aegisshield.pipeline.threat_card_service import mitre_atlas_card
from aegisshield.safeguards import detect

# Every hit in ATLAS 2026.10, as (section, id, field, detector, kind). None of
# them is in a string that reaches a prompt (see the test below): the
# technique hits are past the first sentence of their descriptions, and case
# studies never reach a prompt.
KNOWN_HITS = {
    # "... websites containing malicious instructions for AI agents ..." is
    # marked as text addressed to a model (a mark only; not acted on alone).
    ("techniques", "AML.T0017", "description", "instructions(retrieved)", "addressed"),
    # The description shows the exfiltration markup it describes, twice.
    ("techniques", "AML.T0077", "description", "exfiltration", "an image on another host"),
    ("techniques", "AML.T0077", "description", "exfiltration", "an embedded resource on another host"),
    # A case study quotes the payload it is about.
    ("case_studies", "AML.CS0043", "summary", "instructions(typed)", "override"),
    ("case_studies", "AML.CS0043", "summary", "instructions(retrieved)", "override"),
}


def _strings() -> Iterator[tuple[str, str, str, str]]:
    data = _atlas_data()
    for section in ("tactics", "techniques", "mitigations", "case_studies"):
        for item in data[section]:
            for field in ("name", "description", "summary"):
                if isinstance(item.get(field), str):
                    yield section, item["id"], field, item[field]


def _hits(text: str) -> set[tuple[str, str]]:
    found = set()
    for typed, label in ((True, "instructions(typed)"), (False, "instructions(retrieved)")):
        found |= {(label, h.kind) for h in detect.find_instructions(text, typed=typed)}
    found |= {("demand", d) for d in detect.demands_in(text)}
    found |= {("secret", kind) for kind, _s, _e in detect.find_secrets(text)}
    found |= {("exfiltration", kind) for kind, _s, _e in detect.find_exfiltration(text)}
    return found


def test_every_catalog_string_was_checked_and_the_hits_are_the_known_ones() -> None:
    strings = list(_strings())
    assert len(strings) >= 16 + 221 + 44 + 77
    found = {(section, item_id, field, *hit) for section, item_id, field, text in strings
             for hit in _hits(text)}
    assert found == KNOWN_HITS


def _prompt_strings() -> Iterator[tuple[str, str]]:
    """Every catalog string that can reach a prompt, as the prompts carry it."""
    yield "card", mitre_atlas_card().render()
    for entry in catalog_service.load_atlas_entries():
        yield entry.technique_id, json.dumps(atlas_service.candidate_card(entry))
        reference = atlas_service.mitigation_reference({"threats": [{
            "threat_id": "TC-T01",
            "technique": {"technique_id": entry.technique_id,
                          "name": catalog_service.atlas_display_name(entry)},
            **atlas_service.technique_links(entry.technique_id)}]})
        yield f"reference {entry.technique_id}", reference
    for mitigation in catalog_service.atlas_mitigations():
        yield mitigation.id, mitigation.name
    for tactic in catalog_service.atlas_tactics():
        yield tactic.id, tactic.name
    yield "system", atlas_service.ATLAS_SYSTEM


def test_nothing_that_can_reach_a_prompt_trips_a_detector_or_the_stand_in() -> None:
    stand_in = SusceptibleLLM()
    checked = 0
    for where, text in _prompt_strings():
        checked += 1
        assert _hits(text) == set(), where
        assert stand_in.effects("", text) == [], where
    assert checked > 2 * 221


def test_the_whole_candidate_pool_in_one_prompt_has_no_demand_for_the_answer_rails() -> None:
    """The output rails block an answer that carries a string the prompt
    demands; the bundled text demands none, even all of it at once."""
    entries = catalog_service.load_atlas_entries()
    prompt = atlas_service.create_atlas_prompt({"app_type": "AI/ML Systems"}, ["GenAI"], [
        {"ID": "TC-T01", "Threat Type": "Tampering", "Scenario": "s"}], {"TC-T01": entries})
    assert detect.demands_in(prompt) == []
    assert detect.find_exfiltration(prompt) == []
    assert all(c.summary[:40] not in prompt for c in catalog_service.atlas_case_studies())
