"""The live progress record and its deck.

The workflow tests replay the recorded run (tests/fixtures/stream_capture.json)
through ``ReplayLLM``: streamed calls send the recorded deltas to ``on_text``,
and a fake clock follows the recorded times, so the sequence of progress
records is what a real run would write.
"""

from __future__ import annotations

import copy
import json
import random
import re
import time
from pathlib import Path
from typing import Any

import pytest

from aegisshield.config import Settings
from aegisshield.core.errors import LLMError
from aegisshield.llm.json_extract import extract_json
from aegisshield.llm.mock import MOCK_MITIGATIONS, MOCK_TEST_CASES, MockLLM
from aegisshield.pipeline import workflow_service
from aegisshield.pipeline.live_deck import (
    CAP_FIX,
    CAP_LIVE_TEXT,
    CAP_SCENARIO,
    CAP_TEST_TITLE,
    CAP_TYPE,
    LiveDeck,
    StageStream,
)
from aegisshield.pipeline.nvd_service import NvdLookup
from aegisshield.pipeline.otx_service import OtxLookup
from aegisshield.safeguards.core import STREAM_HOLDBACK

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "stream_capture.json"
_CAPTURE = json.loads(_FIXTURE.read_text(encoding="utf-8"))
_EXPECTED = _CAPTURE["expected"]

_APP_DETAILS = {
    "app_type": "Web application",
    "industry_sector": "Retail",
    "authentication": ["OAuth2"],
    "internet_facing": "Yes",
    "sensitive_data": "Payment card data",
}
_DESCRIPTION = "An online retail checkout service exposing order APIs over the internet."


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class ReplayLLM:
    """Answers each model call with the recorded call for the same stage.

    ``fail_stage`` makes that stage's stream raise after 70% of its deltas.
    """

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.queues: dict[str, list[dict]] = {}
        for call in _CAPTURE["calls"]:
            self.queues.setdefault(call["stage"], []).append(call)
        self.log: list[tuple[str, str]] = []
        self.fail_stage: str | None = None

    @staticmethod
    def _stage(system: str, user: str) -> str:
        if "attack techniques" in system:
            return "mitre_map"
        if "attack tree" in system:
            return "attack_tree"
        if "mitigation" in system:
            return "mitigations"
        if "Gherkin" in system:
            return "test_cases"
        if "DREAD" in user:
            return "dread"
        return "stride"

    def _replay(self, system: str, user: str, on_text) -> str:
        call = self.queues[self._stage(system, user)].pop(0)
        deltas = call["deltas"]
        text = "".join(d[1] for d in deltas)
        if on_text is None:
            self.log.append(("plain", call["stage"]))
            self.clock.now = 1000.0 + call["t_end"]
            return text
        self.log.append(("stream", call["stage"]))
        self.clock.now = 1000.0 + call["t_start"]
        for count, (t, delta) in enumerate(deltas, start=1):
            if call["stage"] == self.fail_stage and count > 0.7 * len(deltas):
                raise LLMError("stream broke")
            self.clock.now = 1000.0 + call["t_start"] + t
            on_text(delta)
        self.clock.now = 1000.0 + call["t_end"]
        return text

    def chat_text(self, *, system, user, model, max_tokens=8192, on_text=None) -> str:
        return self._replay(system, user, on_text)

    def chat_json(self, *, system, user, model, max_tokens=16000, on_text=None) -> dict:
        return extract_json(self._replay(system, user, on_text))

    def describe_image(self, *, image_bytes, media_type, prompt, model, max_tokens=4096) -> str:
        raise AssertionError("the workflow never describes an image")


@pytest.fixture
def replay():
    return ReplayLLM(Clock())


def _run(llm, on_progress=None, addons=None, clock=None) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if addons is not None:
        kwargs["addons"] = addons
    return workflow_service.run_threat_model_workflow(
        llm=llm,
        settings=Settings(),
        nvd_api_key=None,
        otx_api_key=None,
        app_details=dict(_APP_DETAILS),
        app_description=_DESCRIPTION,
        on_progress=on_progress,
        clock=clock if clock is not None else getattr(llm, "clock", None),
        **kwargs,
    )


def _stage(record: dict, sid: str) -> dict:
    return next(s for s in record["stages"] if s["id"] == sid)


def _window(records: list[dict], sid: str) -> list[dict]:
    """Records written while ``sid`` was the current stage (start to finish)."""
    return [r for r in records if r["current"] == sid]


# Workflow replay


def test_replay_streams_threats_techniques_and_tree(replay) -> None:
    records: list[dict] = []
    result = _run(replay, on_progress=lambda r: records.append(copy.deepcopy(r)))

    # The result is produced from the full text exactly as before.
    assert result["threat_model"] == _EXPECTED["threat_model"]
    assert result["attack_tree_code"] == _EXPECTED["attack_tree_code"]
    final_ids = [t["ID"] for t in result["threat_model"]]

    # STRIDE streamed: threats arrive one at a time, in order, with final ids.
    stride = _window(records, "stride")
    counts = [len(r["deck"]["threats"]) for r in stride]
    assert counts[0] == 0
    assert counts[-1] == 18
    assert all(b - a in (0, 1) for a, b in zip(counts, counts[1:], strict=False))
    assert all(
        [t["id"] for t in r["deck"]["threats"]] == final_ids[: len(r["deck"]["threats"])]
        for r in stride
    )
    first_seen = {t["id"]: t["t"] for r in stride for t in reversed(r["deck"]["threats"])}
    assert first_seen["TC-S01"] < first_seen["TC-S02"] < first_seen["TC-E03"]
    # The stage's detail line survives the coalesced streaming writes.
    assert all(_stage(r, "stride")["detail"] == "Writing STRIDE threats" for r in stride[1:-1])
    assert all(
        _stage(r, "attack_tree")["detail"] == "Building Mermaid attack tree"
        for r in _window(records, "attack_tree")[1:-1]
    )
    assert _stage(stride[-1], "stride")["detail"] is None  # finish frame
    # The live panel shows the threat being written and its text tail.
    lives = [r["deck"]["live"] for r in stride if r["deck"]["live"]]
    assert lives and all(lv["stage"] == "stride" for lv in lives)
    assert "TC-S02" in {lv["item"] for lv in lives}
    assert all(len(lv["text"]) <= CAP_LIVE_TEXT for lv in lives)

    # Techniques: one per mapping call.
    mapping = _window(records, "mitre_map")
    tech_counts = [len(r["deck"]["techniques"]) for r in mapping]
    assert sorted(set(tech_counts)) == list(range(0, 19))
    assert mapping[-1]["deck"]["techniques"]["TC-S01"]["id"] == (
        result["mitre_data"][0]["mitre_techniques"][0]["technique_id"]
    )

    # Attack tree: counts grow while it streams; the recorded numbers.
    tree = _window(records, "attack_tree")
    links = [r["deck"]["tree"]["links"] for r in tree]
    assert links == sorted(links) and links[0] < links[-1]
    final_tree = records[-1]["deck"]["tree"]
    assert final_tree["root"] == "Compromise Shopper Portal and eCHD"
    assert final_tree["links"] == 84
    assert final_tree["steps"]["TC-S01"] == 4
    assert set(final_tree["steps"]) == set(final_ids)

    # Final deck equals the result.
    deck = records[-1]["deck"]
    assert [t["id"] for t in deck["threats"]] == final_ids
    assert deck["techniques"] == {
        e["threat"]["ID"]: {
            "id": e["mitre_techniques"][0]["technique_id"],
            "name": e["mitre_techniques"][0]["name"],
            "t": deck["techniques"][e["threat"]["ID"]]["t"],
        }
        for e in result["mitre_data"]
        if e["mitre_techniques"]
    }
    assert deck["live"] is None
    # Stage timings and names are on every stage.
    stride_stage = _stage(records[-1], "stride")
    assert stride_stage["name"] == "Threat writer" and stride_stage["term"] == "STRIDE"
    assert 0 <= stride_stage["started_s"] < stride_stage["finished_s"]
    assert stride_stage["finished_s"] == pytest.approx(73.7, abs=0.2)


def test_replay_write_coalescing(replay) -> None:
    records: list[dict] = []
    _run(replay, on_progress=lambda r: records.append(copy.deepcopy(r)))
    for sid in ("stride", "attack_tree"):
        window = _window(records, sid)
        stage = _stage(window[-1], sid)
        seconds = stage["finished_s"] - stage["started_s"]
        # About three writes a second at most, plus the forced start/finish.
        assert len(window) <= seconds * 3 + 3
        times = [r["deck"]["t"] for r in window[1:-1]]
        gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
        assert min(gaps) >= 0.25  # deck.t is rounded to 0.1 s
    # The stride stage streams 1518 deltas; far fewer writes than that.
    assert len(_window(records, "stride")) < 300


def test_replay_without_on_progress_is_identical(replay) -> None:
    streamed = _run(replay, on_progress=lambda _r: None)
    assert ("stream", "stride") in replay.log
    plain_llm = ReplayLLM(replay.clock)
    plain = _run(plain_llm)
    assert all(kind == "plain" for kind, _ in plain_llm.log)
    assert plain == streamed


# Skips


def _enrich(nvd_key, otx_key, techs) -> dict:
    events: list[dict] = []
    emitter = workflow_service._StageEmitter(events.append)
    details = dict(_APP_DETAILS)
    if techs:
        details["selected_technologies"] = {"nginx": "cpe:nginx"}
        details["selected_versions"] = {"nginx": "1.25"}
    workflow_service.gather_enrichment(
        nvd_api_key=nvd_key,
        otx_api_key=otx_key,
        app_details=details,
        app_description=_DESCRIPTION,
        settings=Settings(),
        emitter=emitter,
    )
    return events[-1]


def test_skip_no_nvd_key() -> None:
    nvd = _stage(_enrich(None, None, True), "nvd")
    assert nvd["status"] == "fallback"
    assert nvd["reason"] == "No NVD API key configured"
    assert nvd["started_s"] is not None and nvd["finished_s"] is not None


def test_skip_key_without_technologies() -> None:
    nvd = _stage(_enrich("test-nvd-key", None, False), "nvd")
    assert nvd["status"] == "fallback"
    assert nvd["reason"] == "No technologies selected"


def test_skip_no_otx_key() -> None:
    otx = _stage(_enrich(None, None, False), "otx")
    assert otx["status"] == "fallback"
    assert otx["reason"] == "No OTX API key configured"


def test_lookups_that_ran_read_done(monkeypatch) -> None:
    monkeypatch.setattr(workflow_service, "lookup_nvd", lambda **_k: NvdLookup(returned=0))
    monkeypatch.setattr(
        workflow_service,
        "lookup_otx",
        lambda **_k: OtxLookup(state="found", returned=1, pulses=[{"name": "p"}]),
    )
    record = _enrich("test-nvd-key", "test-otx-key", True)
    assert _stage(record, "nvd")["status"] == "done"
    assert _stage(record, "otx")["status"] == "done"
    assert _stage(record, "nvd")["reason"] is None


# Record shape


def test_record_keeps_old_keys_and_adds_deck() -> None:
    events: list[dict] = []
    emitter = workflow_service._StageEmitter(events.append)
    emitter.reveal()
    record = events[-1]
    assert {"office", "stages", "step", "total", "current", "deck"} <= set(record)
    assert record["office"] is True and record["total"] == 8
    deck = record["deck"]
    assert deck["v"] == 1
    assert set(deck) == {
        "v", "t", "threats", "techniques", "tree", "fixes", "scores", "tests", "live", "unmatched",
        "truncated",
    }
    assert deck["unmatched"] == {"fixes": 0, "scores": 0, "tests": 0, "tree": 0}
    assert deck["truncated"] is False
    for stage in record["stages"]:
        assert stage["reason"] is None
        assert stage["started_s"] is None and stage["finished_s"] is None


def test_step_counts_resolved_owned_stages() -> None:
    events: list[dict] = []
    emitter = workflow_service._StageEmitter(events.append)
    emitter.skip("nvd", "No NVD API key configured")
    emitter.start("stride")
    emitter.finish("stride")
    assert events[-1]["step"] == 2
    emitter.own_addons()
    emitter.skip("dread", "Not selected")
    assert events[-1]["total"] == 11
    assert events[-1]["step"] == 3


def test_emitter_without_callback_is_inert() -> None:
    emitter = workflow_service._StageEmitter(None)
    assert emitter.enabled is False
    assert emitter.stream("stride") is None
    assert emitter.mapped([{"ID": "TC-S01"}]) is None
    emitter.changed()
    emitter.flush()
    emitter.start("stride")


def test_coalesced_update_is_flushed_by_next_forced_write() -> None:
    clock = Clock()
    events: list[dict] = []
    emitter = workflow_service._StageEmitter(events.append, clock=clock)
    emitter.start("stride")
    on_text = emitter.stream("stride")
    on_text('{"threat_model": [{"Threat Type": "Spoofing", "Scenario": "a"}')
    # Same instant as the start write: coalesced, not written yet.
    assert len(events) == 1
    emitter.flush()
    assert len(events) == 2
    assert [t["id"] for t in events[-1]["deck"]["threats"]] == ["TC-S01"]
    emitter.flush()
    assert len(events) == 2
    clock.now += 0.1
    on_text(', {"Threat Type": "Tampering", "Scenario": "b"}')
    assert len(events) == 2
    emitter.finish("stride")
    assert [t["id"] for t in events[-1]["deck"]["threats"]] == ["TC-S01", "TC-T01"]
    clock.now += 1
    on_text("]}")
    assert len(events) == 4


def test_emit_failure_is_swallowed() -> None:
    def boom(_r):
        raise RuntimeError("store down")

    emitter = workflow_service._StageEmitter(boom)
    emitter.start("stride")
    emitter.error("stride", "x")


def test_mapped_callback_sets_live_and_techniques() -> None:
    events: list[dict] = []
    emitter = workflow_service._StageEmitter(events.append)
    threats = [{"ID": "TC-S01"}, {"ID": "TC-T01"}]
    emitter.deck.final_threats(threats)
    on_mapped = emitter.mapped(threats)
    assert emitter.deck.live == {"stage": "mitre_map", "item": "TC-S01", "text": ""}
    on_mapped(0, threats[0], {"technique_id": "T1110", "name": "Brute Force"})
    on_mapped(1, threats[1], None)
    assert emitter.deck.techniques["TC-S01"]["name"] == "Brute Force"
    assert "TC-T01" not in emitter.deck.techniques
    assert emitter.deck.live["item"] is None


# Deck rules


def _deck_with(ids: list[str]) -> LiveDeck:
    deck = LiveDeck(lambda: 1.0)
    deck.final_threats([{"ID": i, "Threat Type": "Spoofing", "Scenario": "s"} for i in ids])
    return deck


def test_caps_on_model_text() -> None:
    long = "word " * 400
    deck = LiveDeck(lambda: 2.0)
    deck.final_threats([{"ID": "TC-S01", "Threat Type": long, "Scenario": long}])
    assert len(deck.threats[0]["scenario"]) <= CAP_SCENARIO
    assert len(deck.threats[0]["type"]) <= CAP_TYPE
    deck.add_fix(["TC-S01", long])
    assert len(deck.fixes["TC-S01"]["text"]) <= CAP_FIX
    deck.add_test({"heading": "TC-S01", "body": f"Feature: x\n  Scenario: {long}"})
    assert len(deck.tests["TC-S01"]["title"]) <= CAP_TEST_TITLE
    deck.set_live("stride", None, long)
    assert len(deck.live["text"]) <= CAP_LIVE_TEXT
    deck.add_technique("TC-S01", {"technique_id": "T1", "name": long})
    assert len(deck.techniques["TC-S01"]["name"]) <= 120


def test_unmatched_items_are_counted_not_stored() -> None:
    deck = _deck_with(["TC-S01"])
    deck.add_fix(["TC-Z09", "x"])
    deck.add_fix(["no id", "x"])
    deck.add_score({"ID": "TC-Z09", "Damage Potential": 1})
    deck.add_score({"ID": "TC-S01", "Damage Potential": "high"})
    deck.add_test({"heading": "Test cases (mock)", "body": ""})
    assert deck.fixes == {} and deck.scores == {} and deck.tests == {}
    assert deck.unmatched == {"fixes": 2, "scores": 2, "tests": 1, "tree": 0}


def test_score_is_dread_service_mean() -> None:
    deck = _deck_with(["TC-S01"])
    deck.add_score(
        {"ID": "TC-S01", "Damage Potential": 7, "Reproducibility": 6,
         "Exploitability": 5, "Affected Users": 4, "Discoverability": 6}
    )
    score = deck.scores["TC-S01"]
    assert score["risk"] == (7 + 6 + 5 + 4 + 6) / 5
    assert score["affected_users"] == 4


def test_test_title_prefers_scenario_then_feature() -> None:
    deck = _deck_with(["TC-S01", "TC-S02", "TC-S03"])
    deck.add_test({"heading": "TC-S01", "body": "```gherkin\nFeature: F\n  Scenario: Do the thing\n```"})
    deck.add_test({"heading": "TC-S02", "body": "Feature: Only feature"})
    deck.add_test({"heading": "TC-S03", "body": "nothing"})
    assert deck.tests["TC-S01"]["title"] == "Do the thing"
    assert deck.tests["TC-S02"]["title"] == "Only feature"
    assert deck.tests["TC-S03"]["title"] == ""


def test_first_seen_time_is_kept_on_rebuild() -> None:
    now = [5.0]
    deck = LiveDeck(lambda: now[0])
    deck.add_threat("TC-S01", {"Threat Type": "Spoofing", "Scenario": "a"})
    now[0] = 9.0
    deck.final_threats([{"ID": "TC-S01", "Threat Type": "Spoofing", "Scenario": "a"}])
    assert deck.threats[0]["t"] == 5.0


def test_tree_counts_mock_and_inline_shapes() -> None:
    deck = _deck_with(["TC-S01"])
    deck.final_tree(
        "graph TD\n  A[Attacker] --> B[Phishing]\n  B --> C[Account takeover]\n"
        "  subgraph x\n  end\n  endpoint --> A\n  %% note\n"
        '  B -->|label| T1["TC-S01: x"] --> K1[step]\n  T1 --> K2(("two"))\n  T1 --> K1\n'
        "  dangling -->\n"
    )
    assert deck.tree["root"] == "Attacker"
    assert deck.tree["links"] == 7
    assert deck.tree["steps"] == {"TC-S01": 2}


def test_stage_streams_for_addons_fill_deck_and_live() -> None:
    deck = _deck_with(["TC-S01", "TC-S02"])
    changes: list[int] = []

    def bump() -> None:
        changes.append(1)

    fixes = StageStream("mitigations", deck, bump)
    fixes("| ID | Fix |\n|---|---|\n| TC-S01 | rotate keys |\n| TC-S02 | parti")
    assert deck.fixes["TC-S01"]["text"] == "rotate keys"
    assert deck.live["item"] == "TC-S02"

    scores = StageStream("dread", deck, bump)
    scores('{"Risk Assessment": [{"ID": "TC-S01", "Damage Potential": 5, "Reproducibility": 5, '
           '"Exploitability": 5, "Affected Users": 5, "Discoverability": 5}, {"ID": "TC-S02"')
    assert deck.scores["TC-S01"]["risk"] == 5
    assert deck.live == {"stage": "dread", "item": "TC-S02", "text": '{"ID": "TC-S02"'}

    tests = StageStream("test_cases", deck, bump)
    tests("## TC-S01\nScenario: one\n## TC-S02\nFeat")
    assert deck.tests["TC-S01"]["title"] == "one"
    assert deck.live["item"] == "TC-S02"
    assert changes


@pytest.mark.parametrize("addons", [None])
def test_addons_none_leaves_last_three_queued(replay, addons) -> None:
    records: list[dict] = []
    _run(replay, on_progress=records.append, addons=addons)
    for sid in ("mitigations", "dread", "test_cases"):
        assert _stage(records[-1], sid)["status"] == "queued"
    assert records[-1]["total"] == 8


# Add-ons inside the job

_ALL_ADDONS = ["mitigations", "dread", "test_cases"]


def test_replay_with_addons_streams_fixes_scores_and_tests(replay) -> None:
    records: list[dict] = []
    result = _run(replay, on_progress=lambda r: records.append(copy.deepcopy(r)), addons=_ALL_ADDONS)

    # Results are the full-text parses, exactly what the endpoints return.
    assert result["mitigations_markdown"] == _EXPECTED["mitigations_markdown"]
    assert result["dread_assessment"] == _EXPECTED["dread_assessment"]
    assert result["dread_assessment_markdown"] == _EXPECTED["dread_assessment_markdown"]
    assert result["test_cases_markdown"] == _EXPECTED["test_cases_markdown"]
    final_ids = [t["ID"] for t in result["threat_model"]]

    final = records[-1]
    assert final["total"] == 11 and final["step"] == 11
    statuses = {s["id"]: s["status"] for s in final["stages"]}
    assert statuses["nvd"] == statuses["otx"] == "fallback"
    assert all(statuses[s] == "done" for s in _ALL_ADDONS)

    # Each part arrives per threat while its stage streams.
    for sid, part in (("mitigations", "fixes"), ("dread", "scores"), ("test_cases", "tests")):
        window = _window(records, sid)
        counts = [len(r["deck"][part]) for r in window]
        assert counts[0] == 0 and counts[-1] == 18, sid
        # The safeguards hold back the last STREAM_HOLDBACK characters of an
        # answer until its output check passes, so the last record may add
        # the few items in that tail at once; before it, one at a time.
        assert all(b - a in (0, 1) for a, b in zip(counts[:-2], counts[1:-1], strict=False)), sid
        assert counts[-1] - counts[-2] <= STREAM_HOLDBACK // 80, sid
        assert len(window) > 10, sid
        assert any(r["deck"]["live"] and r["deck"]["live"]["stage"] == sid for r in window)

    deck = final["deck"]
    assert set(deck["fixes"]) == set(deck["scores"]) == set(deck["tests"]) == set(final_ids)
    assert deck["unmatched"] == {"fixes": 0, "scores": 0, "tests": 0, "tree": 0}
    assert deck["scores"]["TC-S01"]["risk"] == 5.6
    assert deck["scores"]["TC-S01"]["damage"] == 7
    assert deck["fixes"]["TC-S01"]["text"].startswith("Enforce true MFA")
    assert deck["tests"]["TC-S01"]["title"] == (
        "Attacker with access to shopper's email inbox logs in via OTC alone"
    )
    assert deck["fixes"]["TC-S01"]["t"] < deck["scores"]["TC-S01"]["t"] < deck["tests"]["TC-S01"]["t"]
    assert deck["live"] is None
    dread = _stage(final, "dread")
    assert dread["name"] == "Risk scorer"
    assert dread["finished_s"] == pytest.approx(164.9, abs=0.2)

    # With no progress callback the result is identical.
    plain_llm = ReplayLLM(replay.clock)
    assert _run(plain_llm, addons=_ALL_ADDONS) == result


def test_empty_addons_skips_all_three_as_not_selected(replay) -> None:
    records: list[dict] = []
    result = _run(replay, on_progress=records.append, addons=[])
    for sid in _ALL_ADDONS:
        stage = _stage(records[-1], sid)
        assert stage["status"] == "fallback"
        assert stage["reason"] == "Not selected"
    assert "mitigations_markdown" not in result
    assert records[-1]["total"] == 11 and records[-1]["step"] == 11
    # Unselected add-ons are skipped at the start, before any work.
    first_work = next(r for r in records if _stage(r, "serialize")["status"] == "working")
    assert all(_stage(first_work, sid)["status"] == "fallback" for sid in _ALL_ADDONS)


def test_single_addon_runs_and_others_not_selected(replay) -> None:
    records: list[dict] = []
    result = _run(replay, on_progress=records.append, addons=["dread"])
    statuses = {s["id"]: s["status"] for s in records[-1]["stages"]}
    assert statuses["dread"] == "done"
    assert statuses["mitigations"] == statuses["test_cases"] == "fallback"
    assert set(result) >= {"dread_assessment", "dread_assessment_markdown"}
    assert "test_cases_markdown" not in result


def test_failing_addon_reads_error_and_others_continue(replay, monkeypatch) -> None:
    def boom(*_args, **_kwargs):
        raise RuntimeError("Provider said: secret upstream detail")

    monkeypatch.setattr(workflow_service, "generate_mitigations", boom)
    records: list[dict] = []
    result = _run(replay, on_progress=records.append, addons=_ALL_ADDONS)
    stage = _stage(records[-1], "mitigations")
    assert stage["status"] == "error"
    assert stage["reason"] == "This step did not finish. You can run it again from the results."
    assert "mitigations_markdown" not in result
    assert "dread_assessment" in result and "test_cases_markdown" in result
    assert "secret upstream detail" not in json.dumps(records)
    # Mitigations never streamed, so no fixes; scores still match threats.
    assert records[-1]["deck"]["fixes"] == {}
    assert len(records[-1]["deck"]["scores"]) == 18


def test_mock_mode_job_completes_with_all_addons() -> None:
    records: list[dict] = []
    result = _run(MockLLM(), on_progress=records.append, addons=_ALL_ADDONS)
    assert result["mitigations_markdown"] == MOCK_MITIGATIONS
    assert result["dread_assessment_markdown"].startswith("| ID |")
    assert result["test_cases_markdown"] == MOCK_TEST_CASES
    statuses = {s["id"]: s["status"] for s in records[-1]["stages"]}
    assert all(statuses[s] == "done" for s in _ALL_ADDONS)
    assert len(records[-1]["deck"]["threats"]) == 6


def test_tree_ignores_prose_that_is_not_mermaid() -> None:
    deck = LiveDeck(lambda: 0.0)
    deck.final_tree("Mock answer. Unset AEGIS_MOCK_LLM and add an OpenAI key for a real one.")
    assert deck.tree == {"root": None, "links": 0, "steps": {}}


@pytest.mark.parametrize(
    "line",
    [
        "A" + " " * 100_000 + "x",
        "A" + " -" * 50_000,
        "A -->" + " " * 100_000 + "|",
        "A" + " " * 50_000 + "-->" + " " * 49_990 + "|x",
        "A[" + "-" * 100_000,
    ],
)
def test_tree_counting_is_fast_on_a_hostile_line(line) -> None:
    deck = LiveDeck(lambda: 0.0)
    began = time.perf_counter()
    deck.final_tree(f"graph TD\n{line}\nR[\"Root\"] --> S01[\"TC-S01: x\"]\n")
    assert time.perf_counter() - began < 0.25
    assert deck.tree["links"] == 1 and deck.tree["root"] == "Root"


def test_tree_keeps_arrow_labels_and_counts() -> None:
    deck = _deck_with(["TC-S01"])
    deck.final_tree(
        'graph TD\nR["Root"] -->|first| S01["TC-S01: x"]\n'
        "S01 -- > nope\nS01 --> a1[step] --> a2[next]\nS01 ==>  |  why | b1(other)\n"
    )
    assert deck.tree == {"root": "Root", "links": 4, "steps": {"TC-S01": 2}}


def test_tree_ignores_a_line_over_2000_characters() -> None:
    deck = LiveDeck(lambda: 0.0)
    edge = 'R["Root"] --> S01["TC-S01: x"]'
    deck.final_tree(edge + " " * (2001 - len(edge)))
    assert deck.tree["links"] == 0
    deck.final_tree(edge + " " * (2000 - len(edge)))
    assert deck.tree["links"] == 1


def test_nul_and_control_characters_never_reach_the_record() -> None:
    events: list[dict] = []
    emitter = workflow_service._StageEmitter(events.append)
    emitter.detail("nvd", "Checking Py\x00thon\x1b 3.13")
    emitter.start("stride")
    on_text = emitter.stream("stride")
    on_text(
        '{"threat_model": [{"Threat Type": "Spoofing", '
        '"Scenario": "bad\\u0000 text\\u0007 here\\twith\\nlines'
    )
    emitter.flush()
    on_text('"}]}')
    emitter.finish("stride")
    emitter.start("mitigations")
    emitter.deck.add_fix(["TC-S01", "fix\x00 it\x1f"])
    emitter.deck.add_test({"heading": "TC-S01", "body": "Scenario: t\x00itle"})
    emitter.deck.final_tree('graph TD\nR["Ro\x00ot"] --> S01["TC-S01: x"]')
    emitter.deck.add_technique("TC-S01", {"technique_id": "T1\x00", "name": "N\x00"})
    emitter.error("mitigations", "re\x00ason\x0b")
    dumped = json.dumps(events)
    # A JSON escape for a control character that is not itself escaped text.
    escapes = re.findall(r"(?<!\\)(?:\\\\)*\\u00([01][0-9a-f])", dumped)
    assert [c for c in escapes if int(c, 16) not in (0x09, 0x0A)] == []
    last = events[-1]
    assert last["deck"]["threats"][0]["scenario"] == "bad text here\twith\nlines"
    assert last["deck"]["fixes"]["TC-S01"]["text"] == "fix it"
    assert _stage(last, "mitigations")["reason"] == "reason"
    assert any(_stage(r, "nvd")["detail"] == "Checking Python 3.13" for r in events)


# Ids and bounds


def test_tree_steps_only_hold_threats_in_the_deck() -> None:
    deck = _deck_with(["TC-S01"])
    deck.final_tree(
        'graph TD\nR["Root"] --> S01["TC-S01: a"]\nR --> Z09["TC-Z09: ghost"]\n'
        'R --> B["TC-S012345: long"]\nS01 --> a1[x]\nZ09 --> z1[y]\nB --> b1[z]\n'
    )
    assert deck.tree["steps"] == {"TC-S01": 1}
    assert deck.unmatched["tree"] == 2
    assert deck.as_dict()["unmatched"]["tree"] == 2


_AXES = {
    "Damage Potential": 7,
    "Reproducibility": 6,
    "Exploitability": 5,
    "Affected Users": 4,
    "Discoverability": 6,
}


def test_bad_threat_ids_are_never_stored() -> None:
    deck = LiveDeck(lambda: 1.0)
    deck.final_threats(
        [
            {"ID": "TC-S01", "Threat Type": "Spoofing", "Scenario": "ok"},
            {"ID": "TC-S012345", "Threat Type": "Spoofing", "Scenario": "long"},
            {"ID": "<b>x</b>", "Threat Type": "Spoofing", "Scenario": "html"},
            {"ID": "tc-s02", "Threat Type": "Spoofing", "Scenario": "lower"},
        ]
    )
    assert [t["id"] for t in deck.threats] == ["TC-S01"]
    deck.add_fix(["TC-S012345", "x"])
    deck.add_score({"ID": "TC-S012345", **_AXES})
    deck.add_test({"heading": "TC-S012345", "body": "Scenario: x"})
    assert deck.fixes == {} and deck.scores == {} and deck.tests == {}
    assert deck.unmatched == {"fixes": 1, "scores": 1, "tests": 1, "tree": 0}
    deck.add_technique("TC-S012345", {"technique_id": "T1", "name": "n"})
    deck.add_technique("TC-Z09", {"technique_id": "T1", "name": "n"})
    assert deck.techniques == {}
    deck.set_live("dread", "TC-S012345", "x")
    assert deck.live["item"] is None
    deck.set_live("dread", "TC-S01", "x")
    assert deck.live["item"] == "TC-S01"


@pytest.mark.parametrize(
    "bad",
    [0, 11, -3, 7.5, 7.0, "7", True, None, float("nan"), 10**9],
)
def test_score_axes_must_be_whole_numbers_1_to_10(bad) -> None:
    deck = _deck_with(["TC-S01"])
    deck.add_score({"ID": "TC-S01", **_AXES, "Exploitability": bad})
    assert deck.scores == {}
    assert deck.unmatched["scores"] == 1
    deck.add_score({"ID": "TC-S01", **_AXES})
    assert deck.scores["TC-S01"]["risk"] == 5.6


def test_deck_caps_threats_at_200_and_counts_at_9999() -> None:
    deck = LiveDeck(lambda: 1.0)
    assert deck.as_dict()["truncated"] is False
    many = [{"ID": f"TC-S{i:02d}", "Threat Type": "Spoofing", "Scenario": "s"} for i in range(1, 301)]
    deck.final_threats(many)
    assert len(deck.threats) == 200 and deck.as_dict()["truncated"] is True
    assert deck.threats[-1]["id"] == "TC-S200"
    deck.add_threat("TC-S250", many[249])
    assert len(deck.threats) == 200 and "TC-S250" not in deck.threat_ids()
    deck.add_threat("TC-S10", {"Threat Type": "Spoofing", "Scenario": "new"})
    assert len(deck.threats) == 200
    stream = LiveDeck(lambda: 1.0)
    for i in range(1, 260):
        stream.add_threat(f"TC-T{i:02d}", {"Threat Type": "Tampering", "Scenario": "s"})
    assert len(stream.threats) == 200 and stream.as_dict()["truncated"] is True
    for i in range(1, 260):
        stream.add_technique(f"TC-T{i:02d}", {"technique_id": "T1", "name": "n"})
    assert len(stream.techniques) == 200

    tree = _deck_with(["TC-S01"])
    lines = ["graph TD", 'S01["TC-S01: a"]']
    lines += [f"S01 --> c{i}[x]" for i in range(10_050)]
    tree.final_tree("\n".join(lines))
    assert tree.tree["links"] == 9999
    assert tree.tree["steps"]["TC-S01"] == 9999


_ADDON_PART = {"mitigations": "fixes", "dread": "scores", "test_cases": "tests"}
_ADDON_KEY = {"mitigations": "mitigations_markdown", "dread": "dread_assessment", "test_cases": "test_cases_markdown"}


@pytest.mark.parametrize("stage", _ALL_ADDONS)
def test_addon_failing_mid_stream_removes_its_partial_items(replay, stage) -> None:
    replay.fail_stage = stage
    records: list[dict] = []
    result = _run(replay, on_progress=records.append, addons=_ALL_ADDONS)
    part = _ADDON_PART[stage]
    window = _window(records, stage)
    # Items streamed before the failure; the safeguards' holdback keeps the
    # last STREAM_HOLDBACK characters back, so fewer than without it.
    assert max(len(r["deck"][part]) for r in window) >= 2, "the stream filled items first"
    last_in_stage = window[-1]
    assert _stage(last_in_stage, stage)["status"] == "error"
    assert last_in_stage["deck"][part] == {}
    assert last_in_stage["deck"]["unmatched"][part] == 0
    assert last_in_stage["deck"]["live"] is None
    assert records[-1]["deck"][part] == {}
    assert _ADDON_KEY[stage] not in result
    for other in set(_ADDON_PART) - {stage}:
        assert len(records[-1]["deck"][_ADDON_PART[other]]) == 18


def test_failed_coalesced_write_backs_off_five_seconds(caplog) -> None:
    clock = Clock()
    calls: list[float] = []

    def failing(_record) -> None:
        calls.append(clock.now)
        raise RuntimeError("store slow")

    emitter = workflow_service._StageEmitter(failing, clock=clock)
    emitter.start("stride")  # forced
    on_text = emitter.stream("stride")
    caplog.clear()
    for step in range(1, 8):  # coalesced writes once a second for 7 s
        clock.now = 1000.0 + step
        on_text("x")
    emitter.flush()
    # The write at 1 s fails and starts a back-off; 2 s to 5 s are skipped;
    # 6 s is outside it, tries again, fails, and starts another.
    assert calls == [1000.0, 1001.0, 1006.0]
    clock.now = 1006.5
    emitter.finish("stride")  # forced writes always try
    emitter.start("mitre_load")
    assert calls[-2:] == [1006.5, 1006.5]
    backoffs = [r for r in caplog.records if "office_progress_backoff" in r.getMessage()]
    assert len(backoffs) == 2
    clock.now = 1011.1
    on_text("y")
    assert calls[-1] == 1011.1


# Readable "writing now" text for the threat writer


def _stride_call() -> dict:
    return next(c for c in _CAPTURE["calls"] if c["stage"] == "stride")


def _stride_text() -> str:
    return "".join(d[1] for d in _stride_call()["deltas"])


def _chunkings() -> dict[str, list[str]]:
    text = _stride_text()
    rng = random.Random(24)  # noqa: S311 - fixed-seed test chunking, not crypto
    random_chunks: list[str] = []
    i = 0
    while i < len(text):
        n = rng.randint(1, 40)
        random_chunks.append(text[i : i + n])
        i += n
    return {
        "real": [d[1] for d in _stride_call()["deltas"]],
        "one": list(text),
        "random": random_chunks,
    }


_JSON_ESCAPE_RE = re.compile(r'\\[\\"/bfnrtu]')


@pytest.mark.parametrize("chunking", ["real", "one", "random"])
def test_stride_live_text_is_plain_field_text(chunking) -> None:
    expected = {t["ID"]: t for t in _EXPECTED["threat_model"]}
    suggestions = _EXPECTED["improvement_suggestions"]
    deck = LiveDeck(lambda: 0.0)
    stream = StageStream("stride", deck, lambda: None)
    fields_seen: set = set()
    texts_seen = 0
    for chunk in _chunkings()[chunking]:
        stream(chunk)
        live = deck.live
        assert set(live) == {"stage", "item", "field", "text"}
        fields_seen.add(live["field"])
        text = live["text"]
        assert '":' not in text and '{"' not in text and "{\n" not in text
        assert not _JSON_ESCAPE_RE.search(text), text
        window = text.removeprefix("...")
        if live["field"] == "Recommendations":
            assert live["item"] is None
            assert any(window in s for s in suggestions)
        elif live["item"] is not None and text:
            threat = expected[live["item"]]
            values = [threat["Scenario"], threat["Potential Impact"]]
            assert any(window in v for v in values), (live["item"], text)
            texts_seen += 1
            if "{" in text:
                assert any(window in v and "{" in v for v in values)
        else:
            assert text == "" or any(window in s for s in suggestions)
    assert fields_seen == {"Scenario", "Potential Impact", "Recommendations", None}
    assert texts_seen > 50
    assert [t["id"] for t in deck.threats] == list(expected)
    assert deck.live["field"] == "Recommendations"
    assert suggestions[-1].endswith(deck.live["text"].removeprefix("..."))


def test_stride_live_field_switches_and_holds_between_fields() -> None:
    deck = LiveDeck(lambda: 0.0)
    stream = StageStream("stride", deck, lambda: None)
    stream('{"threat_model": [{"Threat Type": "Spoofing", "Scenario": "An attacker')
    assert deck.live == {"stage": "stride", "item": "TC-S01", "field": "Scenario", "text": "An attacker"}
    stream(' logs in.", "Assumptions": [{"Assumption": "x"')
    assert deck.live == {"stage": "stride", "item": "TC-S01", "field": None, "text": "An attacker logs in."}
    stream('}], "Potential Impact": "Data')
    assert deck.live["field"] == "Potential Impact" and deck.live["text"] == "Data"
    stream(' loss.", "MITRE ATT&CK Keywords": ["Valid')
    assert deck.live["field"] is None and deck.live["text"] == "Data loss."
    stream(' Accounts"]}, {"Threat Type": "Tampering", ')
    assert deck.live["item"] == "TC-S01" and deck.live["text"] == "Data loss."
    stream('"Scenario": "Edit')
    assert deck.live == {"stage": "stride", "item": "TC-T01", "field": "Scenario", "text": "Edit"}
    stream('"}], "improvement_suggestions": ["Add MFA", "Sign')
    assert deck.live == {"stage": "stride", "item": None, "field": "Recommendations", "text": "Sign"}
    stream(' logs"]}')
    assert deck.live["text"] == "Sign logs" and deck.live["field"] == "Recommendations"
    assert [t["id"] for t in deck.threats] == ["TC-S01", "TC-T01"]


def test_stride_live_text_decodes_escapes_at_any_chunking() -> None:
    value = 'He said \\"hi\\" \\\\ path\\nnext caf\\u00e9 \\ud83d\\ude00 end\\/'
    decoded = json.loads(f'"{value}"')
    text = '{"threat_model": [{"Threat Type": "Spoofing", "Scenario": "' + value + '"}]}'
    deck = LiveDeck(lambda: 0.0)
    stream = StageStream("stride", deck, lambda: None)
    for c in text:
        stream(c)
        shown = deck.live["text"]
        # The value holds one real backslash; never a JSON escape or half a pair.
        assert not _JSON_ESCAPE_RE.search(shown), shown
        assert not shown.endswith("\\") or shown == decoded[: len(shown)]
        assert not any(0xD800 <= ord(ch) <= 0xDFFF for ch in shown)
        assert shown in decoded
    assert deck.live["text"] == decoded
    assert deck.threats[0]["scenario"] == decoded


def test_other_stages_live_has_no_field() -> None:
    deck = _deck_with(["TC-S01"])
    for stage in ("dread", "mitigations", "test_cases", "attack_tree"):
        StageStream(stage, deck, lambda: None)("| TC-S01 | x")
        assert deck.live.get("field") is None
