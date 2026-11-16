"""Edge cases in the request model and the agentic pipeline, one test (or more) each."""

from __future__ import annotations

import json
import threading
import time
from typing import Any

import pytest
from pydantic import ValidationError as PydanticValidationError

from aegisshield.config import Settings
from aegisshield.jobs.runner import JobRunner, JobStatus
from aegisshield.llm.mock import MockLLM
from aegisshield.pipeline import agentic_threat_model as atm
from aegisshield.pipeline.run import AGENTIC_RESULT_KEYS, run_threat_model
from aegisshield.pipeline.schemas import ThreatModelRequest
from aegisshield.pipeline.workflow_service import EnrichmentBundle, RunCancelled

PROFILE: dict[str, Any] = {
    "app_type": "Web application",
    "industry_sector": "Retail",
    "sensitive_data": "Payment card data",
    "internet_facing": "Yes",
    "authentication": ["OAuth2"],
}
DESCRIPTION = "An online checkout service where shoppers pay with saved cards and coupons."

FOCUS = {section: f"FOCUS-MARK-{section.value}" for section in atm.Section}


class Sink:
    def __init__(self, cancel_after: int | None = None) -> None:
        self.records: list[dict[str, Any]] = []
        self._cancel_after = cancel_after
        self.checks = 0

    def set(self, record: dict[str, Any]) -> None:
        self.records.append(json.loads(json.dumps(record)))

    def cancelled(self) -> bool:
        self.checks += 1
        return self._cancel_after is not None and self.checks > self._cancel_after


class RecordingLLM(MockLLM):
    """MockLLM that records every prompt and plans with a distinct focus per section."""

    def __init__(self, plan: dict[str, Any] | None = None) -> None:
        super().__init__()
        self.calls: list[tuple[str, str, str]] = []
        self.plan = plan

    def chat_text(self, *, system: str, user: str, model: str, **kwargs: Any) -> str:
        self.calls.append(("text", system, user))
        return super().chat_text(system=system, user=user, model=model, **kwargs)

    def chat_json(self, *, system: str, user: str, model: str, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("json", system, user))
        if self.plan is not None and system == atm.LEAD_SYSTEM_PROMPT:
            return json.loads(json.dumps(self.plan))
        return super().chat_json(system=system, user=user, model=model, **kwargs)


def _request(**overrides: Any) -> ThreatModelRequest:
    data: dict[str, Any] = {"app_profile": dict(PROFILE), "app_description": DESCRIPTION}
    data.update(overrides)
    return ThreatModelRequest(**data)


def _full_plan() -> dict[str, Any]:
    return {
        "plan": [
            {"section": s.value, "focus": FOCUS[s], "skip": False} for s in atm.SECTION_ORDER
        ],
        "rationale": "Every section adds value.",
    }


# 1. Agentic results keep their metadata ---------------------------------------


def test_agentic_result_keeps_the_lead_plan_and_section_outputs() -> None:
    llm = RecordingLLM(plan=_full_plan())
    result = run_threat_model(
        _request(agentic=True), llm=llm, settings=Settings(), progress=Sink()
    )

    assert result["agentic"] is True
    assert result["decider"] == "ai"
    assert [s["section"] for s in result["lead_plan"]["sections"]] == [
        s.value for s in atm.SECTION_ORDER
    ]
    assert result["section_deciders"] == {s.value: "ai" for s in atm.SECTION_ORDER}
    for key in (
        "dread_assessment",
        "dread_assessment_markdown",
        "mitigations_markdown",
        "test_cases_markdown",
        "teammate_review",
        "rebuttal_review",
    ):
        assert key in result, key
    assert set(result) >= {"threat_model", "mitre_data", "attack_tree_code", "pattern_source"}
    assert set(AGENTIC_RESULT_KEYS) <= set(result)


def test_settings_flag_also_selects_the_agentic_path() -> None:
    result = run_threat_model(
        _request(), llm=MockLLM(), settings=Settings(agentic=True), progress=Sink()
    )
    assert result["agentic"] is True and "lead_plan" in result


def test_linear_result_carries_no_agentic_keys() -> None:
    result = run_threat_model(_request(), llm=MockLLM(), settings=Settings(), progress=Sink())
    assert not {"agentic", "lead_plan", "decider", "section_deciders"} & set(result)


# 2. The Lead's focus reaches every specialist ---------------------------------


def _calls_with(llm: RecordingLLM, marker: str) -> list[tuple[str, str, str]]:
    return [call for call in llm.calls if marker in call[2]]


def test_lead_focus_reaches_every_specialist_prompt() -> None:
    llm = RecordingLLM(plan=_full_plan())
    run_threat_model(_request(agentic=True), llm=llm, settings=Settings(), progress=Sink())

    stride = _calls_with(llm, FOCUS[atm.Section.STRIDE])
    assert len(stride) == 1 and "STRIDE threat modeling methodology" in stride[0][2]
    mitre = _calls_with(llm, FOCUS[atm.Section.MITRE])
    assert mitre and all("attack techniques" in call[1] for call in mitre)
    mapped = [c for c in llm.calls if "attack techniques" in c[1]]
    assert len(mitre) == len(mapped) == 6  # one per threat
    dread = _calls_with(llm, FOCUS[atm.Section.DREAD])
    assert len(dread) == 1 and '"Risk Assessment": [' in dread[0][2]
    fixes = _calls_with(llm, FOCUS[atm.Section.MITIGATIONS])
    assert len(fixes) == 1 and "mitigation" in fixes[0][1]
    tests = _calls_with(llm, FOCUS[atm.Section.TEST_CASES])
    assert len(tests) == 1 and "Gherkin" in tests[0][1]
    teammate = _calls_with(llm, FOCUS[atm.Section.TEAMMATE])
    assert len(teammate) == 1 and "Teammate Reviewer" in teammate[0][1]
    rebuttal = _calls_with(llm, FOCUS[atm.Section.REBUTTAL])
    assert len(rebuttal) == 1 and "Rebuttal Analyst" in rebuttal[0][1]

    # No section's focus leaks into another section's prompt.
    for section, marker in FOCUS.items():
        for _kind, system, user in _calls_with(llm, marker):
            for other, other_marker in FOCUS.items():
                if other is not section:
                    assert other_marker not in user


def test_specialists_after_mitre_also_get_the_organization_context() -> None:
    llm = RecordingLLM(plan=_full_plan())
    profile = dict(PROFILE, compliance_requirements=["PCI DSS"])
    run_threat_model(
        _request(app_profile=profile, agentic=True), llm=llm, settings=Settings(), progress=Sink()
    )
    for section in (atm.Section.DREAD, atm.Section.MITIGATIONS, atm.Section.TEST_CASES):
        (call,) = _calls_with(llm, FOCUS[section])
        assert "Compliance requirements selected: PCI DSS" in call[2]


# 3. The progress note names only lookups the run makes ------------------------


def _first_note(**keys: Any) -> str:
    sink = Sink()
    profile = dict(PROFILE, selected_technologies={"nginx": "cpe:2.3:a:f5:nginx:"})
    atm_kwargs = {"nvd_api_key": None, "otx_api_key": None, **keys}
    original = atm.gather_enrichment
    try:
        atm.gather_enrichment = lambda **_kw: EnrichmentBundle()  # no network
        atm.orchestrate_threat_model(
            llm=MockLLM(),
            settings=Settings(),
            app_details=profile,
            app_description=DESCRIPTION,
            on_progress=sink.set,
            **atm_kwargs,
        )
    finally:
        atm.gather_enrichment = original
    return sink.records[0]["lead"]["note"]


@pytest.mark.parametrize(
    ("keys", "note"),
    [
        ({}, "Planning the run"),
        ({"nvd_api_key": "k"}, "Gathering threat intel (NVD) and planning the run"),
        ({"otx_api_key": "k"}, "Gathering threat intel (OTX) and planning the run"),
        (
            {"nvd_api_key": "k", "otx_api_key": "k"},
            "Gathering threat intel (NVD, OTX) and planning the run",
        ),
    ],
)
def test_agentic_first_note_names_only_lookups_made(keys: dict, note: str) -> None:
    text = _first_note(**keys)
    assert text == note
    assert "KEV" not in text and "EPSS" not in text


def test_nvd_is_not_named_without_selected_technologies() -> None:
    note = atm.gathering_note(nvd_api_key="k", otx_api_key=None, app_details={}, settings=Settings())
    assert note == "Planning the run"


# 4. technical_ability accepts Low, Medium, and High ---------------------------


@pytest.mark.parametrize("ability", ["Low", "Medium", "High"])
def test_technical_ability_accepts_all_three_and_reaches_the_prompt(ability: str) -> None:
    llm = RecordingLLM()
    profile = dict(PROFILE, technical_ability=ability)
    run_threat_model(_request(app_profile=profile), llm=llm, settings=Settings(), progress=Sink())
    stride = next(c for c in llm.calls if "STRIDE threat modeling methodology" in c[2])
    assert f"the user's technical ability is: {ability}." in stride[2]


def test_technical_ability_rejects_other_values() -> None:
    with pytest.raises(PydanticValidationError):
        _request(app_profile=dict(PROFILE, technical_ability="Expert"))


def test_technical_ability_defaults_to_medium() -> None:
    assert _request().app_profile.technical_ability == "Medium"


# Agentic sections ---------------------------------------------------------------


def test_rebuttal_challenges_the_highest_risk_rows() -> None:
    """Rebuttal ranks rows by the mean of the DREAD axes, not by a "Risk Score"
    key, which DREAD rows never carry."""
    rows = [
        {"ID": f"TC-S0{i}", **dict.fromkeys(atm._DREAD_AXES, score)}
        for i, score in enumerate([2, 9, 4, 10, 1, 7, 3], start=1)
    ]
    llm = RecordingLLM()
    ctx = atm.SectionContext(
        llm=llm,
        app_details=dict(PROFILE),
        app_description=DESCRIPTION,
        enrichment=EnrichmentBundle(),
        architect_model="m",
        worker_model="m",
        outputs={"dread_assessment": {"Risk Assessment": rows}},
    )
    atm._run_rebuttal(ctx, "")
    user = llm.calls[-1][2]
    top = json.loads(user.split("Top DREAD rows:\n", 1)[1].split("\n\n", 1)[0])
    assert [r["ID"] for r in top] == ["TC-S04", "TC-S02", "TC-S06", "TC-S03", "TC-S07"]


def test_dread_risk_is_the_mean_of_the_axes_and_ignores_bad_values() -> None:
    row = dict.fromkeys(atm._DREAD_AXES, 5)
    assert atm.dread_risk(row) == 5.0
    row["Damage Potential"] = "high"
    row["Reproducibility"] = True
    assert atm.dread_risk(row) == 3.0


def test_a_skip_given_as_a_string_does_not_skip() -> None:
    """A skip of "false" must not skip: ``bool("false")`` is True."""
    plan = atm._normalize_plan(
        [{"section": "DREAD", "skip": "false"}, {"section": "TEST_CASES", "skip": True}]
    )
    skipped = {p.section for p in plan.sections if p.skip}
    assert skipped == {atm.Section.TEST_CASES}


def test_teammate_runs_after_test_cases_and_reads_the_finished_draft() -> None:
    assert atm.SECTION_ORDER.index(atm.Section.TEAMMATE) > atm.SECTION_ORDER.index(
        atm.Section.TEST_CASES
    )
    assert "before mitigations" not in atm.AGENT_ROLES[atm.Section.TEAMMATE].default_focus
    assert "after test cases" in (atm._run_teammate.__doc__ or "")


# Cancellation between stages ---------------------------------------------------


@pytest.mark.parametrize("agentic", [False, True])
def test_a_cancelled_run_stops_between_stages(agentic: bool) -> None:
    llm = RecordingLLM()
    sink = Sink(cancel_after=3)
    with pytest.raises(RunCancelled):
        run_threat_model(_request(agentic=agentic), llm=llm, settings=Settings(), progress=sink)
    assert len(llm.calls) <= 2


def test_a_cancelled_job_reads_cancelled_in_the_runner() -> None:
    runner = JobRunner(max_concurrent_jobs=1, job_timeout_seconds=60)
    ids: list[str] = []
    submitted = threading.Event()

    class CancelOnSet:
        def __init__(self, inner: Any) -> None:
            self.inner = inner

        def set(self, record: dict[str, Any]) -> None:
            self.inner.set(record)
            if record.get("current") == "stride":
                runner.cancel(ids[0])

        def cancelled(self) -> bool:
            return self.inner.cancelled()

    def job(progress: Any) -> dict[str, Any]:
        submitted.wait(5)
        return run_threat_model(
            _request(), llm=MockLLM(), settings=Settings(), progress=CancelOnSet(progress)
        )

    ids.append(runner.submit(job, kind="threat_model"))
    submitted.set()
    snap = runner.snapshot(ids[0])
    for _ in range(500):
        snap = runner.snapshot(ids[0])
        if snap is not None and snap.done:
            break
        time.sleep(0.01)
    assert snap is not None and snap.status is JobStatus.CANCELLED
    assert snap.result is None


# The final record reads complete ------------------------------------------------


@pytest.mark.parametrize("agentic", [False, True])
def test_a_finished_run_writes_current_complete(agentic: bool) -> None:
    sink = Sink()
    run_threat_model(_request(agentic=agentic), llm=MockLLM(), settings=Settings(), progress=sink)
    last, before = sink.records[-1], sink.records[-2]
    assert last["current"] == "complete"
    assert {k: v for k, v in last.items() if k != "current"} == {
        k: v for k, v in before.items() if k != "current"
    }


def test_complete_progress_falls_back_to_the_plain_shape() -> None:
    from aegisshield.pipeline.run import complete_progress

    assert complete_progress(None) == {"step": 1, "total": 1, "current": "complete"}
    assert complete_progress({"step": 2}) == {"step": 1, "total": 1, "current": "complete"}


def test_mock_agentic_run_gets_review_answers_from_the_mock() -> None:
    result = run_threat_model(
        _request(agentic=True), llm=MockLLM(), settings=Settings(), progress=Sink()
    )
    assert result["teammate_review"]["flags"][0]["threat"] == "TC-R01"
    assert result["rebuttal_review"]["rebuttals"][0]["threat"] == "TC-I01"
