"""The agentic orchestrator, including the Teammate and Rebuttal sections.

Covers the load-bearing guarantees of the orchestrator:
  * lead_plan parses a valid AI plan AND falls back to the rule plan on any
    failure.
  * run_section returns SectionResult.experts as a LIST (length 1 now), the
    seam for a later fan-out.
  * orchestrate_threat_model assembles the SAME dict shape as the linear
    workflow plus the additive agentic keys, and emits a populated roster.
  * The offline (MockLLM) path is deterministic and produces a threat model
    with a watchable roster.

MockLLM recognizes the Lead prompt and answers with a plan, so the offline
decider is "ai"; a mock that answered the Lead with the threat-model JSON
would fall back to the rule plan instead.
"""

from __future__ import annotations

import pytest

from aegisshield.config import Settings
from aegisshield.llm.mock import MOCK_LEAD_PLAN, MockLLM
from aegisshield.pipeline import agentic_threat_model as atm
from aegisshield.pipeline.workflow_service import EnrichmentBundle

_APP_DETAILS = {
    "app_type": "Web application",
    "industry_sector": "Retail",
    "sensitive_data": "Payment card data",
    "internet_facing": "Yes",
    "authentication": ["OAuth2"],
}
_DESCRIPTION = "An online retail checkout service exposing payment APIs over the internet."

# Linear-workflow result keys the page and report depend on. The agentic dict
# must carry every one of these so downstream is unchanged.
_LINEAR_KEYS = {
    "threat_model",
    "improvement_suggestions",
    "improvement_suggestions_markdown",
    "threat_model_markdown",
    "mitre_data",
    "mitre_attack_markdown",
    "nvd_vulnerabilities_markdown",
    "otx_data_markdown",
    "attack_tree_code",
    "detected_patterns",
    "pattern_source",
}


@pytest.fixture
def mock_settings() -> Settings:
    return Settings(mock_llm=True, offline=True, agentic=True)


class _JsonLLM:
    """A fake LLM whose chat_json gives ``answer(**kwargs)``."""

    def __init__(self, answer):
        self.answer = answer
        self.calls: list[dict] = []

    def chat_json(self, *, system, user, model, max_tokens=16000, on_text=None):
        self.calls.append({"system": system, "user": user, "model": model})
        return self.answer(system=system, user=user, model=model)


class _PlanLLM(MockLLM):
    """MockLLM, except the Lead's planning call gets ``plan``."""

    def __init__(self, plan: dict):
        super().__init__()
        self.plan = plan

    def chat_json(self, *, system, user, model, max_tokens=16000, on_text=None):
        if system == atm.LEAD_SYSTEM_PROMPT:
            return self.plan
        return super().chat_json(
            system=system, user=user, model=model, max_tokens=max_tokens, on_text=on_text
        )


# lead_plan ------------------------------------------------------------------


def _empty_enrichment() -> EnrichmentBundle:
    return EnrichmentBundle()


def _lead_plan(llm, settings: Settings) -> atm.LeadPlan:
    return atm.lead_plan(
        llm=llm,
        model=settings.architect_model,
        app_details=_APP_DETAILS,
        app_description=_DESCRIPTION,
        enrichment=_empty_enrichment(),
    )


def test_lead_plan_parses_valid_ai_plan(mock_settings):
    def answer(**_kwargs):
        return {
            "plan": [
                {"section": "STRIDE", "focus": "payment card data flows", "skip": False},
                {"section": "MITRE", "focus": "checkout techniques", "skip": False},
                {"section": "DREAD", "focus": "impact", "skip": True},
            ],
            "rationale": "Skip DREAD for this lightweight app.",
        }

    plan = _lead_plan(_JsonLLM(answer), mock_settings)
    assert plan.decider == "ai"
    assert plan.rationale.startswith("Skip DREAD")
    by_section = {p.section: p for p in plan.sections}
    # Optional DREAD respected the skip flag.
    assert by_section[atm.Section.DREAD].skip is True
    # Every section is present (omitted ones backfilled).
    assert set(by_section) == set(atm.SECTION_ORDER)
    # Required sections never skipped.
    assert by_section[atm.Section.STRIDE].skip is False
    assert by_section[atm.Section.MITRE].skip is False


def test_lead_plan_keeps_required_sections_even_if_ai_skips_them(mock_settings):
    def answer(**_kwargs):
        return {"plan": [{"section": "STRIDE", "focus": "x", "skip": True}]}

    plan = _lead_plan(_JsonLLM(answer), mock_settings)
    by_section = {p.section: p for p in plan.sections}
    assert by_section[atm.Section.STRIDE].skip is False
    assert by_section[atm.Section.MITRE].skip is False


def test_lead_plan_orders_stride_before_mitre(mock_settings):
    def answer(**_kwargs):
        return {
            "plan": [
                {"section": "MITRE", "focus": "x", "skip": False},
                {"section": "STRIDE", "focus": "y", "skip": False},
            ]
        }

    plan = _lead_plan(_JsonLLM(answer), mock_settings)
    order = [p.section for p in plan.sections]
    assert order.index(atm.Section.STRIDE) < order.index(atm.Section.MITRE)


def test_lead_plan_falls_back_on_malformed_response(mock_settings):
    plan = _lead_plan(_JsonLLM(lambda **_k: {"not_a_plan": True}), mock_settings)
    assert plan.decider == "rule"
    assert {p.section for p in plan.sections} == set(atm.SECTION_ORDER)


def test_lead_plan_falls_back_on_unknown_sections(mock_settings):
    plan = _lead_plan(
        _JsonLLM(lambda **_k: {"plan": [{"section": "MARKETING", "focus": "x"}]}), mock_settings
    )
    assert plan.decider == "rule"


def test_lead_plan_falls_back_on_exception(mock_settings):
    def boom(**_kwargs):
        raise RuntimeError("model service down")

    plan = _lead_plan(_JsonLLM(boom), mock_settings)
    assert plan.decider == "rule"


def test_mock_llm_lead_plan_is_the_canned_ai_plan(mock_settings):
    # MockLLM answers the Lead with MOCK_LEAD_PLAN (not the threat model
    # JSON, which would mean a rule fallback). The plan names five sections;
    # TEAMMATE and REBUTTAL are backfilled after them.
    plan = _lead_plan(MockLLM(), mock_settings)
    assert plan.decider == "ai"
    assert plan.rationale == MOCK_LEAD_PLAN["rationale"]
    assert [p.section for p in plan.sections] == atm.SECTION_ORDER
    assert not any(p.skip for p in plan.sections)


# run_section: the experts-LIST interface -------------------------------------


def _ctx(settings: Settings, llm=None) -> atm.SectionContext:
    return atm.SectionContext(
        llm=llm or MockLLM(),
        app_details=_APP_DETAILS,
        app_description=_DESCRIPTION,
        enrichment=_empty_enrichment(),
        architect_model=settings.architect_model,
        worker_model=settings.worker_model,
        outputs={
            "nvd_vulnerabilities_markdown": "",
            "otx_data_markdown": "",
            "detected_patterns": [],
            "pattern_source": "none",
        },
    )


def test_run_section_returns_experts_as_list(mock_settings):
    plan = atm._default_plan("rule")
    ctx = _ctx(mock_settings)
    result = atm.run_section(atm.Section.STRIDE, plan, ctx=ctx)
    assert isinstance(result.experts, list)
    assert len(result.experts) == 1  # exactly one expert per section today
    expert = result.primary
    assert expert.status == "done"
    assert "threat_model" in expert.output
    assert result.decider == "rule"


def test_run_section_required_failure_propagates(mock_settings, monkeypatch):
    plan = atm._default_plan("rule")
    ctx = _ctx(mock_settings)

    def boom(_ctx, _focus):
        raise RuntimeError("stride worker failed")

    monkeypatch.setattr(atm, "_run_stride", boom)
    with pytest.raises(RuntimeError, match="stride worker failed"):
        atm.run_section(atm.Section.STRIDE, plan, ctx=ctx)


def test_run_section_optional_failure_degrades_to_fallback(mock_settings, monkeypatch):
    plan = atm._default_plan("rule")
    ctx = _ctx(mock_settings)

    def boom(_ctx, _focus):
        raise RuntimeError("dread worker failed")

    monkeypatch.setattr(atm, "_run_dread", boom)
    result = atm.run_section(atm.Section.DREAD, plan, ctx=ctx)
    assert len(result.experts) == 1
    assert result.primary.status == "fallback"
    assert result.primary.output == {}


# orchestrate_threat_model ----------------------------------------------------


def _orchestrate(settings: Settings, on_progress, llm=None) -> dict:
    return atm.orchestrate_threat_model(
        llm=llm or MockLLM(),
        settings=settings,
        nvd_api_key=None,
        otx_api_key=None,
        app_details=_APP_DETAILS,
        app_description=_DESCRIPTION,
        on_progress=on_progress,
    )


def test_orchestrate_offline_produces_full_dict_and_roster(mock_settings):
    events: list[dict] = []
    result = _orchestrate(mock_settings, events.append)
    # Same shape as the linear workflow.
    assert _LINEAR_KEYS.issubset(result.keys())
    # Additive agentic metadata.
    assert result["agentic"] is True
    assert result["decider"] == "ai"  # MockLLM answers the Lead (source: "rule")
    assert "lead_plan" in result and "sections" in result["lead_plan"]
    # A real threat model came back.
    assert isinstance(result["threat_model"], list) and result["threat_model"]

    # The roster is watchable: the final progress event has every active agent
    # marked done.
    final = events[-1]
    assert final["agentic"] is True
    assert final["current"] == "complete"
    roles = {a["role"] for a in final["agents"]}
    assert "STRIDE Analyst" in roles
    assert "MITRE ATT&CK Mapper" in roles
    assert all(a["status"] in {"done", "fallback"} for a in final["agents"])

    # At least one mid-run event showed an agent "working" (animated board).
    assert any(
        any(a["status"] == "working" for a in ev.get("agents", []))
        for ev in events
    )


def test_orchestrate_first_emit_reveals_office_before_enrichment(mock_settings):
    # The roster must show the instant the run starts: the FIRST progress
    # event is agentic, with the Lead working and every specialist still
    # queued, emitted before enrichment and planning.
    events: list[dict] = []
    _orchestrate(mock_settings, events.append)
    first = events[0]
    assert first["agentic"] is True
    assert first["step"] == 0
    assert first["lead"]["status"] == "working"
    assert first["agents"], "the roster must be there on the very first frame"
    # No specialist has started yet on the reveal frame.
    assert all(a["status"] == "queued" for a in first["agents"])
    # Every specialist is present so the layout is stable from frame one
    # (seven sections: five analysts, then Teammate and Rebuttal).
    assert {a["section"] for a in first["agents"]} == {
        "STRIDE", "MITRE", "DREAD", "MITIGATIONS", "TEST_CASES", "TEAMMATE", "REBUTTAL"
    }


def test_orchestrate_skips_optional_section_from_plan(mock_settings):
    # Force an AI plan that skips every optional section; the roster omits them.
    plan = {
        "plan": [
            {"section": "STRIDE", "focus": "payment card data", "skip": False},
            {"section": "MITRE", "focus": "checkout", "skip": False},
            {"section": "DREAD", "focus": "x", "skip": True},
            {"section": "MITIGATIONS", "focus": "x", "skip": True},
            {"section": "TEST_CASES", "focus": "x", "skip": True},
        ]
    }
    events: list[dict] = []
    result = _orchestrate(mock_settings, events.append, llm=_PlanLLM(plan))
    assert result["decider"] == "ai"
    final_roles = {a["section"] for a in events[-1]["agents"]}
    assert "STRIDE" in final_roles
    assert "MITRE" in final_roles
    assert "DREAD" not in final_roles  # skipped sections do not appear on the board
    # Required output keys still present even with the optionals skipped.
    assert _LINEAR_KEYS.issubset(result.keys())


def test_orchestrate_progress_callback_failure_does_not_break_run(mock_settings):
    def bad_callback(_progress):
        raise RuntimeError("callback blew up")

    # Progress is best-effort; a throwing callback must not fail the run.
    result = _orchestrate(mock_settings, bad_callback)
    assert result["agentic"] is True
    assert result["threat_model"]


# Teammate and Rebuttal sections ------------------------------------------------


def _review_ctx(llm, outputs: dict) -> atm.SectionContext:
    return atm.SectionContext(
        llm=llm,
        app_details={"app_type": "web", "internet_facing": True},
        app_description="online retail checkout",
        enrichment=EnrichmentBundle(),
        architect_model="",
        worker_model="",
        outputs=outputs,
    )


def test_phase_a_new_sections_registered():
    assert atm.Section.TEAMMATE in atm.SECTION_ORDER
    assert atm.Section.REBUTTAL in atm.SECTION_ORDER
    assert atm.Section.TEAMMATE not in atm.REQUIRED_SECTIONS
    assert atm.Section.REBUTTAL not in atm.REQUIRED_SECTIONS
    assert atm.Section.TEAMMATE in atm._SECTION_WORKERS
    assert atm.Section.REBUTTAL in atm._SECTION_WORKERS
    assert atm.Section.TEAMMATE in atm.AGENT_ROLES
    assert atm.Section.REBUTTAL in atm.AGENT_ROLES
    # The two review sections run last, Teammate then Rebuttal.
    assert atm.SECTION_ORDER[-2:] == [atm.Section.TEAMMATE, atm.Section.REBUTTAL]


def test_phase_a_teammate_worker_returns_review():
    llm = _JsonLLM(lambda **_k: {"flags": [{"threat": "x", "reason": "y"}], "notes": "ok"})
    ctx = _review_ctx(llm, {"threat_model": [], "dread_assessment": {}})
    result = atm._run_teammate(ctx, "focus")
    assert result.status == "done"
    assert result.findings == 1
    assert result.output["teammate_review"]["flags"][0]["threat"] == "x"


def test_phase_a_rebuttal_worker_returns_review():
    llm = _JsonLLM(lambda **_k: {"rebuttals": [{"threat": "R1", "adjusted": "7.0"}]})
    ctx = _review_ctx(
        llm,
        {
            "threat_model": [],
            "dread_assessment": {
                "Risk Assessment": [
                    {"Threat": "R1", "Risk Score": 9.2},
                    {"Threat": "R2", "Risk Score": 4.1},
                ]
            },
        },
    )
    result = atm._run_rebuttal(ctx, "focus")
    assert result.status == "done"
    assert result.findings == 1
    assert result.output["rebuttal_review"]["rebuttals"][0]["threat"] == "R1"


def test_phase_a_new_sections_optional_in_default_plan():
    plan = atm._default_plan("rule")
    by_section = {p.section: p for p in plan.sections}
    assert atm.Section.TEAMMATE in by_section
    assert atm.Section.REBUTTAL in by_section
    assert not by_section[atm.Section.TEAMMATE].skip
    assert not by_section[atm.Section.REBUTTAL].skip


def test_phase_a_new_sections_degrade_to_fallback(monkeypatch):
    def boom(ctx, focus):
        raise RuntimeError("model unavailable")

    monkeypatch.setattr(atm, "_run_teammate", boom)
    plan = atm._default_plan("rule")
    result = atm.run_section(atm.Section.TEAMMATE, plan, ctx=_review_ctx(MockLLM(), {}))
    assert result.primary.status == "fallback"
    assert result.primary.output == {}


def _fake_expert(agent_id: str, findings: int = 0) -> atm.ExpertResult:
    return atm.ExpertResult(
        agent_id=agent_id,
        role=agent_id,
        status="done",
        output={},
        findings=findings,
        activity=agent_id,
    )


def test_orchestrate_with_every_section_active(mock_settings, monkeypatch):
    """All 7 sections active on the roster when the Lead includes them."""
    captured: list[dict] = []

    def fake_lead_plan(**kwargs):
        return atm.LeadPlan(
            sections=[
                atm.PlannedSection(section=s, focus="retail checkout", skip=False)
                for s in atm.SECTION_ORDER
            ],
            decider="ai",
        )

    monkeypatch.setattr(atm, "lead_plan", fake_lead_plan)
    monkeypatch.setattr(atm, "gather_enrichment", lambda **kwargs: EnrichmentBundle())
    monkeypatch.setattr(atm, "_run_stride", lambda ctx, f: _fake_expert("stride", 3))
    monkeypatch.setattr(atm, "_run_mitre", lambda ctx, f: _fake_expert("mitre", 2))
    monkeypatch.setattr(atm, "_run_dread", lambda ctx, f: _fake_expert("dread", 5))
    monkeypatch.setattr(atm, "_run_mitigations", lambda ctx, f: _fake_expert("mitigations"))
    monkeypatch.setattr(atm, "_run_test_cases", lambda ctx, f: _fake_expert("test_cases"))
    monkeypatch.setattr(atm, "_run_teammate", lambda ctx, f: _fake_expert("teammate", 1))
    monkeypatch.setattr(atm, "_run_rebuttal", lambda ctx, f: _fake_expert("rebuttal", 2))

    result = _orchestrate(mock_settings, captured.append)
    assert result["agentic"] is True
    assert result["decider"] == "ai"
    assert _LINEAR_KEYS.issubset(result.keys())
    final_sections = {a["section"] for a in captured[-1]["agents"]}
    assert final_sections == {s.value for s in atm.SECTION_ORDER}
