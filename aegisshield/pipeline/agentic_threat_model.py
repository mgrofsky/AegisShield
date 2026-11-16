"""Agentic threat-model orchestrator: a Lead plans, specialists write sections.

A "Threat Model Lead" plans the engagement, then the orchestrator dispatches
one specialist per section. The specialists are not new prompts: each section
calls the per-section service (``threat_model_service``, ``mitre_service``,
``dread_service``, ``mitigations_service``, ``test_cases_service``) as its
worker, with the Lead's focus for that section and the organization context
from the request (``sector_context``) appended. Two review sections follow,
each one model call: the Teammate Reviewer and the Rebuttal Analyst.

Sections run in ``SECTION_ORDER``: STRIDE, MITRE, DREAD, mitigations, test
cases, then Teammate, then Rebuttal. The Teammate therefore reviews the
finished draft (threats, techniques, DREAD rows) after mitigations and test
cases are written; its flags are advisory and change no earlier section. The
Rebuttal Analyst then challenges the highest DREAD rows.

The Lead is an AI decider with a deterministic rule-based fallback on any
failure, and the result records which one decided (``decider``). STRIDE and
MITRE are required; any other section that fails degrades to a ``fallback``
expert and the run continues.

``run_section`` returns a ``SectionResult`` whose ``experts`` is a list (one
expert per section today), so a section can later fan out to several experts
without changing the orchestrator.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from aegisshield.config import Settings
from aegisshield.llm.base import LLMClient
from aegisshield.pipeline.ai_system import is_ai_system
from aegisshield.pipeline.atlas_service import ATLAS_RESULT_KEY, atlas_step, mitigation_reference
from aegisshield.pipeline.attack_tree_service import create_attack_tree_prompt, get_attack_tree
from aegisshield.pipeline.catalog_service import catalog_for_app_type
from aegisshield.pipeline.dread_service import dread_json_to_markdown, generate_dread_assessment
from aegisshield.pipeline.formatting_service import (
    assign_threat_ids,
    mitre_data_to_markdown,
    nvd_to_markdown,
    threat_model_to_markdown,
)
from aegisshield.pipeline.mitigations_service import generate_mitigations
from aegisshield.pipeline.mitre_service import process_mitre_attack_data
from aegisshield.pipeline.sector_context import compact_context, context_lines, focus_block
from aegisshield.pipeline.test_cases_service import generate_test_cases
from aegisshield.pipeline.threat_model_service import (
    create_threat_model_prompt,
    generate_threat_model,
)
from aegisshield.pipeline.workflow_service import (
    EnrichmentBundle,
    RunCancelled,
    gather_enrichment,
    lookup_off_reason,
)
from aegisshield.safeguards import REPORT_KEY, Safeguards, SafeguardsStopped

logger = logging.getLogger(__name__)

# The Lead plan's answer is small, but the provider counts a model's reasoning
# tokens toward this cap, so a cap of 1024 could cut the answer short and
# silently drop the run to the rule plan. Leave room for both.
LEAD_MAX_TOKENS = 4096
# How many of the highest DREAD rows the Rebuttal Analyst challenges.
REBUTTAL_TOP_ROWS = 5


# Section registry -----------------------------------------------------------


class Section(Enum):
    """The sections a Lead can plan."""

    STRIDE = "STRIDE"
    MITRE = "MITRE"
    DREAD = "DREAD"
    MITIGATIONS = "MITIGATIONS"
    TEST_CASES = "TEST_CASES"
    TEAMMATE = "TEAMMATE"
    REBUTTAL = "REBUTTAL"


# Fixed canonical order used by the rule-based default plan and as the
# tie-break when the Lead's ordering is incomplete. STRIDE must precede MITRE
# (MITRE consumes the STRIDE threat list); the optional sections follow, and
# the two review sections come last because they read the finished draft.
SECTION_ORDER: list[Section] = [
    Section.STRIDE,
    Section.MITRE,
    Section.DREAD,
    Section.MITIGATIONS,
    Section.TEST_CASES,
    Section.TEAMMATE,
    Section.REBUTTAL,
]

# STRIDE and MITRE produce the keys every result needs, so they can never be
# skipped. The remaining sections are add-ons the Lead may skip for an app.
REQUIRED_SECTIONS: set[Section] = {Section.STRIDE, Section.MITRE}


@dataclass(frozen=True)
class AgentRole:
    """A section specialist: which section it owns and how it presents."""

    section: Section
    agent_id: str
    role: str
    default_focus: str


AGENT_ROLES: dict[Section, AgentRole] = {
    Section.STRIDE: AgentRole(
        section=Section.STRIDE,
        agent_id="stride",
        role="STRIDE Analyst",
        default_focus=(
            "Follow the sensitive data through every trust boundary: sign-in and "
            "session handling, public APIs and object-level access checks, "
            "third-party integrations, and administrative paths."
        ),
    ),
    Section.MITRE: AgentRole(
        section=Section.MITRE,
        agent_id="mitre",
        role="MITRE ATT&CK Mapper",
        default_focus=(
            "Map techniques against privileged access, credential theft, "
            "exploitation of internet-facing services, ransomware and availability "
            "impact, and abuse of trusted third parties."
        ),
    ),
    Section.DREAD: AgentRole(
        section=Section.DREAD,
        agent_id="dread",
        role="DREAD Risk Scorer",
        default_focus=(
            "Weight Damage and Affected Users by the sensitivity of the data and "
            "the business impact of downtime; outages of core services drive high "
            "Damage and Affected Users."
        ),
    ),
    Section.MITIGATIONS: AgentRole(
        section=Section.MITIGATIONS,
        agent_id="mitigations",
        role="Mitigations Engineer",
        default_focus=(
            "Favor controls that map to the selected compliance requirements, if "
            "any: encryption in transit and at rest, audit logging, least-privilege "
            "access with an emergency access procedure, and network segmentation."
        ),
    ),
    Section.TEST_CASES: AgentRole(
        section=Section.TEST_CASES,
        agent_id="test_cases",
        role="Validation Engineer",
        default_focus=(
            "Exercise confidentiality of the sensitive data, audit logging of "
            "privileged and emergency access, API token scope enforcement, and "
            "segmentation controls."
        ),
    ),
    Section.TEAMMATE: AgentRole(
        section=Section.TEAMMATE,
        agent_id="teammate",
        role="Teammate Reviewer",
        default_focus=(
            "Review the finished draft (threats, techniques, and DREAD rows) for "
            "relevance and false positives; flag anything that does not fit the "
            "application's stated scope so it can be dropped."
        ),
    ),
    Section.REBUTTAL: AgentRole(
        section=Section.REBUTTAL,
        agent_id="rebuttal",
        role="Rebuttal Analyst",
        default_focus=(
            "Negative validation: challenge each high-scoring DREAD row with "
            "exactly one counterexample drawn from the actual scope, then "
            "downgrade or explain. No new attack surface is introduced."
        ),
    ),
}


# Plan and result structures --------------------------------------------------


@dataclass
class PlannedSection:
    """One section in the Lead's plan."""

    section: Section
    focus: str
    skip: bool = False


@dataclass
class LeadPlan:
    """The Lead's engagement plan: which sections run, in what order, focus."""

    sections: list[PlannedSection]
    decider: str  # "ai" | "rule"
    rationale: str = ""

    def active(self) -> list[PlannedSection]:
        """The sections that will run, in order."""
        return [p for p in self.sections if not p.skip]

    def to_dict(self) -> dict[str, Any]:
        """The plan as JSON-safe data for the result."""
        return {
            "decider": self.decider,
            "rationale": self.rationale,
            "sections": [
                {"section": p.section.value, "focus": p.focus, "skip": p.skip}
                for p in self.sections
            ],
        }


@dataclass
class ExpertResult:
    """One specialist's output for a section."""

    agent_id: str
    role: str
    status: str  # done | fallback | error
    output: dict[str, Any] = field(default_factory=dict)
    findings: int | None = None
    activity: str = ""


@dataclass
class SectionResult:
    """A section's experts (one today) and the plan's decider."""

    section: Section
    experts: list[ExpertResult]
    decider: str

    @property
    def primary(self) -> ExpertResult:
        """The lead expert for the section."""
        return self.experts[0]


# Lead plan (AI decider with a rule fallback) ---------------------------------


def _default_plan(decider: str, rationale: str = "") -> LeadPlan:
    """Rule-based default: every section, canonical order, default focus."""
    return LeadPlan(
        sections=[
            PlannedSection(section=s, focus=AGENT_ROLES[s].default_focus, skip=False)
            for s in SECTION_ORDER
        ],
        decider=decider,
        rationale=rationale,
    )


def _normalize_plan(raw_sections: list[dict[str, Any]]) -> LeadPlan:
    """Turn a raw plan into a LeadPlan with all invariants enforced.

    STRIDE and MITRE always run and STRIDE precedes MITRE; every known
    section appears exactly once (missing ones are appended in canonical
    order); unknown section names are ignored.
    """
    by_section: dict[Section, PlannedSection] = {}
    ordered: list[Section] = []
    for item in raw_sections:
        if not isinstance(item, dict):
            continue
        name = str(item.get("section", "")).strip().upper()
        try:
            section = Section(name)
        except ValueError:
            continue
        if section in by_section:
            continue
        focus = str(item.get("focus") or "").strip() or AGENT_ROLES[section].default_focus
        skip = item.get("skip", False) is True
        if section in REQUIRED_SECTIONS:
            skip = False
        by_section[section] = PlannedSection(section=section, focus=focus, skip=skip)
        ordered.append(section)

    for section in SECTION_ORDER:
        if section not in by_section:
            by_section[section] = PlannedSection(
                section=section, focus=AGENT_ROLES[section].default_focus, skip=False
            )
            ordered.append(section)

    if ordered.index(Section.STRIDE) > ordered.index(Section.MITRE):
        ordered.remove(Section.STRIDE)
        ordered.insert(ordered.index(Section.MITRE), Section.STRIDE)

    return LeadPlan(sections=[by_section[s] for s in ordered], decider="ai")


LEAD_SYSTEM_PROMPT = (
    "You are the Threat Model Lead for a security engagement. Plan which "
    "threat-model sections to run, in what order, with a one-sentence focus per "
    "section grounded in the application and the organization context given. "
    "STRIDE and MITRE are required and must run (STRIDE before MITRE). DREAD, "
    "MITIGATIONS, TEST_CASES, TEAMMATE, and REBUTTAL are optional; mark skip true "
    "only when a section adds no value for this app. Do not use em dashes. "
    "Respond with ONLY a JSON object: "
    '{"plan": [{"section": "STRIDE", "focus": "...", "skip": false}], '
    '"rationale": "<25 words max>"}.'
)


def lead_plan(
    *,
    llm: LLMClient,
    model: str,
    app_details: Mapping[str, Any],
    app_description: str,
    enrichment: EnrichmentBundle,
) -> LeadPlan:
    """Ask the architect model to plan the engagement; fall back to the rule plan.

    On any failure (an unreadable answer, no valid sections, an error from
    the model) the deterministic ``_default_plan`` is returned.
    """
    snapshot = {
        "app_type": app_details.get("app_type", ""),
        "organization_context": context_lines(app_details),
        "detected_patterns": enrichment.detected_patterns[:10],
        "has_nvd": bool(enrichment.nvd_vulnerabilities),
        "has_otx": bool(enrichment.otx_vulnerabilities),
        "description_excerpt": (app_description or "")[:600],
    }
    section_menu = [
        {
            "section": role.section.value,
            "role": role.role,
            "required": role.section in REQUIRED_SECTIONS,
        }
        for role in AGENT_ROLES.values()
    ]
    user_prompt = (
        f"App under review: {json.dumps(snapshot)}\n"
        f"Available sections: {json.dumps(section_menu)}"
    )
    try:
        result = llm.chat_json(
            system=LEAD_SYSTEM_PROMPT,
            user=user_prompt,
            model=model,
            max_tokens=LEAD_MAX_TOKENS,
        )
    # Any failure of the planning call falls back to the rule plan, as in the
    # source; the run itself is not affected.
    except Exception as exc:
        logger.info("agentic_lead_plan_fallback kind=%s", type(exc).__name__)
        return _default_plan("rule")

    raw_plan = result.get("plan")
    if not isinstance(raw_plan, list) or not raw_plan:
        logger.debug("agentic_lead_plan: no usable plan in response, rule fallback")
        return _default_plan("rule")
    known = {s.value for s in Section}
    if not any(
        isinstance(it, dict) and str(it.get("section", "")).strip().upper() in known
        for it in raw_plan
    ):
        logger.debug("agentic_lead_plan: no valid section names, rule fallback")
        return _default_plan("rule")

    plan = _normalize_plan(raw_plan)
    plan.rationale = str(result.get("rationale") or "")[:300]
    logger.info("agentic_lead_plan: AI plan with %d active sections", len(plan.active()))
    return plan


# Section workers -------------------------------------------------------------


@dataclass
class SectionContext:
    """Everything a section worker needs, plus the accumulating outputs."""

    llm: LLMClient
    app_details: dict[str, Any]
    app_description: str
    enrichment: EnrichmentBundle
    architect_model: str
    worker_model: str
    outputs: dict[str, Any]  # mutated as sections complete; threaded forward


def section_focus(ctx: SectionContext, focus: str) -> str:
    """The Lead's focus for a section plus the organization context, one paragraph."""
    parts = [focus.strip()] if focus and focus.strip() else []
    context = compact_context(ctx.app_details)
    if context:
        parts.append(context)
    return " ".join(parts)


def _expert(section: Section, output: dict[str, Any], findings: int | None) -> ExpertResult:
    role = AGENT_ROLES[section]
    return ExpertResult(
        agent_id=role.agent_id,
        role=role.role,
        status="done",
        output=output,
        findings=findings,
        activity=role.role,
    )


def _run_stride(ctx: SectionContext, focus: str) -> ExpertResult:
    app = ctx.app_details
    prompt = create_threat_model_prompt(
        app_type=app["app_type"],
        authentication=app.get("authentication", []),
        internet_facing=app["internet_facing"],
        industry_sector=app["industry_sector"],
        sensitive_data=app["sensitive_data"],
        app_input=ctx.app_description,
        nvd_vulnerabilities=ctx.enrichment.nvd_vulnerabilities,
        otx_data=ctx.enrichment.otx_vulnerabilities,
        technical_ability=app.get("technical_ability", "Medium"),
        extra_cards=ctx.enrichment.extra_cards,
        app_details=app,
    )
    # The STRIDE prompt already carries the full organization context.
    prompt = f"{prompt}{focus_block(focus)}"
    threat_model, suggestions = generate_threat_model(ctx.llm, ctx.architect_model, prompt)
    assign_threat_ids(threat_model)
    output = {
        "threat_model": threat_model,
        "improvement_suggestions": suggestions,
        "improvement_suggestions_markdown": (
            "\n".join(f"- {s.strip()}" for s in suggestions)
            or "No improvement suggestions provided."
        ),
        "threat_model_markdown": threat_model_to_markdown(threat_model, []),
    }
    return _expert(Section.STRIDE, output, len(threat_model))


def _run_mitre(ctx: SectionContext, focus: str) -> ExpertResult:
    """The ATT&CK mapping, then for an AI system the ATLAS pick (one more call)."""
    app = ctx.app_details
    patterns = ctx.enrichment.detected_patterns
    enriched_details = dict(app)
    enriched_details["app_input"] = ctx.app_description
    threats = ctx.outputs.get("threat_model", [])
    mitre_data = process_mitre_attack_data(
        threats,
        enriched_details,
        ctx.llm,
        ctx.worker_model,
        catalog=catalog_for_app_type(app["app_type"], patterns),
        focus=focus,
    )
    technique_count = sum(len(e.get("mitre_techniques", []) or []) for e in mitre_data)
    output: dict[str, Any] = {
        "mitre_data": mitre_data,
        "mitre_attack_markdown": mitre_data_to_markdown(mitre_data),
    }
    expert = _expert(Section.MITRE, output, technique_count)
    if is_ai_system(app["app_type"], patterns):
        output[ATLAS_RESULT_KEY] = atlas_step(threats, app, patterns, ctx.llm, ctx.worker_model, focus)
        expert.activity = AI_MITRE_ROLE
    return expert


def _run_dread(ctx: SectionContext, focus: str) -> ExpertResult:
    assessment = generate_dread_assessment(
        ctx.llm,
        ctx.worker_model,
        ctx.outputs.get("threat_model_markdown", ""),
        ctx.outputs.get("mitre_attack_markdown", ""),
        ctx.outputs.get("nvd_vulnerabilities_markdown", ""),
        focus=section_focus(ctx, focus),
    )
    rows = assessment.get("Risk Assessment", [])
    output = {
        "dread_assessment": assessment,
        "dread_assessment_markdown": dread_json_to_markdown(assessment),
    }
    return _expert(Section.DREAD, output, len(rows) if isinstance(rows, list) else None)


def _run_mitigations(ctx: SectionContext, focus: str) -> ExpertResult:
    markdown = generate_mitigations(
        ctx.llm,
        ctx.worker_model,
        ctx.outputs.get("threat_model_markdown", ""),
        ctx.outputs.get("mitre_attack_markdown", ""),
        ctx.outputs.get("nvd_vulnerabilities_markdown", ""),
        focus=section_focus(ctx, focus),
        atlas_reference=mitigation_reference(ctx.outputs.get(ATLAS_RESULT_KEY)) or None,
    )
    return _expert(Section.MITIGATIONS, {"mitigations_markdown": markdown}, None)


def _run_test_cases(ctx: SectionContext, focus: str) -> ExpertResult:
    markdown = generate_test_cases(
        ctx.llm,
        ctx.worker_model,
        ctx.outputs.get("threat_model_markdown", ""),
        focus=section_focus(ctx, focus),
    )
    return _expert(Section.TEST_CASES, {"test_cases_markdown": markdown}, None)


def _dread_rows(outputs: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = outputs.get("dread_assessment")
    rows = raw.get("Risk Assessment", []) if isinstance(raw, dict) else []
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


_DREAD_AXES = (
    "Damage Potential",
    "Reproducibility",
    "Exploitability",
    "Affected Users",
    "Discoverability",
)


def dread_risk(row: Mapping[str, Any]) -> float:
    """A DREAD row's risk: the mean of its five axes (a missing or bad axis counts 0).

    The rows carry only the five axes, never a "Risk Score", so a sort on
    "Risk Score" would leave them in model order. This is the same arithmetic
    as ``dread_json_to_markdown``.
    """
    total = 0.0
    for axis in _DREAD_AXES:
        value = row.get(axis)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            total += float(value)
    return total / len(_DREAD_AXES)


def _review_call(ctx: SectionContext, system: str, user: str) -> dict[str, Any]:
    parsed = ctx.llm.chat_json(system=system, user=user, model=ctx.worker_model)
    return parsed if isinstance(parsed, dict) else {}


def _run_teammate(ctx: SectionContext, focus: str) -> ExpertResult:
    """Teammate Reviewer: a relevance and false-positive check on the finished draft.

    Runs after test cases, so it reads every earlier output (threats, MITRE
    mappings, DREAD rows). Its flags are advisory and change no earlier
    section. A review pass only, defensive.
    """
    system = (
        "You are the Teammate Reviewer on a threat-modeling engagement.\n"
        "Review the drafted threat model and DREAD assessment below. Flag rows that:\n"
        "  1. do not fit the application's stated scope and organization context, or\n"
        "  2. read like false positives given the actual application scope.\n"
        'Return ONLY a JSON object: {"flags": [{"threat": "...", "reason": "..."}], '
        '"notes": "..."}. No prose, no code fences.'
    )
    user = (
        f"Application: {ctx.app_description}\n"
        f"Stated scope: {json.dumps(ctx.app_details, default=str)}\n\n"
        f"Threats:\n{json.dumps(ctx.outputs.get('threat_model', []), default=str)}\n\n"
        f"DREAD rows:\n{json.dumps(_dread_rows(ctx.outputs), default=str)}"
        f"{focus_block(section_focus(ctx, focus))}"
    )
    parsed = _review_call(ctx, system, user)
    flags = parsed.get("flags", [])
    return _expert(
        Section.TEAMMATE,
        {"teammate_review": parsed},
        len(flags) if isinstance(flags, list) else None,
    )


def _run_rebuttal(ctx: SectionContext, focus: str) -> ExpertResult:
    """Rebuttal Analyst: negative validation on the highest DREAD rows.

    For each of the top rows (by ``dread_risk``) the model gives exactly one
    counterexample grounded in the actual scope and either downgrades the
    score or explains why it stands. Validation only; no new attack surface.
    """
    top = sorted(_dread_rows(ctx.outputs), key=dread_risk, reverse=True)[:REBUTTAL_TOP_ROWS]
    system = (
        "You are the Rebuttal Analyst on a threat-modeling engagement.\n"
        "For each of the top DREAD rows below, produce exactly ONE concrete "
        "counterexample drawn from the real application scope that would reduce "
        "the score, then state the adjusted score or explain why it stands.\n"
        'Return ONLY a JSON object: {"rebuttals": [{"threat": "...", '
        '"counterexample": "...", "adjusted": "...", "reason": "..."}]}.\n'
        "No prose, no code fences."
    )
    user = (
        f"Application: {ctx.app_description}\n"
        f"Stated scope: {json.dumps(ctx.app_details, default=str)}\n\n"
        f"Top DREAD rows:\n{json.dumps(top, default=str)}"
        f"{focus_block(section_focus(ctx, focus))}"
    )
    parsed = _review_call(ctx, system, user)
    rebuttals = parsed.get("rebuttals", [])
    return _expert(
        Section.REBUTTAL,
        {"rebuttal_review": parsed},
        len(rebuttals) if isinstance(rebuttals, list) else None,
    )


# Workers by section, looked up by name at call time so tests can replace one.
_SECTION_WORKERS: dict[Section, str] = {
    Section.STRIDE: "_run_stride",
    Section.MITRE: "_run_mitre",
    Section.DREAD: "_run_dread",
    Section.MITIGATIONS: "_run_mitigations",
    Section.TEST_CASES: "_run_test_cases",
    Section.TEAMMATE: "_run_teammate",
    Section.REBUTTAL: "_run_rebuttal",
}


def run_section(section: Section, plan: LeadPlan, *, ctx: SectionContext) -> SectionResult:
    """Dispatch one section to its specialist with the Lead's focus for it.

    A required section that raises propagates (the run cannot produce a
    threat model without it); an optional section that raises degrades to a
    ``fallback`` expert with empty output so the run still completes.
    """
    role = AGENT_ROLES[section]
    focus = next((p.focus for p in plan.sections if p.section == section), role.default_focus)
    worker: Callable[[SectionContext, str], ExpertResult] = globals()[_SECTION_WORKERS[section]]
    try:
        expert = worker(ctx, focus)
    # An optional section may fail in any way (model, parse); the run goes on
    # without it. A required one is raised again.
    except Exception as exc:
        if section in REQUIRED_SECTIONS:
            logger.warning(
                "agentic_section_failed_required section=%s kind=%s",
                section.value,
                type(exc).__name__,
            )
            raise
        logger.warning(
            "agentic_section_degraded section=%s kind=%s", section.value, type(exc).__name__
        )
        expert = ExpertResult(
            agent_id=role.agent_id,
            role=role.role,
            status="fallback",
            output={},
            findings=None,
            activity=(f"{role.role} answer withheld by the safeguards; section skipped"
                      if isinstance(exc, SafeguardsStopped)
                      else f"{role.role} unavailable; section skipped"),
        )
    return SectionResult(section=section, experts=[expert], decider=plan.decider)


# Roster and progress ---------------------------------------------------------

_ACTIVITY: dict[Section, str] = {
    Section.STRIDE: "Mapping tampering and disclosure paths across the application's data flows",
    Section.MITRE: "Aligning threats to ATT&CK techniques for the likely attack paths",
    Section.DREAD: "Scoring business impact and data exposure",
    Section.MITIGATIONS: "Drafting safeguards for the highest risks",
    Section.TEST_CASES: "Writing validation tests for the key controls",
    Section.TEAMMATE: "Reviewing draft threats and DREAD rows for false positives",
    Section.REBUTTAL: "Negative-validating the top DREAD rows against real scope",
}


# An AI system's MITRE specialist also picks ATLAS techniques (one more call).
AI_MITRE_ACTIVITY = "Aligning threats to ATT&CK techniques, then to ATLAS techniques in one request"
AI_MITRE_ROLE = "MITRE ATT&CK and ATLAS Mapper"


def _activity_for(section: Section, ai_system: bool = False) -> str:
    """Short working line for the live roster."""
    if ai_system and section is Section.MITRE:
        return AI_MITRE_ACTIVITY
    return _ACTIVITY[section]


def _build_roster(plan: LeadPlan, agent_state: dict[str, dict[str, Any]],
                  ai_system: bool = False) -> list[dict[str, Any]]:
    """The JSON-safe agent roster from the current per-agent state."""
    roster: list[dict[str, Any]] = []
    for planned in plan.active():
        role = AGENT_ROLES[planned.section]
        state = agent_state.get(role.agent_id, {})
        roster.append(
            {
                "id": role.agent_id,
                "role": role.role,
                "section": planned.section.value,
                "status": state.get("status", "queued"),
                "activity": state.get("activity", _activity_for(planned.section, ai_system)),
                "started_at": state.get("started_at"),
                "finished_at": state.get("finished_at"),
                "findings": state.get("findings"),
            }
        )
    return roster


def _planning_roster() -> list[dict[str, Any]]:
    """All specialists, queued, before the Lead plan exists.

    Lets the page reveal the roster the instant the run starts (during
    enrichment and planning) instead of after the first post-plan write.
    """
    return [
        {
            "id": AGENT_ROLES[section].agent_id,
            "role": AGENT_ROLES[section].role,
            "section": section.value,
            "status": "queued",
            "activity": _activity_for(section),
            "started_at": None,
            "finished_at": None,
            "findings": None,
        }
        for section in SECTION_ORDER
    ]


def gathering_note(
    *,
    nvd_api_key: str | None,
    otx_api_key: str | None,
    app_details: Mapping[str, Any],
    settings: Settings,
) -> str:
    """The Lead's first note, naming only the lookups this run will make:
    a source with a key that is not switched off (``lookup_off_reason``).

    It does not name CISA KEV or EPSS, because this path never looks them up.
    """
    sources: list[str] = []
    if (nvd_api_key and app_details.get("selected_technologies")
            and lookup_off_reason("nvd", settings) is None):
        sources.append("NVD")
    if otx_api_key and lookup_off_reason("otx", settings) is None:
        sources.append("OTX")
    if not sources:
        return "Planning the run"
    return f"Gathering threat intel ({', '.join(sources)}) and planning the run"


ProgressCallback = Callable[[dict[str, Any]], None]

# Result keys a section may add beyond the linear shape.
SECTION_RESULT_KEYS = (
    "dread_assessment",
    "dread_assessment_markdown",
    "mitigations_markdown",
    "test_cases_markdown",
    "teammate_review",
    "rebuttal_review",
)


# Orchestrator ----------------------------------------------------------------


def opening_record(
    *,
    nvd_api_key: str | None,
    otx_api_key: str | None,
    app_details: Mapping[str, Any],
    settings: Settings,
) -> dict[str, Any]:
    """The first progress record of an agentic run: the roster, the Lead gathering.

    ``run.run_threat_model`` writes it before the safeguards' first check,
    so the live view starts at once; the orchestrator writes it again.
    """
    return {
        "step": 0,
        "total": len(SECTION_ORDER),
        "current": "Threat Model Lead gathering threat intelligence",
        "agentic": True,
        "lead": {
            "status": "working",
            "note": gathering_note(
                nvd_api_key=nvd_api_key, otx_api_key=otx_api_key, app_details=app_details,
                settings=settings,
            ),
        },
        "agents": _planning_roster(),
    }


def orchestrate_threat_model(
    *,
    llm: LLMClient,
    settings: Settings,
    nvd_api_key: str | None,
    otx_api_key: str | None,
    app_details: dict[str, Any],
    app_description: str,
    on_progress: ProgressCallback | None = None,
    cancelled: Callable[[], bool] | None = None,
    safeguards: Safeguards | None = None,
) -> dict[str, Any]:
    """Agentic run: the Lead plans, the orchestrator dispatches sections.

    Returns the linear path's result keys plus ``agentic: True``,
    ``lead_plan`` (the plan dict), ``decider``, ``section_deciders``, and any
    section outputs in ``SECTION_RESULT_KEYS``. ``cancelled`` is checked
    before each section (see ``RunCancelled``).

    Every model call goes through ``safeguards.wrap`` (None builds them from
    ``settings``) and the record is the result's ``REPORT_KEY``.
    """
    sg = safeguards if safeguards is not None else Safeguards.from_settings(settings)
    llm = sg.wrap(llm)
    architect_model = settings.architect_model
    worker_model = settings.worker_model

    def _emit(progress: dict[str, Any]) -> None:
        if on_progress is None:
            return
        try:
            on_progress(progress)
        # Progress is best-effort: a failing write must never fail the run.
        except Exception as exc:
            logger.debug("agentic progress callback failed kind=%s", type(exc).__name__)

    def _check_cancelled() -> None:
        if cancelled is not None and cancelled():
            raise RunCancelled()

    # Reveal the roster at once: enrichment and the Lead plan run before the
    # first post-plan write and can take a while.
    _emit(opening_record(nvd_api_key=nvd_api_key, otx_api_key=otx_api_key,
                         app_details=app_details, settings=settings))

    enrichment = gather_enrichment(
        nvd_api_key=nvd_api_key,
        otx_api_key=otx_api_key,
        app_details=app_details,
        app_description=app_description,
        settings=settings,
        safeguards=sg,
    )
    _check_cancelled()

    plan = lead_plan(
        llm=llm,
        model=architect_model,
        app_details=app_details,
        app_description=app_description,
        enrichment=enrichment,
    )
    active = plan.active()
    total = len(active)
    agent_state: dict[str, dict[str, Any]] = {}
    ai_system = is_ai_system(app_details["app_type"], enrichment.detected_patterns)

    def _progress(step: int, current: str, lead_status: str, lead_note: str) -> dict[str, Any]:
        return {
            "step": step,
            "total": total,
            "current": current,
            "agentic": True,
            "lead": {"status": lead_status, "note": lead_note},
            "agents": _build_roster(plan, agent_state, ai_system),
        }

    _emit(
        _progress(
            0,
            "Threat Model Lead planning the engagement",
            "orchestrating",
            f"{total} specialists planned ({plan.decider} plan)",
        )
    )

    outputs: dict[str, Any] = {
        "nvd_vulnerabilities_markdown": nvd_to_markdown(enrichment.nvd_vulnerabilities),
        "otx_data_markdown": enrichment.otx_vulnerabilities,
        "detected_patterns": enrichment.detected_patterns,
        "pattern_source": enrichment.pattern_source,
    }
    ctx = SectionContext(
        llm=llm,
        app_details=app_details,
        app_description=app_description,
        enrichment=enrichment,
        architect_model=architect_model,
        worker_model=worker_model,
        outputs=outputs,
    )

    section_deciders: dict[str, str] = {}
    completed = 0
    for planned in active:
        _check_cancelled()
        section = planned.section
        role = AGENT_ROLES[section]
        agent_state[role.agent_id] = {
            "status": "working",
            "activity": _activity_for(section, ai_system),
            "started_at": time.time(),
            "finished_at": None,
            "findings": None,
        }
        _emit(_progress(completed, f"{role.role} working", "orchestrating", planned.focus))

        result = run_section(section, plan, ctx=ctx)
        expert = result.primary
        outputs.update(expert.output)
        section_deciders[section.value] = result.decider

        agent_state[role.agent_id].update(
            {
                "status": expert.status,
                "finished_at": time.time(),
                "findings": expert.findings,
                "activity": expert.activity or _activity_for(section, ai_system),
            }
        )
        completed += 1
        _emit(_progress(completed, f"{role.role} complete", "orchestrating", planned.focus))

    _check_cancelled()
    _emit(
        _progress(
            completed,
            "Synthesizing attack tree and report",
            "synthesizing",
            "Threat Model Lead assembling the final model",
        )
    )

    attack_tree_prompt = create_attack_tree_prompt(
        app_type=app_details["app_type"],
        authentication=app_details.get("authentication", []),
        internet_facing=app_details["internet_facing"],
        sensitive_data=app_details["sensitive_data"],
        mitre_data=outputs.get("mitre_data", []),
        nvd_vulnerabilities=enrichment.nvd_vulnerabilities,
        otx_vulnerabilities=enrichment.otx_vulnerabilities,
        app_input=app_description,
    )
    attack_tree_code = get_attack_tree(llm, architect_model, attack_tree_prompt)

    result_dict: dict[str, Any] = {
        "threat_model": outputs.get("threat_model", []),
        "improvement_suggestions": outputs.get("improvement_suggestions", []),
        "improvement_suggestions_markdown": outputs.get(
            "improvement_suggestions_markdown", "No improvement suggestions provided."
        ),
        "threat_model_markdown": outputs.get("threat_model_markdown", ""),
        "mitre_data": outputs.get("mitre_data", []),
        "mitre_attack_markdown": outputs.get("mitre_attack_markdown", ""),
        "nvd_vulnerabilities_markdown": outputs["nvd_vulnerabilities_markdown"],
        "otx_data_markdown": outputs["otx_data_markdown"],
        "attack_tree_code": attack_tree_code,
        "detected_patterns": outputs["detected_patterns"],
        "pattern_source": outputs["pattern_source"],
        "agentic": True,
        "lead_plan": plan.to_dict(),
        "decider": plan.decider,
        "section_deciders": section_deciders,
    }
    for key in (*SECTION_RESULT_KEYS, ATLAS_RESULT_KEY):
        if key in outputs:
            result_dict[key] = outputs[key]

    result_dict[REPORT_KEY] = sg.report()
    _emit(
        {
            "step": total,
            "total": total,
            "current": "complete",
            "agentic": True,
            "lead": {"status": "done", "note": "Threat model complete"},
            "agents": _build_roster(plan, agent_state, ai_system),
        }
    )
    return result_dict
