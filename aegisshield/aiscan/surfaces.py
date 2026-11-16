"""The workflow surfaces a scan may target: the allowlist, fixed in code.

Each surface turns one prompt into one answer through a real entry point of
the app, building its request the way the page would. These are the only
targets a scan has; there is no way to name another, and none of them
contacts anything but the model client it is given.

- ``visitor_workflow``: the visitor's own AI workflow, the one surface the
  scan page offers. The visitor gives a system prompt, optional sample
  context, and a model from the app's fixed list (``WorkflowParams``). Each
  prompt garak sends becomes the user turn of one ``LLMClient.chat_text``
  call, after the sample context under a plain label, the way retrieved
  content would arrive. With the safeguards on, garak's prompt passes the
  input rails as typed text (``Source.WORKFLOW_MESSAGE``), the sample
  context passes the retrieved-content rails (``Source.SAMPLE_CONTEXT``),
  and the answer passes the output rails, which check it against the
  visitor's system prompt for a leak. The system prompt itself is the
  visitor's own instruction and is not screened. The client is the app's
  own: its host is fixed in code, and nothing the visitor gives can change
  it.

The other three are developer regression checks of this app's own steps,
refused by the scan service unless a caller asks for them explicitly
(``tools/garak_offon.py`` and the tests do):

- ``threat_description``: the prompt is the application description of a
  threat model. The answer is what the threat-writing (STRIDE) step returns,
  as its markdown table. The vulnerability lookups the full run makes first
  are left out (they need outside sources and add no model call).
- ``retrieved_content``: the prompt is placed where capture-derived text goes
  in the packet capture analysis (the protocol hierarchy lines of the parsed
  summary, one line per prompt line, a long line split across lines at the
  limit tshark output gets). The answer is the analysis. A prompt that needs
  more lines than the analysis prompt includes is recorded as a failure, not
  sent cut short.
- ``policy_profile``: the prompt is the regulatory notes, a free-text field of
  the organization profile, for the access control policy. The answer is the
  policy draft.

Input the app itself refuses (too short, too long, or otherwise invalid for
that step) is reported to the shim as a refusal (``SurfaceRefused``).
"""

from __future__ import annotations

import threading
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pydantic

from aegisshield.aiscan.shim import Surface, SurfaceRefused
from aegisshield.config import Settings
from aegisshield.core.errors import ValidationError
from aegisshield.llm.base import DEFAULT_TEXT_MAX_TOKENS, LLMClient, OnText
from aegisshield.llm.mock import MockLLM
from aegisshield.llm.providers import valid_model_id
from aegisshield.llm.susceptible import SusceptibleLLM
from aegisshield.pipeline.formatting_service import threat_model_to_markdown
from aegisshield.pipeline.run import prepare_description
from aegisshield.pipeline.schemas import ThreatModelRequest
from aegisshield.pipeline.threat_model_service import (
    create_threat_model_prompt,
    generate_threat_model,
)
from aegisshield.safeguards import (
    BLOCKED_INJECTION,
    BLOCKED_LEAK,
    CheckStatus,
    RailSet,
    Safeguards,
    SafeguardsStopped,
    Source,
)
from aegisshield.services import pcap_service, policy_service
from aegisshield.services.org_profile import OrgProfile

# The fixed application profile the threat-description surface uses.
THREAT_PROFILE: dict[str, object] = {
    "app_type": "Web application",
    "authentication": ["OAuth2"],
    "internet_facing": "Yes",
    "industry_sector": "Retail",
    "sensitive_data": "High",
    "technical_ability": "Medium",
}
# The fixed organization the policy surface drafts for.
POLICY_KEY = "access_control_policy"
POLICY_ORG = {"legal_name": "Example Retail Co", "industry": "Retail", "compliance_drivers": ["PCI DSS"]}
_MAX_CAPTURE_LINES = 60


WORKFLOW_SURFACE_ID = "visitor_workflow"
# The longest system prompt and sample context a visitor may give. Each
# scan request sends both, so they bound what one scan spends of the
# visitor's model calls, and they keep the stored record small.
MAX_SYSTEM_PROMPT_CHARS = 6_000
MAX_SAMPLE_CONTEXT_CHARS = 4_000
# The plain label the sample context goes under in the user turn.
SAMPLE_CONTEXT_LABEL = "Context:"
# The output cap of each workflow call, in tokens (the provider counts a
# reasoning model's reasoning in it too). garak's detectors read short
# answers, and the cap bounds what one scan can spend of the visitor's key.
WORKFLOW_MAX_TOKENS = 1024

ERROR_NO_SYSTEM_PROMPT = "Enter the system prompt of the workflow to test."
ERROR_SYSTEM_PROMPT_LONG = f"The system prompt is longer than {MAX_SYSTEM_PROMPT_CHARS:,} characters."
ERROR_SAMPLE_CONTEXT_LONG = f"The sample context is longer than {MAX_SAMPLE_CONTEXT_CHARS:,} characters."
ERROR_CONTROL_CHARACTERS = ("The system prompt and sample context may hold line breaks and tabs, but no other "
                            "control characters.")
ERROR_WORKFLOW_MODEL = "The model is not one chosen in Settings from the provider's list."
ERROR_NO_WORKFLOW = "A workflow scan needs a system prompt and a model."


def _has_control(text: str) -> bool:
    """True when ``text`` holds a control character other than newline and tab,
    or a lone surrogate (which cannot be stored or sent)."""
    return any(c not in "\n\t" and unicodedata.category(c) in ("Cc", "Cs") for c in text)


@dataclass(frozen=True)
class WorkflowParams:
    """What a visitor gives for a scan of their own workflow. Build it with
    ``check_workflow``, which every path into a scan calls."""

    system_prompt: str
    sample_context: str
    model: str


def check_workflow(*, system_prompt: object, sample_context: object = "", model: object) -> WorkflowParams:
    """The visitor's workflow inputs, checked; ``ValidationError`` with a sentence otherwise.

    The system prompt is required and at most ``MAX_SYSTEM_PROMPT_CHARS``;
    the sample context is optional (only whitespace counts as none) and at
    most ``MAX_SAMPLE_CONTEXT_CHARS``; neither may hold a control character
    other than newline and tab. The model is the one the visitor chose in
    Settings from their provider's own list, so here it must be a model id
    of the shape the provider registry allows (``providers.valid_model_id``),
    or empty when no model answers but the simulated stand-in. A real-model
    scan also needs it non-empty (``service.ScanRequest.build``).
    """
    if not isinstance(system_prompt, str) or not system_prompt.strip():
        raise ValidationError(ERROR_NO_SYSTEM_PROMPT)
    if len(system_prompt) > MAX_SYSTEM_PROMPT_CHARS:
        raise ValidationError(ERROR_SYSTEM_PROMPT_LONG)
    context = sample_context if isinstance(sample_context, str) else None
    if sample_context is not None and context is None:
        raise ValidationError(ERROR_NO_WORKFLOW)
    context = context or ""
    if len(context) > MAX_SAMPLE_CONTEXT_CHARS:
        raise ValidationError(ERROR_SAMPLE_CONTEXT_LONG)
    if _has_control(system_prompt) or _has_control(context):
        raise ValidationError(ERROR_CONTROL_CHARACTERS)
    if not isinstance(model, str) or (model and not valid_model_id(model)):
        raise ValidationError(ERROR_WORKFLOW_MODEL)
    return WorkflowParams(system_prompt=system_prompt, sample_context=context if context.strip() else "",
                          model=model)


@dataclass(frozen=True)
class SurfaceSpec:
    """One approved target: its id, plain words for the page, and its builder.

    ``build(llm, settings, guards, workflow)``: ``workflow`` is the visitor's
    ``WorkflowParams`` for ``visitor_workflow`` and None for the others.
    """

    id: str
    title: str
    description: str
    build: Callable[..., Surface]


# A step the safeguards stopped because they found something is a refusal.
# A step stopped because a check could not run (strict mode) was not
# refused by anything: it is a failure, and stays one.
_REFUSING_STOPS = frozenset({BLOCKED_LEAK, BLOCKED_INJECTION})


def _refuse_invalid(call: Callable[[str], str]) -> Surface:
    """``call`` with the app's own input refusals, and safeguards that
    blocked the step, reported as refusals."""

    def surface(prompt: str) -> str:
        try:
            return call(prompt)
        except (ValidationError, pydantic.ValidationError) as exc:
            raise SurfaceRefused from exc
        except SafeguardsStopped as exc:
            if str(exc) in _REFUSING_STOPS:
                raise SurfaceRefused from exc
            raise

    return surface


def _threat_description(llm: LLMClient, settings: Settings, scan_guards: ScanSafeguards,
                        workflow: WorkflowParams | None = None) -> Surface:
    def call(prompt: str) -> str:
        guards = scan_guards.fresh()
        request = ThreatModelRequest.model_validate({"app_profile": THREAT_PROFILE, "app_description": prompt})
        description = prepare_description(request, llm=llm, settings=settings, safeguards=guards)
        profile = request.app_profile.model_dump()
        threat_prompt = create_threat_model_prompt(
            app_type=str(profile["app_type"]),
            authentication=list(profile.get("authentication") or []),
            internet_facing=str(profile["internet_facing"]),
            industry_sector=str(profile["industry_sector"]),
            sensitive_data=str(profile["sensitive_data"]),
            app_input=description,
            nvd_vulnerabilities={},
            otx_data="",
            technical_ability=str(profile.get("technical_ability") or "Medium"),
            app_details=profile,
        )
        threats, suggestions = generate_threat_model(guards.wrap(llm), settings.architect_model, threat_prompt)
        return threat_model_to_markdown(threats, suggestions)

    return _refuse_invalid(call)


class PromptDoesNotFit(Exception):  # noqa: N818 - a reason, raised to the shim as a failure
    """The prompt is longer than the place it goes can hold whole. The scan
    records the step as failed rather than test a prompt that was cut."""


def capture_summary(prompt: str) -> dict[str, object]:
    """A parsed capture summary whose protocol hierarchy lines carry ``prompt``.

    Raises ``PromptDoesNotFit`` when it needs more lines than the analysis
    prompt includes.
    """
    lines: list[str] = []
    for line in prompt.splitlines() or [""]:
        while True:
            lines.append(line[: pcap_service.MAX_STAT_LINE_CHARS])
            line = line[pcap_service.MAX_STAT_LINE_CHARS:]
            if not line:
                break
    if len(lines) > _MAX_CAPTURE_LINES:
        raise PromptDoesNotFit
    return {
        "filesize_bytes": 4096,
        "protocol_hierarchy": lines,
        "conversations": [],
        "sip": {"aggregations": {}},
        "dns_queries": [],
        "tls_sni": [],
        "http_requests": [],
        "truncated": [],
    }


def _retrieved_content(llm: LLMClient, settings: Settings, scan_guards: ScanSafeguards,
                       workflow: WorkflowParams | None = None) -> Surface:
    def call(prompt: str) -> str:
        summary = capture_summary(prompt)
        return pcap_service.analyze_summary(summary, llm=llm, settings=settings, safeguards=scan_guards.fresh())

    return _refuse_invalid(call)


def _policy_profile(llm: LLMClient, settings: Settings, scan_guards: ScanSafeguards,
                    workflow: WorkflowParams | None = None) -> Surface:
    def call(prompt: str) -> str:
        profile = OrgProfile.from_dict({**POLICY_ORG, "regulatory_notes": prompt})
        result = policy_service.generate_policy(POLICY_KEY, profile, llm=llm, settings=settings,
                                                safeguards=scan_guards.fresh())
        return str(result.get("body_markdown") or "")

    return _refuse_invalid(call)


class WorkflowCallFailed(Exception):  # noqa: N818 - a reason, raised to the shim as a failure
    """The visitor's workflow call failed. The message is fixed, so nothing
    the visitor gave (or a model error quoting it) reaches the shim's log."""


def workflow_user_turn(prompt: str, sample_context: str) -> str:
    """The user turn of one call: the sample context under its label, then the prompt."""
    if not sample_context:
        return prompt
    return f"{SAMPLE_CONTEXT_LABEL}\n{sample_context}\n\n{prompt}"


def _visitor_workflow(llm: LLMClient, settings: Settings, scan_guards: ScanSafeguards,
                      workflow: WorkflowParams | None = None) -> Surface:
    if workflow is None:
        raise ValidationError(ERROR_NO_WORKFLOW)

    # The sample context is the same for every call, so it is screened once
    # per scan and its check reported apart from garak's prompts. A check
    # that stops the scan (strict mode, not checked) fails every call.
    context, stopped = "", ""
    try:
        context = scan_guards.screen_context(workflow.sample_context)
    except SafeguardsStopped as exc:
        stopped = str(exc)

    def call(prompt: str) -> str:
        if stopped:
            raise SafeguardsStopped(stopped)
        guards = scan_guards.fresh()
        try:
            message = guards.screen(Source.WORKFLOW_MESSAGE, prompt)
            return guards.wrap(llm).chat_text(system=workflow.system_prompt,
                                              user=workflow_user_turn(message, context), model=workflow.model,
                                              max_tokens=WORKFLOW_MAX_TOKENS)
        except (SurfaceRefused, SafeguardsStopped, ValidationError):
            raise
        # The model client, a rail, or the stand-in can fail in any way; the
        # shim records a failure. The message is replaced because an error
        # could quote the visitor's text, which must never reach a log.
        except Exception as exc:
            raise WorkflowCallFailed(f"The workflow call failed ({type(exc).__name__}).") from None

    return _refuse_invalid(call)


WORKFLOW_SURFACE = SurfaceSpec(
    WORKFLOW_SURFACE_ID, "Your AI workflow",
    "Your system prompt and model, through this app's model client: each garak prompt is the user's "
    "message, after your sample context.", _visitor_workflow)

# The developer regression surfaces (this app's own steps). The scan page
# does not offer them, and the scan service refuses them unless asked for
# them explicitly.
SURFACES: tuple[SurfaceSpec, ...] = (
    SurfaceSpec("threat_description", "Threat model: application description",
                "The prompt is the application description; the answer is the STRIDE threats the "
                "threat-writing step returns.", _threat_description),
    SurfaceSpec("retrieved_content", "PCAP analysis: capture-derived text",
                "The prompt is placed in the parsed capture summary, where text from network traffic "
                "goes; the answer is the analysis.", _retrieved_content),
    SurfaceSpec("policy_profile", "Policy draft: organization profile notes",
                "The prompt is the regulatory notes of the organization profile; the answer is the "
                "access control policy draft.", _policy_profile),
)
_BY_ID = {spec.id: spec for spec in (WORKFLOW_SURFACE, *SURFACES)}

ERROR_UNKNOWN_SURFACE = "That workflow surface is not one a scan may target."


def surface_spec(surface_id: object) -> SurfaceSpec:
    """The approved surface ``surface_id``; ``ValidationError`` for anything else."""
    if not isinstance(surface_id, str) or surface_id not in _BY_ID:
        raise ValidationError(ERROR_UNKNOWN_SURFACE)
    return _BY_ID[surface_id]


SIMULATED_NAME = "simulated stand-in"


WORKFLOW_STAND_IN_ANSWER = ("This is the simulated stand-in's ordinary answer to the message. It is not a real "
                            "model's answer.")


class _WorkflowStandInBase(MockLLM):
    """The stand-in's ordinary text answer for a visitor's workflow.

    ``MockLLM`` picks a canned answer from words in the system prompt (one
    that mentions "policy" gets a policy), which means nothing for a
    visitor's own prompt; this gives one fixed answer instead. The visitor's
    system prompt still reaches ``SusceptibleLLM``, which copies it into the
    answer when a message asks for its instructions, and gives the first
    key-shaped string in it when asked for a secret.
    """

    def chat_text(self, *, system: str, user: str, model: str, max_tokens: int = DEFAULT_TEXT_MAX_TOKENS,
                  on_text: OnText | None = None) -> str:
        """The fixed ordinary answer."""
        return WORKFLOW_STAND_IN_ANSWER


def simulated_llm(surface_id: str | None = None) -> LLMClient:
    """The simulated stand-in model, which follows injected instructions on
    purpose (``aegisshield.llm.susceptible``). For ``visitor_workflow`` its
    ordinary answer is a fixed sentence (``_WorkflowStandInBase``)."""
    if surface_id == WORKFLOW_SURFACE_ID:
        return SusceptibleLLM(_WorkflowStandInBase())
    return SusceptibleLLM()


class ScanSafeguards:
    """The safeguards of one scan: a fresh ``Safeguards`` for every surface call.

    The app builds one ``Safeguards`` per run, and it carries what it saw in
    earlier text (the instructions it flagged) into later answer checks. One
    object across a whole scan would let one prompt's instruction withhold a
    later, unrelated answer, which is not how a deployed run behaves. So each
    call gets its own, and the scan's summary adds their counts.

    ``enabled`` follows the deployment: safeguards chosen on run only where
    the operator has them on (``AEGIS_SAFEGUARDS``).
    """

    def __init__(self, settings: Settings, enabled: bool) -> None:
        self._settings = settings
        self.enabled = bool(enabled and settings.safeguards)
        self._lock = threading.Lock()
        self._used: list[Safeguards] = []
        self._context: Safeguards | None = None

    def fresh(self) -> Safeguards:
        """A new ``Safeguards`` for one call, remembered for the summary.

        Every surface passes it to every entry point it calls: an entry point
        given None builds the deployment's own, so a surface that left one
        out would check even in a scan with safeguards off.
        """
        guards = Safeguards.from_settings(self._settings, enabled=self.enabled)
        with self._lock:
            self._used.append(guards)
        return guards

    def screen_context(self, text: str) -> str:
        """``text`` screened once as the scan's sample context, on its own
        ``Safeguards``, so the summary reports it apart from the calls."""
        guards = Safeguards.from_settings(self._settings, enabled=self.enabled)
        with self._lock:
            self._context = guards
        return guards.screen(Source.SAMPLE_CONTEXT, text)

    def summary(self) -> dict[str, Any]:
        """What the safeguards did during the scan, as counts only.

        The reports' checks carry excerpts of the text they matched; none are
        kept. ``answers_changed`` and ``answers_withheld`` count model answers
        the output rails modified or blocked; ``inputs_changed`` and
        ``inputs_withheld`` count text the input and retrieved-content rails
        modified or blocked before it reached a prompt, per call (garak's
        prompts). ``sample_context`` is the status of the one check of the
        workflow's sample context, or "none" when no check ran (no context,
        or safeguards off); its check counts in ``checks`` and
        ``not_checked`` only. ``status`` is "on" only when every call's
        safeguards were on.
        """
        with self._lock:
            reports = [g.report() for g in self._used]
            context = self._context.report() if self._context is not None else None
        if not reports:
            reports = [Safeguards.from_settings(self._settings, enabled=self.enabled).report()]
        context_checks = list((context or {}).get("checks") or [])
        by_set: dict[str, dict[str, int]] = {r.value: {c.value: 0 for c in CheckStatus} for r in RailSet}
        for report in reports:
            for check in report.get("checks") or []:
                rail_set, status = check.get("rail_set"), check.get("status")
                if rail_set in by_set and status in by_set[rail_set]:
                    by_set[rail_set][status] += 1
        context_status = str(context_checks[0].get("status")) if context_checks else "none"
        context_missed = sum(1 for c in context_checks if c.get("status") == CheckStatus.NOT_CHECKED.value)
        statuses = {str(r.get("status")) for r in (*reports, *([context] if context_checks else []))}
        status = statuses.pop() if len(statuses) == 1 else "mixed"
        inputs = [by_set[RailSet.INPUT.value], by_set[RailSet.RETRIEVED.value]]
        output = by_set[RailSet.OUTPUT.value]
        return {
            "status": status,
            "enabled": self.enabled,
            "strict": reports[0].get("strict"),
            "engine_version": reports[0].get("engine_version"),
            "calls": len(self._used),
            "checks": sum(sum(counts.values()) for counts in by_set.values()) + len(context_checks),
            "not_checked": sum(counts[CheckStatus.NOT_CHECKED.value] for counts in by_set.values())
            + context_missed,
            "answers_changed": output[CheckStatus.MODIFIED.value],
            "answers_withheld": output[CheckStatus.BLOCKED.value],
            "inputs_changed": sum(i[CheckStatus.MODIFIED.value] for i in inputs),
            "inputs_withheld": sum(i[CheckStatus.BLOCKED.value] for i in inputs),
            "sample_context": context_status,
        }


def make_safeguards(settings: Settings, enabled: bool) -> ScanSafeguards:
    """The safeguards for one scan: as deployed when ``enabled``, else off."""
    return ScanSafeguards(settings, enabled)


def safeguards_summary(guards: ScanSafeguards) -> dict[str, Any]:
    """What the safeguards did during a scan, as counts only (``ScanSafeguards.summary``)."""
    return guards.summary()
