"""The one entry point the page submits to the job runner: ``run_threat_model``.

It runs the workflow for one request and closes the progress record of a run
that fails. The job runner does the queueing, and the page stores the result.

Typical use from the page::

    runner.submit(
        lambda progress: run_threat_model(
            request, llm=llm, settings=settings, progress=progress,
            nvd_api_key=nvd_key, otx_api_key=otx_key,
        ),
        kind="threat_model",
    )
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, Protocol

from aegisshield.config import Settings
from aegisshield.core.text import clip_words, sanitize_user_markdown
from aegisshield.jobs.runner import plain_error
from aegisshield.llm.base import LLMClient, LLMImageError
from aegisshield.pipeline.agentic_threat_model import (
    SECTION_RESULT_KEYS,
    opening_record,
    orchestrate_threat_model,
)
from aegisshield.pipeline.atlas_service import ATLAS_RESULT_KEY
from aegisshield.pipeline.schemas import ThreatModelRequest
from aegisshield.pipeline.threat_model_service import analyze_architecture_image
from aegisshield.pipeline.workflow_service import RunCancelled, run_threat_model_workflow
from aegisshield.safeguards import JOB_ERRORS, REPORT_KEY, Safeguards, Source
from aegisshield.services.output_checks import REVIEW_FLAGS_KEY, review_flags

logger = logging.getLogger(__name__)

# The result keys of every run, in job result order.
CORE_RESULT_KEYS = (
    "threat_model",
    "improvement_suggestions",
    "threat_model_markdown",
    "mitre_attack_markdown",
    "nvd_vulnerabilities_markdown",
    "otx_data_markdown",
    "attack_tree_code",
    "mitre_data",
)

# Result keys for the add-ons the linear run did itself (only when they ran).
ADDON_RESULT_KEYS = (
    "mitigations_markdown",
    "dread_assessment",
    "dread_assessment_markdown",
    "test_cases_markdown",
)

# The heading the wizard puts before the reviewed diagram description.
DIAGRAM_HEADING = "Architecture Diagram Analysis:"

# Extra keys of an agentic run. They are copied into the job result too;
# copying only the core keys would lose them.
AGENTIC_RESULT_KEYS = ("agentic", "lead_plan", "decider", "section_deciders", *SECTION_RESULT_KEYS)

_TITLE_SNIPPET_CHARS = 120


class ProgressSink(Protocol):
    """What the run needs from the job's progress sink (``jobs.runner.ProgressSink``)."""

    def set(self, record: dict[str, Any]) -> None:
        """Replace the job's progress record."""
        ...

    def cancelled(self) -> bool:
        """True when the job should stop."""
        ...


class _LastRecord:
    """Passes records to the sink and remembers the last one sent."""

    def __init__(self, sink: ProgressSink) -> None:
        self._sink = sink
        self.last: dict[str, Any] | None = None

    def __call__(self, record: dict[str, Any]) -> None:
        self.last = record
        self._sink.set(record)


def use_agentic(request: ThreatModelRequest, settings: Settings) -> bool:
    """True when the run takes the agentic path (the setting or the request asks)."""
    return settings.agentic or request.agentic


def prepare_description(
    request: ThreatModelRequest,
    *,
    llm: LLMClient,
    settings: Settings,
    safeguards: Safeguards | None = None,
) -> str:
    """The visitor's description, sanitized and screened, with the diagram
    description appended.

    The text before the diagram heading is what the visitor typed (input
    rails); the text after it was written by a model from an uploaded image
    (retrieved-content rails). Text filled in from a saved record is
    screened as imported content instead of typed text, and text that a
    lookup hand-off added to is screened as both. An image in the request is
    described by the architect model; a bad image raises ``ValidationError``
    before any other work starts. A model that takes no images
    (``settings.model_vision`` False) is not sent the image, and an image
    the provider refuses (``LLMImageError``) is left out; either way the run
    goes on without the diagram text.
    """
    sg = safeguards if safeguards is not None else Safeguards.from_settings(settings)
    description = sanitize_user_markdown(request.app_description)
    typed, heading, diagram = description.partition(DIAGRAM_HEADING)
    if request.prefilled_from == "record":
        typed = sg.screen(Source.IMPORT, typed.strip())
    else:
        typed = sg.screen(Source.DESCRIPTION, typed.strip())
        if request.prefilled_from == "lookup":
            typed = sg.screen(Source.LOOKUP, typed)
    parts = [typed]
    if heading:
        parts.append(f"{DIAGRAM_HEADING}\n{sg.screen(Source.DIAGRAM, diagram.strip())}")
    if request.architecture_image_base64 and settings.model_vision is not False:
        # A model whose provider says it takes no images is not sent one; a
        # provider that refuses the image leaves the run without the diagram
        # text, as the wizard does.
        try:
            analysis = analyze_architecture_image(
                llm, settings.architect_model, request.architecture_image_base64,
                settings=settings, safeguards=sg,
            )
        except LLMImageError:
            logger.info("diagram not described: the provider refused the image")
        else:
            parts.append(f"{DIAGRAM_HEADING}\n{analysis}")
    return "\n\n".join(p for p in parts if p).strip()


def assemble_result(workflow_result: Mapping[str, Any], *, agentic: bool) -> dict[str, Any]:
    """The job result: the core keys, patterns, and whatever extras the path produced."""
    result: dict[str, Any] = {key: workflow_result[key] for key in CORE_RESULT_KEYS}
    result["detected_patterns"] = workflow_result.get("detected_patterns", [])
    result["pattern_source"] = workflow_result.get("pattern_source", "none")
    result["improvement_suggestions_markdown"] = workflow_result.get(
        "improvement_suggestions_markdown", "No improvement suggestions provided."
    )
    if REPORT_KEY in workflow_result:
        result[REPORT_KEY] = workflow_result[REPORT_KEY]
    # An AI system's ATLAS mapping, on either path; absent for any other system.
    if ATLAS_RESULT_KEY in workflow_result:
        result[ATLAS_RESULT_KEY] = workflow_result[ATLAS_RESULT_KEY]
    extras = AGENTIC_RESULT_KEYS if agentic else ADDON_RESULT_KEYS
    for key in extras:
        if key in workflow_result:
            result[key] = workflow_result[key]
    return result


def close_failed_progress(progress: object, reason: str) -> dict[str, Any] | None:
    """The final live record for a failed run, or None to leave it alone.

    Only the linear path's record (``office: true``) changes: the stage that
    was working becomes ``error`` with the plain reason and the live panel is
    cleared. The agentic roster is left as it was.
    """
    if not isinstance(progress, dict) or not progress.get("office"):
        return None
    stages = progress.get("stages")
    record = dict(progress)
    if isinstance(stages, list):
        record["stages"] = [
            {**s, "status": "error", "reason": reason}
            if isinstance(s, dict) and s.get("status") == "working"
            else s
            for s in stages
        ]
    deck = progress.get("deck")
    if isinstance(deck, dict):
        record["deck"] = {**deck, "live": None}
    return record


def complete_progress(progress: object) -> dict[str, Any]:
    """The final live record for a finished run .

    A linear (``office``) or agentic record is kept with ``current`` set to
    "complete", so a page that reattaches reads the run as finished; any
    other record becomes the plain complete shape.
    """
    if isinstance(progress, dict) and (progress.get("agentic") or progress.get("office")):
        return {**progress, "current": "complete"}
    return {"step": 1, "total": 1, "current": "complete"}


def run_threat_model(
    request: ThreatModelRequest,
    *,
    llm: LLMClient,
    settings: Settings,
    progress: ProgressSink,
    nvd_api_key: str | None = None,
    otx_api_key: str | None = None,
    safeguards: Safeguards | None = None,
) -> dict[str, Any]:
    """Run one threat model and return the job result.

    The linear path runs unless ``settings.agentic`` or ``request.agentic``
    is set. Progress records go to ``progress.set``; ``progress.cancelled()``
    is checked between stages and a cancelled run raises ``RunCancelled``.
    When the run finishes, the last record is written again with ``current``
    set to "complete" (``complete_progress``). When the run fails, the last
    linear progress record is closed (its
    working stage reads ``error`` with the visitor's sentence) before the
    exception is raised again for the runner. The keys are used for the
    lookups only and are kept nowhere.

    ``safeguards`` None builds them from ``settings``; every model call goes
    through ``safeguards.wrap`` and the record is the result's
    ``REPORT_KEY``.
    """
    sg = safeguards if safeguards is not None else Safeguards.from_settings(settings)
    llm = sg.wrap(llm)
    record = _LastRecord(progress)
    agentic = use_agentic(request, settings)
    try:
        if progress.cancelled():
            raise RunCancelled()
        if agentic:
            # The live view starts before the safeguards' first check, which
            # builds the rails (and loads NeMo the first time in a process).
            record(opening_record(nvd_api_key=nvd_api_key, otx_api_key=otx_api_key,
                                  app_details=request.app_profile.model_dump(), settings=settings))
        description = prepare_description(request, llm=llm, settings=settings, safeguards=sg)
        profile = screen_profile(sg, request.app_profile.model_dump())
        if agentic:
            workflow_result = orchestrate_threat_model(
                llm=llm,
                settings=settings,
                nvd_api_key=nvd_api_key,
                otx_api_key=otx_api_key,
                app_details=profile,
                app_description=description,
                on_progress=record,
                cancelled=progress.cancelled,
                safeguards=sg,
            )
        else:
            workflow_result = run_threat_model_workflow(
                llm=llm,
                settings=settings,
                nvd_api_key=nvd_api_key,
                otx_api_key=otx_api_key,
                app_details=profile,
                app_description=description,
                on_progress=record,
                addons=list(request.addons) if request.addons is not None else None,
                cancelled=progress.cancelled,
                safeguards=sg,
            )
    except RunCancelled:
        raise
    # Any failure closes the live record, then goes to the runner unchanged.
    except Exception as exc:
        closed = close_failed_progress(record.last, plain_error(exc, JOB_ERRORS))
        if closed is not None:
            progress.set(closed)
        raise
    result = assemble_result(workflow_result, agentic=agentic)
    result[REVIEW_FLAGS_KEY] = review_flags(result, profile=profile, addons=request.addons)
    result[REPORT_KEY] = sg.report()
    progress.set(complete_progress(record.last))
    return result


def screen_profile(safeguards: Safeguards, profile: dict[str, Any]) -> dict[str, Any]:
    """The profile with every value screened as ``Source.PROFILE``.

    The NVD CPE prefixes (``selected_technologies`` values) are left as they
    are: they come from the app's own technology catalog and go to the NVD
    query, not into a prompt.
    """
    screened = {k: v for k, v in profile.items() if k != "selected_technologies"}
    screened = safeguards.screen_values(Source.PROFILE, screened)
    techs = profile.get("selected_technologies") or {}
    screened["selected_technologies"] = {
        safeguards.screen(Source.PROFILE, name): cpe for name, cpe in techs.items()
    }
    return screened


def threat_model_title(profile: Mapping[str, Any], description: str) -> str:
    """A short title for a saved threat model: app type, sector, first line."""
    app_type = str(profile.get("app_type") or "Threat model")
    industry = str(profile.get("industry_sector") or "")
    snippet = description.strip().splitlines()[0] if description.strip() else ""
    base = f"{app_type}: {industry}".strip(": ") if industry else app_type
    if snippet:
        clipped = clip_words(snippet, _TITLE_SNIPPET_CHARS)
        return f"{base}. {clipped}" if base else clipped
    return base or "Threat model"


__all__ = [
    "ADDON_RESULT_KEYS",
    "AGENTIC_RESULT_KEYS",
    "CORE_RESULT_KEYS",
    "DIAGRAM_HEADING",
    "ProgressSink",
    "RunCancelled",
    "assemble_result",
    "close_failed_progress",
    "complete_progress",
    "prepare_description",
    "run_threat_model",
    "screen_profile",
    "threat_model_title",
    "use_agentic",
]
