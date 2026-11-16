"""Start, watch, cancel, and settle one threat-model run for the wizard.

How the state is held:

- The runner holds the job; ``state.start_job`` keeps its id in the session.
  The id is also put in the page URL (``?run=``) while the job runs, so a
  browser reload, which starts a new Streamlit session, can find it again.
- ``state.threat_model_run()`` holds the run: a short display id for the
  deck, whether it took the agentic path, the settled deck record once the
  job ended (``final``), and the saved record's id (``record_id``).
- When the job ends, :func:`poll` settles it once: a finished result is saved
  to the workspace, the run is marked saved, and the job is discarded from
  the runner, with no Streamlit element drawn in between (a rerun can only
  interrupt at an element call). Later reruns read ``final``.

The visitor's API keys are read once in :func:`start_run` and captured in the
job closure only.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Mapping
from typing import Any

import pydantic

from aegisshield.core.errors import AegisError, ValidationError
from aegisshield.jobs import JobSnapshot, JobStatus, get_runner
from aegisshield.llm import get_llm
from aegisshield.llm.providers import answered_by
from aegisshield.pipeline.run import (
    close_failed_progress,
    run_threat_model,
    threat_model_title,
    use_agentic,
)
from aegisshield.pipeline.schemas import AppProfile, ThreatModelRequest
from aegisshield.storage import RecordKind
from aegisshield.ui import state
from aegisshield.ui.components.deck import render_deck
from aegisshield.ui.components.office import render_office
from aegisshield.ui.options import technology_choices

__all__ = [
    "CANCELLED_REASON",
    "DECK_KEY",
    "LOST_SENTENCE",
    "MOCK_CALL_DELAY_SECONDS",
    "MOCK_CHUNK_DELAY_SECONDS",
    "OFFICE_KEY",
    "build_profile",
    "build_request",
    "cancel_run",
    "description_for_run",
    "is_agentic_record",
    "is_running",
    "poll",
    "reattach_from_url",
    "render_live",
    "start_run",
    "uses_office",
]

logger = logging.getLogger(__name__)

KIND = state.THREAT_MODEL_JOB
DECK_KEY = "tm_deck"
OFFICE_KEY = "tm_office"
# A short pause per streamed mock chunk, so a run in mock mode takes about
# twelve seconds and the deck's animation plays.
MOCK_CHUNK_DELAY_SECONDS = 0.06
# The agentic path calls the model without streaming, so in mock mode each
# of its calls pauses instead (14 calls, about eleven seconds), and the
# office plays. Linear runs stream and do not take this pause.
MOCK_CALL_DELAY_SECONDS = 0.8
CANCELLED_REASON = "The run was cancelled"
LOST_SENTENCE = "This run could not be found. It may have ended a while ago. Start a new run."
DIAGRAM_HEADING = "Architecture Diagram Analysis:"


# ------------------------------------------------------------- the request


def build_profile(draft: Mapping[str, Any]) -> dict[str, Any]:
    """The request's ``app_profile`` from the wizard's draft."""
    chosen: Mapping[str, str] = draft.get("technologies") or {}
    techs: dict[str, str] = {}
    versions: dict[str, str] = {}
    for choice in technology_choices():
        if choice.key in chosen:
            techs[choice.name] = choice.cpe
            versions[choice.name] = (chosen[choice.key] or "").strip() or "*"
    return {
        "app_type": draft.get("app_type") or "",
        "industry_sector": draft.get("industry_sector") or "",
        "sensitive_data": draft.get("sensitive_data") or "",
        "internet_facing": draft.get("internet_facing") or "",
        "num_employees": draft.get("num_employees") or "",
        "compliance_requirements": list(draft.get("compliance_requirements") or []),
        "technical_ability": draft.get("technical_ability") or "",
        "authentication": list(draft.get("authentication") or []),
        "selected_technologies": techs,
        "selected_versions": versions,
        "app_pattern": list(draft.get("app_pattern") or []),
    }


def description_for_run(draft: Mapping[str, Any]) -> str:
    """The description, with the reviewed diagram description appended when
    the visitor chose to use it (the same heading the pipeline uses)."""
    text = str(draft.get("description") or "").strip()
    diagram = str(draft.get("diagram_text") or "").strip()
    if diagram and draft.get("diagram_use", True):
        text = f"{text}\n\n{DIAGRAM_HEADING}\n{diagram}".strip()
    return text


REQUEST_INVALID = "Some of the input is too long or not one of the choices offered. Check it and try again."


def build_request(draft: Mapping[str, Any], *, agentic: bool) -> ThreatModelRequest:
    """The pipeline request. The diagram was already described and reviewed,
    so the image itself is not sent again. Raises ``ValidationError``
    (``REQUEST_INVALID``) for anything the request refuses, such as text
    over its limit, that the wizard's own checks did not catch."""
    addons = [name for name in ("mitigations", "dread", "test_cases")
              if (draft.get("addons") or {}).get(name, True)]
    try:
        return ThreatModelRequest(
            app_profile=AppProfile(**build_profile(draft)),
            app_description=description_for_run(draft),
            architecture_image_base64=None,
            addons=addons,
            agentic=agentic,
            prefilled_from=draft.get("prefilled_from") if draft.get("prefilled_from") in (
                "lookup", "record") else None,
        )
    except pydantic.ValidationError as exc:
        logger.info("threat model request refused fields=%s",
                    sorted({".".join(map(str, e["loc"])) for e in exc.errors()}))
        raise ValidationError(REQUEST_INVALID) from None


# ------------------------------------------------------------- the job


def start_run(draft: Mapping[str, Any]) -> None:
    """Submit the run. Raises ``AegisError`` (no key, server at its cap, a
    run already going) with a sentence for the visitor."""
    settings = state.get_settings()
    request = build_request(draft, agentic=state.agentic_enabled())
    agentic = use_agentic(request, settings)
    llm = get_llm(settings, state.credential(settings.provider),
                  mock_chunk_delay_seconds=MOCK_CHUNK_DELAY_SECONDS,
                  mock_call_delay_seconds=MOCK_CALL_DELAY_SECONDS if agentic else 0.0)
    nvd_key = state.get_api_key(state.ApiKey.NVD) or None
    otx_key = state.get_api_key(state.ApiKey.OTX) or None
    profile = request.app_profile.model_dump()
    description = request.app_description
    model = answered_by(settings)

    def job(progress: Any) -> dict[str, Any]:
        result = run_threat_model(request, llm=llm, settings=settings, progress=progress,
                                  nvd_api_key=nvd_key, otx_api_key=otx_key)
        # The stored record's shape (workspace PAYLOAD_KEYS): the result plus
        # the profile and description, so a reattached page can save it.
        return {**result, "profile": profile, "description": description, "model": model}

    job_id = state.start_job(KIND, job)
    state.set_threat_model_run({
        "run_id": secrets.token_hex(6),
        "agentic": agentic,
        "final": None,
        "record_id": None,
        "duration": None,
    })
    state.set_run_param(job_id)


def reattach_from_url() -> bool:
    """After a reload, pick the running job named in the URL back up."""
    job_id = state.requested_run_id()
    if not job_id or state.threat_model_run() is not None:
        return False
    if not state.adopt_job(KIND, job_id):
        state.set_run_param(None)
        return False
    snap = get_runner().snapshot(job_id)
    state.set_threat_model_run({
        "run_id": secrets.token_hex(6),
        "agentic": bool(snap and is_agentic_record(snap.progress)),
        "final": None,
        "record_id": None,
        "duration": None,
    })
    return True


def cancel_run() -> None:
    """Ask the running job to stop; the next poll shows it as cancelled."""
    state.cancel_job(KIND)


def is_running() -> bool:
    """True while this session's run has not settled."""
    run = state.threat_model_run()
    return run is not None and run.get("final") is None


def is_agentic_record(progress: object) -> bool:
    """True for the agentic path's frame (the office draws it, not the deck)."""
    return isinstance(progress, dict) and progress.get("agentic") is True


def _settle(run: dict[str, Any], snap: JobSnapshot | None) -> None:
    """Close the run once: final record, save a result, discard the job.

    No Streamlit element is drawn here, so a rerun cannot cut it in half.
    """
    if snap is None:
        run["final"] = {"id": run["run_id"], "status": "failed", "error": LOST_SENTENCE,
                        "progress": None}
    else:
        progress: Any = snap.progress
        if snap.status in (JobStatus.FAILED, JobStatus.CANCELLED):
            reason = snap.error if snap.status is JobStatus.FAILED else CANCELLED_REASON
            progress = close_failed_progress(progress, reason or CANCELLED_REASON) or progress
        run["final"] = {"id": run["run_id"], "status": snap.status.value,
                        "error": snap.error, "progress": progress}
        if snap.started_at and snap.finished_at:
            run["duration"] = max(0.0, snap.finished_at - snap.started_at)
        if snap.status is JobStatus.COMPLETE and run.get("record_id") is None and snap.result:
            payload = dict(snap.result)
            title = threat_model_title(payload.get("profile") or {}, str(payload.get("description") or ""))
            workspace = state.get_workspace()
            record = workspace.add(RecordKind.THREAT_MODELS, title, payload)
            state.save_workspace(workspace)
            run["record_id"] = record.id
    state.set_threat_model_run(run)
    state.forget_job(KIND)
    state.set_run_param(None)


def poll() -> dict[str, Any] | None:
    """The deck record for this session's run, settling it if the job ended.

    Returns ``{"id", "status", "error", "progress"}``, or None before any run.
    """
    run = state.threat_model_run()
    if run is None:
        return None
    if run.get("final") is not None:
        return run["final"]
    job_id = state.active_job_id(KIND)
    snap = get_runner().snapshot(job_id) if job_id else None
    if snap is None or snap.done:
        _settle(run, snap)
        return run["final"]
    return {"id": run["run_id"], "status": snap.status.value, "error": None,
            "progress": snap.progress or None}


# ------------------------------------------------------------- drawing


def uses_office(record: Mapping[str, Any] | None, *, agentic: bool) -> bool:
    """Which live view draws this run: True for the office, False for the deck.

    Routing is on the record: ``progress.agentic is True`` goes to the office,
    any other progress record to the deck. Before the run's first record
    (no progress yet, or no run at all) the run's mode decides, which is the
    same answer, since every record of one run takes the same path. So the
    view is chosen once per run and never flips between records.
    """
    progress = (record or {}).get("progress")
    if isinstance(progress, dict):
        return progress.get("agentic") is True
    return agentic


def render_live(record: dict[str, Any] | None, *, agentic: bool) -> None:
    """Draw the run at the page's one live position: the office for an
    agentic run, the deck for a linear one.

    The two calls sit at this one position, each with its own fixed key
    (a shared key puts both roots in one container and breaks both views).
    """
    if uses_office(record, agentic=agentic):
        render_office(record, key=OFFICE_KEY)
    else:
        render_deck(record, key=DECK_KEY)


def describe_error(exc: AegisError) -> str:
    """The sentence for a run that could not start."""
    return str(exc) or "The run could not start. Try again."

