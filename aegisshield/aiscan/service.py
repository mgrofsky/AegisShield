"""Run one AI workflow scan and build its record.

``run_scan`` starts the shim around the scan's surface, runs garak against
it in a private temporary directory, reads the report, decides the status
from the evidence (``report.derive_status``), and returns the record to
store and garak's own files for a download in the same session.

The record holds the run settings, garak's counts per probe and detector,
each probe's state and taxonomy references (OWASP LLM and AVID tags from
garak's report, ATLAS techniques from ``taxonomy``), the attempts (capped in
number and length, with the caps recorded), and the shim's counts. For a
scan of the visitor's own workflow it also holds the system prompt, the
sample context, and the model, with key-shaped secrets redacted. None of
the visitor's text reaches garak's arguments, environment, or
configuration, or a log line. Every stored string passes the key
redaction (with the scan's token as an explicit secret). garak's
configuration dump is never stored, and the temporary directory is removed
however the scan ends.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from aegisshield.aiscan.availability import Availability
from aegisshield.aiscan.garak_run import GarakRun, ReportTail, run_garak
from aegisshield.aiscan.limits import (
    ERROR_KEYLESS,
    ScanLimits,
    check_budget,
    check_keyless,
    check_seed,
)
from aegisshield.aiscan.probes import check_probe_ids
from aegisshield.aiscan.report import (
    ParsedReport,
    RunFacts,
    ScanStatus,
    ScanVerdict,
    derive_status,
    parse_report,
)
from aegisshield.aiscan.shim import FixedAnswers, Shim, Surface
from aegisshield.aiscan.surfaces import (
    ERROR_WORKFLOW_MODEL,
    MAX_SAMPLE_CONTEXT_CHARS,
    MAX_SYSTEM_PROMPT_CHARS,
    WORKFLOW_SURFACE_ID,
    WorkflowParams,
    check_workflow,
)
from aegisshield.aiscan.taxonomy import atlas_record
from aegisshield.config import PROVIDER_NAMES
from aegisshield.core.errors import ValidationError
from aegisshield.core.text import clean_text, redact_keys

logger = logging.getLogger(__name__)

RECORD_VERSION = 1
MAX_STORED_ATTEMPTS = 100
MAX_ATTEMPTS_PER_PROBE = 20
MAX_STORED_TEXT_CHARS = 2_000
MAX_OUTPUTS_PER_ATTEMPT = 3
# The scan stops itself this long before the job runner's timeout would.
JOB_TIMEOUT_MARGIN_SECONDS = 60

MODEL_REAL = "real"
MODEL_SIMULATED = "simulated"
MODEL_MOCK = "mock"
MODEL_KINDS = frozenset({MODEL_REAL, MODEL_SIMULATED, MODEL_MOCK})

ERROR_UNAVAILABLE = "AI workflow scans are not available on this server."
ERROR_MODEL_KIND = "The model choice is not one this page offers."
ERROR_DEVELOPER_SURFACE = ("That workflow surface is a developer check of this app's own steps and is not "
                           "offered here.")
ERROR_NO_WORKFLOW = "A scan of your workflow needs its system prompt and model."
ERROR_NO_PROVIDER = "A scan with a real model needs the model provider chosen in Settings."
JOB_ERRORS = frozenset({ERROR_UNAVAILABLE, ERROR_MODEL_KIND, ERROR_KEYLESS, ERROR_DEVELOPER_SURFACE,
                        ERROR_NO_WORKFLOW, ERROR_NO_PROVIDER, ERROR_WORKFLOW_MODEL})

SIMULATED_LABEL = "simulated model, not a real model run"
CLEAN_COUNT_NOTE = (
    "A detector that found nothing is not evidence that the workflow resists an attack, "
    "only that these prompts did not succeed in this run."
)


class ProgressLike(Protocol):
    """The part of the job runner's ``ProgressSink`` this module uses."""

    def set(self, record: dict[str, Any]) -> None: ...

    def cancelled(self) -> bool: ...


@dataclass(frozen=True)
class ScanRequest:
    """What the visitor chose. Build it with ``ScanRequest.build``."""

    surface_id: str
    surface_title: str
    probe_ids: tuple[str, ...]
    limits: ScanLimits
    seed: int | None
    safeguards_on: bool
    model_kind: str
    model_name: str
    workflow: WorkflowParams | None = None
    developer: bool = False
    # The provider that answers a real-model scan ("" for the stand-in and
    # the mock); stored beside the model name.
    model_provider: str = ""

    @classmethod
    def build(cls, *, surface_id: str, surface_title: str, probe_ids: Sequence[object], limits: ScanLimits,
              seed: object = None, safeguards_on: bool = True, model_kind: str, model_name: str,
              workflow: Mapping[str, object] | None = None, developer: bool = False,
              model_provider: str = "") -> ScanRequest:
        """Check the target, the probes, the request budget, the seed, and the
        model kind, and, for a model that needs no key, the lower keyless
        maximums.

        ``visitor_workflow`` needs ``workflow`` (``system_prompt``,
        ``sample_context``, ``model``), checked by ``surfaces.check_workflow``;
        with the real model the model named there is the one called, through
        ``model_provider`` (one of ``config.PROVIDER_NAMES``), and both are
        required: they are the visitor's choice in Settings. Any other
        surface is a developer check, refused unless ``developer`` is True
        (the scan page never passes it).

        Raises ``ValidationError`` with a sentence for the visitor.
        """
        probes = check_probe_ids(probe_ids)
        check_budget(probes, limits)
        if model_kind not in MODEL_KINDS:
            raise ValidationError(ERROR_MODEL_KIND)
        if model_kind != MODEL_REAL:
            check_keyless(limits)
        params = None
        if surface_id == WORKFLOW_SURFACE_ID:
            if not isinstance(workflow, Mapping):
                raise ValidationError(ERROR_NO_WORKFLOW)
            params = check_workflow(system_prompt=workflow.get("system_prompt"),
                                    sample_context=workflow.get("sample_context", ""),
                                    model=workflow.get("model"))
            if model_kind == MODEL_REAL:
                model_name = params.model
        request = cls(surface_id=surface_id, surface_title=surface_title, probe_ids=probes, limits=limits,
                      seed=check_seed(seed), safeguards_on=bool(safeguards_on), model_kind=model_kind,
                      model_name=model_name, workflow=params, developer=bool(developer),
                      model_provider=model_provider if model_kind == MODEL_REAL else "")
        check_target(request)
        return request


def check_target(request: ScanRequest) -> WorkflowParams | None:
    """The request's target, checked again wherever a scan starts.

    ``visitor_workflow`` needs workflow inputs that pass
    ``surfaces.check_workflow`` and, with the real model, a model and one of
    the app's providers; every other surface needs ``developer``. Raises
    ``ValidationError``.
    """
    if request.surface_id != WORKFLOW_SURFACE_ID:
        if request.developer is not True:
            raise ValidationError(ERROR_DEVELOPER_SURFACE)
        return None
    params = request.workflow
    if not isinstance(params, WorkflowParams):
        raise ValidationError(ERROR_NO_WORKFLOW)
    checked = check_workflow(system_prompt=params.system_prompt, sample_context=params.sample_context,
                             model=params.model)
    if request.model_kind == MODEL_REAL:
        if not checked.model or request.model_name != checked.model:
            raise ValidationError(ERROR_WORKFLOW_MODEL)
        if request.model_provider not in PROVIDER_NAMES:
            raise ValidationError(ERROR_NO_PROVIDER)
    return checked


class _Progress:
    """Builds the live progress record from the shim and the report tail.

    The record holds only counts and probe ids from ``PROBES``, never a
    prompt or an answer.
    """

    def __init__(self, sink: ProgressLike | None, request: ScanRequest, planned: int) -> None:
        self._sink = sink
        self._lock = threading.Lock()
        self._record: dict[str, Any] = {
            "step": 0,
            "total": len(request.probe_ids),
            "current": "Starting garak",
            "requests": 0,
            "request_limit": request.limits.total_requests,
            "planned_requests": planned,
            "probes": list(request.probe_ids),
        }
        self._probes = request.probe_ids
        self._push()

    def _push(self) -> None:
        if self._sink is not None:
            self._sink.set(dict(self._record))

    def on_request(self, count: int) -> None:
        with self._lock:
            self._record["requests"] = count
            self._push()

    def on_poll(self, tail: ReportTail) -> None:
        current = tail.current
        if current is None or current not in self._probes:
            return
        with self._lock:
            # garak runs probes in its own order, so the step is how many of
            # the requested probes have started, not a position in the list.
            step = sum(1 for name in tail.probes_seen if name in self._probes)
            if (step, current) != (self._record["step"], self._record["current"]):
                self._record.update(step=step, current=current)
                self._push()

    def stage(self, text: str) -> None:
        with self._lock:
            self._record["current"] = text
            self._push()


def _now() -> str:
    return datetime.now(UTC).isoformat()


class _Scrub:
    """Every stored string: control characters removed, keys and the token
    redacted, and clipped to ``limit`` characters (counting what was cut)."""

    def __init__(self, token: str) -> None:
        self._token = token
        self.clipped = 0

    def __call__(self, text: str | None, limit: int | None = None) -> str:
        limit = MAX_STORED_TEXT_CHARS if limit is None else limit
        value = redact_keys(clean_text(text or ""), self._token)
        if len(value) > limit:
            self.clipped += 1
            value = value[:limit]
        return value


def _attempts(parsed: ParsedReport, probe_ids: Sequence[str], scrub: _Scrub) -> tuple[list[dict[str, Any]], int]:
    """The attempts to store, capped per probe and in total, and how many there were."""
    stored: list[dict[str, Any]] = []
    total = 0
    for probe_id in probe_ids:
        attempts = parsed.attempts_for(probe_id)
        total += len(attempts)
        for attempt in attempts[:MAX_ATTEMPTS_PER_PROBE]:
            if len(stored) >= MAX_STORED_ATTEMPTS:
                break
            stored.append({
                "probe": probe_id,
                "seq": attempt.seq,
                "evaluated": attempt.status >= 2,
                "prompt": scrub(attempt.prompt),
                "outputs": [None if o is None else scrub(o) for o in attempt.outputs[:MAX_OUTPUTS_PER_ATTEMPT]],
                "detectors": {scrub(name, 200): list(scores[:MAX_OUTPUTS_PER_ATTEMPT])
                              for name, scores in attempt.detector_results.items()},
            })
    return stored, total


def _probe_rows(verdict: ScanVerdict, parsed: ParsedReport, scrub: _Scrub) -> list[dict[str, Any]]:
    rows = []
    for outcome in verdict.probes:
        rows.append({
            "probe": outcome.probe,
            "state": outcome.state.value,
            "reason": outcome.reason,
            "prompts": outcome.prompts,
            "answers": outcome.answers,
            "missing_answers": outcome.missing_answers,
            "refusals": outcome.refusals,
            "failures": outcome.failures,
            "evaluations": [{**e.to_dict(), "detector": scrub(e.detector, 200)}
                            for e in parsed.evaluations_for(outcome.probe)],
            "taxonomy": {**parsed.tags_for(outcome.probe), "atlas": atlas_record(outcome.probe)},
        })
    return rows


def _safeguard_reasons(request: ScanRequest, summary: Mapping[str, Any] | None) -> list[str]:
    """Why a scan with safeguards chosen on did not test them as chosen."""
    if not request.safeguards_on:
        return []
    if summary is None:
        return ["The safeguards were chosen on, but no record of what they did was kept."]
    reasons = []
    if summary.get("status") != "on":
        reasons.append(f"The safeguards were chosen on but did not run as on (status: {summary.get('status')}).")
    not_checked = summary.get("not_checked")
    if isinstance(not_checked, int) and not_checked > 0:
        reasons.append(f"{not_checked} safeguard checks could not run.")
    return reasons


def build_record(
    request: ScanRequest,
    *,
    parsed: ParsedReport,
    run: GarakRun,
    shim_counts: Mapping[str, int],
    limit_hit: bool,
    token: str,
    garak_version: str | None,
    started_at: str,
    ended_at: str,
    planned: int,
    wall_clock_seconds: int,
    safeguards_report: Mapping[str, Any] | None,
    fixed: FixedAnswers | None = None,
) -> dict[str, Any]:
    """The scan record: plain JSON values, every string scrubbed.

    ``fixed`` is the shim's fixed answers for this scan; without them no
    answer is read as a refusal or a failure of the step.
    """
    facts = RunFacts(started=run.started, exit_code=run.exit_code, stopped=run.stopped, limit_hit=limit_hit,
                     report_found=run.files.report is not None, fixed=fixed)
    verdict = derive_status(parsed, request.probe_ids, facts)
    scrub = _Scrub(token)
    attempts, total = _attempts(parsed, request.probe_ids, scrub)
    probes = _probe_rows(verdict, parsed, scrub)
    reasons = [scrub(r, 500) for r in verdict.reasons]
    if run.files.report_truncated:
        reasons.append("The report was larger than this app keeps; only its start was read.")
    reasons += _safeguard_reasons(request, safeguards_report)
    status = ScanStatus.INCOMPLETE.value if reasons and verdict.status is ScanStatus.COMPLETE else (
        verdict.status.value)
    workflow = None
    if request.workflow is not None:
        workflow = {
            "system_prompt": scrub(request.workflow.system_prompt, MAX_SYSTEM_PROMPT_CHARS),
            "sample_context": scrub(request.workflow.sample_context, MAX_SAMPLE_CONTEXT_CHARS),
            "model": scrub(request.workflow.model, 80),
        }
    record: dict[str, Any] = {
        "version": RECORD_VERSION,
        "status": status,
        "reasons": reasons,
        "settings": {
            "garak_version": scrub(parsed.garak_version or garak_version or "", 40) or None,
            "probes": list(request.probe_ids),
            "limits": {**request.limits.to_dict(), "wall_clock_seconds": wall_clock_seconds},
            "planned_requests": planned,
            "seed": request.seed,
            "surface": {"id": request.surface_id, "title": scrub(request.surface_title, 200)},
            "safeguards_on": request.safeguards_on,
            "model": {"kind": request.model_kind, "name": scrub(request.model_name, 80),
                      "provider": scrub(request.model_provider, 20)},
            "workflow": workflow,
            "started_at": started_at,
            "ended_at": ended_at,
            "seconds": round(run.seconds, 1),
            "stopped": run.stopped,
            "exit_code": run.exit_code,
        },
        "probes": probes,
        "attempts": attempts,
        "caps": {
            "max_attempts": MAX_STORED_ATTEMPTS,
            "max_attempts_per_probe": MAX_ATTEMPTS_PER_PROBE,
            "max_outputs_per_attempt": MAX_OUTPUTS_PER_ATTEMPT,
            "max_text_chars": MAX_STORED_TEXT_CHARS,
            "attempts_in_report": total,
            "attempts_stored": len(attempts),
            "texts_clipped": scrub.clipped,
        },
        "shim": dict(shim_counts),
        "report": {
            "lines": parsed.lines,
            "bad_lines": parsed.bad_lines,
            "oversize_lines": parsed.oversize_lines,
            "unknown_entries": parsed.unknown_entries,
        },
        "safeguards": dict(safeguards_report) if safeguards_report is not None else None,
    }
    return record


SCAN_DIR_PLACEHOLDER = "<scan directory>"
GARAK_ENV_PLACEHOLDER = "<garak environment>"


def _server_paths(workdir: str, python: str) -> list[tuple[str, str]]:
    """Paths on this server that garak writes into its files, longest first.

    garak's report names its own install (configuration and payload files)
    and the scan's temporary directory; a visitor downloading the files
    learns neither.
    """
    pairs: dict[str, str] = {}
    for path in {workdir, os.path.realpath(workdir)}:
        pairs[path] = SCAN_DIR_PLACEHOLDER
    for path in {python, os.path.realpath(python)}:
        env = os.path.dirname(os.path.dirname(path))
        if len(env) > 1:
            pairs[env] = GARAK_ENV_PLACEHOLDER
    return sorted(pairs.items(), key=lambda pair: len(pair[0]), reverse=True)


def downloadable_files(run: GarakRun, *, token: str, workdir: str, python: str) -> dict[str, bytes]:
    """garak's own files for download: the token and key-shaped strings
    redacted, and this server's paths replaced (``_server_paths``)."""
    found = {"garak.report.jsonl": run.files.report, "garak.hitlog.jsonl": run.files.hitlog,
             "garak.report.html": run.files.html}
    paths = _server_paths(workdir, python)
    files: dict[str, bytes] = {}
    for name, data in found.items():
        if not data:
            continue
        pieces = []
        for piece in _pieces(data.decode("utf-8", "replace")):
            for path, placeholder in paths:
                piece = piece.replace(path, placeholder)
            pieces.append(redact_keys(piece, token))
        files[name] = "".join(pieces).encode("utf-8")
    return files


SCRUB_PIECE_CHARS = 64 * 1024
# A path, the token, and a key-shaped string never hold a newline or a
# double quote, and garak writes both around every value, so a cut just
# after one never splits what is being replaced.
_CUTS = ("\n", '"')


def _pieces(text: str) -> list[str]:
    """``text`` in pieces of about ``SCRUB_PIECE_CHARS``, each cut just after
    a newline or a double quote, so no single replacement call holds the
    interpreter lock for long on a large file."""
    pieces = []
    start = 0
    while start < len(text):
        end = start + SCRUB_PIECE_CHARS
        if end < len(text):
            cut = max(text.rfind(c, start, end) for c in _CUTS)
            end = cut + 1 if cut >= start else end
        pieces.append(text[start:end])
        start = end
    return pieces


def run_scan(
    request: ScanRequest,
    *,
    surface: Surface,
    availability: Availability,
    job_timeout_seconds: float,
    progress: ProgressLike | None = None,
    safeguards_report: Callable[[], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run the scan and return ``{"record": ..., "files": {name: bytes}}``.

    Raises ``ValidationError`` (``ERROR_UNAVAILABLE``) when scans cannot run
    here. Every other way a scan can end (garak missing at run time, a crash,
    no report, the time or request limit, a cancel) is in the record's
    status and reasons, never an exception.
    """
    if not availability.available or not availability.python:
        raise ValidationError(ERROR_UNAVAILABLE)
    check_target(request)  # again here: a request need not come through ``build``
    if request.model_kind != MODEL_REAL:
        check_keyless(request.limits)  # again here: a request need not come through ``build``
    planned = check_budget(request.probe_ids, request.limits)
    wall = int(min(request.limits.wall_clock_seconds, max(60, job_timeout_seconds - JOB_TIMEOUT_MARGIN_SECONDS)))
    limits = ScanLimits(**{**request.limits.to_dict(), "wall_clock_seconds": wall})
    live = _Progress(progress, request, planned)
    started_at = _now()
    workdir = tempfile.mkdtemp(prefix="aegis-aiscan-")
    try:
        with Shim(surface, max_requests=limits.total_requests, request_timeout=limits.request_timeout_seconds,
                  on_request=live.on_request) as shim:
            run = run_garak(
                python=availability.python,
                probe_ids=request.probe_ids,
                limits=limits,
                port=shim.port,
                token=shim.token,
                workdir=workdir,
                seed=request.seed,
                should_stop=progress.cancelled if progress is not None else (lambda: False),
                on_poll=live.on_poll,
            )
            token, counts, limit_hit, fixed = shim.token, shim.counts(), shim.limit_hit, shim.fixed
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    live.stage("Reading the report")
    parsed = parse_report(run.files.report)
    report = None
    if safeguards_report is not None:
        try:
            report = safeguards_report()
        # The safeguards record is extra evidence; a scan record without it
        # still holds everything garak found, so log and go on.
        except Exception as exc:
            logger.warning("safeguards report failed kind=%s", type(exc).__name__)
    record = build_record(
        request, parsed=parsed, run=run, shim_counts=counts, limit_hit=limit_hit, token=token,
        garak_version=availability.version, started_at=started_at, ended_at=_now(), planned=planned,
        wall_clock_seconds=wall, safeguards_report=report, fixed=fixed,
    )
    logger.info("ai scan finished status=%s probes=%d requests=%d", record["status"], len(request.probe_ids),
                counts.get("requests", 0))
    files = downloadable_files(run, token=token, workdir=workdir, python=availability.python)
    return {"record": record, "files": files}
