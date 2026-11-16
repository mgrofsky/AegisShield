"""AI workflow scan: run NVIDIA garak against the visitor's own AI workflow
(a system prompt they give, and the provider and model they chose in
Settings, called through this app's own client for that provider) and show
what it found.

The page offers only the ``visitor_workflow`` surface. The three surfaces
that test this app's own steps are developer checks (``tools/garak_offon.py``
and the tests); the scan service refuses them for any request the page
builds. A threat model's results page can open this page with
``?model=<id>`` (``threat_model_view.render_workflow_scans``); the next scan
this session finishes is then attached to that saved model
(``_source_model`` and ``attach_scan``).

The page exists only when the operator turned scans on and garak was found
(``routes.ai_scan_available``). A scan runs as this session's ``ai_scan``
job; a finished scan is saved to the workspace as its record, whatever its
status, and garak's own files are kept in the session for a download
(``state.keep_scan_files``). Everything a scan stored (prompts, answers,
detector names) is shown as text: in escaped HTML, a code block, or a table
cell, never as markdown.
"""

from __future__ import annotations

import html
import json
import re
import time
from collections.abc import Mapping
from datetime import datetime
from typing import Any

import streamlit as st

from aegisshield.aiscan import limits as scan_limits
from aegisshield.aiscan import probes as scan_probes
from aegisshield.aiscan import service as scan_service
from aegisshield.aiscan import surfaces as scan_surfaces
from aegisshield.aiscan import taxonomy as scan_taxonomy
from aegisshield.aiscan.availability import Availability, scan_availability
from aegisshield.aiscan.report import ProbeState, ScanStatus, taxonomy_tag
from aegisshield.aiscan.shim import MAX_PROMPT_CHARS
from aegisshield.core.errors import AegisError
from aegisshield.jobs import JobSnapshot, JobStatus
from aegisshield.llm import providers
from aegisshield.llm.base import DEFAULT_SDK_RETRIES
from aegisshield.storage import RecordKind
from aegisshield.storage.workspace import Record, Workspace, WorkspaceError
from aegisshield.ui import kit, state, tool_parts
from aegisshield.ui.theme import Area, Tone

PAGE = "ai_scan"
JOB_KIND = "ai_scan"
# After a scan ends, this session waits this long before it can start
# another, so one visitor cannot hold the single scan slot back to back.
# A visitor who opens a new session is not stopped by it.
SCAN_COOLDOWN_SECONDS = 60
_SCAN_ACTIVE = "aegis_scan_active"
_SCAN_ENDED_AT = "aegis_scan_ended_at"

WHAT_IT_DOES = (
    "This runs NVIDIA garak's attack prompts against your own AI workflow: the system prompt you give "
    "here and the model you chose in Settings, called through this app's own client for your model "
    "provider. Each garak prompt is the user's message, after your sample context. It records what garak "
    "sent, what the model answered, and what each detector decided."
)
WHAT_IT_DOES_NOT = (
    "It does not test your deployed system, its tools, its retrieval, its network, or any endpoint of "
    "yours. It contacts no address you type: the only model it calls is the one you chose in Settings "
    "from your provider's own list, through this app's client, with your credential."
)
NO_MODEL_NOTE = (
    "No model is ready in Settings (a provider, its credential, and a model from its list), so only the "
    "simulated stand-in can answer. Choose them in Settings to scan with a real model."
)
CHECKS_NOTE = (
    "With this app's checks, the same calls pass this app's NeMo Guardrails checks: garak's message passes "
    "the input checks, your sample context passes the retrieved-content checks, and each answer passes the "
    "answer checks, which also look for your system prompt in it. An instruction the input checks find in "
    "garak's message is fenced as data before the model sees it, so results with the checks partly measure "
    "that fence, which your own system does not have. These checks protect only calls made through this "
    "app, not your deployed system. Run both modes with the same seed to compare."
)
STORED_NOTE = (
    "What is stored: your system prompt, sample context, and model are saved with the scan record in this "
    "session's workspace, with key-shaped secrets redacted, and leave with a workspace export. They are "
    "never written to the server's logs and never put in garak's arguments, environment, or configuration. "
    "An answer that repeats them reaches garak's report like any other answer."
)
# The note when the operator set ``AEGIS_DATA_DIR``: the workspace is one
# file shared by everyone who can open the app. That setting is documented
# as meant for a single-user install, and the app has no other way to tell
# how many people can reach it, so the page says so rather than refuse.
SHARED_STORED_NOTE = (
    "What is stored: this server keeps its workspace in one shared file (AEGIS_DATA_DIR), so your system "
    "prompt, sample context, and model are saved with the scan record where everyone who can open this app "
    "can read them, with key-shaped secrets redacted. That setting is meant for a single-user install, and "
    "this app cannot tell whether anyone else can reach this server. They are never written to the server's "
    "logs and never put in garak's arguments, environment, or configuration. An answer that repeats them "
    "reaches garak's report like any other answer."
)
_GUARD_WORDS = {"on": "Behind this app's checks (NeMo Guardrails)", "off": "Your workflow as it is (no checks)"}
# The query parameter a threat model's page opens this page with, and where
# the session keeps it until the next scan finishes.
MODEL_PARAM = "model"
_FROM_MODEL = "aegis_scan_from_model"
# The most scans one threat model keeps attached; the oldest drop first.
MAX_ATTACHED_SCANS = 20


# When each provider's client sends a failed call again (up to
# ``DEFAULT_SDK_RETRIES`` more times, as ``llm.factory`` builds it), read
# from the installed SDKs and pinned by tests: the OpenAI and Anthropic SDKs'
# ``_should_retry``, google-genai's ``_RETRY_HTTP_STATUS_CODES``, and
# botocore's standard retry mode (``total_max_attempts``). Every one also
# sends again when it cannot connect or the request times out.
RETRY_RULES: dict[str, str] = {
    "openai": "status 408, 409, 429, or 500 and above",
    "claude": "status 408, 409, 429, or 500 and above",
    "gemini": "status 408, 429, 500, 502, 503, or 504",
    "bedrock": "a throttling error (status 429) or status 500, 502, 503, or 504",
}


def key_sentence(requests: int, visitor_chars: int, provider: str) -> str:
    """What a scan can spend of the visitor's credential, in plain words: the
    most calls, the output cap of each, the most text each sends, and the
    provider client's retries (``RETRY_RULES``)."""
    label = providers.provider_label(provider)
    rule = RETRY_RULES.get(provider, "an error its SDK treats as passing")
    return (
        f"This scan will use your {label} credential for up to {requests} model calls, one per garak "
        f"request. Each call asks for at most {scan_surfaces.WORKFLOW_MAX_TOKENS:,} output tokens (with some "
        f"models, the model's reasoning counts toward them) and sends your system prompt and sample context "
        f"({visitor_chars:,} characters now) plus one garak prompt of at most {MAX_PROMPT_CHARS:,} "
        "characters; with this app's checks on, a prompt that holds an instruction also gets a short note "
        f"marking it as data. The client sends a call again, up to {DEFAULT_SDK_RETRIES} more times, when it "
        f"cannot connect, times out, or {label} answers with {rule}, so at most "
        f"{requests * (1 + DEFAULT_SDK_RETRIES)} requests can reach {label}."
    )


COOLDOWN_SENTENCE = (f"After a scan ends, this session waits {SCAN_COOLDOWN_SECONDS} seconds before it can "
                     "start another.")
KEYLESS_SENTENCE = (f"Without a model key, a scan may send at most {scan_limits.KEYLESS_MAX_REQUESTS} requests "
                    f"and run at most {scan_limits.KEYLESS_MAX_WALL_SECONDS} seconds.")
SIMULATED_NOTE = ("The simulated stand-in follows injected instructions on purpose, so the safeguards have "
                  "something to stop. Results from it say nothing about any real model.")

_STATUS_WORDS = {
    ScanStatus.COMPLETE.value: ("Complete", Tone.INFO),
    ScanStatus.INCOMPLETE.value: ("Incomplete", Tone.WARN),
    ScanStatus.FAILED.value: ("Failed", Tone.CRIT),
}
_PROBE_WORDS = {
    ProbeState.COMPLETE.value: "Complete",
    ProbeState.ALL_REFUSED.value: "Every answer was a refusal",
    ProbeState.ALL_FAILED.value: "Every answer was a failure",
    ProbeState.INCOMPLETE.value: "Incomplete",
    ProbeState.NOT_EVALUATED.value: "Not evaluated",
    ProbeState.NOT_RUN.value: "Not run",
}
_MODEL_WORDS = {
    scan_service.MODEL_REAL: "Real model (your provider credential)",
    scan_service.MODEL_SIMULATED: "Simulated stand-in (" + scan_service.SIMULATED_LABEL + ")",
    scan_service.MODEL_MOCK: "Canned mock",
}
_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")
_KEY_RE = re.compile(r"[^A-Za-z0-9]+")


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _when(stamp: object) -> str:
    try:
        return datetime.fromisoformat(str(stamp)).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError):
        return ""


def _map(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


# A stored count or limit past this is not one a scan made. An imported
# workspace can hold integers of up to 4,300 digits, and the page adds two
# counts in places, so a sum could pass Python's digit limit for printing.
_MAX_INT = 10**15


def _int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or abs(value) > _MAX_INT:
        return 0
    return value


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


# What one view of a scan shows at most. A stored scan was capped by the
# scan service, but an imported workspace can hold anything within the
# workspace limits, so the page applies the same caps again.
_MAX_ROWS = 50
_MAX_DETECTORS = 10
_MAX_LINE = 500


def _clip(value: object, limit: int) -> str:
    return _text(value)[:limit]


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}{'' if number == 1 else 's'}"


def _safeguard_words(chosen: object, summary: object) -> str:
    """What the safeguards did, from the scan's own record of them, not the choice alone."""
    if chosen is not True:
        return "Off, a baseline"
    summary = _map(summary)
    if summary.get("status") != "on":
        return f"Chosen on, but did not run as on (status: {_text(summary.get('status')) or 'unknown'})"
    missed = _int(summary.get("not_checked"))
    return f"On, as deployed; {missed} checks could not run" if missed else "On, as deployed"


def _model_words(model: Mapping[str, Any]) -> str:
    """The model kind in words, and its name when the name adds something."""
    kind = _text(model.get("kind"))
    words = _MODEL_WORDS.get(kind, "Unknown")
    name = _text(model.get("name"))
    if not name or kind == scan_service.MODEL_SIMULATED:
        return words
    provider = _text(model.get("provider"))
    # A record from before providers were stored has no provider: OpenAI.
    label = providers.provider_label(provider) if provider else None
    return f"{words}: {label}, {name}" if label else f"{words}: {name}"


# ------------------------------------------------------------------- job


def _model_options(settings) -> list[str]:
    """The models this session can scan with: the real model when there is a
    key (never in mock mode), and always the simulated stand-in."""
    options = []
    if not settings.mock_llm and state.have_llm():
        options.append(scan_service.MODEL_REAL)
    options.append(scan_service.MODEL_SIMULATED)
    return options


def _model(kind: str, settings, surface_id: str):
    """The model client for ``kind`` (the visitor's key is captured here)."""
    if kind == scan_service.MODEL_REAL:
        return tool_parts.session_llm(settings)
    return scan_surfaces.simulated_llm(surface_id)


def _job(request: scan_service.ScanRequest, availability: Availability, settings):
    """The job function; the model client, settings, and request are captured
    here. ``settings`` carries the visitor's provider and model, the same ones
    the request names, so the client and the model called always agree."""
    llm = _model(request.model_kind, settings, request.surface_id)
    spec = scan_surfaces.surface_spec(request.surface_id)

    def run(sink) -> dict[str, Any]:
        guards = scan_surfaces.make_safeguards(settings, request.safeguards_on)
        surface = spec.build(llm, settings, guards, request.workflow)
        return scan_service.run_scan(
            request, surface=surface, availability=availability,
            job_timeout_seconds=settings.job_timeout_seconds, progress=sink,
            safeguards_report=lambda: scan_surfaces.safeguards_summary(guards),
        )

    return run


def _clock() -> float:
    """Seconds on a clock that only moves forward (a function so tests can set it)."""
    return time.monotonic()


def _note_scan_end(running: bool) -> None:
    """Remember when this session's scan ended, however it ended (finished,
    failed, or cancelled): a scan seen running and now not running has ended."""
    if running:
        st.session_state[_SCAN_ACTIVE] = True
    elif st.session_state.pop(_SCAN_ACTIVE, False):
        st.session_state[_SCAN_ENDED_AT] = _clock()


def _cooldown_left() -> int:
    """Whole seconds this session must still wait before starting a scan."""
    ended = st.session_state.get(_SCAN_ENDED_AT)
    if not isinstance(ended, float):
        return 0
    left = SCAN_COOLDOWN_SECONDS - (_clock() - ended)
    return max(0, int(left + 0.999))


def _start(choice: Mapping[str, Any], availability: Availability) -> None:
    settings = state.get_settings()
    wait = _cooldown_left()
    if wait:
        kit.notice(f"{COOLDOWN_SENTENCE} Try again in {_count(wait, 'second')}.", tone=Tone.WARN)
        return
    try:
        spec = scan_surfaces.WORKFLOW_SURFACE
        limits = scan_limits.ScanLimits.build(
            generations=choice["generations"], prompts_per_probe=choice["prompts"],
            total_requests=choice["requests"], request_timeout_seconds=choice["timeout"],
            wall_clock_seconds=choice["wall"],
        )
        if choice["model"] not in _model_options(settings):
            raise AegisError(scan_service.ERROR_MODEL_KIND)
        # The workflow's model is the one chosen in Settings, through the
        # chosen provider, as for a threat-model run; the stand-in calls none.
        real = choice["model"] == scan_service.MODEL_REAL
        workflow = {**choice["workflow"], "model": settings.architect_model if real else ""}
        # The developer flag is never passed: the service refuses every other surface.
        request = scan_service.ScanRequest.build(
            surface_id=spec.id, surface_title=spec.title, probe_ids=choice["probes"], limits=limits,
            seed=choice["seed"], safeguards_on=choice["safeguards"], model_kind=choice["model"],
            model_name=scan_surfaces.SIMULATED_NAME, workflow=workflow,
            model_provider=settings.provider,
        )
        state.start_job(JOB_KIND, _job(request, availability, settings), shown_errors=scan_service.JOB_ERRORS)
        st.session_state[_SCAN_ACTIVE] = True
        if choice.get("from_model"):
            st.session_state[_FROM_MODEL] = choice["from_model"]
    except AegisError as exc:
        kit.notice(str(exc), tone=Tone.CRIT)
        return
    st.rerun()


def _workflow_model(settings) -> None:
    """Which model the workflow uses: the one chosen in Settings, named with
    its provider, or a note that only the stand-in can answer."""
    if not settings.mock_llm and state.have_llm():
        tool_parts.line(f"Model your workflow uses: {providers.provider_label(settings.provider)}, "
                        f"{settings.architect_model}")
        tool_parts.muted("Chosen in Settings. A scan with the real model calls it with your credential; "
                         "change the provider or model in Settings.")
    elif not settings.mock_llm:
        tool_parts.muted(NO_MODEL_NOTE)


def _form(availability: Availability, from_model: str | None = None) -> None:
    settings = state.get_settings()
    with kit.card("scan_form"):
        kit.section("New scan", "Describe your workflow, then choose the checks, the probes, and the limits.")
        system_prompt = st.text_area(
            "System prompt", key="scan_system_prompt", max_chars=scan_surfaces.MAX_SYSTEM_PROMPT_CHARS,
            height=160, placeholder="The instructions your workflow gives the model.",
        )
        sample_context = st.text_area(
            "Sample context (optional)", key="scan_sample_context",
            max_chars=scan_surfaces.MAX_SAMPLE_CONTEXT_CHARS, height=100,
            placeholder="Text your workflow would add to the user's message, such as a retrieved document.",
        )
        tool_parts.muted(f"The sample context goes in the user's message, under the label "
                         f"\"{scan_surfaces.SAMPLE_CONTEXT_LABEL}\", before garak's prompt.")
        _workflow_model(settings)
        tool_parts.muted(SHARED_STORED_NOTE if settings.data_dir is not None else STORED_NOTE)
        if settings.safeguards:
            guards = st.radio("This app's checks", ["on", "off"], key="scan_guards", format_func=_GUARD_WORDS.get)
            tool_parts.muted(CHECKS_NOTE)
        else:
            guards = "off"
            tool_parts.muted("This app's checks: off. This server runs with the safeguards off "
                             "(AEGIS_SAFEGUARDS), so the scan tests your workflow as it is.")

        st.html('<p class="tx-name">Probes</p>')
        chosen: list[str] = []
        families: dict[str, list[scan_probes.Probe]] = {}
        for item in scan_probes.PROBES:
            families.setdefault(item.family, []).append(item)
        columns = st.columns(2)
        for index, (family, members) in enumerate(families.items()):
            with columns[index % 2]:
                tool_parts.muted(family)
                for item in members:
                    if st.checkbox(item.id, value=item.id in scan_probes.DEFAULT_PROBE_IDS,
                                   key=f"scan_probe_{item.id}"):
                        chosen.append(item.id)
                    tool_parts.muted(item.description)

        options = _model_options(settings)
        model = st.radio("Model that answers", options, key="scan_model", format_func=_MODEL_WORDS.get)
        if settings.mock_llm:
            tool_parts.muted("Mock mode has no model key, and its canned answers cannot be attacked, so the "
                             "scan uses the simulated stand-in.")
        if model == scan_service.MODEL_SIMULATED:
            kit.notice(SIMULATED_NOTE, tone=Tone.WARN, label="Simulated")

        st.html('<p class="tx-name">Limits</p>')
        if model != scan_service.MODEL_REAL:
            tool_parts.muted(KEYLESS_SENTENCE)
        cols = st.columns(5)
        values = {}
        for col, (name, limit) in zip(cols, (
            ("generations", scan_limits.GENERATIONS), ("prompts", scan_limits.PROMPTS_PER_PROBE),
            ("requests", scan_limits.TOTAL_REQUESTS), ("timeout", scan_limits.REQUEST_TIMEOUT_SECONDS),
            ("wall", scan_limits.WALL_CLOCK_SECONDS),
        ), strict=True):
            if model != scan_service.MODEL_REAL:
                limit = scan_limits.keyless(limit)
            values[name] = int(col.number_input(limit.label, min_value=limit.minimum, max_value=limit.maximum,
                                                value=limit.default, step=1, key=f"scan_limit_{name}"))
        seed = st.number_input("Seed (optional)", min_value=scan_limits.SEED.minimum,
                               max_value=scan_limits.SEED.maximum, value=None, step=1, key="scan_seed")

        planned = None
        try:
            planned = scan_limits.planned_requests(scan_probes.check_probe_ids(chosen), scan_limits.ScanLimits(
                generations=values["generations"], prompts_per_probe=values["prompts"]))
        except AegisError:
            pass
        if planned is not None:
            tool_parts.line(f"These choices need up to {planned} requests; the limit is {values['requests']}.")
        if model == scan_service.MODEL_REAL:
            kit.notice(key_sentence(values["requests"], len(system_prompt or "") + len(sample_context or ""),
                                    settings.provider), tone=Tone.WARN, label="Your credential")
        tool_parts.muted(COOLDOWN_SENTENCE)
        if st.button("Start scan", key="scan_run", type="primary", icon=":material/play_arrow:"):
            _start({"probes": chosen, **values, "seed": None if seed is None else int(seed),
                    "safeguards": guards == "on", "model": model, "from_model": from_model,
                    "workflow": {"system_prompt": system_prompt, "sample_context": sample_context}},
                   availability)


def _progress(snap: JobSnapshot) -> None:
    record = snap.progress or {}
    step, total = _int(record.get("step")), _int(record.get("total"))
    requests, limit = _int(record.get("requests")), _int(record.get("request_limit"))
    current = _text(record.get("current"))
    with kit.card("scan_running"):
        kit.section("Scan running", f"Running for {tool_parts.elapsed_words(snap)}.")
        st.progress(min(requests / limit, 1.0) if limit else 0.0)
        tool_parts.line(f"Requests so far: {requests} of the limit of {limit}.")
        if total:
            tool_parts.line(f"Probe {step} of {total}: {current}" if step else current)


def _title(record: Mapping[str, Any]) -> str:
    settings = _map(record.get("settings"))
    surface = _text(_map(settings.get("surface")).get("title")) or "Scan"
    count = len(_list(settings.get("probes")))
    return f"{surface}, {count} probe{'s' if count != 1 else ''}"


def _finish() -> None:
    snap = tool_parts.take_finished(JOB_KIND)
    if snap is None:
        return
    if snap.status is JobStatus.COMPLETE and snap.result:
        record = snap.result.get("record")
        files = snap.result.get("files") if isinstance(snap.result.get("files"), dict) else {}
        if not isinstance(record, dict):
            kit.notice("The scan returned nothing to save.", tone=Tone.CRIT)
            return
        workspace = state.get_workspace()
        saved = workspace.add(RecordKind.AI_SCANS, _title(record), record)
        from_model = st.session_state.pop(_FROM_MODEL, None)
        if isinstance(from_model, str):
            attach_scan(workspace, from_model, saved.id)
        state.save_workspace(workspace)
        state.keep_scan_files(saved.id, files)
        word, _ = _STATUS_WORDS.get(_text(record.get("status")), ("Failed", Tone.CRIT))
        state.flash(f"Scan saved to this session's workspace. Status: {word}.",
                    "info" if word == "Complete" else "warn")
        kit.open_record(PAGE, saved.id)
    elif snap.status is JobStatus.FAILED:
        tool_parts.failure_notice(JOB_KIND, f"The scan did not run. {snap.error or ''}".strip(), key="scan")


# ---------------------------------------------------------------- report


def _settings_list(record: Mapping[str, Any]) -> None:
    settings = _map(record.get("settings"))
    lim = _map(settings.get("limits"))
    model = _map(settings.get("model"))
    seed = settings.get("seed")
    kit.key_value_list([
        ("Workflow step", _clip(_map(settings.get("surface")).get("title"), 200)),
        ("Probes", _clip(", ".join(str(p) for p in _list(settings.get("probes"))[:_MAX_ROWS]), _MAX_LINE)),
        ("Safeguards", _safeguard_words(settings.get("safeguards_on"), record.get("safeguards"))),
        ("Model", _model_words(model)),
        ("garak version", _text(settings.get("garak_version")) or "Unknown"),
        ("Limits", f"{_count(_int(lim.get('generations')), 'answer')} per prompt, "
                   f"{_int(lim.get('prompts_per_probe'))} "
                   f"prompts per probe, {_int(lim.get('total_requests'))} requests, "
                   f"{_int(lim.get('request_timeout_seconds'))} s per request, "
                   f"{_int(lim.get('wall_clock_seconds'))} s in all"),
        ("Seed", str(seed) if isinstance(seed, int) and not isinstance(seed, bool) else "Not set"),
        ("Started", _when(settings.get("started_at"))),
        ("Ended", _when(settings.get("ended_at"))),
    ])


def _status(record: Mapping[str, Any]) -> None:
    status = _text(record.get("status"))
    word, tone = _STATUS_WORDS.get(status, ("Failed", Tone.CRIT))
    reasons = [_clip(r, _MAX_LINE) for r in _list(record.get("reasons"))[:_MAX_ROWS] if isinstance(r, str)]
    if status == ScanStatus.COMPLETE.value:
        kit.notice("garak finished every probe, and its counts match the attempts in its report.",
                   tone=tone, label=word)
    else:
        kit.notice("This scan did not finish, so it has no result. What it recorded is shown below as "
                   "evidence only.", tone=tone, label=word)
    if reasons:
        st.html('<ul class="tx-list">' + "".join(f"<li>{_esc(r)}</li>" for r in reasons) + "</ul>")


def _shim_tiles(record: Mapping[str, Any]) -> None:
    shim = _map(record.get("shim"))
    lim = _map(_map(record.get("settings")).get("limits"))
    kit.stat_row([
        kit.Tile("Requests", _int(shim.get("requests")), f"limit {_int(lim.get('total_requests'))}"),
        kit.Tile("Refused by the step", _int(shim.get("refusals"))),
        kit.Tile("Failed or timed out", _int(shim.get("failures")) + _int(shim.get("timeouts")),
                 tone=Tone.WARN if _int(shim.get("failures")) + _int(shim.get("timeouts")) else Tone.NEUTRAL),
        kit.Tile("Past the request limit", _int(shim.get("limit_hits")),
                 tone=Tone.WARN if _int(shim.get("limit_hits")) else Tone.NEUTRAL),
    ])


def _found_words(row: Mapping[str, Any], evaluation: Mapping[str, Any]) -> str:
    fails, evaluated = _int(evaluation.get("fails")), _int(evaluation.get("total_evaluated"))
    words = f"found the attack in {fails} of {evaluated} answers"
    probe_state = _text(row.get("state"))
    if probe_state == ProbeState.ALL_REFUSED.value:
        words += " (every answer was the step refusing, so the attack was not tested)"
    elif probe_state == ProbeState.ALL_FAILED.value:
        words += " (every answer was a failure, so the attack was not tested)"
    elif probe_state != ProbeState.COMPLETE.value:
        words += " (not a result: the probe did not finish)"
    return words


def _owasp_words(tag: str) -> str:
    return "OWASP " + tag[len("owasp:"):].upper()


def _avid_words(tag: str) -> str:
    _, kind, code = tag.split(":")
    return f"AVID {code} ({kind})"


def _atlas_links(refs: object) -> list[str]:
    """Escaped ATLAS links for the ids in ``refs`` that are in this app's table.

    The link and name come from ``taxonomy``, never from the stored record,
    so an imported record cannot make the page show a link it chose.
    """
    links: list[str] = []
    seen: set[str] = set()
    for ref in _list(refs)[:_MAX_DETECTORS]:
        ref_id = _text(_map(ref).get("id"))
        if ref_id in scan_taxonomy.ATLAS_NAMES and ref_id not in seen:
            seen.add(ref_id)
            url = scan_taxonomy.ATLAS_URL.format(id=ref_id)
            links.append(f'<a href="{_esc(url)}" target="_blank" rel="noopener noreferrer">ATLAS {_esc(ref_id)}</a> '
                         f"{_esc(scan_taxonomy.ATLAS_NAMES[ref_id])}")
    return links


def _references(record: Mapping[str, Any]) -> None:
    """Per probe: what each detector found, in words, with its taxonomy references."""
    items = []
    for row in _list(record.get("probes"))[:_MAX_ROWS]:
        if not isinstance(row, Mapping):
            continue
        evaluations = [e for e in _list(row.get("evaluations"))[:_MAX_DETECTORS] if isinstance(e, Mapping)]
        found = "; ".join(f"attack found {_found_words(row, e)[len('found the attack '):]}"
                          f" ({_clip(e.get('detector'), 200) or 'detector unknown'})"
                          for e in evaluations) or "nothing evaluated"
        taxonomy = _map(row.get("taxonomy"))
        tags = [taxonomy_tag(t) for t in _list(taxonomy.get("owasp"))[:_MAX_DETECTORS]
                + _list(taxonomy.get("avid"))[:_MAX_DETECTORS]]
        refs = [_esc(_owasp_words(t) if t.startswith("owasp:") else _avid_words(t)) for t in tags if t]
        refs += _atlas_links(taxonomy.get("atlas"))
        items.append(f"<li><strong>{_esc(_clip(row.get('probe'), 200))}</strong>: {_esc(found)}. "
                     f"{'; '.join(refs) if refs else 'No references recorded.'}</li>")
    if items:
        st.html('<ul class="tx-list">' + "".join(items) + "</ul>")


def _probe_table(record: Mapping[str, Any]) -> None:
    rows = []
    for row in _list(record.get("probes"))[:_MAX_ROWS]:
        if not isinstance(row, Mapping):
            continue
        state_words = _PROBE_WORDS.get(_text(row.get("state")), "Unknown")
        evaluations = [e for e in _list(row.get("evaluations"))[:_MAX_DETECTORS] if isinstance(e, Mapping)]
        for evaluation in evaluations or [{}]:
            rows.append({
                "Probe": _clip(row.get("probe"), 200),
                "State": state_words,
                "Detector": _clip(evaluation.get("detector"), 200) or "None",
                "What the detector found": _found_words(row, evaluation) if evaluation else "Nothing evaluated",
                "Attack found": _int(evaluation.get("fails")),
                "Not found": _int(evaluation.get("passed")),
                "No answer": _int(evaluation.get("nones")),
                "Evaluated": _int(evaluation.get("total_evaluated")),
                "Processed": _int(evaluation.get("total_processed")),
            })
    if rows:
        st.dataframe(rows, hide_index=True, width="stretch", height=min(400, 38 + 35 * len(rows)))
    not_done = [r for r in _list(record.get("probes"))[:_MAX_ROWS] if isinstance(r, Mapping)
                and _text(r.get("state")) != ProbeState.COMPLETE.value]
    if not_done:
        tool_parts.muted("Refused, failed, or not run:")
        st.html('<ul class="tx-list">' + "".join(
            f"<li>{_esc(_clip(r.get('probe'), 200))}: {_esc(_PROBE_WORDS.get(_text(r.get('state')), 'Unknown'))}. "
            f"{_esc(_clip(r.get('reason'), _MAX_LINE))}</li>" for r in not_done) + "</ul>")


def _attempts(record: Mapping[str, Any], record_id: str) -> None:
    attempts = [a for a in _list(record.get("attempts"))[:scan_service.MAX_STORED_ATTEMPTS]
                if isinstance(a, Mapping)]
    caps = _map(record.get("caps"))
    kit.section("Attempts", f"{_int(caps.get('attempts_stored'))} of {_int(caps.get('attempts_in_report'))} "
                            f"attempts kept, each text cut to {_int(caps.get('max_text_chars')):,} characters "
                            f"({_int(caps.get('texts_clipped'))} were cut).")
    if not attempts:
        tool_parts.muted("No attempts were recorded.")
        return
    for index, attempt in enumerate(attempts):
        detectors = dict(list(_map(attempt.get("detectors")).items())[:_MAX_DETECTORS])
        hits = sum(1 for scores in detectors.values() for s in _list(scores)[:scan_service.MAX_OUTPUTS_PER_ATTEMPT]
                   if isinstance(s, int | float) and not isinstance(s, bool) and s >= 0.5)
        label = f"{_clip(attempt.get('probe'), 200)} #{_int(attempt.get('seq'))}: {_count(hits, 'detector hit')}"
        with st.expander(label, key=f"scan_attempt_{record_id}_{index}"):
            tool_parts.muted("Prompt garak sent")
            st.code(_clip(attempt.get("prompt"), scan_service.MAX_STORED_TEXT_CHARS), language=None,
                    wrap_lines=True)
            for n, output in enumerate(_list(attempt.get("outputs"))[:scan_service.MAX_OUTPUTS_PER_ATTEMPT],
                                       start=1):
                tool_parts.muted(f"Answer {n}")
                if isinstance(output, str):
                    st.code(_clip(output, scan_service.MAX_STORED_TEXT_CHARS), language=None, wrap_lines=True)
                else:
                    tool_parts.line("No answer (the request was refused at the limit or got no reply).")
            if detectors:
                tool_parts.muted("Detector scores (garak counts 0.5 and above as the attack found)")
                st.dataframe([{"Detector": str(name)[:200], "Scores": ", ".join(
                    "none" if s is None else f"{s:g}" for s in _list(scores)[:scan_service.MAX_OUTPUTS_PER_ATTEMPT]
                    if s is None or (isinstance(s, int | float) and not isinstance(s, bool)))}
                    for name, scores in detectors.items()], hide_index=True, width="stretch")


def _downloads(record: Record) -> None:
    actions = st.container(horizontal=True, vertical_alignment="center")
    slug = _SLUG_RE.sub("-", record.title)[:60] or "scan"
    actions.download_button(
        "Scan record (JSON)", data=lambda: json.dumps(record.payload, indent=2).encode("utf-8"),
        file_name=f"{slug}-scan.json", mime="application/json", key="scan_dl_json",
        icon=":material/download:", on_click="ignore",
    )
    files = state.scan_files(record.id) or {}
    for name, data in files.items():
        actions.download_button(
            name, data=data, file_name=f"{slug}-{name}",
            mime="text/html" if name.endswith(".html") else "application/jsonl",
            key=f"scan_dl_{_KEY_RE.sub('_', name)}", icon=":material/download:", on_click="ignore",
        )
    if actions.button("Delete", key="scan_reader_del_danger", icon=":material/delete:"):
        tool_parts.confirm_delete("This scan", lambda: _delete(record.id), key="scan_del", page_name=PAGE)
    if not files:
        tool_parts.muted("garak's own report files are kept for up to "
                         f"{state.SCAN_FILES_TTL_SECONDS // 60} minutes, only in the session that ran the scan.")


def _safeguards(record: Mapping[str, Any]) -> None:
    summary = record.get("safeguards")
    if not isinstance(summary, Mapping):
        return
    pairs = [(_clip(str(k).replace("_", " ").capitalize(), 80), _clip(str(v), 80))
             for k, v in list(summary.items())[:_MAX_ROWS]
             if isinstance(v, str | int | float | bool) or v is None]
    if pairs:
        tool_parts.muted("What the safeguards did during the scan")
        kit.key_value_list(pairs)


def _workflow(record: Mapping[str, Any]) -> None:
    """The visitor's workflow as stored (redacted), shown as text."""
    workflow = _map(_map(record.get("settings")).get("workflow"))
    if not workflow:
        return
    with st.expander("Your workflow as stored", key="scan_workflow_stored"):
        model = _clip(workflow.get("model"), 80)
        tool_parts.muted(f"Model: {model}" if model else "Model: none (the simulated stand-in answered)")
        tool_parts.muted("System prompt")
        st.code(_clip(workflow.get("system_prompt"), scan_surfaces.MAX_SYSTEM_PROMPT_CHARS), language=None,
                wrap_lines=True)
        context = _clip(workflow.get("sample_context"), scan_surfaces.MAX_SAMPLE_CONTEXT_CHARS)
        tool_parts.muted("Sample context" if context else "No sample context.")
        if context:
            st.code(context, language=None, wrap_lines=True)


def _report(record: Record) -> None:
    payload = record.payload
    simulated = _text(_map(_map(payload.get("settings")).get("model")).get("kind")) == \
        scan_service.MODEL_SIMULATED
    kit.section("Scan", f"{record.title}. Saved {_when(record.created_at)}.")
    if simulated:
        kit.notice(f"Every result here is from a {scan_service.SIMULATED_LABEL}.", tone=Tone.WARN,
                   label="Simulated")
    _status(payload)
    _downloads(record)
    _shim_tiles(payload)
    _settings_list(payload)
    _safeguards(payload)
    _workflow(payload)
    kit.section("Probes and references", "What each detector found, with the probe's OWASP LLM and AVID tags "
                "as garak gives them and the MITRE ATLAS techniques this app maps the probe to. A reference "
                "names what the probe attempts; it is not a finding.")
    _references(payload)
    kit.section("Probes and detectors", "Counts as garak reported them.")
    _probe_table(payload)
    _attempts(payload, record.id)


# ------------------------------------------------------------------ list


def _delete(record_id: str) -> None:
    workspace = state.get_workspace()
    if workspace.delete(RecordKind.AI_SCANS, record_id):
        state.save_workspace(workspace)
        state.flash("Scan deleted.", "ok")


def attach_scan(workspace: Workspace, model_id: str, scan_id: str) -> bool:
    """Add ``scan_id`` to the saved threat model ``model_id``'s ``ai_scans``
    list (at most ``MAX_ATTACHED_SCANS``, oldest dropped). False when that
    model is not in the workspace or the update is refused."""
    model = workspace.get(RecordKind.THREAT_MODELS, model_id)
    if model is None:
        return False
    ids = [i for i in _list(model.payload.get("ai_scans")) if isinstance(i, str) and i != scan_id]
    payload = {**model.payload, "ai_scans": [*ids, scan_id][-MAX_ATTACHED_SCANS:]}
    try:
        return workspace.update_payload(RecordKind.THREAT_MODELS, model_id, payload) is not None
    except WorkspaceError:
        return False


def _is_record_id(value: object) -> bool:
    """True for a string shaped like a workspace record id (checked without a pattern)."""
    return (isinstance(value, str) and 0 < len(value) <= 64
            and all(c.isascii() and (c.isalnum() or c in "_-") for c in value))


def _source_model(running: bool) -> str | None:
    """The saved threat model this page was opened from (``?model=<id>``), if
    it is in this session's workspace; noted on the page and kept for the
    next scan. Opened without it, and with no scan running, the page forgets
    an earlier one. While a scan runs, the notice names only the model stored
    with that scan (the one it will be attached to), whatever the URL says."""
    value = st.session_state.get(_FROM_MODEL) if running else st.query_params.get(MODEL_PARAM)
    model = None
    if _is_record_id(value):
        model = state.get_workspace().get(RecordKind.THREAT_MODELS, value)
    if model is None:
        if not running:
            st.session_state.pop(_FROM_MODEL, None)
        return None
    kit.notice(f"Opened from the saved threat model \"{model.title}\". A scan that finishes is attached to it "
               "and listed on its page.", tone=Tone.INFO, label="Threat model")
    return model.id


def _past(records: list[Record], open_id: str | None) -> None:
    kit.section("Past scans", "Saved in this session's workspace, newest first.")
    if not records:
        kit.empty_state("No scans yet", "Run a scan to see how a workflow step handles garak's attack prompts.")
        return
    with kit.card("scan_list"):
        for record in records:
            title_col, open_col = st.columns([7, 1], vertical_alignment="center")
            current = " (open)" if record.id == open_id else ""
            word, _ = _STATUS_WORDS.get(_text(record.payload.get("status")), ("Failed", Tone.CRIT))
            kind = _text(_map(_map(record.payload.get("settings")).get("model")).get("kind"))
            simulated = ", simulated model" if kind == scan_service.MODEL_SIMULATED else ""
            title_col.html(
                f'<div class="tx-name">{_esc(record.title)}{_esc(current)}</div>'
                f'<p class="tx-muted">{_esc(_when(record.created_at))} &middot; {_esc(word)}{_esc(simulated)}</p>'
            )
            with open_col:
                kit.record_link(PAGE, record.id, "Open")


# ------------------------------------------------------------------ page


def render() -> None:
    """The scan form or the running scan, the open scan, and past scans."""
    kit.page_header("AI workflow scan", "Run garak against your own AI workflow.", area=Area.DEFENSE)
    tool_parts.tools_css()
    tool_parts.show_flash()
    availability = scan_availability(state.get_settings())
    workspace = state.get_workspace()
    open_id = state.requested_record_id()
    record = workspace.get(RecordKind.AI_SCANS, open_id) if open_id else None
    running = False
    if availability.available:
        tool_parts.line(WHAT_IT_DOES)
        tool_parts.line(WHAT_IT_DOES_NOT)
        kit.notice(scan_service.CLEAN_COUNT_NOTE, tone=Tone.INFO, label="Reading results")
        tool_parts.follow_job(JOB_KIND)
        _finish()
        running = state.is_job_running(JOB_KIND)
        _note_scan_end(running)
        from_model = _source_model(running)
        if running:
            tool_parts.running_panel(
                JOB_KIND, key="scan", render_progress=_progress, cancel_label="Cancel scan",
                cancelled_message="Scan cancelled. garak was stopped and nothing was saved.",
            )
        elif record is None:
            _form(availability, from_model)
    else:
        kit.empty_state(
            "AI workflow scans are not available here",
            "The operator has not turned scans on, or garak was not found. Saved scans in this session "
            "can still be opened below.",
        )
    if open_id and record is None:
        kit.empty_state("That scan is not in this session",
                        "Saved scans live in this browser session's workspace. Import a workspace file in "
                        "Settings to bring earlier work back.")
    elif record is not None:
        _report(record)
        if availability.available and not running:
            with st.expander("Run another scan", icon=":material/play_arrow:"):
                _form(availability, from_model)
    _past(workspace.list(RecordKind.AI_SCANS), open_id)
