"""The linear threat-model pipeline and its live progress record.

``run_threat_model_workflow`` runs the stages in ``THREAT_MODEL_STAGES`` in
order and pushes a progress record (the "office" frame plus its ``deck``)
through ``on_progress`` on every stage start, finish, skip, and detail, with
streamed updates coalesced in between. The record's shape is a contract with
the page's live view; see ``_office_progress`` and ``live_deck``.

``gather_enrichment`` (NVD, OTX, pattern detection, threat cards) is shared
with the agentic path so both paths build the same STRIDE prompt.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from aegisshield.config import Settings
from aegisshield.core.errors import AegisError
from aegisshield.core.text import clip_words
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
from aegisshield.pipeline.live_deck import CAP_REASON, LiveDeck, StageStream, lookup_count
from aegisshield.pipeline.mitigations_service import generate_mitigations
from aegisshield.pipeline.mitre_service import process_mitre_attack_data
from aegisshield.pipeline.nvd_service import (
    NoCpeMatch,
    NvdLookup,
    NvdSearchConfig,
    lookup_nvd,
    nvd_text,
)
from aegisshield.pipeline.otx_service import OtxLookup, lookup_otx, otx_text
from aegisshield.pipeline.pattern_detection_service import detect_patterns
from aegisshield.pipeline.test_cases_service import generate_test_cases
from aegisshield.pipeline.threat_card_service import cards_for_app
from aegisshield.pipeline.threat_model_service import (
    create_threat_model_prompt,
    generate_threat_model,
)
from aegisshield.safeguards import REPORT_KEY, Safeguards, SafeguardsStopped, Source
from aegisshield.services import lookup_switches

logger = logging.getLogger(__name__)


# Canonical pipeline stage list (single source of truth)
#
# The live "office" view binds one worker desk to each real pipeline stage. This
# is the ONE place those stages are defined; the frontend builds its desks from
# the stages EMITTED in progress, so the office stays correct if this list
# changes. Each entry is {id, label, phase, name, term}: ``name`` is the plain
# agent name and ``term`` the technical term the view shows. The phase groups
# desks into readable clusters (enrichment, modeling, scoring/validation).
#
# Stages 1-3 run in ``gather_enrichment``; 4-8 are this workflow's main body.
# 9-11 (mitigations / DREAD / test cases) run here when the request lists
# ``addons``; when it does not, they stay queued for the page to run later.
THREAT_MODEL_STAGES: list[dict[str, str]] = [
    {"id": "serialize", "label": "Serializing app profile and selected technologies", "phase": "enrichment",
     "name": "Intake", "term": "profile and technology list"},
    {"id": "nvd", "label": "Querying NVD for CVEs on selected technology versions", "phase": "enrichment",
     "name": "Vulnerability lookup", "term": "NVD"},
    {"id": "otx", "label": "Querying AlienVault OTX for sector threat pulses", "phase": "enrichment",
     "name": "Threat intelligence", "term": "AlienVault OTX"},
    {"id": "stride", "label": "Calling the AI model for STRIDE threat generation", "phase": "modeling",
     "name": "Threat writer", "term": "STRIDE"},
    {"id": "mitre_load", "label": "Loading MITRE ATT&CK STIX corpus (enterprise/mobile/ICS)", "phase": "modeling",
     "name": "Technique library", "term": "MITRE ATT&CK catalog"},
    {"id": "mitre_map", "label": "Mapping each threat to its most relevant ATT&CK technique", "phase": "modeling",
     "name": "Technique mapper", "term": "MITRE ATT&CK mapping"},
    {"id": "attack_tree", "label": "Generating Mermaid attack tree from the enriched model", "phase": "modeling",
     "name": "Attack path builder", "term": "attack tree"},
    {"id": "markdown", "label": "Rendering markdown tables for downstream steps", "phase": "modeling",
     "name": "Report assembler", "term": "tables"},
    {"id": "mitigations", "label": "Calling the AI model for mitigation recommendations", "phase": "scoring",
     "name": "Fix planner", "term": "mitigations"},
    {"id": "dread", "label": "Calling the AI model for DREAD risk scoring", "phase": "scoring",
     "name": "Risk scorer", "term": "DREAD"},
    {"id": "test_cases", "label": "Calling the AI model for Gherkin test cases", "phase": "validation",
     "name": "Test author", "term": "validation tests"},
]

# For an AI system the two MITRE stages also load and map ATLAS, and say so.
AI_STAGE_TEXT: dict[str, dict[str, str]] = {
    "mitre_load": {"label": "Loading the MITRE ATT&CK and ATLAS catalogs",
                   "term": "MITRE ATT&CK and ATLAS catalogs"},
    "mitre_map": {"label": "Mapping each threat to ATT&CK, then to ATLAS in one request",
                  "term": "MITRE ATT&CK and ATLAS mapping"},
}

# Stage ids this workflow always owns and emits (1-8). The remaining three
# (mitigations / dread / test_cases) count only when the request lists add-ons.
_BACKEND_STAGE_IDS: list[str] = [s["id"] for s in THREAT_MODEL_STAGES[:8]]

_ADDON_STAGE_IDS: list[str] = [s["id"] for s in THREAT_MODEL_STAGES[8:]]

# Status literals shared with the page's live view.
_QUEUED = "queued"
_WORKING = "working"
_DONE = "done"
_FALLBACK = "fallback"
_ERROR = "error"
_RESOLVED = {_DONE, _FALLBACK, _ERROR}

# Plain reasons shown on a stage. Fixed strings only: never model, prompt, or
# exception text. (The wording is part of the contract.)
REASON_NO_NVD_KEY = "No NVD API key configured"
REASON_NO_TECH = "No technologies selected"
REASON_NO_OTX_KEY = "No OTX API key configured"
REASON_NOT_SELECTED = "Not selected"
REASON_ADDON_FAILED = "This step did not finish. You can run it again from the results."
# About our side, so true whatever stopped the lookup.
REASON_NVD_FAILED = "The NVD lookup did not finish."
REASON_OTX_FAILED = "The OTX lookup did not finish."
REASON_OTX_OFF = "OTX is switched off (offline mode)"
REASON_NVD_OFF = "NVD is switched off (offline mode)"
REASON_NVD_DISABLED = "NVD is switched off on this server"
REASON_OTX_DISABLED = "OTX is switched off on this server"


def lookup_off_reason(source: str, settings: Settings) -> str | None:
    """Why the threat-model run must not call ``source`` ("nvd" or "otx"),
    or None when it may. The decision is ``lookup_switches.source_disabled``,
    the one the vulnerability lookup page also uses: offline mode
    (``AEGIS_OFFLINE``) or the source's own ``AEGIS_DISABLE_*`` flag."""
    if not lookup_switches.source_disabled(source, settings):
        return None
    offline = lookup_switches.offline(settings)
    if source == "nvd":
        return REASON_NVD_OFF if offline else REASON_NVD_DISABLED
    return REASON_OTX_OFF if offline else REASON_OTX_DISABLED

# Streamed deck updates are coalesced to about three writes a second. Stage
# start, finish, skip, and detail frames are always written.
MIN_WRITE_INTERVAL_S = 1 / 3
# After a coalesced write fails, further coalesced writes wait this long.
# Forced writes (stage start, finish, skip, error, detail) always try.
WRITE_BACKOFF_S = 5.0

# Lookup settings: retries, the base retry delay, and the OTX window and
# result count.
LOOKUP_MAX_RETRIES = 3
LOOKUP_RETRY_BASE_DELAY_S = 1.0
NVD_TOP_N = 10
OTX_DAYS = 2920
OTX_MAX_RESULTS = 10
# NVD text (per technology) and OTX text are third-party text with no length
# of their own, so each is clipped here, with a visible note, before it is
# screened and placed in a prompt: no screened lookup text is long enough for
# the retrieved-content check to come near its time limit.
LOOKUP_TEXT_MAX_CHARS = 40_000
NVD_CLIPPED_NOTE = "[NVD results cut at 40,000 characters]"
OTX_CLIPPED_NOTE = "[OTX results cut at 40,000 characters]"


def clip_lookup_text(text: str, note: str) -> str:
    """``text`` cut at a line end within ``LOOKUP_TEXT_MAX_CHARS``, with ``note``."""
    if len(text) <= LOOKUP_TEXT_MAX_CHARS:
        return text
    head = text[:LOOKUP_TEXT_MAX_CHARS]
    if "\n" in head:
        head = head.rsplit("\n", 1)[0]
    return f"{head}\n{note}"


class RunCancelled(AegisError):
    """The run was cancelled between stages (see ``ProgressSink.cancelled``)."""

    def __init__(self) -> None:
        super().__init__("The assessment was cancelled.")


def _monotonic() -> float:
    """The run clock (a seam so tests can replay recorded timings)."""
    return time.monotonic()


def _stage_seed() -> dict[str, str]:
    """Per-stage status map seeded all-queued, in canonical order."""
    return {stage["id"]: _QUEUED for stage in THREAT_MODEL_STAGES}


def _office_progress(
    statuses: dict[str, str],
    current: str,
    detail: str | None = None,
    *,
    reasons: dict[str, str | None] | None = None,
    started: dict[str, float] | None = None,
    finished: dict[str, float] | None = None,
    owned: list[str] | None = None,
    deck: dict[str, Any] | None = None,
    text: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Build an office progress event from the per-stage status map.

    ``office: True`` is distinct from the agentic orchestrator's ``agentic:
    True`` so the linear path's record is never mistaken for an agentic run.
    ``stages`` carries the canonical list and each stage's live status so the
    page renders its desks straight from the emitted progress.

    ``detail`` is an OPTIONAL live sub-step string for the ``current`` stage
    (e.g. "Checking Python 3.13" while NVD iterates). It rides ADDITIVELY on the
    matching stage dict; every other stage carries ``detail: None``. The
    office/stages/step/total/current shape is otherwise unchanged.

    ``text`` replaces a stage's ``label`` and ``term`` for this run (an AI
    system's MITRE stages, ``AI_STAGE_TEXT``); other runs keep the canonical ones.
    """

    reasons = reasons or {}
    started = started or {}
    finished = finished or {}
    owned = owned or _BACKEND_STAGE_IDS
    text = text or {}
    stages = [
        {
            "id": s["id"],
            "label": text.get(s["id"], s)["label"],
            "phase": s["phase"],
            "name": s["name"],
            "term": text.get(s["id"], s)["term"],
            "status": statuses[s["id"]],
            "detail": detail if s["id"] == current else None,
            "reason": reasons.get(s["id"]),
            "started_s": started.get(s["id"]),
            "finished_s": finished.get(s["id"]),
        }
        for s in THREAT_MODEL_STAGES
    ]
    resolved = sum(1 for s in owned if statuses[s] in _RESOLVED)
    record: dict[str, Any] = {
        "office": True,
        "stages": stages,
        "step": resolved,
        "total": len(owned),
        "current": current,
    }
    if deck is not None:
        record["deck"] = deck
    return record


class _StageEmitter:
    """Drives the per-stage progress record and its ``deck``.

    Holds the canonical per-stage status map, reasons, and timings, and pushes
    the whole record through ``on_progress`` on every stage start, finish,
    skip, and detail. Streamed text (``stream``) updates the deck and the live
    panel; those writes are coalesced to about three a second, and the next
    forced write carries anything pending, so the last state before a stage
    finishes is never lost. A missing callback makes every method a no-op and
    ``stream`` returns None, so model calls stay on the non-streaming path.

    ``cancelled`` is checked at every stage start; when it returns True the
    run stops with ``RunCancelled``.
    """

    def __init__(
        self,
        on_progress: Callable[[dict[str, Any]], None] | None,
        clock: Callable[[], float] | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        self._on_progress = on_progress
        self._cancelled = cancelled
        self._clock = clock or _monotonic
        self._t0 = self._clock()
        self._statuses = _stage_seed()
        self._reasons: dict[str, str | None] = {}
        self._started: dict[str, float] = {}
        self._finished: dict[str, float] = {}
        self._owned: list[str] = list(_BACKEND_STAGE_IDS)
        self._current = "running"
        # The working stage's latest detail line, kept until it resolves so
        # coalesced streaming writes do not blank it.
        self._detail: str | None = None
        self._last_write: float | None = None
        self._dirty = False
        self._backoff_until: float | None = None
        self._text: dict[str, dict[str, str]] = {}
        self.deck = LiveDeck(self.elapsed)

    @property
    def enabled(self) -> bool:
        """True when progress records are being written."""
        return self._on_progress is not None

    def elapsed(self) -> float:
        """Seconds since the run started, to the millisecond."""
        return round(self._clock() - self._t0, 3)

    def check_cancelled(self) -> None:
        """Raise ``RunCancelled`` when the job was cancelled."""
        if self._cancelled is not None and self._cancelled():
            raise RunCancelled()

    def relabel(self, text: dict[str, dict[str, str]]) -> None:
        """Use these stage labels and terms from the next write on."""
        self._text = dict(text)

    def own_addons(self) -> None:
        """The job runs stages 9 to 11 itself, so they count toward the total."""
        self._owned = [s["id"] for s in THREAT_MODEL_STAGES]

    def record(self, detail: str | None = None) -> dict[str, Any]:
        """The whole progress record as it stands now."""
        return _office_progress(
            self._statuses,
            self._current,
            detail,
            reasons=self._reasons,
            started=self._started,
            finished=self._finished,
            owned=self._owned,
            deck=self.deck.as_dict(),
            text=self._text,
        )

    def _emit(self, current: str | None = None, *, forced: bool = True) -> None:
        if current is not None:
            self._current = current
        if self._on_progress is None:
            return
        now = self._clock()
        self._last_write = now
        self._dirty = False
        try:
            self._on_progress(self.record(self._detail))
        # Progress is best-effort: a failing write must never fail the run.
        except Exception as exc:
            if forced:
                logger.warning("office_progress_emit_failed err=%s", type(exc).__name__)
                return
            self._backoff_until = now + WRITE_BACKOFF_S
            logger.warning(
                "office_progress_backoff err=%s seconds=%s", type(exc).__name__, WRITE_BACKOFF_S
            )

    def _backing_off(self) -> bool:
        return self._backoff_until is not None and self._clock() < self._backoff_until

    def changed(self) -> None:
        """Coalesced write after a streamed update."""
        if self._on_progress is None:
            return
        now = self._clock()
        recent = self._last_write is not None and now - self._last_write < MIN_WRITE_INTERVAL_S
        if recent or self._backing_off():
            self._dirty = True
            return
        self._emit(forced=False)

    def flush(self) -> None:
        """Write a pending coalesced update, unless writes are backing off."""
        if self._dirty and not self._backing_off():
            self._emit(forced=False)

    def reveal(self) -> None:
        """Emit the initial all-queued office frame the instant the run starts."""
        self._emit("running")

    def start(self, stage_id: str) -> None:
        """Mark a stage working (after checking for cancel) and write the record."""
        self.check_cancelled()
        self._statuses[stage_id] = _WORKING
        self._started[stage_id] = self.elapsed()
        self._detail = None
        self._emit(stage_id)

    def detail(self, stage_id: str, text: str) -> None:
        """Emit a live sub-step frame for a WORKING stage.

        Sets the stage WORKING (idempotent, so a stage can stream several detail
        frames between its ``start`` and ``finish``) and emits with the detail
        string attached to that stage. The text can carry request values (a
        technology name), so the page must treat it as untrusted.
        """
        self._statuses[stage_id] = _WORKING
        self._started.setdefault(stage_id, self.elapsed())
        self._detail = clip_words(text, CAP_REASON)
        self._emit(stage_id)

    def finish(self, stage_id: str) -> None:
        """Mark a stage done and write the record."""
        self._statuses[stage_id] = _DONE
        self._finished[stage_id] = self.elapsed()
        self._detail = None
        self.deck.clear_live()
        self._emit(stage_id)

    def _resolve(self, stage_id: str, status: str, reason: str) -> None:
        now = self.elapsed()
        self._statuses[stage_id] = status
        self._reasons[stage_id] = clip_words(reason, CAP_REASON)
        self._started.setdefault(stage_id, now)
        self._finished[stage_id] = now
        self._detail = None
        self.deck.clear_live()
        self._emit(stage_id)

    def skip(self, stage_id: str, reason: str) -> None:
        """Mark a stage skipped (``fallback``) with a plain reason."""
        self._resolve(stage_id, _FALLBACK, reason)

    def error(self, stage_id: str, reason: str) -> None:
        """Mark a stage failed (``error``) with a plain reason."""
        self._resolve(stage_id, _ERROR, reason)

    def nvd_answer(self, tech: str, version: str, lookup: NvdLookup | None, state: str) -> None:
        """Record one technology's answer in the deck and write it now, with
        a stage detail line that carries both numbers. ``state`` is
        ``unknown`` (NVD has no entry) or ``failed`` when ``lookup`` is None.
        The write is forced, so each answer shows as it arrives."""
        if lookup is None:
            self.deck.add_nvd_lookup(tech, version, state, 0, 0, [])
            line = f"{tech}: NVD has no entry" if state == "unknown" else f"{tech}: lookup did not finish"
        else:
            returned = lookup_count(lookup.returned)
            at_least = "at least " if lookup.truncated else ""
            line = (f"{tech}: NVD returned {at_least}{returned}, {len(lookup.items)} passed on" if returned
                    else f"{tech}: NVD returned none")
            self.deck.add_nvd_lookup(
                tech,
                version,
                "found" if lookup.returned else "none",
                lookup.returned,
                len(lookup.items),
                [(item.id, item.score) for item in lookup.items],
            )
        self.detail("nvd", line)

    def otx_answer(self, sector: str, lookup: OtxLookup | None) -> None:
        """Record the OTX answer (None: the lookup failed) in the deck. The
        stage's finish or error, which follows, writes it."""
        if lookup is None:
            self.deck.set_otx_lookup(sector, "failed", 0, 0, [])
            return
        self.deck.set_otx_lookup(
            sector,
            lookup.state,
            lookup.returned,
            len(lookup.pulses),
            [(pulse.get("name"), pulse.get("modified")) for pulse in lookup.pulses if isinstance(pulse, dict)],
            at_least=lookup.capped,
        )

    def stream(self, stage_id: str) -> Callable[[str], None] | None:
        """``on_text`` for a model call in ``stage_id``, or None with no callback."""
        if self._on_progress is None:
            return None
        return StageStream(stage_id, self.deck, self.changed)

    def mapped(self, threats: list[dict[str, Any]]) -> Callable[[int, dict, dict | None], None] | None:
        """Per-threat callback for the MITRE mapping loop."""
        if self._on_progress is None:
            return None
        ids = [str(t.get("ID") or "") for t in threats]
        if ids:
            self.deck.set_live("mitre_map", ids[0], "")

        def on_mapped(index: int, threat: dict, technique: dict | None) -> None:
            self.deck.add_technique(str(threat.get("ID") or ""), technique)
            nxt = ids[index + 1] if index + 1 < len(ids) else None
            self.deck.set_live("mitre_map", nxt, "")
            self.changed()

        return on_mapped


@dataclass
class EnrichmentBundle:
    """External-intel + pattern context shared by the linear and agentic paths.

    Both ``run_threat_model_workflow`` and the agentic orchestrator gather the
    same NVD / OTX / pattern / threat-card context before any model call so
    the STRIDE prompt is identical regardless of which path runs. Extracted so
    the two paths cannot drift.
    """

    nvd_vulnerabilities: dict[str, str] = field(default_factory=dict)
    otx_vulnerabilities: str = ""
    detected_patterns: list[str] = field(default_factory=list)
    pattern_source: str = "none"
    extra_cards: list[Any] = field(default_factory=list)


def _display(record: Callable[..., None], *args: Any) -> None:
    """Record a lookup's answer for the live view. Display only: an error
    here is logged and the run carries on with the same prompt inputs."""
    try:
        record(*args)
    # Display only: whatever goes wrong here, the run's inputs are unchanged.
    except Exception as exc:
        logger.warning("Lookup display record failed: %s", type(exc).__name__)


def gather_enrichment(
    *,
    nvd_api_key: str | None,
    otx_api_key: str | None,
    app_details: dict[str, Any],
    app_description: str,
    settings: Settings,
    emitter: _StageEmitter | None = None,
    safeguards: Safeguards | None = None,
) -> EnrichmentBundle:
    """Run NVD search, OTX fetch, pattern detection, and threat-card lookup.

    Shared by both paths so the agentic orchestrator makes exactly the same
    calls in the same order. A lookup that fails never stops the run.

    When an ``emitter`` is supplied, the three enrichment stages (serialize,
    NVD, OTX) emit queued -> working -> done through it so the live view
    animates them. The agentic path calls without one.

    NVD and OTX text is screened as ``Source.LOOKUP`` and
    ``Source.THREAT_INTEL`` before it can reach a prompt (``safeguards``
    None builds them from ``settings``). Screening sits outside the
    best-effort blocks, so a strict-mode stop is never read as a failed
    lookup.
    """
    sg = safeguards if safeguards is not None else Safeguards.from_settings(settings)

    nvd_vulnerabilities: dict[str, str] = {}
    selected_technologies = app_details.get("selected_technologies", {})
    selected_versions = app_details.get("selected_versions", {})

    # Stage 1: serializing the app profile + selected technologies (the cheap
    # profile extraction that precedes any upstream call).
    if emitter:
        emitter.start("serialize")
        emitter.detail("serialize", f"Extracting {len(selected_technologies)} selected technologies")
        emitter.finish("serialize")

    nvd_off = lookup_off_reason("nvd", settings)
    if emitter and nvd_off:
        emitter.skip("nvd", nvd_off)
    elif emitter and not nvd_api_key:
        emitter.skip("nvd", REASON_NO_NVD_KEY)
    elif emitter and not selected_technologies:
        emitter.skip("nvd", REASON_NO_TECH)
    elif emitter:
        emitter.start("nvd")
    if nvd_api_key and selected_technologies and not nvd_off:
        nvd_config = NvdSearchConfig(
            max_retries=LOOKUP_MAX_RETRIES,
            base_delay_seconds=LOOKUP_RETRY_BASE_DELAY_S,
            top_n=NVD_TOP_N,
        )
        failed = 0
        for tech, cpe_name in selected_technologies.items():
            state = "failed"
            version = selected_versions.get(tech, "*")
            if emitter:
                emitter.detail("nvd", f"Checking {tech} {version}")
            lookup: NvdLookup | None = None
            vulnerabilities = ""
            try:
                lookup = lookup_nvd(
                    api_key=nvd_api_key,
                    cpe_prefix=cpe_name,
                    version=version,
                    config=nvd_config,
                )
                vulnerabilities = nvd_text(
                    lookup,
                    tech=tech,
                    category=app_details.get("app_type", ""),
                    version=version,
                )
            # Best effort: one technology's lookup failing, in any way, must
            # not stop the others or the run. Logged by class only (the
            # exception text could quote the key).
            except Exception as exc:
                lookup = None
                # NVD has no entry for this product and version: an answer
                state = "unknown" if isinstance(exc, NoCpeMatch) else "failed"
                if state == "failed":
                    failed += 1
                logger.warning("nvd_lookup_failed kind=%s state=%s", type(exc).__name__, state)
            if vulnerabilities:
                nvd_vulnerabilities[f"{tech} {version}"] = sg.screen(
                    Source.LOOKUP, clip_lookup_text(vulnerabilities, NVD_CLIPPED_NOTE))
            if emitter:
                _display(emitter.nvd_answer, str(tech), str(version), lookup, state)

        if emitter:
            # Every lookup failed: the step did not do its job, so it must not
            # read Done. The run carries on exactly as before.
            if failed and failed == len(selected_technologies):
                emitter.error("nvd", REASON_NVD_FAILED)
            else:
                emitter.finish("nvd")

    otx_vulnerabilities = ""
    otx_off = lookup_off_reason("otx", settings)
    if otx_api_key and otx_off:
        # Switched off with a key set: no call, the same "off" answer and
        # prompt sentence the lookup gives in offline mode, and a skipped stage.
        sector = app_details.get("industry_sector", "")
        off = OtxLookup(state="off")
        otx_vulnerabilities = otx_text(off, sector)
        if emitter:
            _display(emitter.otx_answer, str(sector), off)
    if emitter and otx_off:
        emitter.skip("otx", otx_off)
    elif emitter and not otx_api_key:
        emitter.skip("otx", REASON_NO_OTX_KEY)
    if otx_api_key and not otx_off:
        if emitter:
            emitter.start("otx")
            emitter.detail("otx", f"Fetching {app_details.get('industry_sector', '')} sector pulses")
        sector = app_details.get("industry_sector", "")
        otx_lookup: OtxLookup | None = None
        try:
            otx_lookup = lookup_otx(
                api_key=otx_api_key,
                industry=sector,
                days=OTX_DAYS,
                max_results=OTX_MAX_RESULTS,
                max_retries=LOOKUP_MAX_RETRIES,
                base_delay_seconds=LOOKUP_RETRY_BASE_DELAY_S,
                offline=settings.offline,
            )
            otx_vulnerabilities = otx_text(otx_lookup, sector)
        # Best effort, as for NVD: logged by class only.
        except Exception as exc:
            otx_lookup = None
            otx_vulnerabilities = ""
            logger.warning("otx_lookup_failed kind=%s", type(exc).__name__)
        otx_vulnerabilities = sg.screen(Source.THREAT_INTEL, clip_lookup_text(otx_vulnerabilities, OTX_CLIPPED_NOTE))
        if emitter:
            _display(emitter.otx_answer, str(sector), otx_lookup)
            if otx_lookup is None:
                emitter.error("otx", REASON_OTX_FAILED)
            elif otx_lookup.state == "off":
                # the step did nothing, so it reads skipped, not Done
                emitter.skip("otx", REASON_OTX_OFF)
            else:
                emitter.finish("otx")

    explicit_patterns = app_details.get("app_pattern", []) or []
    if explicit_patterns:
        detected_patterns = list(explicit_patterns)
        pattern_source = "user"
    else:
        detection = detect_patterns(app_description)
        detected_patterns = detection.patterns
        pattern_source = detection.method if detection.patterns else "none"
    extra_cards = cards_for_app(
        app_type=app_details["app_type"],
        patterns=detected_patterns,
    )

    return EnrichmentBundle(
        nvd_vulnerabilities=nvd_vulnerabilities,
        otx_vulnerabilities=otx_vulnerabilities,
        detected_patterns=detected_patterns,
        pattern_source=pattern_source,
        extra_cards=extra_cards,
    )


def run_threat_model_workflow(
    *,
    llm: LLMClient,
    settings: Settings,
    nvd_api_key: str | None,
    otx_api_key: str | None,
    app_details: dict[str, Any],
    app_description: str,
    on_progress: Callable[[dict[str, Any]], None] | None = None,
    addons: list[str] | None = None,
    cancelled: Callable[[], bool] | None = None,
    clock: Callable[[], float] | None = None,
    safeguards: Safeguards | None = None,
) -> dict[str, Any]:
    """Run the linear threat-model pipeline.

    ``addons`` None (the request did not name any) runs stages 1 to 8 and
    leaves 9 to 11 queued for the page. A list, even empty, means the run owns
    all eleven: the listed add-ons run after the markdown stage in the order
    mitigations, DREAD, test cases, and the others are skipped as "Not
    selected". ``cancelled`` is checked at every stage start (see
    ``RunCancelled``); ``clock`` is the run clock, a seam for tests.

    Every model call goes through ``safeguards.wrap`` (None builds them from
    ``settings``) and the record is the result's ``REPORT_KEY``. The
    description is expected to be screened already (``run.prepare_description``).
    """
    sg = safeguards if safeguards is not None else Safeguards.from_settings(settings)
    llm = sg.wrap(llm)
    architect_model = settings.architect_model
    worker_model = settings.worker_model

    # The emitter pushes queued -> working -> done through ``on_progress`` as
    # the run crosses each stage it owns. With no ``on_progress`` nothing is
    # written and the model calls do not stream.
    emitter = _StageEmitter(on_progress, clock=clock, cancelled=cancelled)
    emitter.reveal()
    if addons is not None:
        emitter.own_addons()
        for stage_id in _ADDON_STAGE_IDS:
            if stage_id not in addons:
                emitter.skip(stage_id, REASON_NOT_SELECTED)

    enrichment = gather_enrichment(
        nvd_api_key=nvd_api_key,
        otx_api_key=otx_api_key,
        app_details=app_details,
        app_description=app_description,
        settings=settings,
        emitter=emitter,
        safeguards=sg,
    )
    nvd_vulnerabilities = enrichment.nvd_vulnerabilities
    otx_vulnerabilities = enrichment.otx_vulnerabilities

    prompt = create_threat_model_prompt(
        app_type=app_details["app_type"],
        authentication=app_details.get("authentication", []),
        internet_facing=app_details["internet_facing"],
        industry_sector=app_details["industry_sector"],
        sensitive_data=app_details["sensitive_data"],
        app_input=app_description,
        nvd_vulnerabilities=nvd_vulnerabilities,
        otx_data=otx_vulnerabilities,
        technical_ability=app_details.get("technical_ability", "Medium"),
        extra_cards=enrichment.extra_cards,
        app_details=app_details,
    )

    emitter.start("stride")
    emitter.detail("stride", "Writing STRIDE threats")
    threat_model, suggestions = generate_threat_model(
        llm, architect_model, prompt, on_text=emitter.stream("stride")
    )
    assign_threat_ids(threat_model)
    emitter.deck.final_threats(threat_model)
    emitter.finish("stride")

    patterns = enrichment.detected_patterns
    ai_system = is_ai_system(app_details["app_type"], patterns)
    if ai_system:
        emitter.relabel(AI_STAGE_TEXT)
    emitter.start("mitre_load")
    emitter.detail("mitre_load", "Loading MITRE ATT&CK and ATLAS catalogs" if ai_system
                   else "Loading MITRE ATT&CK corpus")
    catalog = catalog_for_app_type(app_details["app_type"], patterns)
    emitter.finish("mitre_load")
    enriched_details = dict(app_details)
    enriched_details["app_input"] = app_description
    emitter.start("mitre_map")
    emitter.detail("mitre_map", f"Mapping {len(threat_model)} threats to ATT&CK")
    mitre_data = process_mitre_attack_data(
        threat_model,
        enriched_details,
        llm,
        worker_model,
        catalog=catalog,
        on_mapped=emitter.mapped(threat_model),
    )
    emitter.deck.final_techniques(mitre_data)
    atlas: dict[str, Any] | None = None
    if ai_system:
        emitter.detail("mitre_map", f"Picking ATLAS techniques for {len(threat_model)} threats in one request")
        atlas = atlas_step(threat_model, app_details, patterns, llm, worker_model)
    emitter.finish("mitre_map")

    attack_tree_prompt = create_attack_tree_prompt(
        app_type=app_details["app_type"],
        authentication=app_details.get("authentication", []),
        internet_facing=app_details["internet_facing"],
        sensitive_data=app_details["sensitive_data"],
        mitre_data=mitre_data,
        nvd_vulnerabilities=nvd_vulnerabilities,
        otx_vulnerabilities=otx_vulnerabilities,
        app_input=app_description,
    )
    emitter.start("attack_tree")
    emitter.detail("attack_tree", "Building Mermaid attack tree")
    attack_tree_code = get_attack_tree(
        llm, architect_model, attack_tree_prompt, on_text=emitter.stream("attack_tree")
    )
    emitter.deck.final_tree(attack_tree_code)
    emitter.finish("attack_tree")

    emitter.start("markdown")
    emitter.detail("markdown", "Rendering markdown tables")
    threat_model_markdown = threat_model_to_markdown(threat_model, [])
    mitre_attack_markdown = mitre_data_to_markdown(mitre_data)
    nvd_vulnerabilities_markdown = nvd_to_markdown(nvd_vulnerabilities)
    improvement_suggestions_markdown = (
        "\n".join(f"- {s.strip()}" for s in suggestions) or "No improvement suggestions provided."
    )
    emitter.finish("markdown")

    addon_results = (
        _run_addons(
            addons,
            emitter=emitter,
            llm=llm,
            model=architect_model,
            threats_markdown=threat_model_markdown,
            mitre_markdown=mitre_attack_markdown,
            nvd_markdown=nvd_vulnerabilities_markdown,
            atlas_reference=mitigation_reference(atlas) or None,
        )
        if addons is not None
        else {}
    )

    result: dict[str, Any] = {
        "threat_model": threat_model,
        "improvement_suggestions": suggestions,
        "improvement_suggestions_markdown": improvement_suggestions_markdown,
        "threat_model_markdown": threat_model_markdown,
        "mitre_data": mitre_data,
        "mitre_attack_markdown": mitre_attack_markdown,
        "nvd_vulnerabilities_markdown": nvd_vulnerabilities_markdown,
        "otx_data_markdown": otx_vulnerabilities,
        "attack_tree_code": attack_tree_code,
        "detected_patterns": enrichment.detected_patterns,
        "pattern_source": enrichment.pattern_source,
        **addon_results,
    }
    if atlas is not None:
        result[ATLAS_RESULT_KEY] = atlas
    result[REPORT_KEY] = sg.report()
    return result


def _run_addons(
    addons: list[str],
    *,
    emitter: _StageEmitter,
    llm: LLMClient,
    model: str,
    threats_markdown: str,
    mitre_markdown: str,
    nvd_markdown: str,
    atlas_reference: str | None = None,
) -> dict[str, Any]:
    """Run the selected add-ons with the inputs the page's add-on calls take.

    An add-on that fails does not fail the job: its stage reads ``error``
    with a plain reason and its keys are left out of the result. A cancel
    still stops the run.
    """
    results: dict[str, Any] = {}
    for stage_id in _ADDON_STAGE_IDS:
        if stage_id not in addons:
            continue
        emitter.start(stage_id)
        try:
            part = _run_addon(
                stage_id,
                llm=llm,
                model=model,
                threats_markdown=threats_markdown,
                mitre_markdown=mitre_markdown,
                nvd_markdown=nvd_markdown,
                on_text=emitter.stream(stage_id),
                atlas_reference=atlas_reference,
            )
        # An add-on can fail in any way (model, parse, display); the core
        # result is already complete, so the run carries on without it.
        except Exception as exc:
            logger.warning("threat_model_addon_failed stage=%s kind=%s", stage_id, type(exc).__name__)
            emitter.deck.drop_addon(stage_id)
            # The safeguards' sentence says why; any other failure stays plain.
            emitter.error(stage_id, str(exc) if isinstance(exc, SafeguardsStopped) else REASON_ADDON_FAILED)
            continue
        if stage_id == "mitigations":
            emitter.deck.final_fixes(part["mitigations_markdown"])
        elif stage_id == "dread":
            emitter.deck.final_scores(part["dread_assessment"])
        else:
            emitter.deck.final_tests(part["test_cases_markdown"])
        results.update(part)
        emitter.finish(stage_id)
    return results


def _run_addon(
    stage_id: str,
    *,
    llm: LLMClient,
    model: str,
    threats_markdown: str,
    mitre_markdown: str,
    nvd_markdown: str,
    on_text: Callable[[str], None] | None,
    atlas_reference: str | None = None,
) -> dict[str, Any]:
    """One add-on's result keys. ``atlas_reference`` (an AI system's mapped
    ATLAS techniques and mitigation names) goes to the mitigations step only."""
    if stage_id == "mitigations":
        markdown = generate_mitigations(
            llm, model, threats_markdown, mitre_markdown, nvd_markdown, on_text=on_text,
            atlas_reference=atlas_reference,
        )
        return {"mitigations_markdown": markdown}
    if stage_id == "dread":
        assessment = generate_dread_assessment(
            llm, model, threats_markdown, mitre_markdown, nvd_markdown, on_text=on_text
        )
        return {
            "dread_assessment": assessment,
            "dread_assessment_markdown": dread_json_to_markdown(assessment),
        }
    markdown = generate_test_cases(llm, model, threats_markdown, on_text=on_text)
    return {"test_cases_markdown": markdown}
