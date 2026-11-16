"""The live "agents at work" deck as a Streamlit component.

The deck's model is deck.js (pure pacing and view-model logic), its view is
deck_view.js (DOM and one canvas), and its styles are deck.css. This module
bundles them with the shim (shim.js) into one ES module string when it is imported, and
registers it with ``st.components.v2.component``. No Node build is needed.

Only :func:`render_deck` is public.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from pathlib import Path
from typing import Any

import streamlit as st

__all__ = ["render_deck"]

_DIR = Path(__file__).resolve().parent
_COMPONENT_NAME = "aegis_deck"

# The canonical stage list, used for the idle and queued previews before a
# job has written its first record. Same ids, names, and order as the
# stages deck.js expects, with the provider named generically in the
# labels.
_STAGES: tuple[dict[str, str], ...] = (
    {"id": "serialize", "name": "Intake", "term": "profile and technology list",
     "label": "Serializing app profile and selected technologies", "phase": "enrichment"},
    {"id": "nvd", "name": "Vulnerability lookup", "term": "NVD",
     "label": "Querying NVD for CVEs on selected technology versions", "phase": "enrichment"},
    {"id": "otx", "name": "Threat intelligence", "term": "AlienVault OTX",
     "label": "Querying AlienVault OTX for sector threat pulses", "phase": "enrichment"},
    {"id": "stride", "name": "Threat writer", "term": "STRIDE",
     "label": "Calling the model for STRIDE threat generation", "phase": "modeling"},
    {"id": "mitre_load", "name": "Technique library", "term": "MITRE ATT&CK catalog",
     "label": "Loading MITRE ATT&CK STIX corpus (enterprise/mobile/ICS)", "phase": "modeling"},
    {"id": "mitre_map", "name": "Technique mapper", "term": "MITRE ATT&CK mapping",
     "label": "Mapping each threat to its most relevant ATT&CK technique", "phase": "modeling"},
    {"id": "attack_tree", "name": "Attack path builder", "term": "attack tree",
     "label": "Generating Mermaid attack tree from the enriched model", "phase": "modeling"},
    {"id": "markdown", "name": "Report assembler", "term": "tables",
     "label": "Rendering markdown tables for downstream steps", "phase": "modeling"},
    {"id": "mitigations", "name": "Fix planner", "term": "mitigations",
     "label": "Calling the model for mitigation recommendations", "phase": "scoring"},
    {"id": "dread", "name": "Risk scorer", "term": "DREAD",
     "label": "Calling the model for DREAD risk scoring", "phase": "scoring"},
    {"id": "test_cases", "name": "Test author", "term": "validation tests",
     "label": "Calling the model for Gherkin test cases", "phase": "validation"},
)

_JOB_STATUS = frozenset({"idle", "queued", "running", "complete", "failed", "cancelled"})
_ERROR_MAX = 600

# deck_view.js imports exactly these names from deck.js.
_VIEW_IMPORT = 'import { createDeckFeed, fmtClock, MAX_PIPS, nvdLink } from "./deck.js";\n'
_SHIM_IMPORTS = (
    'import { isDeckProgress } from "./deck.js";\n',
    'import { deckInit, deckSync, deckHide } from "./deck_view.js";\n',
)
_EXPORT_RE = re.compile(r"^export (function|const|let|class) ([A-Za-z_$][\w$]*)", re.M)


def _read(name: str) -> str:
    return (_DIR / name).read_text(encoding="utf-8")


def _unexport(source: str, name: str) -> tuple[str, list[str]]:
    """Drop the column-0 ``export`` keywords and return the exported names."""
    names = [m.group(2) for m in _EXPORT_RE.finditer(source)]
    if not names:
        raise RuntimeError(f"{name}: no exports found")
    if re.search(r"^export\s+(default|\{|\*)", source, re.M):
        raise RuntimeError(f"{name}: an export form the bundler does not handle")
    stripped = _EXPORT_RE.sub(r"\1 \2", source)
    if re.search(r"^\s*export\s", stripped, re.M):
        raise RuntimeError(f"{name}: an export was left behind")
    return stripped, names


def _scope(var: str, body: str, names: list[str], prelude: str = "") -> str:
    exported = ", ".join(names)
    return f"const {var} = (() => {{\n{prelude}{body}\nreturn {{ {exported} }};\n}})();\n"


def _bundle_js() -> str:
    """deck.js, deck_view.js, and the shim as one ES module.

    Each source file keeps its own function scope (both define helpers with
    the same names, such as ``clamp``). deck_view.js gets the probe's frame
    functions in place of the window ones, which counts its frames without
    editing it.
    """
    deck, deck_names = _unexport(_read("deck.js"), "deck.js")

    view = _read("deck_view.js")
    if view.count(_VIEW_IMPORT) != 1 or view.count("import ") != 1:
        raise RuntimeError("deck_view.js: the deck.js import line changed")
    view, view_names = _unexport(view.replace(_VIEW_IMPORT, ""), "deck_view.js")

    shim = _read("shim.js")
    for line in _SHIM_IMPORTS:
        if shim.count(line) != 1:
            raise RuntimeError("shim.js: an import line changed")
        shim = shim.replace(line, "")
    if "\nimport " in shim:
        raise RuntimeError("shim.js: an import the bundler does not handle")

    view_prelude = (
        "const { createDeckFeed, fmtClock, MAX_PIPS, nvdLink } = __aegisDeckModel;\n"
        "const requestAnimationFrame = __aegisProbe.requestFrame;\n"
        "const cancelAnimationFrame = __aegisProbe.cancelFrame;\n"
        "const document = __aegisHooks.document;\n"
        "const ResizeObserver = __aegisHooks.ResizeObserver;\n"
    )
    shim_prelude = (
        "const { isDeckProgress } = __aegisDeckModel;\n"
        "const { deckInit, deckSync, deckHide } = __aegisDeckView;\n"
    )
    return (
        "// Bundled at import time by aegisshield/ui/components/deck/__init__.py\n"
        + _read("probe.js")
        + _read("hooks.js")
        + _scope("__aegisDeckModel", deck, deck_names)
        + _scope("__aegisDeckView", view, view_names, view_prelude)
        + shim_prelude
        + shim
    )


def _bundle_css() -> str:
    return _read("deck.css") + "\n" + _read("host.css")


_DECK = st.components.v2.component(
    _COMPONENT_NAME,
    css=_bundle_css(),
    js=_bundle_js(),
    # The view reads document.activeElement and tests host.contains() on
    # document events, which a shadow root would retarget. deck.css scopes
    # every deck rule to .dk / dk- classes.
    isolate_styles=False,
)


def _is_deck_progress(progress: Any) -> bool:
    # deck.js isDeckProgress
    return isinstance(progress, dict) and progress.get("office") is True and isinstance(progress.get("deck"), dict)


def _unpack(record: dict | None) -> tuple[str, str | None, dict | None, Any]:
    """(status, error, progress, run id) from a record.

    ``record`` is either the job's progress record itself, or the job as a
    poll returns it: ``{"status", "error", "progress"}`` with an optional
    ``"id"`` (or ``"job_id"``). ``None`` shows the idle preview.
    """
    if record is None:
        return "idle", None, None, None
    if not isinstance(record, dict):
        raise TypeError("render_deck: record must be a dict or None")
    if "progress" in record or ("status" in record and "stages" not in record):
        status = record.get("status")
        progress = record.get("progress")
        run = record.get("id", record.get("job_id"))
        error = record.get("error")
    else:
        progress = record
        status = "complete" if record.get("current") == "complete" else "running"
        run = None
        error = None
    if status not in _JOB_STATUS:
        status = "running"
    if not isinstance(progress, dict):
        progress = None
    if run is not None and not isinstance(run, (str, int)):
        run = str(run)
    error = str(error)[:_ERROR_MAX] if error else None
    return status, error, progress, run


def render_deck(record: dict | None, *, key: str = "deck") -> None:
    """Show the deck for one threat model job.

    Call it on every rerun (a fragment with ``run_every`` works) with the
    job's latest record. The deck mounts once per ``key`` and keeps its
    animation going across reruns; the page is called again only when the
    record changes.
    One deck per page: the view is a module singleton.
    """
    status, error, progress, run = _unpack(record)
    payload: dict[str, Any] = {"status": status, "error": error, "progress": progress, "run": run}
    if not _is_deck_progress(progress):
        payload["stages"] = [dict(s) for s in _STAGES]

    # A sequence number that moves only when the payload does, so the page
    # can drop a superseded call that lands late. The nonce names this
    # counter: a new session or cleared state starts a new one, and the page
    # resets its high mark when the nonce changes. An unchanged payload gives
    # the same data, so the page is not called again, though Streamlit still
    # sends the element on every rerun.
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
    slot = f"_aegis_deck_seq::{key}"
    last = st.session_state.get(slot)
    if last:
        nonce, last_digest, last_seq = last
        seq = last_seq if last_digest == digest else last_seq + 1
    else:
        nonce, seq = secrets.token_hex(8), 0
    st.session_state[slot] = (nonce, digest, seq)
    payload["seq"] = seq
    payload["nonce"] = nonce

    _DECK(data=payload, key=key)
