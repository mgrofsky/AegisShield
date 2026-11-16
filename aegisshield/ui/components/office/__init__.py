"""The live agentic "office" view as a Streamlit component.

The office's model is roster.js (desk layout, status, and tween math, with no
DOM) and its view is office_vector.js (an SVG and DOM renderer); office.css
holds its styles, every rule scoped to the component's wrapper. This module
bundles them with the shim (shim.js) into one ES module string when
it is imported, and registers it with ``st.components.v2.component``. No
Node build is needed. It follows the deck component's pattern
(``aegisshield/ui/components/deck``).

Only :func:`render_office` is public.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from pathlib import Path
from typing import Any

import streamlit as st

__all__ = ["render_office"]

_DIR = Path(__file__).resolve().parent
_COMPONENT_NAME = "aegis_office"

_JOB_STATUS = frozenset({"idle", "queued", "running", "complete", "failed", "cancelled"})
_ERROR_MAX = 600

# office_vector.js imports exactly these names from roster.js, over several
# lines; the bundler removes the import and binds the names in its scope.
_VIEW_IMPORT = (
    "import {\n"
    "  advanceDeskAnim,\n"
    "  allDeskAnimsSettled,\n"
    "  isTerminalStatus,\n"
    "  staggerDelayMs,\n"
    "  officeFracPos,\n"
    "  officeEdges,\n"
    '} from "./roster.js";\n'
)
_SHIM_IMPORTS = (
    'import { buildDeskModel, DESK_SLOTS, isAgenticProgress } from "./roster.js";\n',
    'import { officeRenderInit, officeRenderSync, officeRenderHide } from "./office_vector.js";\n',
)
_EXPORT_RE = re.compile(r"^export (async function|function|const|let|class) ([A-Za-z_$][\w$]*)", re.M)


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
    """roster.js, office_vector.js, and the shim as one ES module.

    Each source file keeps its own function scope. office_vector.js gets the
    probe's frame functions in place of the window ones, which counts its
    frames without editing it.
    """
    roster, roster_names = _unexport(_read("roster.js"), "roster.js")
    if re.search(r"^\s*import\s", roster, re.M):
        raise RuntimeError("roster.js: an import the bundler does not handle")

    view = _read("office_vector.js")
    if view.count(_VIEW_IMPORT) != 1 or len(re.findall(r"^import\s", view, re.M)) != 1:
        raise RuntimeError("office_vector.js: the roster.js import changed")
    view, view_names = _unexport(view.replace(_VIEW_IMPORT, ""), "office_vector.js")

    shim = _read("shim.js")
    for line in _SHIM_IMPORTS:
        if shim.count(line) != 1:
            raise RuntimeError("shim.js: an import line changed")
        shim = shim.replace(line, "")
    if re.search(r"^\s*import\s", shim, re.M):
        raise RuntimeError("shim.js: an import the bundler does not handle")

    view_prelude = (
        "const { advanceDeskAnim, allDeskAnimsSettled, isTerminalStatus, staggerDelayMs, "
        "officeFracPos, officeEdges } = __aegisOfficeModel;\n"
        "const requestAnimationFrame = __aegisProbe.requestFrame;\n"
        "const cancelAnimationFrame = __aegisProbe.cancelFrame;\n"
    )
    shim_prelude = (
        "const { buildDeskModel, DESK_SLOTS, isAgenticProgress } = __aegisOfficeModel;\n"
        "const { officeRenderInit, officeRenderSync, officeRenderHide } = __aegisOfficeView;\n"
    )
    return (
        "// Bundled at import time by aegisshield/ui/components/office/__init__.py\n"
        + _read("probe.js")
        + _scope("__aegisOfficeModel", roster, roster_names)
        + _scope("__aegisOfficeView", view, view_names, view_prelude)
        + shim_prelude
        + shim
    )


def _bundle_css() -> str:
    return _read("office.css") + "\n" + _read("host.css")


_OFFICE = st.components.v2.component(
    _COMPONENT_NAME,
    css=_bundle_css(),
    js=_bundle_js(),
    # office_vector.js finds its mount and its panel with
    # document.getElementById, which cannot see into a shadow root. Every
    # office rule is scoped to .aegis-office-root instead.
    isolate_styles=False,
)


def _unpack(record: dict | None) -> tuple[str, str | None, dict | None, Any]:
    """(status, error, progress, run id) from a record.

    ``record`` is the job as a poll returns it: ``{"status", "error",
    "progress"}`` with an optional ``"id"`` (or ``"job_id"``), or a bare
    progress record. ``None`` shows the idle preview.
    """
    if record is None:
        return "idle", None, None, None
    if not isinstance(record, dict):
        raise TypeError("render_office: record must be a dict or None")
    if "progress" in record or ("status" in record and "agents" not in record):
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


def render_office(record: dict | None, *, key: str = "office") -> None:
    """Show the office for one agentic threat model job.

    Call it on every rerun (a fragment with ``run_every`` works) with the
    job's latest poll body ``{"id", "status", "error", "progress"}``. The
    office mounts once per ``key`` and keeps its animation going across
    reruns; the page is called again only when the record changes.
    One office per page: the view is a module singleton.
    """
    status, error, progress, run = _unpack(record)
    payload: dict[str, Any] = {"status": status, "error": error, "progress": progress, "run": run}

    # A sequence number that moves only when the payload does, so the page
    # can drop a superseded call that lands late. The nonce names this
    # counter: a new session or cleared state starts a new one. Same scheme
    # as the deck.
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
    slot = f"_aegis_office_seq::{key}"
    last = st.session_state.get(slot)
    if last:
        nonce, last_digest, last_seq = last
        seq = last_seq if last_digest == digest else last_seq + 1
    else:
        nonce, seq = secrets.token_hex(8), 0
    st.session_state[slot] = (nonce, digest, seq)
    payload["seq"] = seq
    payload["nonce"] = nonce

    _OFFICE(data=payload, key=key)
