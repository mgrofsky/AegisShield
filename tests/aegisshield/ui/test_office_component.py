"""Tests for the office component (aegisshield/ui/components/office)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import aegisshield.ui.components.office as office
from aegisshield.pipeline.agentic_threat_model import AGENT_ROLES

ROOT = Path(__file__).resolve().parents[3]
OFFICE_DIR = ROOT / "aegisshield" / "ui" / "components" / "office"
FIXTURE = ROOT / "tests" / "fixtures" / "office_replay.json"
NODE_TESTS = Path(__file__).with_name("office_roster.test.mjs")

COMPONENT_FILES = [
    *sorted(OFFICE_DIR.glob("*.py")),
    *sorted(OFFICE_DIR.glob("*.js")),
    *sorted(OFFICE_DIR.glob("*.css")),
    *sorted(OFFICE_DIR.glob("*.md")),
    ROOT / "tools" / "build_office_replay.py",
    ROOT / "tools" / "browser_check.py",
    NODE_TESTS,
    Path(__file__),
]

DASHES = re.compile("[\\u2013\\u2014]")


# Roster ---------------------------------------------------------------------------


def test_every_agent_the_pipeline_can_plan_has_a_desk():
    roster = (OFFICE_DIR / "roster.js").read_text(encoding="utf-8")
    ring = re.search(r"^const RING_IDS = \[(.*)\];$", roster, re.M)
    assert ring is not None
    ids = re.findall(r'"([a-z_]+)"', ring.group(1))
    assert ids == [role.agent_id for role in AGENT_ROLES.values()]
    for role in AGENT_ROLES.values():
        assert f'role: "{role.role}"' in roster, role.role


# Static checks on the office scripts -------------------------------------------


def test_roster_lib_is_dom_free():
    roster = (OFFICE_DIR / "roster.js").read_text(encoding="utf-8")
    for forbidden in ("document.", "innerHTML", "getContext", "window."):
        assert forbidden not in roster, forbidden


def test_roster_lib_handles_every_status():
    roster = (OFFICE_DIR / "roster.js").read_text(encoding="utf-8")
    for status in ("queued", "working", "done", "fallback", "error"):
        assert f'"{status}"' in roster


def test_vector_office_is_csp_clean_no_innerhtml_no_eval():
    view = (OFFICE_DIR / "office_vector.js").read_text(encoding="utf-8")
    for forbidden in ("innerHTML", "eval(", "new Function", "cdn.jsdelivr.net", "unpkg.com", "getContext"):
        assert forbidden not in view, forbidden


def test_vector_office_exposes_the_renderer_contract():
    view = (OFFICE_DIR / "office_vector.js").read_text(encoding="utf-8")
    for fn in ("officeRenderInit", "officeRenderSync", "officeRenderHide", "officeRenderReady"):
        assert f"export function {fn}" in view or f"export async function {fn}" in view


def test_shim_and_probe_never_use_inner_html():
    for name in ("shim.js", "probe.js"):
        text = (OFFICE_DIR / name).read_text(encoding="utf-8")
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            assert sink not in text, (name, sink)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_roster_node_tests_pass(tmp_path):
    shutil.copy(OFFICE_DIR / "roster.js", tmp_path / "roster.mjs")
    shutil.copy(NODE_TESTS, tmp_path / NODE_TESTS.name)
    done = subprocess.run(
        ["node", "--test", str(tmp_path / NODE_TESTS.name)], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stdout[-3000:] + done.stderr[-2000:]
    assert re.search(r"^\S* ?fail 0$", done.stdout, re.M), done.stdout[-1500:]


# Bundle -----------------------------------------------------------------------


def test_bundle_has_no_module_syntax_left_but_the_default_export():
    js = office._bundle_js()
    assert not re.search(r"^[ \t]*import\s", js, re.M)
    exports = re.findall(r"^[ \t]*export\s.*$", js, re.M)
    assert exports == ["export default function (component) {"]
    assert "const __aegisOfficeModel = (() => {" in js
    assert "const __aegisOfficeView = (() => {" in js
    assert "const requestAnimationFrame = __aegisProbe.requestFrame;" in js
    assert "async function officeRenderInit" in js


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_bundle_parses_as_an_es_module(tmp_path):
    out = tmp_path / "bundle.mjs"
    out.write_text(office._bundle_js(), encoding="utf-8")
    subprocess.run(["node", "--check", str(out)], check=True, capture_output=True)


@pytest.mark.parametrize(
    ("name", "old", "new"),
    [
        ("office_vector.js", '} from "./roster.js";', '} from "./model.js";'),
        ("office_vector.js", "  officeEdges,\n}", "  officeEdges,\n  OFFICE_GEO,\n}"),
        ("shim.js", 'from "./office_vector.js";', 'from "./office_view.js";'),
        ("shim.js", "const FONT_ID", 'import { x } from "./x.js";\nconst FONT_ID'),
        ("roster.js", "export const ROSTER_STATUSES", 'import { y } from "./y.js";\nexport const ROSTER_STATUSES'),
        ("roster.js", "export const ROSTER_STATUSES", "export default 1;\nexport const ROSTER_STATUSES"),
    ],
)
def test_bundler_refuses_what_it_does_not_handle(monkeypatch, name, old, new):
    real = office._read

    def fake(n):
        text = real(n)
        if n == name:
            assert old in text
            return text.replace(old, new, 1)
        return text

    monkeypatch.setattr(office, "_read", fake)
    with pytest.raises(RuntimeError):
        office._bundle_js()


def test_unexport_refuses_a_file_with_no_exports():
    with pytest.raises(RuntimeError):
        office._unexport("const a = 1;\n", "x.js")


def test_unexport_refuses_an_indented_export_it_would_leave_behind():
    with pytest.raises(RuntimeError):
        office._unexport("export const a = 1;\n  export const b = 2;\n", "x.js")


def test_css_is_scoped_to_the_office_root():
    for name in ("office.css", "host.css"):
        css = (OFFICE_DIR / name).read_text(encoding="utf-8")
        css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
        # selectors are the text before each "{" that is not inside a
        # keyframes block or an at-rule header
        depth_keyframes = False
        for m in re.finditer(r"([^{}]+)\{|\}", css):
            head = (m.group(1) or "").strip()
            if not head:
                continue
            if head.startswith("@keyframes"):
                assert head.split()[1].startswith("aegis-office-"), head
                depth_keyframes = True
                continue
            if head.startswith("@media"):
                continue
            if depth_keyframes and re.fullmatch(r"(from|to|[\d.%, ]+)", head):
                continue
            depth_keyframes = False
            for selector in head.split(","):
                assert selector.strip().startswith(".aegis-office-root"), (name, selector.strip())
        for anim in re.findall(r"animation:\s*([\w-]+)", css):
            assert anim == "none" or anim.startswith("aegis-office-"), anim


def test_only_render_office_is_public():
    assert office.__all__ == ["render_office"]


# render_office ------------------------------------------------------------------


def test_unpack_shapes():
    assert office._unpack(None) == ("idle", None, None, None)
    progress = {"agentic": True, "lead": {"status": "working"}, "agents": [], "current": "x"}
    assert office._unpack(progress) == ("running", None, progress, None)
    assert office._unpack(dict(progress, current="complete"))[0] == "complete"
    job = {"id": "j1", "status": "failed", "error": "x" * 900, "progress": progress}
    status, error, prog, run = office._unpack(job)
    assert (status, len(error), prog, run) == ("failed", 600, progress, "j1")
    assert office._unpack({"job_id": 7, "status": "complete", "progress": progress})[3] == 7
    assert office._unpack({"id": ("a",), "status": "running", "progress": progress})[3] == "('a',)"
    assert office._unpack({"status": "bogus", "progress": None})[0] == "running"
    assert office._unpack({"status": "queued"}) == ("queued", None, None, None)
    assert office._unpack({"status": "running", "progress": "not a dict"})[2] is None
    with pytest.raises(TypeError):
        office.render_office("nope")  # type: ignore[arg-type]


def test_render_office_sends_a_sequence_that_moves_only_on_change(monkeypatch):
    calls = []
    monkeypatch.setattr(office, "_OFFICE", lambda **kw: calls.append(kw))
    monkeypatch.setattr(office.st, "session_state", {})
    frames = json.loads(FIXTURE.read_text(encoding="utf-8"))["frames"]
    first = next(i for i, f in enumerate(frames) if f["progress"] != frames[0]["progress"])

    office.render_office(None, key="o")
    office.render_office(None, key="o")
    office.render_office({"id": "r", **frames[0]}, key="o")
    office.render_office({"id": "r", **frames[1]}, key="o")  # same record as frames[0]
    office.render_office({"id": "r", **frames[first]}, key="o")

    seqs = [c["data"]["seq"] for c in calls]
    assert seqs == [0, 0, 1, 1, 2]
    assert all(c["key"] == "o" for c in calls)
    assert calls[0]["data"]["status"] == "idle" and calls[0]["data"]["progress"] is None
    assert calls[2]["data"]["run"] == "r" and calls[2]["data"]["progress"]["agentic"] is True
    assert len({c["data"]["nonce"] for c in calls}) == 1


def test_cleared_session_state_starts_a_new_counter(monkeypatch):
    calls = []
    monkeypatch.setattr(office, "_OFFICE", lambda **kw: calls.append(kw))
    monkeypatch.setattr(office.st, "session_state", {})
    office.render_office(None, key="o")
    office.render_office({"status": "queued"}, key="o")
    office.st.session_state.clear()
    office.render_office(None, key="o")
    assert [c["data"]["seq"] for c in calls] == [0, 1, 0]
    assert calls[0]["data"]["nonce"] == calls[1]["data"]["nonce"] != calls[2]["data"]["nonce"]


def test_two_keys_keep_their_own_counters(monkeypatch):
    calls = []
    monkeypatch.setattr(office, "_OFFICE", lambda **kw: calls.append(kw))
    monkeypatch.setattr(office.st, "session_state", {})
    office.render_office(None, key="a")
    office.render_office({"status": "queued"}, key="a")
    office.render_office(None, key="b")
    assert [(c["key"], c["data"]["seq"]) for c in calls] == [("a", 0), ("a", 1), ("b", 0)]


# Fixture ----------------------------------------------------------------------


def test_replay_fixture_is_one_agentic_run_in_order():
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    frames = data["frames"]
    assert len(frames) > 60
    ids = [role.agent_id for role in AGENT_ROLES.values()]
    last_seen = -1.0
    for f in frames:
        assert set(f) == {"seen", "status", "error", "progress"}
        assert f["seen"] >= last_seen
        last_seen = f["seen"]
        p = f["progress"]
        assert p["agentic"] is True and isinstance(p["lead"], dict)
        assert [a["id"] for a in p["agents"]] == ids
        for a in p["agents"]:
            assert set(a) == {"id", "role", "section", "status", "activity", "started_at", "finished_at", "findings"}
    assert frames[-1]["status"] == "complete" and frames[-1]["progress"]["lead"]["status"] == "done"
    assert all(f["status"] == "running" for f in frames[:-1])
    assert all(a["status"] == "done" for a in frames[-1]["progress"]["agents"])


def test_replay_fixture_shows_each_agent_working_for_a_while():
    frames = json.loads(FIXTURE.read_text(encoding="utf-8"))["frames"]
    working: dict[str, int] = {}
    order: list[str] = []
    for f in frames:
        for a in f["progress"]["agents"]:
            if a["status"] == "working":
                working[a["id"]] = working.get(a["id"], 0) + 1
                if a["id"] not in order:
                    order.append(a["id"])
    assert order == [role.agent_id for role in AGENT_ROLES.values()]
    assert min(working.values()) >= 4, working


def test_component_files_have_no_long_dashes():
    for path in [*COMPONENT_FILES, FIXTURE]:
        assert DASHES.search(path.read_text(encoding="utf-8")) is None, path.name
