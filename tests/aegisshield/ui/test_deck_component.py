"""Tests for the deck component (aegisshield/ui/components/deck)."""

from __future__ import annotations

import gzip
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import aegisshield.ui.components.deck as deck

ROOT = Path(__file__).resolve().parents[3]
DECK_DIR = ROOT / "aegisshield" / "ui" / "components" / "deck"
FIXTURE = ROOT / "tests" / "fixtures" / "deck_replay.json.gz"


def _fixture_text() -> str:
    with gzip.open(FIXTURE, "rt", encoding="utf-8") as fh:
        return fh.read()


COMPONENT_FILES = [
    *sorted(DECK_DIR.glob("*.py")),
    *sorted(DECK_DIR.glob("*.js")),
    *sorted(DECK_DIR.glob("*.css")),
    *sorted(DECK_DIR.glob("*.md")),
    ROOT / "tools" / "build_deck_replay.py",
    Path(__file__),
]

DASHES = re.compile(r"[\u2013\u2014]")


def test_bundle_has_no_module_syntax_left_but_the_default_export():
    js = deck._bundle_js()
    assert not re.search(r"^[ \t]*import\s", js, re.M)
    exports = re.findall(r"^[ \t]*export\s.*$", js, re.M)
    assert exports == ["export default function (component) {"]
    # each source file keeps its own scope
    assert "const __aegisDeckModel = (() => {" in js
    assert "const __aegisDeckView = (() => {" in js
    assert "const requestAnimationFrame = __aegisProbe.requestFrame;" in js


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_bundle_parses_as_an_es_module(tmp_path):
    out = tmp_path / "bundle.mjs"
    out.write_text(deck._bundle_js(), encoding="utf-8")
    subprocess.run(["node", "--check", str(out)], check=True, capture_output=True)


def test_bundler_refuses_a_changed_import_line(monkeypatch):
    real = deck._read

    def fake(name):
        text = real(name)
        return text.replace('from "./deck.js";', 'from "./deck2.js";') if name == "deck_view.js" else text

    monkeypatch.setattr(deck, "_read", fake)
    with pytest.raises(RuntimeError):
        deck._bundle_js()


def test_shim_and_probe_never_use_inner_html():
    for name in ("shim.js", "probe.js"):
        text = (DECK_DIR / name).read_text(encoding="utf-8")
        assert "innerHTML" not in text and "insertAdjacentHTML" not in text, name


def test_only_render_deck_is_public():
    assert deck.__all__ == ["render_deck"]


def test_unpack_shapes():
    assert deck._unpack(None) == ("idle", None, None, None)
    progress = {"office": True, "stages": [], "deck": {"t": 1}, "current": "stride"}
    assert deck._unpack(progress) == ("running", None, progress, None)
    done = dict(progress, current="complete")
    assert deck._unpack(done)[0] == "complete"
    job = {"id": "j1", "status": "failed", "error": "x" * 900, "progress": progress}
    status, error, prog, run = deck._unpack(job)
    assert (status, len(error), prog, run) == ("failed", 600, progress, "j1")
    assert deck._unpack({"status": "bogus", "progress": None})[0] == "running"
    assert deck._unpack({"status": "queued"}) == ("queued", None, None, None)
    with pytest.raises(TypeError):
        deck.render_deck("nope")  # type: ignore[arg-type]


def test_render_deck_sends_a_sequence_that_moves_only_on_change(monkeypatch):
    calls = []
    monkeypatch.setattr(deck, "_DECK", lambda **kw: calls.append(kw))
    monkeypatch.setattr(deck.st, "session_state", {})
    frames = json.loads(_fixture_text())["frames"]

    deck.render_deck(None, key="d")
    deck.render_deck(None, key="d")
    deck.render_deck({"id": "r", **frames[0]}, key="d")
    deck.render_deck({"id": "r", **frames[0]}, key="d")
    deck.render_deck({"id": "r", **frames[1]}, key="d")

    seqs = [c["data"]["seq"] for c in calls]
    assert seqs == [0, 0, 1, 1, 2]
    assert all(c["key"] == "d" for c in calls)
    assert calls[0]["data"]["status"] == "idle" and len(calls[0]["data"]["stages"]) == 11
    assert "stages" not in calls[2]["data"]
    assert calls[2]["data"]["run"] == "r"
    nonces = {c["data"]["nonce"] for c in calls}
    assert len(nonces) == 1


def test_cleared_session_state_starts_a_new_counter(monkeypatch):
    calls = []
    monkeypatch.setattr(deck, "_DECK", lambda **kw: calls.append(kw))
    monkeypatch.setattr(deck.st, "session_state", {})
    deck.render_deck(None, key="d")
    deck.render_deck({"status": "queued"}, key="d")
    deck.st.session_state.clear()
    deck.render_deck(None, key="d")
    assert [c["data"]["seq"] for c in calls] == [0, 1, 0]
    assert calls[0]["data"]["nonce"] == calls[1]["data"]["nonce"] != calls[2]["data"]["nonce"]


def test_idle_stage_list_matches_the_recorded_run():
    first = json.loads(_fixture_text())["frames"][0]["progress"]["stages"]
    assert [s["id"] for s in deck._STAGES] == [s["id"] for s in first]
    assert [s["name"] for s in deck._STAGES] == [s["name"] for s in first]
    assert [s["phase"] for s in deck._STAGES] == [s["phase"] for s in first]


def test_replay_fixture_is_deck_records_in_order():
    data = json.loads(_fixture_text())
    frames = data["frames"]
    assert len(frames) > 100
    last_t = -1.0
    for f in frames:
        assert set(f) == {"seen", "status", "progress"}
        p = f["progress"]
        assert p["office"] is True and isinstance(p["deck"], dict) and isinstance(p["stages"], list)
        assert p["deck"]["t"] >= last_t
        last_t = p["deck"]["t"]
        for th in p["deck"]["threats"]:
            assert set(th) == {"t", "id", "type", "scenario"} and th["scenario"]
    assert frames[-1]["status"] == "complete"
    assert all(f["status"] == "running" for f in frames[:-1])


def test_replay_fixture_live_text_moves_forward_per_item():
    frames = json.loads(_fixture_text())["frames"]
    prev: dict = {}
    for f in frames:
        live = f["progress"]["deck"]["live"]
        if not live or not live["item"]:
            continue
        # an unnamed stride field may be any of the three, so only named ones
        if not (live["stage"] == "mitigations" or live.get("field") == "Scenario"):
            continue
        key = (live["stage"], live["item"], live.get("field"))
        text = live["text"]
        if key in prev and not text.startswith("...") and not prev[key].startswith("..."):
            assert text.startswith(prev[key]) or prev[key].startswith(text), key
        prev[key] = text


def test_component_files_have_no_long_dashes():
    for path in [*COMPONENT_FILES, FIXTURE]:
        text = _fixture_text() if path == FIXTURE else path.read_text(encoding="utf-8")
        assert DASHES.search(text) is None, path.name


# ------------------------------------------------- listeners released at unmount


def test_deck_view_reads_document_only_through_members():
    """hooks.js hands deck_view.js a stand-in document that forwards member
    reads. That is safe only while deck_view.js never passes document itself
    to another API, and names ResizeObserver only to construct one."""
    view = (DECK_DIR / "deck_view.js").read_text(encoding="utf-8")
    assert re.findall(r"\bdocument\b(?!\.)", view) == []
    uses = re.findall(r"(new |window\.|)\bResizeObserver\b", view)
    assert sorted(uses) == ["new ", "window."]


def test_the_view_scope_gets_the_hooks_and_the_shim_releases_them():
    js = deck._bundle_js()
    hooks_at = js.index("const __aegisHooks = ")
    view_at = js.index("const __aegisDeckView = ")
    assert hooks_at < view_at
    view_scope = js[view_at: js.index("})();", view_at)]
    assert "const document = __aegisHooks.document;" in view_scope
    assert "const ResizeObserver = __aegisHooks.ResizeObserver;" in view_scope
    assert "__aegisHooks.collect(inst.hooks, () => deckInit(inst.host));" in js
    assert "__aegisHooks.release(mine.hooks);" in js


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_hooks_record_and_release_what_deck_init_adds(tmp_path):
    script = tmp_path / "hooks_check.mjs"
    script.write_text(
        "const doc = new EventTarget();\n"
        "doc.createTextNode = function (t) { return { text: t, owner: this }; };\n"
        "doc.hidden = false;\n"
        "globalThis.document = doc;\n"
        "let live = 0;\n"
        "globalThis.ResizeObserver = class { constructor() { live += 1; } disconnect() { live -= 1; } };\n"
        + (DECK_DIR / "hooks.js").read_text(encoding="utf-8")
        + "\nconst hits = [];\n"
        "const list = [];\n"
        "__aegisHooks.collect(list, () => {\n"
        "  __aegisHooks.document.addEventListener('click', () => hits.push('a'));\n"
        "  __aegisHooks.document.addEventListener('keydown', () => hits.push('k'));\n"
        "  new __aegisHooks.ResizeObserver(() => {});\n"
        "});\n"
        "__aegisHooks.document.addEventListener('click', () => hits.push('outside'));\n"
        "const node = __aegisHooks.document.createTextNode('x');\n"
        "doc.dispatchEvent(new Event('click'));\n"
        "const before = { hits: hits.join(','), live, recorded: list.length };\n"
        "__aegisHooks.release(list);\n"
        "hits.length = 0;\n"
        "doc.dispatchEvent(new Event('click'));\n"
        "doc.dispatchEvent(new Event('keydown'));\n"
        "console.log(JSON.stringify({ before, after: { hits: hits.join(','), live, recorded: list.length },\n"
        "  bound: node.owner === doc, hidden: __aegisHooks.document.hidden }));\n",
        encoding="utf-8",
    )
    done = subprocess.run(["node", str(script)], check=True, capture_output=True, text=True)
    out = json.loads(done.stdout)
    assert out["before"] == {"hits": "a,outside", "live": 1, "recorded": 3}
    assert out["after"] == {"hits": "outside", "live": 0, "recorded": 0}
    assert out["bound"] is True and out["hidden"] is False
