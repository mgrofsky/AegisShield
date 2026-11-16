"""The scan page asks for the visitor's workflow first, shows each probe's
taxonomy references, and links to and from a saved threat model."""

from __future__ import annotations

import html

import pytest
from streamlit.testing.v1 import AppTest

from aegisshield.aiscan import availability as scan_availability_mod
from aegisshield.aiscan import surfaces
from aegisshield.storage import RecordKind, Workspace
from aegisshield.ui import tool_parts
from aegisshield.ui.pages import ai_scan as page
from tests.aegisshield.aiscan.garak_fakes import install
from tests.aegisshield.ui.test_ai_scan_page import _record
from tests.aegisshield.ui.tm_records import mock_payload
from tests.aegisshield.ui.tool_helpers import (
    Gate,
    click_and_finish,
    fresh_runner,
    html_of,
    make_app,
    wait_for_jobs,
)

__all__ = ["fresh_runner"]

SYSTEM = "You answer billing questions for Example Retail in two sentences or fewer."
ATLAS_DIRECT = "https://atlas.mitre.org/techniques/AML.T0051.000"


@pytest.fixture(autouse=True)
def scans_on(tmp_path, monkeypatch: pytest.MonkeyPatch):
    scan_availability_mod.clear_cache()
    fake = install(tmp_path / "garak-env")
    monkeypatch.setenv("AEGIS_MOCK_LLM", "1")
    monkeypatch.setenv("AEGIS_AI_SCAN", "1")
    monkeypatch.setenv("AEGIS_GARAK_PYTHON", fake.python)
    monkeypatch.setattr(tool_parts, "MOCK_STREAM_DELAY", 0.0)
    yield fake
    scan_availability_mod.clear_cache()


def _esc(text: str) -> str:
    return html.escape(text, quote=True)


def _one_probe(at) -> None:
    for item in ("latentinjection.LatentInjectionReport", "web_injection.MarkdownImageExfil",
                 "encoding.InjectBase64"):
        at.checkbox(key=f"scan_probe_{item}").uncheck()
    at.number_input(key="scan_limit_prompts").set_value(1)


def _ai_model(ws: Workspace):
    payload = mock_payload()
    payload["profile"] = {**payload["profile"], "app_type": "AI/ML Systems"}
    return ws.add(RecordKind.THREAT_MODELS, "Support chatbot", payload)


def test_the_form_asks_for_the_workflow_first_and_offers_no_other_surface(fresh_runner) -> None:
    at = make_app(page.PAGE).run()
    assert not at.exception
    keys = [w.key for w in at.main if getattr(w, "key", None)]
    assert keys.index("scan_system_prompt") < keys.index("scan_sample_context") < keys.index("scan_guards")
    assert keys.index("scan_guards") < keys.index("scan_probe_promptinject.HijackHateHumans")
    assert "scan_surface" not in keys
    # The model is the one chosen in Settings, never picked or typed here.
    assert "scan_workflow_model" not in keys and not at.selectbox and not at.text_input
    assert at.text_area(key="scan_system_prompt").max_chars == surfaces.MAX_SYSTEM_PROMPT_CHARS
    assert at.text_area(key="scan_sample_context").max_chars == surfaces.MAX_SAMPLE_CONTEXT_CHARS
    body = html_of(at)
    for sentence in (page.WHAT_IT_DOES, page.WHAT_IT_DOES_NOT, page.CHECKS_NOTE, page.STORED_NOTE):
        assert _esc(sentence) in body
    for title in ("Threat model: application description", "PCAP analysis", "Policy draft"):
        assert title not in body
    assert at.radio(key="scan_guards").options == [page._GUARD_WORDS["on"], page._GUARD_WORDS["off"]]


def test_a_scan_without_a_system_prompt_is_refused_before_anything_runs(fresh_runner, scans_on) -> None:
    at = make_app(page.PAGE).run()
    at.button(key="scan_run").click().run()
    assert _esc(surfaces.ERROR_NO_SYSTEM_PROMPT) in html_of(at)
    assert fresh_runner._jobs == {} and scans_on.calls() == []


def test_a_workflow_scan_stores_the_workflow_and_shows_its_references(fresh_runner, scans_on) -> None:
    at = make_app(page.PAGE).run()
    at.text_area(key="scan_system_prompt").input(SYSTEM)
    at.text_area(key="scan_sample_context").input("Invoice 42 is due on the 3rd.")
    _one_probe(at)
    at.run()
    click_and_finish(at, "scan_run", fresh_runner)
    assert not at.exception
    (record,) = at.session_state["aegis_workspace"].list(RecordKind.AI_SCANS)
    assert record.payload["settings"]["workflow"] == {
        "system_prompt": SYSTEM, "sample_context": "Invoice 42 is due on the 3rd.", "model": ""}
    (row,) = record.payload["probes"]
    assert row["taxonomy"]["atlas"][0]["id"] == "AML.T0051.000"
    body = html_of(at)
    assert f'<a href="{ATLAS_DIRECT}" target="_blank" rel="noopener noreferrer">ATLAS AML.T0051.000</a>' in body
    assert "attack found in" in body
    assert "Your workflow as stored" in [e.label for e in at.expander]


def test_references_from_an_imported_record_are_checked_before_they_are_shown(fresh_runner) -> None:
    hostile = "<img src=x onerror=alert(1)>"
    row = {**_record()["probes"][0], "taxonomy": {
        "owasp": ["owasp:llm01", hostile, "owasp:llm01:passed"],
        "avid": ["avid-effect:security:S0403", {"x": 1}],
        "atlas": [{"id": "AML.T0051.000", "name": hostile}, {"id": "javascript:alert(1)"},
                  {"id": "AML.T9999"}, "AML.T0057"]}}
    ws = Workspace()
    saved = ws.add(RecordKind.AI_SCANS, "Scan", _record(probes=[row], settings={
        **_record()["settings"], "workflow": {"system_prompt": hostile, "sample_context": 5, "model": hostile}}))
    at = make_app(page.PAGE, aegis_workspace=ws)
    at.query_params["id"] = saved.id
    at.run()
    assert not at.exception
    body = html_of(at)
    assert "OWASP LLM01" in body and "AVID S0403 (security)" in body
    assert ATLAS_DIRECT in body and "javascript:" not in body and "AML.T9999" not in body
    assert hostile not in body and "LLM01:PASSED" not in body
    assert "attack found in 1 of 2 answers (promptinject.AttackRogueString)" in body


def test_a_scan_opened_from_a_threat_model_is_attached_to_it(fresh_runner, scans_on) -> None:
    ws = Workspace()
    model = _ai_model(ws)
    at = make_app(page.PAGE, aegis_workspace=ws)
    at.query_params[page.MODEL_PARAM] = model.id
    at.run()
    assert _esc('Opened from the saved threat model "Support chatbot".') in html_of(at)
    at.text_area(key="scan_system_prompt").input(SYSTEM)
    _one_probe(at)
    at.run()
    click_and_finish(at, "scan_run", fresh_runner)
    assert not at.exception
    ws = at.session_state["aegis_workspace"]
    (scan,) = ws.list(RecordKind.AI_SCANS)
    assert ws.get(RecordKind.THREAT_MODELS, model.id).payload["ai_scans"] == [scan.id]
    assert page._FROM_MODEL not in at.session_state


@pytest.mark.parametrize("value", ["unknown_id", "bad id!", "x" * 65])
def test_an_unknown_or_malformed_model_param_is_ignored(fresh_runner, value) -> None:
    at = make_app(page.PAGE)
    at.query_params[page.MODEL_PARAM] = value
    at.run()
    assert not at.exception and "Opened from the saved threat model" not in html_of(at)


def test_attach_keeps_a_bounded_list_without_repeats() -> None:
    ws = Workspace()
    model = _ai_model(ws)
    assert page.attach_scan(ws, "missing", "s0") is False
    for n in range(page.MAX_ATTACHED_SCANS + 5):
        assert page.attach_scan(ws, model.id, f"s{n}")
    page.attach_scan(ws, model.id, "s10")
    ids = ws.get(RecordKind.THREAT_MODELS, model.id).payload["ai_scans"]
    assert len(ids) == page.MAX_ATTACHED_SCANS and ids[-1] == "s10" and ids.count("s10") == 1


def _detail_app() -> None:
    import streamlit as st

    from aegisshield.ui import routes
    from aegisshield.ui.pages import threat_model_detail
    from aegisshield.ui.theme import apply_theme

    apply_theme()
    st.navigation(routes.build_navigation(with_tshark=False, with_ai_scan=routes.ai_scan_available()))
    threat_model_detail.render()


def _detail(ws: Workspace, record_id: str) -> AppTest:
    at = AppTest.from_function(_detail_app, default_timeout=30)
    at.session_state["aegis_workspace"] = ws
    at.query_params["id"] = record_id
    return at.run()


def test_the_threat_model_page_lists_attached_scans_and_links_to_the_scan_page() -> None:
    ws = Workspace()
    model = _ai_model(ws)
    done = ws.add(RecordKind.AI_SCANS, "Your AI workflow, 1 probe", _record())
    cut = ws.add(RecordKind.AI_SCANS, "<b>Cut short</b>", _record(status="incomplete"))
    ws.update_payload(RecordKind.THREAT_MODELS, model.id,
                      {**model.payload, "ai_scans": [done.id, cut.id, "gone", 7]})
    at = _detail(ws, model.id)
    assert not at.exception
    body = "\n".join(str(node.value) for node in at.get("html"))
    assert "AI workflow scans" in body
    assert "Your AI workflow, 1 probe &middot; Complete, simulated model" in body
    assert "&lt;b&gt;Cut short&lt;/b&gt; &middot; Incomplete, no result" in body
    assert "A scan that is no longer in this session." in body
    links = {link.label: link for link in at.get("page_link")}
    assert "Test this workflow with garak" in links and "Open scan" in links


def test_a_threat_model_that_is_not_an_ai_system_shows_no_scan_block(monkeypatch) -> None:
    ws = Workspace()
    model = ws.add(RecordKind.THREAT_MODELS, "Checkout", mock_payload())
    at = _detail(ws, model.id)
    assert not at.exception
    assert "AI workflow scans" not in "\n".join(str(node.value) for node in at.get("html"))
    monkeypatch.setenv("AEGIS_AI_SCAN", "")
    scan_availability_mod.clear_cache()
    ws2 = Workspace()
    at = _detail(ws2, _ai_model(ws2).id)
    assert "Test this workflow with garak" not in [link.label for link in at.get("page_link")]


def test_with_a_shared_data_directory_the_page_says_where_the_workflow_is_stored(
        fresh_runner, tmp_path, monkeypatch) -> None:
    """``AEGIS_DATA_DIR`` keeps one workspace file that everyone who can open
    the app shares. The app cannot tell whether more than one person can, so
    the page says so instead of the per-session note."""
    (tmp_path / "data").mkdir()
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path / "data"))
    at = make_app(page.PAGE).run()
    assert not at.exception
    body = html_of(at)
    assert _esc(page.SHARED_STORED_NOTE) in body and _esc(page.STORED_NOTE) not in body
    assert "everyone who can open this app" in page.SHARED_STORED_NOTE
    assert "cannot tell" in page.SHARED_STORED_NOTE


def test_while_a_scan_runs_the_notice_names_only_the_model_stored_with_it(fresh_runner) -> None:
    """A scan started from one model, then the page opened from another while
    it runs: the scan is attached to the first, so only the first is named."""
    ws = Workspace()
    first = _ai_model(ws)
    second = ws.add(RecordKind.THREAT_MODELS, "Other chatbot", _ai_model(Workspace()).payload)
    gate = Gate()

    def fn(progress):
        gate.wait()
        return {"record": _record(), "files": {}}

    job_id = fresh_runner.submit(fn, kind=page.JOB_KIND)
    assert gate.started.wait(5)
    at = make_app(page.PAGE, aegis_workspace=ws, aegis_jobs={page.JOB_KIND: job_id},
                  **{page._FROM_MODEL: first.id})
    at.query_params[page.MODEL_PARAM] = second.id
    at.run()
    assert not at.exception
    body = html_of(at)
    assert "Scan running" in body
    assert _esc('"Other chatbot"') not in body
    assert _esc('Opened from the saved threat model "Support chatbot".') in body
    # With nothing stored for the running scan, no model is named at all.
    at.session_state[page._FROM_MODEL] = None
    at.run()
    assert "Opened from the saved threat model" not in html_of(at)
    at.session_state[page._FROM_MODEL] = first.id
    gate.release.set()
    wait_for_jobs(fresh_runner)
    at.run()
    ws = at.session_state["aegis_workspace"]
    (scan,) = ws.list(RecordKind.AI_SCANS)
    assert ws.get(RecordKind.THREAT_MODELS, first.id).payload["ai_scans"] == [scan.id]
    assert "ai_scans" not in ws.get(RecordKind.THREAT_MODELS, second.id).payload


def test_the_checks_note_says_guarded_results_partly_measure_the_fence() -> None:
    assert "fenced as data" in page.CHECKS_NOTE and "partly measure that fence" in page.CHECKS_NOTE
