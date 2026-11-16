"""The AI workflow scan page under AppTest, with a fake garak interpreter."""

from __future__ import annotations

import html
import json

import httpx2 as httpx  # the HTTP library the installed openai SDK uses
import openai
import pytest

from aegisshield.aiscan import availability as scan_availability_mod
from aegisshield.aiscan import service as scan_service
from aegisshield.llm.openai_client import DEFAULT_SDK_RETRIES
from aegisshield.storage import RecordKind, Workspace
from aegisshield.ui import routes, state, tool_parts
from aegisshield.ui.pages import ai_scan as page
from tests.aegisshield.aiscan.garak_fakes import install
from tests.aegisshield.ui.lookup_fakes import HOSTILE
from tests.aegisshield.ui.tool_helpers import (
    Gate,
    click_and_finish,
    fresh_runner,
    html_of,
    make_app,
    openai_session,
    wait_for_jobs,
)

__all__ = ["fresh_runner"]


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


def _ws(at) -> Workspace:
    return at.session_state["aegis_workspace"]


def _record(**overrides) -> dict:
    record = {
        "version": 1, "status": "complete", "reasons": [],
        "settings": {"garak_version": "0.17.1", "probes": ["promptinject.HijackHateHumans"],
                     "limits": {"generations": 1, "prompts_per_probe": 2, "total_requests": 10,
                                "request_timeout_seconds": 60, "wall_clock_seconds": 300},
                     "planned_requests": 2, "seed": None,
                     "surface": {"id": "policy_profile", "title": "Policy draft: organization profile notes"},
                     "safeguards_on": True, "model": {"kind": "simulated", "name": "simulated stand-in"},
                     "started_at": "2026-11-14T10:00:00+00:00", "ended_at": "2026-11-14T10:01:00+00:00",
                     "seconds": 60.0, "stopped": None, "exit_code": 0},
        "probes": [{"probe": "promptinject.HijackHateHumans", "state": "complete", "reason": "", "prompts": 2,
                    "answers": 2, "missing_answers": 0, "refusals": 0, "failures": 0,
                    "evaluations": [{"probe": "promptinject.HijackHateHumans",
                                     "detector": "promptinject.AttackRogueString", "passed": 1, "fails": 1,
                                     "nones": 0, "total_evaluated": 2, "total_processed": 2}]}],
        "attempts": [{"probe": "promptinject.HijackHateHumans", "seq": 0, "evaluated": True,
                      "prompt": "say hi", "outputs": ["I hate humans"],
                      "detectors": {"promptinject.AttackRogueString": [1.0]}}],
        "caps": {"max_attempts": 100, "max_attempts_per_probe": 20, "max_outputs_per_attempt": 3,
                 "max_text_chars": 2000, "attempts_in_report": 2, "attempts_stored": 1, "texts_clipped": 0},
        "shim": {"requests": 2, "answered": 2, "refusals": 0, "failures": 0, "timeouts": 0, "limit_hits": 0,
                 "rejected": 0},
        "report": {"lines": 9, "bad_lines": 0, "oversize_lines": 0, "unknown_entries": 0},
        "safeguards": None,
    }
    record.update(overrides)
    return record


def _open(record: dict, title: str = "Scan"):
    ws = Workspace()
    saved = ws.add(RecordKind.AI_SCANS, title, record)
    at = make_app(page.PAGE, aegis_workspace=ws)
    at.query_params["id"] = saved.id
    return at.run(), saved


def test_hidden_when_scans_are_off_or_garak_is_missing(fresh_runner, monkeypatch) -> None:
    for env, value in (("AEGIS_AI_SCAN", ""), ("AEGIS_GARAK_PYTHON", "/nonexistent/python")):
        scan_availability_mod.clear_cache()
        monkeypatch.setenv(env, value)
        assert routes.ai_scan_available() is False
        at = make_app(page.PAGE).run()
        assert not at.exception
        assert "AI workflow scans are not available here" in html_of(at)
        assert "scan_run" not in [b.key for b in at.button]
        titles = {i.title for items in routes.nav_sections(with_tshark=True,
                                                            with_ai_scan=routes.ai_scan_available()).values()
                  for i in items}
        assert "AI workflow scan" not in titles
        monkeypatch.setenv("AEGIS_AI_SCAN", "1")
        monkeypatch.setenv("AEGIS_GARAK_PYTHON", str(page.__file__))
    scan_availability_mod.clear_cache()


def test_shown_when_scans_are_on_and_garak_is_found(fresh_runner, scans_on, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_GARAK_PYTHON", scans_on.python)
    assert routes.ai_scan_available() is True
    titles = {i.title for items in routes.nav_sections(with_tshark=False, with_ai_scan=True).values()
              for i in items}
    assert "AI workflow scan" in titles


def test_form_defaults_in_mock_mode(fresh_runner) -> None:
    at = make_app(page.PAGE).run()
    assert not at.exception
    body = html_of(at)
    assert _esc(page.WHAT_IT_DOES) in body and _esc(scan_service.CLEAN_COUNT_NOTE) in body
    checked = {c.label for c in at.checkbox if c.value}
    assert checked == {"promptinject.HijackHateHumans", "latentinjection.LatentInjectionReport",
                       "web_injection.MarkdownImageExfil", "encoding.InjectBase64"}
    assert at.radio(key="scan_model").options == ["Simulated stand-in (simulated model, not a real model run)"]
    assert at.radio(key="scan_guards").value == "on"
    assert _esc(page.SIMULATED_NOTE) in body
    assert "These choices need up to 27 requests; the limit is 60." in body
    assert "will use your" not in body


def test_real_model_option_says_the_key_will_be_used(fresh_runner, monkeypatch) -> None:
    monkeypatch.delenv("AEGIS_MOCK_LLM")
    at = make_app(page.PAGE, **openai_session()).run()
    assert not at.exception
    assert at.radio(key="scan_model").value == "real"
    body = html_of(at)
    assert _esc(page.key_sentence(60, 0, "openai")) in body
    assert _esc("Model your workflow uses: OpenAI, gpt-5.4") in body
    at = make_app(page.PAGE).run()  # no key: only the stand-in
    assert at.radio(key="scan_model").options == ["Simulated stand-in (simulated model, not a real model run)"]


@pytest.mark.parametrize("guards", ["on", "off"])
def test_a_scan_runs_saves_and_shows_its_record(fresh_runner, scans_on, guards) -> None:
    at = make_app(page.PAGE).run()
    at.text_area(key="scan_system_prompt").input(SYSTEM_PROMPT)
    at.radio(key="scan_guards").set_value(guards)
    for item in ("latentinjection.LatentInjectionReport", "web_injection.MarkdownImageExfil",
                 "encoding.InjectBase64"):
        at.checkbox(key=f"scan_probe_{item}").uncheck()
    at.number_input(key="scan_limit_prompts").set_value(2)
    at.run()
    click_and_finish(at, "scan_run", fresh_runner)
    assert not at.exception
    (record,) = _ws(at).list(RecordKind.AI_SCANS)
    assert record.payload["status"] == "complete"
    assert record.payload["settings"]["model"]["kind"] == "simulated"
    assert record.payload["settings"]["surface"]["id"] == "visitor_workflow"
    # The simulated stand-in answered, so no model is stored for the workflow.
    assert record.payload["settings"]["workflow"] == {"system_prompt": SYSTEM_PROMPT, "sample_context": "",
                                                      "model": ""}
    assert record.payload["settings"]["model"]["provider"] == ""
    assert record.payload["settings"]["safeguards_on"] is (guards == "on")
    summary = record.payload["safeguards"]
    assert summary["status"] == guards and (summary["checks"] > 0) is (guards == "on")
    assert "excerpt" not in json.dumps(summary)
    body = html_of(at)
    assert "Scan saved to this session&#x27;s workspace. Status: Complete." in body
    assert "Every result here is from a simulated model, not a real model run." in body
    assert {b.label for b in at.get("download_button")} >= {"Scan record (JSON)", "garak.report.jsonl"}
    assert state.RUN_PARAM not in at.query_params


def test_a_bad_selection_is_refused_before_anything_runs(fresh_runner, scans_on) -> None:
    at = make_app(page.PAGE).run()
    at.number_input(key="scan_limit_requests").set_value(5).run()
    at.button(key="scan_run").click().run()
    assert "need up to 27 requests" in html_of(at)
    assert fresh_runner._jobs == {} and scans_on.calls() == []
    for item in page.scan_probes.DEFAULT_PROBE_IDS:
        at.checkbox(key=f"scan_probe_{item}").uncheck()
    at.run()
    at.button(key="scan_run").click().run()
    assert "Choose at least one probe." in html_of(at)


def test_running_scan_shows_progress_and_can_be_cancelled(fresh_runner, scans_on) -> None:
    gate = Gate()

    def fn(progress):
        progress.set({"step": 1, "total": 2, "current": "promptinject.HijackHateHumans", "requests": 3,
                      "request_limit": 60})
        gate.wait()
        return {"record": _record(), "files": {}}

    job_id = fresh_runner.submit(fn, kind=page.JOB_KIND)
    assert gate.started.wait(5)
    at = make_app(page.PAGE, aegis_jobs={page.JOB_KIND: job_id}).run()
    assert not at.exception
    body = html_of(at)
    assert "Requests so far: 3 of the limit of 60." in body
    assert "Probe 1 of 2: promptinject.HijackHateHumans" in body
    at.button(key="scan_cancel_danger").click().run()
    assert "Scan cancelled. garak was stopped and nothing was saved." in html_of(at)
    gate.release.set()
    wait_for_jobs(fresh_runner)
    at.run()
    assert _ws(at).list(RecordKind.AI_SCANS) == []


def test_a_reload_finds_the_running_scan_again(fresh_runner, scans_on) -> None:
    gate = Gate()

    def fn(progress):
        gate.wait()
        return {"record": _record(), "files": {"garak.report.jsonl": b"{}\n"}}

    job_id = fresh_runner.submit(fn, kind=page.JOB_KIND)
    at = make_app(page.PAGE)
    at.query_params[state.RUN_PARAM] = job_id
    at.run()
    assert "Scan running" in html_of(at)
    gate.release.set()
    wait_for_jobs(fresh_runner)
    at.run()
    assert len(_ws(at).list(RecordKind.AI_SCANS)) == 1


def test_a_job_that_fails_shows_a_fixed_sentence(fresh_runner, scans_on) -> None:
    def fn(progress):
        raise RuntimeError("secret detail sk-abcdefghijklmnopqrstu")

    job_id = fresh_runner.submit(fn, kind=page.JOB_KIND)
    wait_for_jobs(fresh_runner)
    at = make_app(page.PAGE, aegis_jobs={page.JOB_KIND: job_id}).run()
    body = html_of(at)
    assert "The scan did not run." in body and "secret detail" not in body


@pytest.mark.parametrize("status", ["incomplete", "failed"])
def test_a_scan_that_did_not_finish_shows_no_result(fresh_runner, status) -> None:
    probes = [{**_record()["probes"][0], "state": "incomplete", "reason": "1 of 2 prompts got no answer."}]
    at, _ = _open(_record(status=status, reasons=["The scan reached its request limit."], probes=probes))
    assert not at.exception
    body = html_of(at)
    assert "This scan did not finish, so it has no result." in body
    assert "ax-tone-ok" not in body and "%" not in body.split("Probes and detectors")[-1][:2000]
    assert "garak finished every probe" not in body
    (table,) = [d for d in at.dataframe if "What the detector found" in d.value.columns]
    assert "(not a result: the probe did not finish)" in table.value["What the detector found"][0]
    assert "1 of 2 prompts got no answer." in body


def test_complete_scan_shows_counts_in_words_and_no_rate(fresh_runner) -> None:
    at, record = _open(_record())
    body = html_of(at)
    assert "garak finished every probe" in body
    (table,) = [d for d in at.dataframe if "What the detector found" in d.value.columns]
    assert table.value["What the detector found"][0] == "found the attack in 1 of 2 answers"
    assert "ax-tone-ok" not in body and "rate" not in body.lower()
    assert "garak&#x27;s own report files are kept for up to 15 minutes" in body


def test_refused_probe_is_listed_as_refused(fresh_runner) -> None:
    probes = [{**_record()["probes"][0], "state": "all_refused",
               "reason": "Every answer was the workflow step refusing the input."}]
    at, _ = _open(_record(probes=probes))
    assert "Every answer was a refusal" in html_of(at)
    (table,) = [d for d in at.dataframe if "What the detector found" in d.value.columns]
    assert "so the attack was not tested" in table.value["What the detector found"][0]
    assert "did not finish" not in table.value["What the detector found"][0]


def test_hostile_strings_in_every_field_are_shown_as_text(fresh_runner) -> None:
    record = _record(reasons=[HOSTILE], status=HOSTILE)
    record["settings"].update(garak_version=HOSTILE, probes=[HOSTILE], surface={"id": HOSTILE, "title": HOSTILE},
                              model={"kind": HOSTILE, "name": HOSTILE}, started_at=HOSTILE, seed=HOSTILE)
    record["probes"] = [{"probe": HOSTILE, "state": HOSTILE, "reason": HOSTILE,
                         "evaluations": [{"detector": HOSTILE, "fails": HOSTILE}]}, HOSTILE]
    record["attempts"] = [{"probe": HOSTILE, "seq": HOSTILE, "prompt": HOSTILE, "outputs": [HOSTILE, None, 5],
                           "detectors": {HOSTILE: [HOSTILE, 1.0, None, True]}}, HOSTILE]
    record["safeguards"] = {HOSTILE: HOSTILE, "nested": {"x": 1}}
    record["caps"] = HOSTILE
    at, _ = _open(record, title=HOSTILE)
    assert not at.exception
    body = html_of(at)
    assert "<script>" not in body and "<img" not in body
    assert "&lt;script&gt;" in body
    for md in at.markdown:
        assert not md.allow_html
    codes = [c.value for c in at.code]
    assert HOSTILE in codes  # prompts and answers are shown in code blocks, as text
    assert {c.language for c in at.code} == {"plaintext"}


def test_downloads_of_a_kept_scan_and_delete(fresh_runner) -> None:
    ws = Workspace()
    saved = ws.add(RecordKind.AI_SCANS, "Scan", _record())
    at = make_app(page.PAGE, aegis_workspace=ws,
                  aegis_scan_files={saved.id: (9e18, {"garak.report.jsonl": b"{}\n",
                                                      "garak.report.html": b"<html></html>"})})
    at.query_params["id"] = saved.id
    at.run()
    labels = [b.label for b in at.get("download_button")]
    assert labels == ["Scan record (JSON)", "garak.report.jsonl", "garak.report.html"]
    json.dumps(saved.payload)
    at.button(key="scan_reader_del_danger").click().run()
    at.button(key="scan_del_confirm_danger").click().run()
    assert not at.exception
    assert _ws(at).list(RecordKind.AI_SCANS) == []


def test_unknown_id_and_past_list(fresh_runner) -> None:
    ws = Workspace()
    ws.add(RecordKind.AI_SCANS, "First scan", _record(status="incomplete"))
    at = make_app(page.PAGE, aegis_workspace=ws)
    at.query_params["id"] = "nope"
    at.run()
    body = html_of(at)
    assert "That scan is not in this session" in body
    assert "First scan" in body and "Incomplete, simulated model" in body.replace(" &middot; ", ", ")


def test_scan_files_expire(fresh_runner) -> None:
    from streamlit.testing.v1 import AppTest

    def app() -> None:
        import streamlit as st

        from aegisshield.ui import state as s

        for i in range(4):
            s.keep_scan_files(f"r{i}", {"a": b"x"}, now=100.0)
        st.session_state["kept"] = sorted(st.session_state["aegis_scan_files"])
        st.session_state["live"] = s.scan_files("r3", now=100.0)
        st.session_state["dead"] = s.scan_files("r3", now=100.0 + s.SCAN_FILES_TTL_SECONDS + 1)
        third = s.SCAN_FILES_MAX_BYTES // 3
        for i in range(4):
            s.keep_scan_files(f"r{i}", {"a": b"x"}, now=100.0)
        s.keep_scan_files("x", {"garak.report.jsonl": b"r" * third, "garak.hitlog.jsonl": b"h" * third,
                                "garak.report.html": b"h" * (third + 10)}, now=100.0)
        st.session_state["big"] = sorted(s.scan_files("x", now=100.0) or {})
        st.session_state["after_big"] = sorted(st.session_state["aegis_scan_files"])
        s.keep_scan_files("y", {"garak.report.jsonl": b"r" * (s.SCAN_FILES_MAX_BYTES + 1)}, now=100.0)
        st.session_state["too_big"] = s.scan_files("y", now=100.0)

    at = AppTest.from_function(app).run()
    assert at.session_state["kept"] == ["r1", "r2", "r3"]
    assert at.session_state["big"] == ["garak.hitlog.jsonl", "garak.report.jsonl"]  # HTML dropped first
    assert at.session_state["after_big"] == ["r2", "r3", "x"]
    assert at.session_state["too_big"] == {}  # nothing kept rather than more than the limit
    assert at.session_state["live"] == {"a": b"x"} and at.session_state["dead"] is None


def test_an_oversized_imported_scan_renders_capped_and_without_stalling(fresh_runner) -> None:
    from tests.aegisshield.stall import STALL_LIMIT_S, measure

    big = "x" * 150_000
    record = _record(reasons=[big] * 10)
    record["attempts"] = [{"probe": big[:5_000], "seq": i, "prompt": big, "outputs": [big] * 4 + ["a"] * 40,
                           "detectors": {f"d{j}": [1.0] * 500 for j in range(100)}} for i in range(3)] + \
        [{"probe": "p", "seq": i, "prompt": "short", "outputs": ["a"]} for i in range(2_000)]
    record["probes"] = [{**_record()["probes"][0], "reason": "r" * 1_000}] * 500
    source = Workspace()
    source.add(RecordKind.AI_SCANS, "Imported", record)
    workspace = Workspace.from_json(json.dumps(source.to_dict()).encode())  # within every import limit
    (saved,) = workspace.list(RecordKind.AI_SCANS)
    at = make_app(page.PAGE, aegis_workspace=workspace)
    at.query_params["id"] = saved.id
    run = measure(at.run)
    assert not at.exception, at.exception
    assert run.stall < STALL_LIMIT_S
    assert len(at.expander) <= scan_service.MAX_STORED_ATTEMPTS + 1
    assert max(len(c.value) for c in at.code) <= scan_service.MAX_STORED_TEXT_CHARS
    (table,) = [d for d in at.dataframe if "What the detector found" in d.value.columns]
    assert len(table.value) <= 50


def test_deployment_with_safeguards_off_offers_only_off(fresh_runner, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_SAFEGUARDS", "0")
    at = make_app(page.PAGE).run()
    assert not at.exception
    assert "scan_guards" not in [r.key for r in at.radio]
    assert "This server runs with the safeguards off" in html_of(at)


@pytest.mark.parametrize("summary,words", [
    ({"status": "on", "not_checked": 0}, "On, as deployed"),
    ({"status": "on", "not_checked": 3}, "On, as deployed; 3 checks could not run"),
    ({"status": "unavailable"}, "Chosen on, but did not run as on (status: unavailable)"),
])
def test_the_settings_say_what_the_safeguards_did(fresh_runner, summary, words) -> None:
    record = _record(safeguards=summary)
    record["settings"]["safeguards_on"] = True
    at, _ = _open(record)
    assert _esc(words) in html_of(at)


# -- One visitor and the single scan slot ----------------------------------------------


def test_keyless_scans_have_lower_maximums_on_the_page(fresh_runner, monkeypatch) -> None:
    at = make_app(page.PAGE).run()  # mock mode: the stand-in only
    assert not at.exception
    assert _esc(page.KEYLESS_SENTENCE) in html_of(at)
    requests, wall = at.number_input(key="scan_limit_requests"), at.number_input(key="scan_limit_wall")
    assert (requests.max, requests.value) == (60, 60)
    assert (wall.max, wall.value) == (300, 300)
    monkeypatch.delenv("AEGIS_MOCK_LLM")
    at = make_app(page.PAGE, **openai_session()).run()
    assert at.number_input(key="scan_limit_wall").max == 1500
    assert _esc(page.KEYLESS_SENTENCE) not in html_of(at)
    at.number_input(key="scan_limit_wall").set_value(1000).run()
    at.radio(key="scan_model").set_value("simulated").run()
    assert not at.exception
    assert at.number_input(key="scan_limit_wall").value <= 300


SYSTEM_PROMPT = "You answer billing questions for Example Retail in two sentences or fewer."


def _scan_once(at, fresh_runner) -> None:
    at.text_area(key="scan_system_prompt").input(SYSTEM_PROMPT)
    for item in ("latentinjection.LatentInjectionReport", "web_injection.MarkdownImageExfil",
                 "encoding.InjectBase64"):
        at.checkbox(key=f"scan_probe_{item}").uncheck()
    at.number_input(key="scan_limit_prompts").set_value(1)
    at.run()
    click_and_finish(at, "scan_run", fresh_runner)


def test_a_session_waits_after_a_scan_before_starting_another(fresh_runner, scans_on, monkeypatch) -> None:
    now = [1000.0]
    monkeypatch.setattr(page, "_clock", lambda: now[0])
    at = make_app(page.PAGE).run()
    assert _esc(page.COOLDOWN_SENTENCE) in html_of(at)
    _scan_once(at, fresh_runner)
    assert len(_ws(at).list(RecordKind.AI_SCANS)) == 1
    calls = len(scans_on.calls())
    # The finished scan's page offers another; starting it inside the wait is refused.
    now[0] += page.SCAN_COOLDOWN_SECONDS - 10
    at.text_area(key="scan_system_prompt").input(SYSTEM_PROMPT)
    at.run()
    at.button(key="scan_run").click().run()
    assert "Try again in 10 seconds." in html_of(at)
    wait_for_jobs(fresh_runner)
    assert len(scans_on.calls()) == calls
    now[0] += 11
    at.text_area(key="scan_system_prompt").input(SYSTEM_PROMPT)
    at.run()
    click_and_finish(at, "scan_run", fresh_runner)
    assert len(scans_on.calls()) == calls + 1
    assert len(_ws(at).list(RecordKind.AI_SCANS)) == 2


def test_a_cancelled_scan_also_starts_the_wait(fresh_runner, scans_on, monkeypatch) -> None:
    now = [1000.0]
    monkeypatch.setattr(page, "_clock", lambda: now[0])
    gate = Gate()

    def fn(progress):
        gate.wait()
        return {"record": _record(), "files": {}}

    job_id = fresh_runner.submit(fn, kind=page.JOB_KIND)
    assert gate.started.wait(5)
    at = make_app(page.PAGE, aegis_jobs={page.JOB_KIND: job_id}).run()
    at.button(key="scan_cancel_danger").click().run()
    gate.release.set()
    wait_for_jobs(fresh_runner)
    at.run()
    at.button(key="scan_run").click().run()
    assert f"Try again in {page.SCAN_COOLDOWN_SECONDS} seconds." in html_of(at)
    assert scans_on.calls() == []


def test_an_imported_scan_with_integers_at_the_digit_limit_renders(fresh_runner) -> None:
    huge = int("9" * 4300)  # the longest integer a workspace import can read
    record = _record()
    record["shim"] = {**record["shim"], "failures": huge, "timeouts": huge, "requests": huge}
    record["caps"] = {**record["caps"], "max_text_chars": huge}
    record["probes"][0]["evaluations"][0].update(fails=huge, total_evaluated=huge)
    at, _ = _open(record)
    assert not at.exception
    assert "Failed or timed out" in html_of(at)


def test_the_key_sentence_states_calls_output_cap_input_and_retries() -> None:
    sentence = page.key_sentence(60, 1234, "openai")
    assert "your OpenAI credential" in sentence and "can reach OpenAI" in sentence
    assert "up to 60 model calls" in sentence
    assert "at most 1,024 output tokens" in sentence
    assert "1,234 characters" in sentence and "20,000 characters" in sentence
    assert "up to 2 more times" in sentence and "180 requests" in sentence
    for status in ("408", "409", "429", "500"):
        assert status in sentence


def test_the_sdk_retries_what_the_key_sentence_says() -> None:
    """The client's retry count and the SDK's retry rule, pinned, so the
    page's sentence about retries stays true (no request is sent)."""
    client = openai.OpenAI(api_key="sk-test-0123456789abcdefghij", max_retries=DEFAULT_SDK_RETRIES)
    retried = {code for code in (400, 401, 403, 404, 408, 409, 422, 429, 500, 502, 503, 504)
               if client._should_retry(httpx.Response(code))}
    assert retried == {408, 409, 429, 500, 502, 503, 504}
    assert client.max_retries == DEFAULT_SDK_RETRIES == 2
