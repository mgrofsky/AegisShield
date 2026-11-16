"""The wizard under AppTest: validation, steps keeping input, hand-offs, and
real mock runs through the job runner to saved results, cancel, failure,
the server's cap, reattaching, and saving exactly once."""

from __future__ import annotations

import base64
import html
import threading
import time

import pytest

from aegisshield.core.errors import LLMError
from aegisshield.jobs import JobRunner
from aegisshield.jobs import runner as runner_mod
from aegisshield.jobs.runner import ERROR_CAP, ERROR_UPSTREAM
from aegisshield.storage import RecordKind, Workspace
from aegisshield.ui import options
from aegisshield.ui import threat_model_run as runs
from aegisshield.ui.pages import threat_model_new as page
from tests.aegisshield.ui.tm_support import (
    READY_DRAFT,
    html_of,
    live_views,
    new_wizard,
    png_bytes,
    run_record,
    saved_threat_models,
    switchable_app,
    wait_settled,
)
from tests.aegisshield.ui.tool_helpers import jobs_held

PNG = png_bytes()


@pytest.fixture(autouse=True)
def fresh_runner(monkeypatch: pytest.MonkeyPatch) -> JobRunner:
    """A runner of our own per test, and no pause between mock chunks."""
    runner = JobRunner(max_concurrent_jobs=2, job_timeout_seconds=60)
    monkeypatch.setattr(runner_mod, "_runner", runner)
    monkeypatch.setattr(runs, "MOCK_CHUNK_DELAY_SECONDS", 0.0)
    monkeypatch.setattr(runs, "MOCK_CALL_DELAY_SECONDS", 0.0)
    return runner


# ------------------------------------------------------------ step 1


def test_opens_on_the_description_step(mock_mode: None) -> None:
    at = new_wizard().run()
    assert not at.exception
    assert [b.label for b in at.button][:4] == ["1  Description", "2  Technology", "3  Threat model",
                                                "4  Export"]
    assert "Characters: 0 (at least 50)" in html_of(at)
    assert at.button(key="tm_step_1").disabled and at.button(key="tm_step_3").disabled


def test_a_short_description_is_refused(mock_mode: None) -> None:
    at = new_wizard().run()
    at.text_area(key="tmw_description").input("Too short.").run()
    at.button(key="tm_next_1").click().run()
    assert page.DESCRIPTION_SHORT in html_of(at)
    assert at.session_state["aegis_tm_draft"]["step"] == 0


def test_the_example_can_be_inserted_once(mock_mode: None) -> None:
    at = new_wizard().run()
    at.button(key="tm_example").click().run()
    assert at.text_area(key="tmw_description").value == options.EXAMPLE_DESCRIPTION
    assert at.button(key="tm_example").disabled
    assert f"Characters: {len(options.EXAMPLE_DESCRIPTION)}" in html_of(at)


def test_steps_keep_their_input_going_back_and_forth(mock_mode: None) -> None:
    at = new_wizard().run()
    text = "An online checkout service where shoppers pay by card and staff issue refunds."
    at.text_area(key="tmw_description").input(text).run()
    at.button(key="tm_next_1").click().run()
    at.selectbox(key="tmw_app_type").select("Mobile application").run()
    at.button(key="tm_back_0").click().run()
    assert at.text_area(key="tmw_description").value == text
    at.button(key="tm_step_1").click().run()
    assert at.selectbox(key="tmw_app_type").value == "Mobile application"


def test_input_survives_a_page_switch(mock_mode: None) -> None:
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_function(switchable_app, default_timeout=30).run()
    text = "An online checkout service where shoppers pay by card and staff issue refunds."
    at.text_area(key="tmw_description").input(text).run()
    at.session_state["away"] = True
    at.run()  # another page: Streamlit drops the wizard's widget state
    at.run()
    at.session_state["away"] = False
    at.run()
    assert at.text_area(key="tmw_description").value == text


# ------------------------------------------------------------ step 2


def test_missing_context_fields_are_named(mock_mode: None) -> None:
    draft = {**READY_DRAFT, "step": 1, "reached": 1, "app_type": None, "industry_sector": None}
    at = new_wizard(draft).run()
    at.button(key="tm_next_2").click().run()
    assert "Complete every required field: Application type, Industry sector." in html_of(at)
    assert at.session_state["aegis_tm_draft"]["step"] == 1


def test_no_context_field_is_chosen_for_the_visitor(mock_mode: None) -> None:
    at = new_wizard({"step": 1, "reached": 1}).run()
    for key in ("tmw_app_type", "tmw_industry_sector", "tmw_sensitive_data", "tmw_internet_facing",
                "tmw_num_employees"):
        assert at.selectbox(key=key).value is None
    assert at.multiselect(key="tmw_compliance_requirements").value == []


def test_technologies_versions_and_patterns_reach_the_request(mock_mode: None) -> None:
    at = new_wizard({**READY_DRAFT, "step": 1}).run()
    pg = next(c for c in options.technology_choices() if c.name == "PostgreSQL")
    redis = next(c for c in options.technology_choices() if c.name == "Redis")
    at.multiselect(key="tmw_tech_pick").set_value([pg.key, redis.key]).run()
    at.text_input(key=f"tmw_ver_{pg.key}").input("15.4").run()
    at.checkbox(key="tmw_pat_RAG").check().run()
    draft = at.session_state["aegis_tm_draft"]
    profile = runs.build_profile(draft)
    assert profile["selected_technologies"] == {"PostgreSQL": pg.cpe, "Redis": redis.cpe}
    assert profile["selected_versions"] == {"PostgreSQL": "15.4", "Redis": "*"}
    assert profile["app_pattern"] == ["RAG"]
    request = runs.build_request(draft, agentic=False)
    assert request.addons == ["mitigations", "dread", "test_cases"]


def test_a_bad_version_is_shown_and_blocks_next(mock_mode: None) -> None:
    pg = next(c for c in options.technology_choices() if c.name == "PostgreSQL")
    at = new_wizard({**READY_DRAFT, "step": 1, "technologies": {pg.key: "15.x"}}).run()
    assert "Version should be numbers or wildcards" in html_of(at)
    at.button(key="tm_next_2").click().run()
    assert "PostgreSQL: Version should be numbers or wildcards" in html_of(at)
    assert at.session_state["aegis_tm_draft"]["step"] == 1


def test_valid_context_moves_to_the_threat_model_step(mock_mode: None) -> None:
    at = new_wizard({**READY_DRAFT, "step": 1, "reached": 1}).run()
    at.button(key="tm_next_2").click().run()
    assert at.session_state["aegis_tm_draft"]["step"] == 2
    assert at.button(key="tm_generate").label == "Generate"


# ------------------------------------------------------------ the image


def test_image_checks() -> None:
    assert page.image_error(PNG) is None
    assert page.image_error(b"\xff\xd8\xff\xe0" + b"\x00" * 8) is None
    assert page.image_error(b"GIF89a") == page.IMAGE_TYPE
    assert page.image_error(b"\x89PNG\r\n\x1a\n" + b"\x00" * options.MAX_IMAGE_BYTES) == page.IMAGE_SIZE


def test_the_diagram_is_described_reviewed_and_added(mock_mode: None) -> None:
    draft = {**READY_DRAFT, "step": 0, "image_b64": base64.b64encode(PNG).decode(),
             "image_name": "arch.png", "image_size": len(PNG)}
    at = new_wizard(draft).run()
    at.button(key="tm_describe").click().run()
    text = at.text_area(key="tmw_diagram_text").value
    assert text
    at.text_area(key="tmw_diagram_text").input("Reviewed: a load balancer in front of the API.").run()
    final = runs.description_for_run(at.session_state["aegis_tm_draft"])
    assert final.endswith("Architecture Diagram Analysis:\nReviewed: a load balancer in front of the API.")
    at.checkbox(key="tmw_diagram_use").uncheck().run()
    assert "Architecture" not in runs.description_for_run(at.session_state["aegis_tm_draft"])
    at.button(key="tm_image_remove").click().run()
    assert "image_b64" not in at.session_state["aegis_tm_draft"]


def test_describing_needs_a_model() -> None:
    draft = {**READY_DRAFT, "step": 0, "image_b64": base64.b64encode(PNG).decode(),
             "image_name": "arch.png", "image_size": len(PNG)}
    at = new_wizard(draft).run()
    assert at.button(key="tm_describe").disabled
    caption = "".join(c.value for c in at.caption)
    assert "Add an OpenAI API key to run this step." in caption
    assert "the model you choose in Settings" in caption


# ------------------------------------------------------------ runs


def test_a_full_mock_run_saves_once_and_shows_results(mock_mode: None, fresh_runner: JobRunner) -> None:
    at = new_wizard(READY_DRAFT).run()
    with jobs_held(fresh_runner):
        at.button(key="tm_generate").click().run()
        job_id = at.session_state["aegis_jobs"]["threat_model"]
        assert at.query_params["run"] == [job_id] or at.query_params.get("run") in (job_id, [job_id])
    run = wait_settled(at)
    assert run["final"]["status"] == "complete" and run["record_id"]
    for _ in range(5):
        at.run()
    records = saved_threat_models(at)
    assert len(records) == 1
    payload = records[0].payload
    assert payload["profile"]["industry_sector"] == "Retail"
    assert payload["description"].startswith("An online checkout service")
    assert payload["dread_assessment_markdown"]
    assert fresh_runner.snapshot(job_id) is None
    assert "run" not in at.query_params
    assert [t.label for t in at.tabs][:3] == ["Attack path", "STRIDE findings", "MITRE ATT&CK mapping"]
    assert "Saved to your workspace as: Web application: Retail." in html_of(at)
    assert not at.button(key="tm_step_3").disabled
    at.button(key="tm_step_3").click().run()
    labels = [b.label for b in at.get("download_button")]
    assert labels[:5] == ["PDF", "HTML", "JSON", "SARIF", "Markdown"]


def test_generate_refuses_incomplete_input(mock_mode: None) -> None:
    at = new_wizard({**READY_DRAFT, "description": "short"}).run()
    at.button(key="tm_generate").click().run()
    assert "Complete steps 1 and 2 first." in html_of(at)
    assert run_record(at) is None


def test_generate_without_a_key_says_so() -> None:
    at = new_wizard(READY_DRAFT).run()
    at.button(key="tm_generate").click().run()
    assert "Add an OpenAI API key to run this step." in html_of(at)


def test_cancel_stops_the_run_and_offers_it_again(mock_mode: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runs, "MOCK_CHUNK_DELAY_SECONDS", 0.05)
    at = new_wizard(READY_DRAFT).run()
    at.button(key="tm_generate").click().run()
    assert at.button(key="tm_generate").disabled and not at.button(key="tm_cancel").disabled
    at.button(key="tm_cancel").click().run()
    run = wait_settled(at)
    assert run["final"]["status"] == "cancelled" and run["record_id"] is None
    at.run()
    assert "run" not in at.query_params
    assert "The run was cancelled." in html_of(at)
    assert at.button(key="tm_generate").label == "Run it again"
    assert saved_threat_models(at) == []


def test_a_failed_run_shows_the_plain_sentence(mock_mode: None, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> dict:
        raise LLMError("upstream said: key sk-secret was rejected")

    monkeypatch.setattr(runs, "run_threat_model", boom)
    at = new_wizard(READY_DRAFT).run()
    at.button(key="tm_generate").click().run()
    run = wait_settled(at)
    assert run["final"]["status"] == "failed" and run["final"]["error"] == ERROR_UPSTREAM
    at.run()
    assert "run" not in at.query_params
    body = html_of(at)
    assert ERROR_UPSTREAM in body and "sk-secret" not in body
    assert at.button(key="tm_generate").label == "Run it again"
    # Run it again starts a fresh run that succeeds.
    monkeypatch.undo()
    monkeypatch.setattr(runs, "MOCK_CHUNK_DELAY_SECONDS", 0.0)
    monkeypatch.setenv("AEGIS_MOCK_LLM", "1")
    at.button(key="tm_generate").click().run()
    assert wait_settled(at)["final"]["status"] == "complete"


def test_the_servers_cap_is_explained(mock_mode: None, monkeypatch: pytest.MonkeyPatch) -> None:
    busy = JobRunner(max_concurrent_jobs=1, job_timeout_seconds=60)
    monkeypatch.setattr(runner_mod, "_runner", busy)
    release = threading.Event()
    busy.submit(lambda _p: (release.wait(5), {})[1], kind="other")
    try:
        at = new_wizard(READY_DRAFT).run()
        at.button(key="tm_generate").click().run()
        assert ERROR_CAP in html_of(at)
        assert run_record(at) is None
    finally:
        release.set()


def test_a_run_survives_a_rerun_and_a_reload(mock_mode: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runs, "MOCK_CHUNK_DELAY_SECONDS", 0.01)
    at = new_wizard(READY_DRAFT).run()
    at.button(key="tm_generate").click().run()
    job_id = at.session_state["aegis_jobs"]["threat_model"]
    at.run()
    assert runs.is_running.__name__  # still the same session; nothing to assert beyond no error
    assert not at.exception
    # A reload is a new session with only the URL: ?run=<job id>.
    fresh = new_wizard()
    fresh.query_params["run"] = job_id
    fresh.run()
    assert fresh.session_state["aegis_tm_draft"]["step"] == 2
    run = wait_settled(fresh)
    assert run["final"]["status"] == "complete"
    assert len(saved_threat_models(fresh)) == 1


def test_an_unknown_run_in_the_url_is_dropped(mock_mode: None) -> None:
    at = new_wizard()
    at.query_params["run"] = "x" * 43
    at.run()
    assert run_record(at) is None and "run" not in at.query_params


def test_a_run_the_runner_forgot_reads_as_lost(mock_mode: None, fresh_runner: JobRunner,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runs, "MOCK_CHUNK_DELAY_SECONDS", 0.05)
    at = new_wizard(READY_DRAFT).run()
    at.button(key="tm_generate").click().run()
    job_id = at.session_state["aegis_jobs"]["threat_model"]
    fresh_runner.cancel(job_id)
    fresh_runner.discard(job_id)
    run = wait_settled(at)
    assert run["final"]["status"] == "failed" and run["final"]["error"] == runs.LOST_SENTENCE


def test_the_agentic_path_hides_addons_and_runs_in_the_office(mock_mode: None) -> None:
    at = new_wizard(READY_DRAFT)
    at.session_state["aegis_agentic"] = True
    at.run()
    assert "Agent team" in html_of(at)
    assert not any(t.key and t.key.startswith("tmw_addon_") for t in at.toggle)
    assert live_views(at) == ["aegis_office"]
    at.button(key="tm_generate").click().run()
    assert live_views(at) == ["aegis_office"]
    run = wait_settled(at)
    assert run["agentic"] is True and run["final"]["status"] == "complete"
    assert run["final"]["progress"]["agentic"] is True
    at.run()
    assert live_views(at) == ["aegis_office"]
    assert "Teammate review" in html_of(at)
    assert saved_threat_models(at)[0].payload.get("lead_plan")


def test_a_linear_run_after_an_agentic_run_shows_the_deck(mock_mode: None,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runs, "MOCK_CHUNK_DELAY_SECONDS", 0.0)
    at = new_wizard(READY_DRAFT)
    at.session_state["aegis_agentic"] = True
    at.run()
    at.button(key="tm_generate").click().run()
    wait_settled(at)
    at.run()
    assert live_views(at) == ["aegis_office"]
    at.session_state["aegis_agentic"] = False
    at.run()
    at.button(key="tm_generate").click().run()
    assert live_views(at) == ["aegis_deck"]
    run = wait_settled(at)
    assert run["agentic"] is False and run["final"]["status"] == "complete"
    at.run()
    assert live_views(at) == ["aegis_deck"]
    assert len(saved_threat_models(at)) == 2


@pytest.mark.parametrize(("record", "agentic", "office"), [
    (None, False, False),
    (None, True, True),
    ({"status": "queued", "progress": None}, True, True),
    ({"status": "running", "progress": {"agentic": True, "lead": {}}}, False, True),
    ({"status": "running", "progress": {"office": True, "stages": []}}, True, False),
    ({"status": "running", "progress": {"agentic": "yes"}}, True, False),
])
def test_the_live_view_routes_on_the_record(record: dict | None, agentic: bool,
                                             office: bool) -> None:
    assert runs.uses_office(record, agentic=agentic) is office


def test_each_live_view_has_its_own_fixed_key() -> None:
    from streamlit.testing.v1 import AppTest

    def app() -> None:
        from aegisshield.ui import threat_model_run

        threat_model_run.render_live({"status": "running", "progress": {
            "agentic": True, "lead": {"status": "working"}, "agents": []}}, agentic=False)
        threat_model_run.render_live(None, agentic=False)

    at = AppTest.from_function(app).run()
    nodes = at.get("bidi_component")
    assert [n.proto.component_name for n in nodes] == ["aegis_office", "aegis_deck"]
    assert nodes[0].proto.id.endswith("-" + runs.OFFICE_KEY)
    assert nodes[1].proto.id.endswith("-" + runs.DECK_KEY)
    assert runs.OFFICE_KEY != runs.DECK_KEY


# ------------------------------------------------------------ hand-offs


def test_a_lookup_fills_the_technologies_once(mock_mode: None) -> None:
    ws = Workspace()
    lookup = ws.add(RecordKind.LOOKUPS, "Lookup", {"request": {}, "result": {"technologies": [
        {"name": "PostgreSQL", "product": "postgresql:postgresql", "lookup_version": "15.4.0",
         "state": "found"}]}})
    at = new_wizard(workspace=ws)
    at.query_params["id"] = lookup.id
    at.run()
    draft = at.session_state["aegis_tm_draft"]
    pg = next(c for c in options.technology_choices() if c.name == "PostgreSQL")
    assert draft["technologies"] == {pg.key: "15.4.0"}
    assert "Filled in from your vulnerability lookup: 1 technology selected" in html_of(at)
    draft["technologies"] = {}
    at.run()  # applied once: the visitor's later change stands
    assert at.session_state["aegis_tm_draft"]["technologies"] == {}


def test_an_empty_lookup_says_it_could_not_be_used(mock_mode: None) -> None:
    ws = Workspace()
    lookup = ws.add(RecordKind.LOOKUPS, "Lookup", {"request": {}, "result": {"technologies": []}})
    at = new_wizard(workspace=ws)
    at.query_params["id"] = lookup.id
    at.run()
    assert html.escape(page.LOOKUP_FAILED_NOTICE) in html_of(at)


def test_run_again_fills_every_input_from_a_saved_model(mock_mode: None) -> None:
    pg = next(c for c in options.technology_choices() if c.name == "PostgreSQL")
    ws = Workspace()
    record = ws.add(RecordKind.THREAT_MODELS, "Earlier", {
        "profile": {"app_type": "Mobile application", "industry_sector": "Financial",
                    "sensitive_data": "Medium", "internet_facing": "No", "num_employees": "0-10",
                    "technical_ability": "High", "compliance_requirements": ["SOC 2"],
                    "authentication": ["Passkeys"], "app_pattern": ["GenAI"],
                    "selected_technologies": {"PostgreSQL": pg.cpe},
                    "selected_versions": {"PostgreSQL": "*"}},
        "description": "A banking app.\n\nArchitecture Diagram Analysis:\nTwo tiers."})
    at = new_wizard(workspace=ws)
    at.query_params["id"] = record.id
    at.run()
    draft = at.session_state["aegis_tm_draft"]
    assert draft["description"] == "A banking app."
    assert draft["diagram_text"] == "Two tiers." and draft["diagram_use"] is True
    assert draft["app_type"] == "Mobile application" and draft["technical_ability"] == "High"
    assert draft["technologies"] == {pg.key: ""}
    assert draft["app_pattern"] == ["GenAI"]
    at.button(key="tm_step_1").click().run()
    assert at.selectbox(key="tmw_industry_sector").value == "Financial"


def test_an_unknown_id_changes_nothing(mock_mode: None) -> None:
    at = new_wizard()
    at.query_params["id"] = "nope"
    at.run()
    assert "applied" not in at.session_state["aegis_tm_draft"]


def test_export_step_before_a_run_is_empty(mock_mode: None) -> None:
    at = new_wizard({**READY_DRAFT, "step": 3, "reached": 3}).run()
    assert "Nothing to export yet" in html_of(at)


def test_wait_helper_gives_up(mock_mode: None) -> None:
    at = new_wizard(READY_DRAFT).run()
    start = time.time()
    with pytest.raises(AssertionError):
        wait_settled(at, seconds=0.2)
    assert time.time() - start < 5


def test_export_opens_on_the_run_that_saves(mock_mode: None) -> None:
    at = new_wizard(READY_DRAFT).run()
    at.button(key="tm_generate").click().run()
    # Settle with the run of the page that saves, then check the stepper
    # drawn on that same run (the browser does not rerun once more).
    deadline = time.time() + 20
    while time.time() < deadline and not (run_record(at) or {}).get("record_id"):
        time.sleep(0.05)
        at.run()
    assert not at.button(key="tm_step_3").disabled


def test_the_run_bar_folds_to_one_line_once_a_run_starts(mock_mode: None) -> None:
    at = new_wizard(READY_DRAFT).run()
    body = html_of(at)
    assert "On by default. Each adds a stage to the run." in body
    assert '<p class="tm-runline">' not in body
    at.toggle(key="tmw_addon_dread").set_value(False).run()
    at.button(key="tm_generate").click().run()
    wait_settled(at)
    at.run()
    body = html_of(at)
    assert "On by default. Each adds a stage to the run." not in body
    assert ('<p class="tm-runline"><strong>Additional analyses:</strong> '
            "Mitigations, Test cases</p>") in body
    # The switches stay in the Analyses popover for the next run.
    assert at.toggle(key="tmw_addon_dread").value is False
    assert not at.toggle(key="tmw_addon_dread").disabled
    assert at.button(key="tm_generate").label == "Generate"


def test_the_agentic_path_says_what_it_will_produce(mock_mode: None) -> None:
    at = new_wizard(READY_DRAFT)
    at.session_state["aegis_agentic"] = True
    at.run()
    assert page.AGENTIC_SUMMARY in html_of(at).replace("&amp;", "&")
    at.button(key="tm_generate").click().run()
    wait_settled(at)
    at.run()
    assert "STRIDE, MITRE ATT&amp;CK, and the attack tree; the lead picks the rest." in html_of(at)
    assert not any(t.key and t.key.startswith("tmw_addon_") for t in at.toggle)


def test_after_a_run_the_bar_follows_the_setting_and_the_view_keeps_the_run(
        mock_mode: None) -> None:
    at = new_wizard(READY_DRAFT)
    at.session_state["aegis_agentic"] = True
    at.run()
    at.button(key="tm_generate").click().run()
    wait_settled(at)
    at.session_state["aegis_agentic"] = False
    at.run()
    body = html_of(at)
    # Generate starts a linear run next, so the bar offers its add-ons...
    assert "<strong>Additional analyses:</strong>" in body
    assert "the lead picks the rest" not in body
    assert at.toggle(key="tmw_addon_dread")
    # ...while the finished agentic run stays in the office.
    assert live_views(at) == ["aegis_office"]
    at.session_state["aegis_agentic"] = True
    at.run()
    assert "the lead picks the rest" in html_of(at)
    assert live_views(at) == ["aegis_office"]


def test_while_a_run_is_going_the_bar_keeps_the_runs_mode(mock_mode: None,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runs, "MOCK_CHUNK_DELAY_SECONDS", 0.05)
    at = new_wizard(READY_DRAFT).run()
    at.button(key="tm_generate").click().run()
    at.session_state["aegis_agentic"] = True
    at.run()
    assert run_record(at)["final"] is None  # still going
    assert "<strong>Additional analyses:</strong>" in html_of(at)
    assert live_views(at) == ["aegis_deck"]
    wait_settled(at)


def test_an_oversized_image_is_refused_before_it_is_read(mock_mode: None,
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    import streamlit as st

    seen: dict = {}

    class Oversized:
        name = "huge.png"
        size = options.MAX_IMAGE_BYTES + 1

        def getvalue(self) -> bytes:
            raise AssertionError("an oversized upload must not be read")

    def fake_uploader(*args, **kwargs):
        seen.update(kwargs)
        return Oversized()

    monkeypatch.setattr(st, "file_uploader", fake_uploader)
    at = new_wizard().run()
    assert not at.exception
    assert seen["max_upload_size"] == page.MAX_IMAGE_MB == 10
    assert page.IMAGE_SIZE in html_of(at)
    assert "image_b64" not in at.session_state["aegis_tm_draft"]


def test_a_run_outside_mock_mode_through_claude_records_the_model_and_never_the_key(
        fresh_runner: JobRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    """The wizard with a Claude choice runs the real ``AnthropicClient`` on a
    canned fake SDK (every answer is the mock's, in Claude's stream shape)."""
    import json

    from aegisshield.config import PRESELECTED_CLAUDE_MODEL
    from aegisshield.llm import factory
    from aegisshield.llm.anthropic_client import AnthropicClient
    from aegisshield.llm.base import ModelInfo
    from aegisshield.llm.providers import Provider
    from tests.aegisshield.llm.provider_fakes import AnsweringAnthropic

    monkeypatch.setenv("AEGIS_OFFLINE", "1")
    key = "sk-ant-" + "api03-" + "k" * 40
    fake = AnsweringAnthropic(sizes=(9, 120))
    built: list[str] = []

    def build(provider: Provider, cred: object) -> AnthropicClient:
        assert provider is Provider.CLAUDE
        built.append(provider.value)
        return AnthropicClient("unused", sdk_client=fake)

    monkeypatch.setattr(factory, "_build", build)
    progress: list[str] = []
    real_set = runner_mod.ProgressSink.set

    def keep(self: runner_mod.ProgressSink, record: dict) -> None:
        progress.append(json.dumps(record, default=str))
        real_set(self, record)

    monkeypatch.setattr(runner_mod.ProgressSink, "set", keep)

    at = new_wizard(READY_DRAFT)
    at.session_state["aegis_provider"] = "claude"
    at.session_state["aegis_creds"] = {"claude": {"api_key": key}}
    at.session_state["aegis_model_lists"] = {"claude": {
        "at": time.time(), "models": (ModelInfo(PRESELECTED_CLAUDE_MODEL, True),), "failed": False}}
    at.run()
    with jobs_held(fresh_runner):
        at.button(key="tm_generate").click().run()
    run = wait_settled(at)
    assert run["final"]["status"] == "complete" and run["record_id"]
    for _ in range(3):
        at.run()

    assert built == ["claude"]
    assert fake.calls and {c["model"] for c in fake.calls} == {PRESELECTED_CLAUDE_MODEL}
    [record] = saved_threat_models(at)
    assert record.payload["model"] == {"provider": "claude", "name": PRESELECTED_CLAUDE_MODEL}
    assert record.payload["threat_model"]
    page_html = html_of(at)
    assert f"Answered by Claude (Anthropic), {PRESELECTED_CLAUDE_MODEL}" in html.unescape(page_html)

    workspace_json = at.session_state["aegis_workspace"].to_json().decode()
    assert progress
    assert key not in page_html and key not in workspace_json
    assert all(key not in item for item in progress)
    assert all(key not in json.dumps(c, default=str) for c in fake.calls)
