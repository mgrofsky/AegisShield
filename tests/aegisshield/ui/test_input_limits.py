"""Visitor text that reaches a model call is limited on the server, not only
by the browser's ``max_chars``: the wizard's description and diagram
description, the request itself, version strings, and policy edits."""

from __future__ import annotations

import pytest

from aegisshield.core.errors import ValidationError
from aegisshield.pipeline import schemas
from aegisshield.storage import RecordKind, Workspace
from aegisshield.ui import options
from aegisshield.ui import threat_model_run as runs
from aegisshield.ui.pages import threat_model_new as page
from tests.aegisshield.ui.tm_support import READY_DRAFT, html_of, new_wizard

LONG = "word " * 4010  # over the 20,000-character limit


@pytest.fixture
def no_browser_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Text areas without ``max_chars``: what a client that skips the
    browser's limit sends. Only the server's checks are left."""
    import streamlit as st

    real = st.text_area

    def text_area(*args, **kwargs):
        kwargs.pop("max_chars", None)
        return real(*args, **kwargs)

    monkeypatch.setattr(st, "text_area", text_area)


def test_an_over_long_description_is_refused_with_its_own_sentence(mock_mode: None, no_browser_limit) -> None:
    at = new_wizard().run()
    at.text_area(key="tmw_description").input(LONG).run()
    at.button(key="tm_next_1").click().run()
    assert "must be at most 20,000 characters" in html_of(at)
    assert at.session_state["aegis_tm_draft"]["step"] == 0


def test_generate_refuses_an_over_long_description_or_diagram_text(mock_mode: None) -> None:
    long_desc = {**READY_DRAFT, "description": LONG.strip()}
    assert page.description_error(long_desc) == page.DESCRIPTION_LONG.format(count=len(LONG.strip()))
    diagram = "d" * (options.MAX_DIAGRAM_TEXT_CHARS + 1)
    with_diagram = {**READY_DRAFT, "diagram_text": diagram, "diagram_use": True}
    assert page.description_error(with_diagram) == page.DIAGRAM_LONG.format(count=len(diagram))
    # A diagram description that is not used does not count.
    assert page.description_error({**with_diagram, "diagram_use": False}) is None
    at = new_wizard(with_diagram).run()
    at.button(key="tm_generate").click().run()
    assert "The diagram description must be at most 10,000 characters" in html_of(at)
    assert at.session_state.get("aegis_tm_run") is None


def test_the_request_refuses_text_the_wizard_did_not_check() -> None:
    draft = {**READY_DRAFT, "description": "x" * (schemas.MAX_APP_DESCRIPTION_CHARS + 1)}
    with pytest.raises(ValidationError) as info:
        runs.build_request(draft, agentic=False)
    assert str(info.value) == runs.REQUEST_INVALID
    with pytest.raises(ValidationError):
        runs.build_request({**READY_DRAFT, "app_type": "a" * 201}, agentic=False)
    with pytest.raises(ValidationError):
        runs.build_request({**READY_DRAFT, "compliance_requirements": ["x"] * (schemas.MAX_PROFILE_ITEMS + 1)},
                           agentic=False)
    assert runs.build_request(READY_DRAFT, agentic=False).app_description


def test_a_long_version_string_is_refused() -> None:
    assert options.validate_version("1" * 33) == "Version should be at most 32 characters."
    assert options.validate_version("1.2.3") is None


def test_an_over_long_policy_edit_is_refused_and_nothing_is_saved(monkeypatch, no_browser_limit) -> None:
    from aegisshield.jobs import runner as runner_module
    from aegisshield.jobs.runner import JobRunner
    from aegisshield.services import policy_service
    from aegisshield.ui.pages import policies
    from tests.aegisshield.ui.tool_helpers import html_of as tool_html
    from tests.aegisshield.ui.tool_helpers import make_app

    monkeypatch.setattr(runner_module, "_runner", JobRunner(max_concurrent_jobs=4, job_timeout_seconds=60))
    monkeypatch.setattr(policy_service, "MAX_BODY_CHARS", 40)
    ws = Workspace()
    record = ws.add(RecordKind.POLICIES, "Access control", {
        "policy_key": "access_control", "title": "Access control", "body_markdown": "## Purpose\n\nShort.",
        "version": 1,
    })
    at = make_app(policies.PAGE, aegis_workspace=ws)
    at.query_params["id"] = record.id
    at.run()
    at.toggle(key=f"pol_edit_on_{record.id}").set_value(True).run()
    at.text_area[0].input("This edit is longer than the forty characters allowed here.")
    next(b for b in at.button if b.label == "Save as a new version").click().run()
    assert not at.exception
    assert "Nothing was saved." in tool_html(at)
    (kept,) = at.session_state["aegis_workspace"].list(RecordKind.POLICIES)
    assert kept.id == record.id and kept.payload["body_markdown"] == "## Purpose\n\nShort."


def test_the_request_limits_fit_every_choice_the_wizard_offers() -> None:
    """Picking everything the wizard offers never trips the request's limits."""
    choices = list(options.technology_choices())
    lists = [choices, options.COMPLIANCE_OPTIONS, options.AUTHENTICATION_OPTIONS, options.PATTERN_OPTIONS]
    assert max(len(x) for x in lists) <= schemas.MAX_PROFILE_ITEMS
    values = [*options.COMPLIANCE_OPTIONS, *options.AUTHENTICATION_OPTIONS,
              *(c.cpe for c in choices), *(c.name for c in choices)]
    assert max(len(str(v)) for v in values) <= schemas.MAX_PROFILE_VALUE_CHARS


def test_an_over_long_lookup_paste_is_refused_before_it_is_read(monkeypatch, no_browser_limit) -> None:
    from aegisshield.jobs import runner as runner_module
    from aegisshield.jobs.runner import JobRunner
    from aegisshield.ui import lookup_data
    from aegisshield.ui.pages import vulnerability_lookup
    from tests.aegisshield.ui.tool_helpers import html_of as tool_html
    from tests.aegisshield.ui.tool_helpers import make_app

    runner = JobRunner(max_concurrent_jobs=4, job_timeout_seconds=60)
    monkeypatch.setattr(runner_module, "_runner", runner)

    def unread(_raw):
        raise AssertionError("an oversized paste must not be parsed")

    monkeypatch.setattr(lookup_data, "parse_pasted", unread)
    at = make_app(vulnerability_lookup.PAGE).run()
    at.text_area(key="vl_paste").input("nginx 1.25.3\n" * (lookup_data.MAX_PASTE_CHARS // 10)).run()
    at.button(key="vl_run").click().run()
    assert not at.exception
    assert vulnerability_lookup.PASTE_TOO_LONG in tool_html(at)
    assert runner._jobs == {}
