"""The dashboard under AppTest: first run, sample data, posture, banner, recent list."""

from __future__ import annotations

import pytest
from streamlit.testing.v1 import AppTest

from aegisshield.services.posture_service import aggregate_posture
from aegisshield.storage import RecordKind, Workspace
from tests.aegisshield.ui.tm_records import dread_payload, mock_payload

HOSTILE = "<img src=x onerror=alert(1)>"


def _app() -> None:
    import streamlit as st

    from aegisshield.ui import routes
    from aegisshield.ui.pages import dashboard
    from aegisshield.ui.theme import apply_theme

    apply_theme()
    st.navigation(routes.build_navigation(with_tshark=False))
    dashboard.render()


def _run(ws: Workspace | None = None) -> AppTest:
    at = AppTest.from_function(_app, default_timeout=30)
    if ws is not None:
        at.session_state["aegis_workspace"] = ws
    return at.run()


def _html(at: AppTest) -> str:
    return "\n".join(str(node.value) for node in at.get("html"))


def _buttons(at: AppTest) -> list[str]:
    return [b.label for b in at.button]


def test_first_run_in_mock_mode_offers_sample_data(mock_mode: None) -> None:
    at = _run()
    assert not at.exception
    body = _html(at)
    assert "Start here" in body and "STRIDE threat model" in body
    assert "Try with sample data" in _buttons(at)
    assert "No threat models yet" in body


def test_first_run_without_mock_mode_has_no_sample_button() -> None:
    at = _run()
    assert not at.exception
    assert "Start here" in _html(at)
    assert "Try with sample data" not in _buttons(at)


def test_sample_button_adds_one_scored_record_and_flashes(mock_mode: None) -> None:
    at = _run()
    at.button(key="dash_sample").click().run()
    assert not at.exception
    ws = at.session_state["aegis_workspace"]
    records = ws.list(RecordKind.THREAT_MODELS)
    assert len(records) == 1
    assert records[0].payload.get("dread_assessment_markdown")
    assert "Sample threat model added" in _html(at)
    # The welcome card is gone once there is a threat model.
    assert "Start here" not in _html(at)


def test_populated_tiles_and_recent_list_escape_titles() -> None:
    ws = Workspace()
    ws.add(RecordKind.THREAT_MODELS, HOSTILE, dread_payload(5.0, 4.2))
    at = _run(ws)
    assert not at.exception
    body = _html(at)
    assert "1 threat model on file" in body
    assert "Medium risk, 2 threats scored" in body
    assert "All threat models have DREAD" in body
    assert "<img src=x" not in body
    # The record link carries the title as a label (plain text, not markup).
    labels = [link.label for link in at.get("page_link")]
    assert HOSTILE in labels
    assert "Start here" not in body


@pytest.mark.parametrize("score, word", [(9.1, "Critical"), (6.5, "High")])
def test_urgent_banner_for_high_and_critical(score: float, word: str) -> None:
    ws = Workspace()
    ws.add(RecordKind.THREAT_MODELS, "Checkout", dread_payload(score, 2.0))
    body = _html(_run(ws))
    assert "Needs attention now" in body
    assert f"{word}-severity threat open: highest DREAD risk is {score:.1f}" in body
    assert "2 threats scored" in body


@pytest.mark.parametrize("score", [5.0, 2.0])
def test_no_urgent_banner_for_medium_or_low(score: float) -> None:
    ws = Workspace()
    ws.add(RecordKind.THREAT_MODELS, "Checkout", dread_payload(score))
    assert "Needs attention now" not in _html(_run(ws))


def test_unscored_record_shows_not_scored() -> None:
    ws = Workspace()
    ws.add(RecordKind.THREAT_MODELS, "Checkout", {"profile": {"app_type": "Web application"}})
    body = _html(_run(ws))
    assert "Not scored" in body and "No DREAD assessments yet" in body


def test_last_lookup_cell_shows_its_status() -> None:
    ws = Workspace()
    ws.add(RecordKind.LOOKUPS, "Lookup", {"request": {}, "result": {
        "status": "complete", "finished_at": "2026-11-13T12:00:00+00:00",
        "summary": {"tech_count": 3}}})
    at = _run(ws)
    assert not at.exception
    body = _html(at)
    assert "Last vulnerability lookup" in body and "Complete" in body
    assert "3 technologies" in body
    # A lookup alone is not a first run.
    assert "Start here" not in body


def test_a_real_mock_result_feeds_the_posture_snapshot() -> None:
    ws = Workspace()
    ws.add(RecordKind.THREAT_MODELS, "Checkout", mock_payload())
    snap = aggregate_posture(ws)
    assert snap.threat_model_count == 1
    assert snap.coverage_pct == 100
    assert snap.dread_highest is not None
    assert snap.dread_threats_assessed > 0


def test_sample_data_is_never_added_outside_mock_mode() -> None:
    def app() -> None:
        from aegisshield.ui.pages import dashboard

        dashboard.add_sample_threat_model()

    at = AppTest.from_function(app, default_timeout=30).run()
    assert not at.exception
    assert "aegis_workspace" not in at.session_state


def test_recent_titles_end_in_an_ellipsis_rule() -> None:
    """The dashboard row's title link keeps to one line with an ellipsis (the
    browser check measures it rendered; this keeps the rule in place)."""
    from aegisshield.ui import tm_style

    css = tm_style.CSS
    rule = '[class*="st-key-dash_row_"] [data-testid="stPageLink"] a p'
    assert rule in css
    block = css[css.index(rule):css.index("}", css.index(rule))]
    assert "text-overflow: ellipsis" in block and "white-space: nowrap" in block

