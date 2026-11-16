"""The threat model detail page: not found, a full record, an empty payload,
Run again, rename, and delete."""

from __future__ import annotations

import pytest
from streamlit.testing.v1 import AppTest

from aegisshield.storage import Record, RecordKind, Workspace
from aegisshield.ui.pages.threat_model_detail import HEADING_CHARS, header_text, meta_items
from tests.aegisshield.ui.tm_records import mock_payload

HOSTILE = "<img src=x onerror=alert(1)>"


def _app() -> None:
    import streamlit as st

    from aegisshield.ui import routes
    from aegisshield.ui.pages import threat_model_detail
    from aegisshield.ui.theme import apply_theme

    apply_theme()
    st.navigation(routes.build_navigation(with_tshark=False))
    action = st.session_state.pop("test_action", None)
    if action:
        name, args = action
        getattr(threat_model_detail, name)(*args)
    threat_model_detail.render()


def _at(ws: Workspace, record_id: str | None) -> AppTest:
    at = AppTest.from_function(_app, default_timeout=30)
    at.session_state["aegis_workspace"] = ws
    if record_id is not None:
        at.query_params["id"] = record_id
    return at


def _html(at: AppTest) -> str:
    return "\n".join(str(node.value) for node in at.get("html"))


@pytest.fixture(scope="module")
def full() -> tuple[Workspace, Record]:
    ws = Workspace()
    record = ws.add(RecordKind.THREAT_MODELS, "Checkout service", mock_payload())
    return ws, record


@pytest.mark.parametrize("record_id", [None, "unknown_id", "bad id!"])
def test_missing_or_unknown_id_shows_not_found(record_id: str | None) -> None:
    at = _at(Workspace(), record_id).run()
    assert not at.exception
    body = _html(at)
    assert "Threat model not found" in body
    assert [link.label for link in at.get("page_link")] == ["All threat models"]


def test_a_full_record_renders_header_meta_tabs_and_exports(full: tuple[Workspace, Record]) -> None:
    ws, record = full
    at = _at(ws, record.id).run()
    assert not at.exception
    body = _html(at)
    assert '<h1 class="ax-title">Checkout service</h1>' in body
    assert "Web application, Retail" in body
    assert "DREAD " in body and "Saved" in body
    assert "<dt>Application type</dt>" in body and "<dt>Technologies</dt>" in body
    assert "PostgreSQL 15.4" in body
    tabs = [t.label for t in at.tabs]
    for name in ("Attack path", "STRIDE findings", "MITRE ATT&CK mapping", "DREAD", "Mitigations",
                 "Test cases", "Compliance mapping", "Lookup results"):
        assert name in tabs
    downloads = at.get("download_button")
    labels = [d.proto.label for d in downloads]
    for label in ("PDF", "HTML", "JSON", "SARIF", "Markdown", "Attack tree (.mmd)",
                  "Test cases (.feature)"):
        assert label in labels
    assert "the server is busy or a table is too long for a PDF" in body
    assert [b.label for b in at.button if b.key == "tmd_rerun"] == ["Run again with these inputs"]


def test_meta_items_omit_empty_rows(full: tuple[Workspace, Record]) -> None:
    _, record = full
    labels = [label for label, _ in meta_items(record)]
    assert labels[:2] == ["Application type", "Industry sector"]
    assert "Patterns" not in labels  # no pattern was chosen
    assert labels[-1] == "Created"
    bare = Record(id="r1", created_at="2026-11-13T12:00:00+00:00", title="T", payload={})
    assert [label for label, _ in meta_items(bare)] == ["Created"]
    assert meta_items(bare)[0][1].startswith("2026-11-13 (")


def test_an_empty_payload_still_renders() -> None:
    ws = Workspace()
    record = ws.add(RecordKind.THREAT_MODELS, HOSTILE, {})
    at = _at(ws, record.id).run()
    assert not at.exception
    body = _html(at)
    assert "&lt;img src=x onerror=alert(1)&gt;" in body
    assert "<img src=x" not in body
    assert "Threat model not found" not in body
    assert "One threat model and its results." in body


def test_run_again_clears_the_wizard_draft_and_opens_the_wizard(
        full: tuple[Workspace, Record]) -> None:
    ws, record = full
    at = _at(ws, record.id)
    at.session_state["aegis_tm_draft"] = {"description": "old", "applied": record.id}
    at.run()
    at.button(key="tmd_rerun").click().run()
    assert not at.exception
    assert at.session_state["aegis_tm_draft"] == {}
    assert at.query_params.get("id") in (record.id, [record.id])


def test_rename_keeps_the_id() -> None:
    ws = Workspace()
    record = ws.add(RecordKind.THREAT_MODELS, "Old", {})
    at = _at(ws, record.id).run()
    at.text_input(key=f"tmd_title_{record.id}").input("New name")
    at.button(key="tmd_rename").click().run()
    assert not at.exception
    stored = at.session_state["aegis_workspace"].get(RecordKind.THREAT_MODELS, record.id)
    assert stored.title == "New name"
    assert "Renamed." in _html(at)


def test_rename_rejects_an_empty_title() -> None:
    ws = Workspace()
    record = ws.add(RecordKind.THREAT_MODELS, "Old", {})
    at = _at(ws, record.id).run()
    at.text_input(key=f"tmd_title_{record.id}").input("   ")
    at.button(key="tmd_rename").click().run()
    assert at.session_state["aegis_workspace"].get(RecordKind.THREAT_MODELS, record.id).title == "Old"
    assert "A title cannot be empty." in _html(at)


def test_delete_button_asks_first() -> None:
    ws = Workspace()
    record = ws.add(RecordKind.THREAT_MODELS, "Old", {})
    at = _at(ws, record.id).run()
    at.button(key="tmd_delete").click().run()
    assert not at.exception
    assert any("cannot be undone" in c.value for c in at.caption)
    assert at.session_state["aegis_workspace"].get(RecordKind.THREAT_MODELS, record.id) is not None


def test_delete_removes_the_record_and_returns_to_the_list(monkeypatch: pytest.MonkeyPatch) -> None:
    import streamlit as st

    went: list[object] = []

    def fake_switch(page: object, **_kwargs: object) -> None:
        went.append(page)
        raise st.runtime.scriptrunner.StopException()

    monkeypatch.setattr(st, "switch_page", fake_switch)
    ws = Workspace()
    record = ws.add(RecordKind.THREAT_MODELS, "Old", {})
    at = _at(ws, record.id)
    at.session_state["test_action"] = ("_delete", (record.id,))
    at.run()
    assert at.session_state["aegis_workspace"].get(RecordKind.THREAT_MODELS, record.id) is None
    assert len(went) == 1 and getattr(went[0], "url_path", "") == "threat-models"
    assert at.session_state["aegis_flash"] == ("Deleted: Old", "ok")


def test_an_agentic_record_carries_the_agent_team_badge() -> None:
    ws = Workspace()
    record = ws.add(RecordKind.THREAT_MODELS, "Agentic", {"agentic": True})
    body = _html(_at(ws, record.id).run())
    assert "Agent team" in body


def test_a_long_title_gives_way_to_a_short_heading_with_the_full_title_below() -> None:
    profile = {"app_type": "Web application", "industry_sector": "Retail"}
    long_title = "Web application: Retail. " + "An online checkout service for a retailer " * 3
    assert len(long_title) > HEADING_CHARS
    assert header_text(long_title, profile) == ("Web application, Retail", long_title)
    assert header_text("Checkout service", profile) == ("Checkout service", "Web application, Retail")
    # No app type or sector to fall back on: the title stays the heading.
    assert header_text(long_title, {})[0] == long_title


def test_the_page_shows_the_short_heading_and_the_full_stored_title(full: tuple[Workspace, Record]) -> None:
    ws, record = full
    long_title = "Web application: Retail. " + "<b>An online checkout</b> service " * 5
    ws.rename(RecordKind.THREAT_MODELS, record.id, long_title)
    body = _html(_at(ws, record.id).run())
    assert '<h1 class="ax-title">Web application, Retail</h1>' in body
    assert "&lt;b&gt;An online checkout&lt;/b&gt;" in body and "<b>An online" not in body
