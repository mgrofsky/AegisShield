"""The threat model list: empty state, order, search, sort, rename, delete."""

from __future__ import annotations

import pytest
from streamlit.testing.v1 import AppTest

from aegisshield.storage import Record, RecordKind, Workspace
from aegisshield.ui.pages.threat_models import SORTS, list_rows
from tests.aegisshield.ui.tm_records import dread_payload

HOSTILE = "<script>alert(1)</script>"


def _app() -> None:
    import streamlit as st

    from aegisshield.ui import routes
    from aegisshield.ui.pages import threat_models
    from aegisshield.ui.theme import apply_theme

    apply_theme()
    st.navigation(routes.build_navigation(with_tshark=False))
    action = st.session_state.pop("test_action", None)
    if action:
        name, args = action
        getattr(threat_models, name)(*args)
    threat_models.render()


def _run(ws: Workspace, action: tuple[str, tuple] | None = None) -> AppTest:
    at = AppTest.from_function(_app, default_timeout=30)
    at.session_state["aegis_workspace"] = ws
    if action:
        at.session_state["test_action"] = action
    return at.run()


def _html(at: AppTest) -> str:
    return "\n".join(str(node.value) for node in at.get("html"))


def _record(ws: Workspace, title: str, created: str, app_type: str = "Web application",
            sector: str = "Retail", scores: tuple[float, ...] = ()) -> Record:
    payload = dread_payload(*scores) if scores else {"profile": {}}
    payload["profile"] = {"app_type": app_type, "industry_sector": sector}
    record = ws.add(RecordKind.THREAT_MODELS, title, payload)
    # Fix the time so the order is known.
    import dataclasses

    fixed = dataclasses.replace(record, created_at=created)
    ws._items[RecordKind.THREAT_MODELS][record.id] = fixed
    return fixed


@pytest.fixture
def three() -> tuple[Workspace, list[Record]]:
    ws = Workspace()
    records = [
        _record(ws, "Beta checkout", "2026-11-10T10:00:00+00:00", "Mobile application",
                "Retail", (5.0,)),
        _record(ws, "alpha payroll", "2026-11-12T10:00:00+00:00", "SaaS application",
                "Financial", (8.6, 3.0)),
        _record(ws, "Gamma kiosk", "2026-11-11T10:00:00+00:00", "IoT application",
                "Education"),
    ]
    return ws, records


def test_empty_state_leads_to_the_wizard() -> None:
    at = _run(Workspace())
    assert not at.exception
    assert "No threat models yet" in _html(at)
    assert [link.label for link in at.get("page_link")] == ["Create your first threat model"]
    assert len(at.dataframe) == 0


def test_rows_are_newest_first(three: tuple[Workspace, list[Record]]) -> None:
    ws, _ = three
    rows = list_rows(ws.list(RecordKind.THREAT_MODELS), "", SORTS[0])
    assert [r["Title"] for r in rows] == ["alpha payroll", "Gamma kiosk", "Beta checkout"]
    assert rows[0]["Threats"] == 2 and rows[0]["Highest DREAD"] == 8.6
    assert rows[0]["Severity"] == "Critical" and rows[1]["Severity"] == "Not scored"
    assert rows[0]["Created"] == "2026-11-12 10:00"
    at = _run(ws)
    assert not at.exception
    assert len(at.dataframe) == 1
    assert list(at.dataframe[0].value["Title"]) == ["alpha payroll", "Gamma kiosk", "Beta checkout"]


@pytest.mark.parametrize("query, titles", [
    ("CHECKOUT", ["Beta checkout"]),
    ("saas", ["alpha payroll"]),
    ("EDUCATION", ["Gamma kiosk"]),
    ("  ", ["alpha payroll", "Gamma kiosk", "Beta checkout"]),
    ("nothing matches", []),
])
def test_search_matches_title_type_and_sector(three: tuple[Workspace, list[Record]], query: str,
                                              titles: list[str]) -> None:
    ws, _ = three
    rows = list_rows(ws.list(RecordKind.THREAT_MODELS), query, SORTS[0])
    assert [r["Title"] for r in rows] == titles


@pytest.mark.parametrize("sort, titles", [
    ("Newest first", ["alpha payroll", "Gamma kiosk", "Beta checkout"]),
    ("Oldest first", ["Beta checkout", "Gamma kiosk", "alpha payroll"]),
    ("Highest DREAD first", ["alpha payroll", "Beta checkout", "Gamma kiosk"]),
    ("Title A to Z", ["alpha payroll", "Beta checkout", "Gamma kiosk"]),
])
def test_each_sort_order(three: tuple[Workspace, list[Record]], sort: str, titles: list[str]) -> None:
    ws, _ = three
    assert [r["Title"] for r in list_rows(ws.list(RecordKind.THREAT_MODELS), "", sort)] == titles


def test_search_with_no_match_says_so(three: tuple[Workspace, list[Record]]) -> None:
    ws, _ = three
    at = AppTest.from_function(_app, default_timeout=30)
    at.session_state["aegis_workspace"] = ws
    at.run()
    at.text_input(key="tml_search").input("zzz").run()
    assert not at.exception
    assert "No threat model matches that search." in _html(at)
    at.text_input(key="tml_search").input("kiosk").run()
    assert list(at.dataframe[0].value["Title"]) == ["Gamma kiosk"]


def test_sort_select_reorders_the_table(three: tuple[Workspace, list[Record]]) -> None:
    ws, _ = three
    at = AppTest.from_function(_app, default_timeout=30)
    at.session_state["aegis_workspace"] = ws
    at.run()
    at.selectbox(key="tml_sort").select("Oldest first").run()
    assert list(at.dataframe[0].value["Title"]) == ["Beta checkout", "Gamma kiosk", "alpha payroll"]


def test_rename_keeps_the_id_and_flashes(three: tuple[Workspace, list[Record]]) -> None:
    ws, records = three
    target = records[0]
    at = AppTest.from_function(_app, default_timeout=30)
    at.session_state["aegis_workspace"] = ws
    at.session_state["tml_title_x"] = "  Renamed checkout  "
    at.session_state["test_action"] = ("_rename", (target.id, "tml_title_x"))
    at.run()
    assert not at.exception
    stored = at.session_state["aegis_workspace"].get(RecordKind.THREAT_MODELS, target.id)
    assert stored.title == "Renamed checkout" and stored.id == target.id
    assert stored.created_at == target.created_at
    assert "Renamed." in _html(at)


def test_rename_rejects_an_empty_title(three: tuple[Workspace, list[Record]]) -> None:
    ws, records = three
    at = AppTest.from_function(_app, default_timeout=30)
    at.session_state["aegis_workspace"] = ws
    at.session_state["tml_title_x"] = "   "
    at.session_state["test_action"] = ("_rename", (records[0].id, "tml_title_x"))
    at.run()
    stored = at.session_state["aegis_workspace"].get(RecordKind.THREAT_MODELS, records[0].id)
    assert stored.title == "Beta checkout"
    assert "A title cannot be empty." in _html(at)


def test_delete_removes_the_record_and_flashes(three: tuple[Workspace, list[Record]]) -> None:
    ws, records = three
    at = _run(ws, ("_delete", (records[1].id,)))
    assert not at.exception
    remaining = at.session_state["aegis_workspace"].list(RecordKind.THREAT_MODELS)
    assert [r.title for r in remaining] == ["Gamma kiosk", "Beta checkout"]
    assert "Deleted: alpha payroll" in _html(at)


def test_delete_of_an_unknown_id_changes_nothing(three: tuple[Workspace, list[Record]]) -> None:
    ws, _ = three
    at = _run(ws, ("_delete", ("missing",)))
    assert len(at.session_state["aegis_workspace"].list(RecordKind.THREAT_MODELS)) == 3
    assert "Deleted" not in _html(at)


def test_hostile_titles_are_escaped() -> None:
    ws = Workspace()
    record = ws.add(RecordKind.THREAT_MODELS, HOSTILE, {"profile": {}})
    at = _run(ws, ("_delete", (record.id,)))
    body = _html(at)
    assert "<script>" not in body
    assert "Deleted: &lt;script&gt;" in body


def _selected(ws: Workspace, row: int = 0) -> AppTest:
    at = AppTest.from_function(_app, default_timeout=30)
    at.session_state["aegis_workspace"] = ws
    at.session_state["tml_table"] = {"selection": {"rows": [row], "columns": [], "cells": []}}
    return at.run()


def test_without_a_selection_the_hint_shows(three: tuple[Workspace, list[Record]]) -> None:
    ws, _ = three
    at = _run(ws)
    assert any("Select a row to open, rename, or delete it." in c.value for c in at.caption)
    assert "Rename" not in [b.label for b in at.button]


def test_selecting_a_row_shows_its_actions(three: tuple[Workspace, list[Record]]) -> None:
    ws, records = three
    at = _selected(ws)
    assert not at.exception
    assert [b.label for b in at.button] == ["Rename", "Open", "Delete"]
    newest = records[1]
    assert at.text_input(key=f"tml_title_{newest.id}").value == "alpha payroll"


def test_rename_through_the_selected_card(three: tuple[Workspace, list[Record]]) -> None:
    ws, records = three
    at = _selected(ws)
    newest = records[1]
    at.text_input(key=f"tml_title_{newest.id}").input("Payroll API")
    at.button(key="tml_rename").click().run()
    assert not at.exception
    assert at.session_state["aegis_workspace"].get(RecordKind.THREAT_MODELS, newest.id).title == "Payroll API"


def test_delete_asks_first_then_deletes(three: tuple[Workspace, list[Record]]) -> None:
    ws, records = three
    at = _selected(ws)
    at.button(key="tml_delete").click().run()
    assert not at.exception
    assert any("cannot be undone" in c.value for c in at.caption)
    assert len(at.session_state["aegis_workspace"].list(RecordKind.THREAT_MODELS)) == 3
    at.button(key="tml_confirm_danger").click().run()
    remaining = at.session_state["aegis_workspace"].list(RecordKind.THREAT_MODELS)
    assert records[1].id not in [r.id for r in remaining] and len(remaining) == 2


def test_open_goes_to_the_detail_page(three: tuple[Workspace, list[Record]]) -> None:
    ws, records = three
    at = _selected(ws)
    at.button(key="tml_open").click().run()
    assert not at.exception
    assert at.query_params.get("id") in (records[1].id, [records[1].id])
