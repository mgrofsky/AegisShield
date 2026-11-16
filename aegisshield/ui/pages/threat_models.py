"""Threat models: the workspace's saved threat models, with search, sort,
open, rename, and delete.

Each row shows status, title, and time, plus the profile, threat count,
and highest DREAD score so the list can be searched and sorted.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

from aegisshield.services.posture_service import parse_highest_dread
from aegisshield.storage import Record, RecordKind
from aegisshield.ui import kit, routes, state, tm_style
from aegisshield.ui.theme import Area, Tone

__all__ = ["SORTS", "list_rows", "render"]

SORTS = ("Newest first", "Oldest first", "Highest DREAD first", "Title A to Z")
_SEARCH = "tml_search"
_SORT = "tml_sort"
_TABLE = "tml_table"


def _row(record: Record) -> dict[str, Any]:
    payload = record.payload
    profile = payload.get("profile") if isinstance(payload.get("profile"), dict) else {}
    threats = payload.get("threat_model") if isinstance(payload.get("threat_model"), list) else []
    top = parse_highest_dread(payload.get("dread_assessment_markdown"))
    return {
        "id": record.id,
        "Title": record.title,
        "Created": record.created_at[:16].replace("T", " "),
        "Application type": str(profile.get("app_type") or ""),
        "Sector": str(profile.get("industry_sector") or ""),
        "Threats": len(threats),
        "Highest DREAD": top.highest_score,
        "Severity": (top.severity or "").capitalize() or "Not scored",
    }


def list_rows(records: list[Record], query: str, sort: str) -> list[dict[str, Any]]:
    """Table rows for ``records`` that match ``query``, in ``sort`` order."""
    rows = [_row(r) for r in records]
    needle = query.strip().lower()
    if needle:
        rows = [r for r in rows if needle in " ".join(
            str(r[k]) for k in ("Title", "Application type", "Sector")).lower()]
    if sort == "Oldest first":
        rows.reverse()
    elif sort == "Highest DREAD first":
        rows.sort(key=lambda r: -1.0 if r["Highest DREAD"] is None else r["Highest DREAD"],
                  reverse=True)
    elif sort == "Title A to Z":
        rows.sort(key=lambda r: r["Title"].lower())
    return rows


def _delete(record_id: str) -> None:
    workspace = state.get_workspace()
    record = workspace.get(RecordKind.THREAT_MODELS, record_id)
    if record and workspace.delete(RecordKind.THREAT_MODELS, record_id):
        state.save_workspace(workspace)
        state.flash(f"Deleted: {record.title}", "ok")


def _rename(record_id: str, widget: str) -> None:
    title = str(state.widget_value(widget) or "").strip()
    if not title:
        state.flash("A title cannot be empty.", "warn")
        return
    workspace = state.get_workspace()
    if workspace.rename(RecordKind.THREAT_MODELS, record_id, title):
        state.save_workspace(workspace)
        state.flash("Renamed.", "ok")


@st.dialog("Delete this threat model?")
def _confirm_delete(record_id: str, title: str) -> None:
    st.text(title)
    st.caption("This threat model will be removed from the workspace. This cannot be undone.")
    with st.container(horizontal=True, key="tml_dialog_danger"):
        st.button("Delete", key="tml_confirm_danger", type="primary",
                  on_click=_delete, args=(record_id,))
        st.button("Keep it", key="tml_keep")


def render() -> None:
    """The list, or an empty state leading to the wizard."""
    tm_style.apply()
    kit.page_header("Threat models", "Every threat model in this workspace, newest first.",
                    area=Area.DEFENSE)
    pending = state.consume_flash()
    if pending:
        kit.notice(pending[0], tone=Tone(pending[1]) if pending[1] in Tone else Tone.OK)
    records = state.get_workspace().list(RecordKind.THREAT_MODELS)
    if not records:
        kit.empty_state("No threat models yet", "Describe an application and AegisShield builds "
                        "its threat model. It is saved here when the run finishes.",
                        action_label="Create your first threat model",
                        action_page="threat_model_new")
        return
    with st.container(horizontal=True, vertical_alignment="bottom"):
        query = st.text_input("Search", key=_SEARCH, placeholder="Title, application type, or sector")
        sort = st.selectbox("Sort", SORTS, key=_SORT)
        st.page_link(routes.page("threat_model_new"), label="New threat model", icon=":material/add:")
    rows = list_rows(records, query or "", sort or SORTS[0])
    if not rows:
        kit.notice("No threat model matches that search.", tone=Tone.NEUTRAL)
        return
    event = st.dataframe(
        rows, key=_TABLE, hide_index=True, width="stretch", on_select="rerun",
        selection_mode="single-row", column_order=[k for k in rows[0] if k != "id"],
        column_config={"Highest DREAD": st.column_config.NumberColumn(format="%.1f"),
                       "Threats": st.column_config.NumberColumn(format="%d")})
    selected = event.selection.rows if event and event.selection else []
    if not selected:
        st.caption(f"{len(rows)} of {len(records)} shown. Select a row to open, rename, or delete it.")
        return
    row = rows[selected[0]]
    with kit.card("selected"):
        kit.section("Selected", row["Title"])
        rename_key = f"tml_title_{row['id']}"
        state.seed_widget(rename_key, row["Title"])
        with st.container(horizontal=True, vertical_alignment="bottom"):
            st.text_input("Title", key=rename_key, max_chars=200, width=520)
            st.button("Rename", key="tml_rename", on_click=_rename, args=(row["id"], rename_key))
            opened = st.button("Open", key="tml_open", type="primary", icon=":material/open_in_new:")
            with st.container(key="tml_delete_danger", width="content"):
                deleting = st.button("Delete", key="tml_delete", icon=":material/delete:")
        if opened:
            kit.open_record("threat_model_detail", row["id"])
        if deleting:
            _confirm_delete(row["id"], row["Title"])
