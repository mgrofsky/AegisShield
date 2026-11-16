"""Threat model: one saved threat model, opened through ``?id=<record id>``.

The header, a meta card, the results, the exports, "Run again with these
inputs" (which fills the wizard), rename, and delete.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

from aegisshield.services.posture_service import parse_highest_dread
from aegisshield.storage import Record, RecordKind
from aegisshield.ui import kit, routes, state, tm_style
from aegisshield.ui.posture_view import relative_time
from aegisshield.ui.theme import Area, Tone
from aegisshield.ui.threat_model_view import render_exports, render_results

__all__ = ["HEADING_CHARS", "header_text", "meta_items", "render"]

SUBTITLE = "One threat model and its results."
DELETED = "Deleted:"


def meta_items(record: Record) -> list[tuple[str, str]]:
    """The meta card's rows; a row appears only when it has a value."""
    payload = record.payload
    profile = payload.get("profile") if isinstance(payload.get("profile"), dict) else {}

    def joined(field: str) -> str:
        values = profile.get(field)
        return ", ".join(str(v) for v in values) if isinstance(values, list) else ""

    techs = profile.get("selected_technologies") if isinstance(profile.get("selected_technologies"), dict) else {}
    versions = profile.get("selected_versions") if isinstance(profile.get("selected_versions"), dict) else {}
    stack = ", ".join(f"{name} {versions.get(name, '*')}" for name in techs)
    rows = [
        ("Application type", str(profile.get("app_type") or "")),
        ("Industry sector", str(profile.get("industry_sector") or "")),
        ("Data sensitivity", str(profile.get("sensitive_data") or "")),
        ("Internet-facing", str(profile.get("internet_facing") or "")),
        ("Employees", str(profile.get("num_employees") or "")),
        ("Technical ability", str(profile.get("technical_ability") or "")),
        ("Frameworks", joined("compliance_requirements")),
        ("Authentication", joined("authentication")),
        ("Patterns", joined("app_pattern")),
        ("Technologies", stack),
        ("Created", f"{record.created_at[:10]} ({relative_time(record.created_at)})"),
    ]
    return [(label, value) for label, value in rows if value]


def _delete(record_id: str) -> None:
    workspace = state.get_workspace()
    record = workspace.get(RecordKind.THREAT_MODELS, record_id)
    if record and workspace.delete(RecordKind.THREAT_MODELS, record_id):
        state.save_workspace(workspace)
        state.flash(f"{DELETED} {record.title}", "ok")


def _rename(record_id: str, widget: str) -> None:
    title = str(state.widget_value(widget) or "").strip()
    if not title:
        state.flash("A title cannot be empty.", "warn")
        return
    workspace = state.get_workspace()
    if workspace.rename(RecordKind.THREAT_MODELS, record_id, title):
        state.save_workspace(workspace)
        state.flash("Renamed.", "ok")


def _run_again() -> None:
    """Start the wizard over, so it takes this record's inputs."""
    state.replace_wizard_draft({})


@st.dialog("Delete this threat model?")
def _confirm_delete(record_id: str, title: str) -> None:
    st.text(title)
    st.caption("This threat model will be removed from the workspace. This cannot be undone.")
    with st.container(horizontal=True, key="tmd_dialog_danger"):
        st.button("Delete", key="tmd_confirm_danger", type="primary", on_click=_delete,
                  args=(record_id,))
        st.button("Keep it", key="tmd_keep")


# A stored title longer than this (the default one runs to about 150
# characters) gives way to a short heading, with the full title below it.
HEADING_CHARS = 60


def header_text(title: str, profile: dict[str, Any]) -> tuple[str, str]:
    """The page heading and the line under it.

    A short title (one the visitor chose) is the heading, with the app type
    and sector below. A long one keeps its full text below a concise heading
    made of the app type and sector, so the header stays on one line.
    """
    parts = [str(v) for v in (profile.get("app_type"), profile.get("industry_sector")) if v]
    context = ", ".join(parts)
    if len(title) <= HEADING_CHARS or not context:
        return title, context or SUBTITLE
    return context, title


def _header(record: Record) -> None:
    payload = record.payload
    profile: dict[str, Any] = payload.get("profile") if isinstance(payload.get("profile"), dict) else {}
    heading, subtitle = header_text(record.title, profile)
    kit.page_header(heading, subtitle, area=Area.DEFENSE)
    top = parse_highest_dread(payload.get("dread_assessment_markdown"))
    badges = [kit.badge_html("Saved", tone=Tone.OK)]
    if top.highest_score is not None:
        badges.append(kit.badge_html(f"DREAD {top.highest_score:.1f}", tone=Tone.NEUTRAL))
        badges.append(kit.severity_badge_html(top.severity))
    if payload.get("agentic"):
        badges.append(kit.badge_html("Agent team", tone=Tone.ACCENT))
    st.html(f'<div class="tm-chips">{" ".join(badges)}</div>')


def render() -> None:
    """The requested threat model, or an empty state."""
    tm_style.apply()
    record_id = state.requested_record_id()
    record = state.get_workspace().get(RecordKind.THREAT_MODELS, record_id) if record_id else None
    if record is None:
        pending = state.consume_flash()
        if pending and pending[0].startswith(DELETED):
            # Just deleted here: show the list, with the message.
            state.flash(*pending)
            st.switch_page(routes.page("threat_models"))
        kit.page_header("Threat model", SUBTITLE, area=Area.DEFENSE)
        kit.empty_state(
            "Threat model not found",
            "This link points to a threat model that is not in this browser session. Import a "
            "workspace that holds it, or open one from the list.",
            action_label="All threat models",
            action_page="threat_models",
        )
        return
    _header(record)
    pending = state.consume_flash()
    if pending:
        kit.notice(pending[0], tone=Tone(pending[1]) if pending[1] in Tone else Tone.OK)
    # Details and actions sit above the results, so neither is squeezed
    # into a narrow side column on a small screen.
    meta_col, action_col = st.columns([3, 2], gap="medium")
    with meta_col:
        with kit.card("meta"):
            kit.section("Details")
            kit.key_value_list(meta_items(record))
    with action_col:
        with kit.card("actions"):
            kit.section("Actions")
            if st.button("Run again with these inputs", key="tmd_rerun", type="primary",
                         on_click=_run_again, icon=":material/replay:", width="stretch"):
                kit.open_record("threat_model_new", record.id)
            rename_key = f"tmd_title_{record.id}"
            state.seed_widget(rename_key, record.title)
            st.text_input("Title", key=rename_key, max_chars=200)
            st.button("Rename", key="tmd_rename", on_click=_rename, args=(record.id, rename_key),
                      width="stretch")
            with st.container(key="tmd_delete_danger"):
                if st.button("Delete", key="tmd_delete", width="stretch", icon=":material/delete:"):
                    _confirm_delete(record.id, record.title)
    description = str(record.payload.get("description") or "").strip()
    if description:
        with st.expander("Application description"):
            st.text(description)
    render_results(record, key_prefix="tmd")
    with kit.card("exports"):
        render_exports(record, key_prefix="tmd")
