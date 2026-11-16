"""Policies: the catalog, generation from the organization profile, and a
reader and editor for each generated policy.

One policy generates at a time per session (the ``policy`` job), with its
text streaming into view. A finished policy is saved to the workspace as the
whole ``generate_policy`` result plus ``policy_key``, ``status``, and
``version``, one record per catalog key: regenerating or editing replaces the
record (the workspace has no update), so the reader reopens the new id.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

import streamlit as st

from aegisshield.core.errors import AegisError
from aegisshield.core.text import sanitize_user_markdown
from aegisshield.jobs import JobSnapshot, JobStatus
from aegisshield.llm.providers import answered_by
from aegisshield.services import policy_catalog, policy_service
from aegisshield.services.org_profile import OrgProfile
from aegisshield.storage import RecordKind
from aegisshield.storage.workspace import Record
from aegisshield.ui import kit, org_profile_form, routes, safeguards_view, state, tool_parts
from aegisshield.ui.theme import Area, Tone

PAGE = "policies"
JOB_KIND = "policy"
STATUS_READY = "ready"

DRAFT_NOTE = (
    "Generated policies are drafts. Have your organization's own counsel and leadership review "
    "and approve each one before you adopt it. Coverage reflects generated policies, not an audit attestation."
)
_CSF_FUNCTIONS = (("GV", "Govern"), ("ID", "Identify"), ("PR", "Protect"), ("DE", "Detect"),
                  ("RS", "Respond"), ("RC", "Recover"))
_TAB_CATALOG = "Policy catalog"
_TAB_PROFILE = "Organization profile"
_SLUG_RE = re.compile(r"[^a-z0-9]+")
# Streamlit shows its own fixed text when a download cannot be built, so the
# reasons a PDF can be refused are said here, before the click.
PDF_FAILED_HINT = ("If the PDF download fails, the server is busy or a table is too long "
                   "for a PDF: try again in a minute, or download the Markdown.")


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _when(stamp: str) -> str:
    try:
        return datetime.fromisoformat(stamp).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError):
        return ""


def _by_key(records: list[Record]) -> dict[str, Record]:
    """The newest record for each catalog key."""
    found: dict[str, Record] = {}
    for record in records:  # newest first
        key = record.payload.get("policy_key")
        if isinstance(key, str) and key not in found:
            found[key] = record
    return found


def _text_list(value: object) -> list[Any]:
    return list(value) if isinstance(value, list) else []


# ------------------------------------------------------------------- job


def _job(policy_key: str, title: str, profile: OrgProfile):
    """The job function; the model client, settings, and profile are captured here."""
    settings = state.get_settings()
    llm = tool_parts.session_llm(settings)
    model = answered_by(settings)

    def run(sink) -> dict[str, Any]:
        progress = tool_parts.StreamingProgress(sink, {"policy_key": policy_key, "title": title})
        result = policy_service.generate_policy(
            policy_key, profile, llm=llm, settings=settings, on_text=progress.on_text,
        )
        progress.flush()
        return {**result, "model": model}

    return run


def _start(policy_key: str, profile: OrgProfile) -> None:
    entry = policy_catalog.get_entry(policy_key)
    if entry is None:  # pragma: no cover - keys come from the catalog itself
        return
    try:
        state.start_job(JOB_KIND, _job(policy_key, entry["title"], profile))
    except AegisError as exc:
        state.flash(str(exc), "crit")
    st.rerun()


def _save(payload: dict[str, Any], title: str, replaces: Record | None) -> Record:
    workspace = state.get_workspace()
    if replaces is not None:
        workspace.delete(RecordKind.POLICIES, replaces.id)
    record = workspace.add(RecordKind.POLICIES, title, payload)
    state.save_workspace(workspace)
    return record


def _finish(records: dict[str, Record]) -> None:
    snap = tool_parts.take_finished(JOB_KIND)
    if snap is None:
        return
    title = snap.progress.get("title") if isinstance(snap.progress.get("title"), str) else "The policy"
    if snap.status is JobStatus.COMPLETE and snap.result:
        key = snap.progress.get("policy_key")
        previous = records.get(key) if isinstance(key, str) else None
        version = previous.payload.get("version", 0) if previous else 0
        payload = {**snap.result, "policy_key": key, "status": STATUS_READY,
                   "version": (version if isinstance(version, int) else 0) + 1}
        record = _save(payload, snap.result.get("title") or title, previous)
        state.flash(f"{record.title} is ready. Review it before you adopt it.", "ok")
        kit.open_record(PAGE, record.id)
    elif snap.status is JobStatus.FAILED:
        tool_parts.failure_notice(JOB_KIND, f"{title} was not generated. {snap.error or ''}".strip(), key="pol")


def _progress(snap: JobSnapshot) -> None:
    record = snap.progress or {}
    title = record.get("title") if isinstance(record.get("title"), str) else "Policy"
    text = record.get("text") if isinstance(record.get("text"), str) else ""
    with kit.card("policy_running"):
        kit.section(f"Writing the {title}", f"Running for {tool_parts.elapsed_words(snap)}. "
                    "The text appears as the model writes it.")
        with st.container(key="tx_stream"):
            if text:
                kit.model_markdown(text)
            else:
                tool_parts.muted("Waiting for the first words.")


# --------------------------------------------------------------- catalog


def _coverage(records: dict[str, Record], catalog: list[dict[str, Any]]) -> None:
    done = sum(1 for e in catalog if e["key"] in records)
    total = len(catalog)
    per_function: dict[str, list[int]] = {fid: [0, 0] for fid, _ in _CSF_FUNCTIONS}
    for entry in catalog:
        functions = {cid.split(".", 1)[0] for cid in entry.get("csf_baseline", [])}
        for fid in functions & set(per_function):
            per_function[fid][1] += 1
            per_function[fid][0] += entry["key"] in records
    kit.stat_row([
        kit.Tile("Policies generated", f"{done} / {total}", "from the catalog",
                 tone=Tone.OK if done == total else Tone.NEUTRAL),
        kit.Tile("Coverage", f"{round(100 * done / total) if total else 0}%", "of catalog policies"),
    ])
    bars = []
    for fid, name in _CSF_FUNCTIONS:
        got, of = per_function[fid]
        if not of:
            continue
        low = " tx-low" if got / of < 0.5 else ""
        bars.append(
            f"<span>{_esc(name)}</span>"
            f'<progress class="tx-progress{low}" value="{got}" max="{of}" '
            f'aria-label="{_esc(name)} {got} of {of}"></progress><span>{got}/{of}</span>'
        )
    with kit.card("policy_coverage"):
        tool_parts.muted("By NIST CSF 2.0 function")
        st.html(f'<div class="tx-bars">{"".join(bars)}</div>')


def _status_badge(entry_key: str, records: dict[str, Record], running_key: str | None) -> str:
    if entry_key == running_key:
        return kit.badge_html("Generating", tone=Tone.ACCENT)
    record = records.get(entry_key)
    if record is not None:
        version = record.payload.get("version")
        label = f"Ready, v{version}" if isinstance(version, int) else "Ready"
        return kit.badge_html(label, tone=Tone.OK)
    return kit.badge_html("Not generated", tone=Tone.NEUTRAL)


CATALOG_COLUMNS = 3

def _catalog_card(entry: dict[str, Any], records: dict[str, Record], *, running_key: str | None,
                  blocked: bool, profile: OrgProfile | None) -> None:
    record = records.get(entry["key"])
    with kit.card(f"pol_{entry['key']}"):
        badges = "".join(kit.badge_html(cid, tone=Tone.INFO) for cid in entry.get("csf_baseline", []))
        st.html(
            f'<div class="tx-row" style="justify-content:space-between">'
            f'<h3 class="tx-card-title">{_esc(entry["title"])}</h3>'
            f"{_status_badge(entry['key'], records, running_key)}</div>"
            f'<p class="tx-card-summary">{_esc(entry["summary"])}</p>'
            f'<div class="tx-badges" aria-label="NIST CSF categories">{badges}</div>'
        )
        if record is not None:
            tool_parts.muted(f"Updated {_when(record.created_at)}")
            open_col, again_col = st.columns(2)
            with open_col:
                kit.record_link(PAGE, record.id, "Open")
            if again_col.button("Regenerate", key=f"pol_regen_{entry['key']}", disabled=blocked,
                                icon=":material/refresh:", width="stretch"):
                _start(entry["key"], profile)
        elif st.button("Generate", key=f"pol_gen_{entry['key']}", type="primary", disabled=blocked,
                       icon=":material/auto_awesome:", width="stretch"):
            _start(entry["key"], profile)


def _catalog(records: dict[str, Record], profile: OrgProfile | None, profile_error: str | None) -> None:
    catalog = policy_catalog.get_catalog()
    running = state.job_snapshot(JOB_KIND)
    running_key = running.progress.get("policy_key") if running and not running.done else None
    missing = org_profile_form.missing_fields(profile)
    if profile_error:
        kit.notice(f"The saved organization profile could not be read: {profile_error} "
                   "Save it again on the Organization profile tab.", tone=Tone.CRIT)
    elif missing:
        kit.notice(
            "Policies are written for your organization, so they need a profile first. "
            f"Missing: {', '.join(missing)}. Fill them in on the Organization profile tab.",
            tone=Tone.WARN, label="Profile needed",
        )
    if not state.have_llm():
        kit.notice(state.llm_blocker() or "", tone=Tone.WARN)
    blocked = bool(missing or profile_error) or running_key is not None or not state.have_llm()
    _coverage(records, catalog)
    kit.section("Catalog", "Each policy maps to NIST CSF 2.0 categories.")
    # One row of three at a time, so the cards of a row share one height
    # (tools.css stretches them and keeps the button at the bottom).
    with st.container(key="pol_catalog"):
        for start in range(0, len(catalog), CATALOG_COLUMNS):
            columns = st.columns(CATALOG_COLUMNS)
            for column, entry in zip(columns, catalog[start:start + CATALOG_COLUMNS], strict=False):
                with column:
                    _catalog_card(entry, records, running_key=running_key, blocked=blocked,
                                  profile=profile)


# ---------------------------------------------------------------- reader


def _slug(title: str) -> str:
    return _SLUG_RE.sub("-", title.lower()).strip("-") or "policy"


def _delete(record_id: str) -> None:
    workspace = state.get_workspace()
    if workspace.delete(RecordKind.POLICIES, record_id):
        state.save_workspace(workspace)
        state.flash("Policy deleted.", "ok")


EDIT_TOO_LONG = (f"The policy text must be at most {policy_service.MAX_BODY_CHARS:,} characters; "
                 "it has {count:,}. Nothing was saved.")


def _save_edit(record: Record, body: str) -> None:
    text = sanitize_user_markdown(body)
    if not text.strip():
        kit.notice("The policy text cannot be empty.", tone=Tone.WARN)
        return
    # Checked here, not only by the text area's max_chars, which the browser enforces.
    if len(text) > policy_service.MAX_BODY_CHARS:
        kit.notice(EDIT_TOO_LONG.format(count=len(text)), tone=Tone.CRIT)
        return
    version = record.payload.get("version")
    payload = {**record.payload, "body_markdown": text, "edited": True,
               "version": (version if isinstance(version, int) else 0) + 1}
    saved = _save(payload, record.title, record)
    state.flash("Your edits were saved as a new version.", "ok")
    kit.open_record(PAGE, saved.id)


def _reader(record: Record, profile: OrgProfile | None, blocked: bool) -> None:
    payload = record.payload
    body = payload.get("body_markdown") if isinstance(payload.get("body_markdown"), str) else ""
    version = payload.get("version") if isinstance(payload.get("version"), int) else 1
    edited = ", edited" if payload.get("edited") else ""
    st.page_link(_policies_page(), label="All policies", icon=":material/arrow_back:")
    with kit.card("policy_reader_head"):
        st.html(
            f'<h2 class="tx-card-title" style="font-size:var(--type-lg)">{_esc(record.title)}</h2>'
            f'<p class="tx-muted">Version {version}{_esc(edited)} &middot; updated {_esc(_when(record.created_at))}</p>'
        )
        mappings = [m for m in _text_list(payload.get("csf_mappings")) if isinstance(m, Mapping)]
        if mappings:
            badges = "".join(
                kit.badge_html(f"{m.get('id', '')} {m.get('name', '')}", tone=Tone.INFO) for m in mappings
            )
            st.html(f'<div class="tx-badges" aria-label="NIST CSF categories">{badges}</div>')
        citations = [c for c in _text_list(payload.get("regulatory_citations")) if isinstance(c, str)]
        if citations:
            items = "".join(f"<li>{_esc(c)}</li>" for c in citations)
            st.html(f'<p class="tx-muted">Regulatory references for your compliance drivers</p>'
                    f'<ul class="tx-list">{items}</ul>')
        cols = st.container(horizontal=True, vertical_alignment="center", gap="medium")
        editing = cols.toggle("Edit as Markdown", key=f"pol_edit_on_{record.id}")
        cols.download_button(
            "PDF", data=lambda: policy_service.render_policy_pdf(payload),
            file_name=f"{_slug(record.title)}.pdf", mime="application/pdf",
            key="pol_dl_pdf", icon=":material/download:", on_click="ignore",
        )
        cols.download_button(
            "Markdown", data=lambda: policy_service.policy_markdown_export(payload).encode("utf-8"),
            file_name=f"{_slug(record.title)}.md",
            mime="text/markdown", key="pol_dl_md", icon=":material/download:", on_click="ignore",
        )
        key = payload.get("policy_key")
        if cols.button("Regenerate", key="pol_reader_regen", disabled=blocked or not isinstance(key, str),
                          icon=":material/refresh:"):
            _start(key, profile)
        if cols.button("Delete", key="pol_reader_del_danger", icon=":material/delete:"):
            tool_parts.confirm_delete(f"The {record.title}", lambda: _delete(record.id),
                                      key="pol_del", page_name=PAGE)
    st.caption(PDF_FAILED_HINT)
    kit.answered_by(payload.get("model"))
    safeguards_view.render_safeguards(payload.get("safeguards"), key="policy",
                                      edited=bool(payload.get("edited")))
    if editing:
        with st.form(f"pol_edit_form_{record.id}", border=False):
            text = st.text_area("Policy text (Markdown)", value=body, height=520,
                                max_chars=policy_service.MAX_BODY_CHARS)
            save = st.form_submit_button("Save as a new version", type="primary")
        if save:
            _save_edit(record, text)
    else:
        with kit.card("policy_reader_body"):
            kit.model_markdown(body)


def _policies_page() -> st.Page:
    return routes.page(PAGE)


# ------------------------------------------------------------------ page


def render() -> None:
    """The catalog and profile tabs, or one policy's reader and editor."""
    kit.page_header("Policies", "Security policies drafted for your organization.", area=Area.COMPLIANCE)
    tool_parts.tools_css()
    tool_parts.show_flash()

    workspace = state.get_workspace()
    records = _by_key(workspace.list(RecordKind.POLICIES))
    tool_parts.follow_job(JOB_KIND)
    _finish(records)
    kit.notice(DRAFT_NOTE, tone=Tone.INFO, label="Drafts")

    running = state.is_job_running(JOB_KIND)
    if running:
        tool_parts.running_panel(
            JOB_KIND, key="pol", render_progress=_progress, cancel_label="Cancel",
            cancelled_message="Policy generation cancelled. Nothing was saved.",
        )

    profile, profile_error = org_profile_form.load_profile()
    blocked = bool(org_profile_form.missing_fields(profile) or profile_error) or running or not state.have_llm()

    open_id = state.requested_record_id()
    if open_id:
        record = workspace.get(RecordKind.POLICIES, open_id)
        if record is None:
            kit.empty_state(
                "That policy is not in this session",
                "Generated policies live in this browser session's workspace. Import a workspace file "
                "in Settings to bring earlier work back.",
            )
            st.page_link(_policies_page(), label="All policies", icon=":material/arrow_back:")
        else:
            _reader(record, profile, blocked)
        return

    catalog_tab, profile_tab = st.tabs([_TAB_CATALOG, _TAB_PROFILE], key="pol_tabs",
                                       default=_TAB_CATALOG if profile else _TAB_PROFILE)
    with catalog_tab:
        if profile is None and not records:
            kit.empty_state("Start with your organization profile",
                            "Policies are written for your organization. Save its profile, then generate "
                            "policies from the catalog below.")
        _catalog(records, profile, profile_error)
    with profile_tab:
        org_profile_form.profile_form(profile)
