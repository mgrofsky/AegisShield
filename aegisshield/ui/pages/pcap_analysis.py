"""PCAP analysis: summarize an uploaded packet capture and have the model
triage the summary.

The capture is parsed with ``tshark`` on the server running the app; only the
parsed summary goes to the model provider. The analysis runs as this
session's ``pcap`` job; a finished analysis is trimmed (``trim_for_storage``)
and saved to the workspace, then opened by its record id.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

import streamlit as st

from aegisshield.core.errors import AegisError
from aegisshield.jobs import JobSnapshot, JobStatus
from aegisshield.llm.providers import answered_by
from aegisshield.services import pcap_service
from aegisshield.storage import RecordKind
from aegisshield.storage.workspace import Record
from aegisshield.ui import kit, pcap_data, routes, safeguards_view, state, tool_parts
from aegisshield.ui.theme import Area, Tone

PAGE = "pcap_analysis"
JOB_KIND = "pcap"
MAX_UPLOAD_MB = pcap_service.MAX_UPLOAD_BYTES // (1024 * 1024)

PRIVACY_SENTENCE = (
    "Your capture is parsed with tshark on the server running this app, and the file is deleted "
    "when parsing ends. Only a summary (protocol counts, conversations, DNS names, TLS server names, "
    "HTTP requests, and SIP details) is sent to the model provider, never the raw capture. Captures can "
    "hold sensitive data such as addresses, host names, credentials, and call details, so upload only "
    "captures you may share this way."
)
_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _when(stamp: str) -> str:
    try:
        return datetime.fromisoformat(stamp).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError):
        return ""


def _table(rows: list[dict[str, Any]], *, height: int | str = "auto") -> None:
    if isinstance(height, int):
        height = min(height, 38 + 35 * len(rows))  # no empty rows under a short table
    st.dataframe(rows, hide_index=True, width="stretch", height=height)


# ------------------------------------------------------------------- job


def _job(data: bytes, filename: str):
    """The job function; the bytes, model client, and settings are captured here."""
    settings = state.get_settings()
    llm = tool_parts.session_llm(settings)
    model = answered_by(settings)

    def run(sink) -> dict[str, Any]:
        progress = tool_parts.StreamingProgress(sink, {"filename": pcap_service.display_filename(filename)})
        result = pcap_service.analyze_pcap(
            data, filename, llm=llm, settings=settings, progress=progress, on_text=progress.on_text,
        )
        progress.flush()
        return {**result, "model": model}

    return run


def _start(uploaded) -> None:
    if uploaded is None:
        kit.notice("Choose a capture file first.", tone=Tone.WARN)
        return
    data = uploaded.getvalue()
    try:
        pcap_service.validate_upload(data, uploaded.name)
        state.start_job(JOB_KIND, _job(data, uploaded.name), shown_errors=pcap_service.JOB_ERRORS)
    except AegisError as exc:
        kit.notice(str(exc), tone=Tone.CRIT)
        return
    st.rerun()


def _upload() -> None:
    with kit.card("pcap_upload"):
        uploaded = st.file_uploader(
            "Packet capture", type=["pcap", "pcapng"], max_upload_size=MAX_UPLOAD_MB, key="pcap_file",
            help=f"A .pcap or .pcapng file, up to {MAX_UPLOAD_MB} MB.",
        )
        tool_parts.muted(
            f"A .pcap or .pcapng file up to {MAX_UPLOAD_MB} MB. The app reads SIP, RTP, DNS, TLS, and HTTP "
            f"from it; tshark gets {pcap_service.EXTRACTION_BUDGET_SECONDS // 60} minutes in all."
        )
        if not state.have_llm():
            kit.notice(state.llm_blocker() or "", tone=Tone.WARN)
        if st.button("Analyze capture", key="pcap_run", type="primary", icon=":material/troubleshoot:",
                     disabled=not state.have_llm()):
            _start(uploaded)


def _progress(snap: JobSnapshot) -> None:
    record = snap.progress or {}
    step, total = record.get("step"), record.get("total")
    text = record.get("text") if isinstance(record.get("text"), str) else ""
    name = record.get("filename") if isinstance(record.get("filename"), str) else "capture"
    with kit.card("pcap_running"):
        kit.section(f"Analyzing {name}", f"Running for {tool_parts.elapsed_words(snap)}.")
        if isinstance(step, int) and isinstance(total, int) and total > 0:
            st.progress(min(step / total, 1.0))
            current = record.get("current") if isinstance(record.get("current"), str) else ""
            tool_parts.line(f"Step {step} of {total}: {current}")
        else:
            st.progress(0.0)
            tool_parts.line("Starting.")
        if text:
            with st.container(key="tx_stream"):
                kit.model_markdown(text)


def _finish() -> None:
    snap = tool_parts.take_finished(JOB_KIND)
    if snap is None:
        return
    if snap.status is JobStatus.COMPLETE and snap.result:
        result = pcap_data.trim_for_storage(snap.result)
        name = result.get("filename") or "capture.pcap"
        workspace = state.get_workspace()
        record = workspace.add(RecordKind.PCAP_ANALYSES, name, {
            "filename": name, "filesize_bytes": result.get("filesize_bytes"), "result": result,
            "model": snap.result.get("model"),
        })
        state.save_workspace(workspace)
        state.flash("Analysis finished and saved to this session's workspace.", "ok")
        kit.open_record(PAGE, record.id)
    elif snap.status is JobStatus.FAILED:
        tool_parts.failure_notice(JOB_KIND, f"The analysis did not finish. {snap.error or ''}".strip(), key="pcap")


# ---------------------------------------------------------------- report


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _tiles(result: Mapping[str, Any]) -> None:
    sip = result.get("sip") if isinstance(result.get("sip"), Mapping) else {}
    agg = sip.get("aggregations") if isinstance(sip.get("aggregations"), Mapping) else {}
    general = result.get("general") if isinstance(result.get("general"), Mapping) else {}
    scanner = len(agg.get("scanner_ua_hits") or []) + len(general.get("http_scanner_ua_hits") or [])
    value = lambda v: "None" if v is None else v  # noqa: E731
    kit.stat_row([
        kit.Tile("DNS queries", value(_int(general.get("dns_query_count"))),
                 f"{value(_int(general.get('unique_dns_names')))} names"),
        kit.Tile("TLS client hellos", value(_int(general.get("tls_client_hello_count")))),
        kit.Tile("HTTP requests", value(_int(general.get("http_request_count")))),
        kit.Tile("SIP messages", value(_int(agg.get("total_messages"))),
                 f"{value(_int(agg.get('unique_call_ids')))} calls"),
        kit.Tile("SIP auth failures", value(_int(agg.get("auth_failures"))),
                 tone=Tone.WARN if _int(agg.get("auth_failures")) else Tone.NEUTRAL),
        kit.Tile("Scanner user agents", scanner, tone=Tone.CRIT if scanner else Tone.NEUTRAL),
    ])


def _pairs(pairs: object, label: str, title: str) -> None:
    rows = pcap_data.pair_rows(pairs, label)
    if rows:
        tool_parts.muted(title)
        _table(rows)


def _report(record: Record) -> None:
    result = record.payload.get("result")
    if not isinstance(result, Mapping):
        kit.notice("This saved analysis has no result to show.", tone=Tone.WARN)
        return
    size = pcap_data.size_words(record.payload.get("filesize_bytes"))
    fmt = result.get("capture_format") if isinstance(result.get("capture_format"), str) else ""
    kit.section("Analysis", f"{record.title}, {size}{f', {fmt}' if fmt else ''}. Saved {_when(record.created_at)}.")
    actions = st.container(horizontal=True, vertical_alignment="center")
    actions.download_button(
        "Markdown report", data=lambda: pcap_service.render_markdown_report(dict(result)).encode("utf-8"),
        file_name=f"{_SLUG_RE.sub('-', record.title)}-analysis.md", mime="text/markdown",
        key="pcap_dl_md", icon=":material/download:", on_click="ignore",
    )
    if actions.button("Delete", key="pcap_reader_del_danger", icon=":material/delete:"):
        tool_parts.confirm_delete("This analysis", lambda: _delete(record.id), key="pcap_del", page_name=PAGE)
    _tiles(result)
    kit.answered_by(record.payload.get("model"))
    safeguards_view.render_safeguards(result.get("safeguards"), key="pcap")
    notes = [str(t) for t in result.get("truncated") or [] if isinstance(t, str)]
    stored = result.get("stored_rows") if isinstance(result.get("stored_rows"), Mapping) else {}
    if result.get("cut_short") is True:
        kit.notice(pcap_service.CUT_SHORT_NOTE, tone=Tone.WARN)
    if notes:
        tool_parts.muted("tshark output was cut at the row limit for: " + ", ".join(notes) + ".")
    if stored:
        tool_parts.muted(f"Saved with the first {pcap_data.STORED_ROWS} rows of: "
                         + ", ".join(f"{k} ({v})" for k, v in stored.items() if isinstance(v, int)) + ".")

    sip = result.get("sip") if isinstance(result.get("sip"), Mapping) else {}
    agg = sip.get("aggregations") if isinstance(sip.get("aggregations"), Mapping) else {}
    rtp = [line for line in result.get("rtp_streams_raw") or [] if isinstance(line, str)]
    names = ["AI analysis", "Protocols", "Conversations", "DNS", "TLS", "HTTP"]
    has_sip = bool(_int(agg.get("total_messages")))
    has_rtp = len(rtp) > 3
    names += (["SIP"] if has_sip else []) + (["RTP"] if has_rtp else [])
    tabs = dict(zip(names, st.tabs(names, key=f"pcap_tabs_{record.id}"), strict=True))

    with tabs["AI analysis"]:
        error = result.get("ai_error")
        if isinstance(error, str) and error:
            kit.notice(f"{error} The parsed summary in the other tabs is complete.", tone=Tone.WARN)
        analysis = result.get("ai_analysis")
        if isinstance(analysis, str) and analysis:
            with kit.card("pcap_ai"):
                kit.model_markdown(analysis)
    with tabs["Protocols"]:
        rows = pcap_data.phs_rows(result.get("protocol_hierarchy"))
        if rows:
            _table(rows)
        else:
            tool_parts.muted("No protocol hierarchy was read.")
    with tabs["Conversations"]:
        rows = pcap_data.conversation_rows(result.get("conversations"))
        if rows:
            _table(rows)
        else:
            tool_parts.muted("No IP conversations were read.")
    general = result.get("general") if isinstance(result.get("general"), Mapping) else {}
    with tabs["DNS"]:
        _pairs(general.get("top_dns_names"), "Name", "Most queried names")
        _pairs(general.get("top_dns_sources"), "Source", "Busiest sources")
        rows = pcap_data.field_rows(result.get("dns_queries"))
        if rows:
            tool_parts.muted("Queries")
            _table(rows, height=320)
        else:
            tool_parts.muted("No DNS queries were read.")
    with tabs["TLS"]:
        _pairs(general.get("top_tls_sni"), "Server name", "Most requested server names")
        rows = pcap_data.field_rows(result.get("tls_sni"))
        if rows:
            _table(rows, height=320)
        else:
            tool_parts.muted("No TLS client hellos were read.")
    with tabs["HTTP"]:
        _pairs(general.get("top_http_hosts"), "Host", "Most requested hosts")
        _pairs(general.get("top_http_user_agents"), "User agent", "User agents")
        hits = pcap_data.field_rows(general.get("http_scanner_ua_hits"))
        if hits:
            tool_parts.muted("Requests from known scanner user agents")
            _table(hits)
        rows = pcap_data.field_rows(result.get("http_requests"))
        if rows:
            _table(rows, height=320)
        else:
            tool_parts.muted("No HTTP requests were read.")
    if has_sip:
        with tabs["SIP"]:
            left, right = st.columns(2)
            with left:
                _pairs(agg.get("methods"), "Method", "Methods")
                _pairs(agg.get("top_user_agents"), "User agent", "User agents")
                _pairs(agg.get("top_from_users"), "From user", "Callers")
            with right:
                _pairs(agg.get("status_codes"), "Status", "Status codes")
                _pairs(agg.get("top_source_ips"), "Source", "Sources")
                _pairs(agg.get("top_to_users"), "To user", "Called users")
            hits = pcap_data.field_rows(agg.get("scanner_ua_hits"))
            if hits:
                tool_parts.muted("Messages from known scanner user agents")
                _table(hits)
            messages = pcap_data.field_rows(sip.get("messages"))
            if messages:
                tool_parts.muted("Messages")
                _table(messages, height=320)
    if has_rtp:
        with tabs["RTP"]:
            st.code("\n".join(rtp), language=None)


# ------------------------------------------------------------------ list


def _delete(record_id: str) -> None:
    workspace = state.get_workspace()
    if workspace.delete(RecordKind.PCAP_ANALYSES, record_id):
        state.save_workspace(workspace)
        state.flash("Analysis deleted.", "ok")


def _past(records: list[Record], open_id: str | None) -> None:
    kit.section("Past analyses", "Saved in this session's workspace, newest first.")
    if not records:
        kit.empty_state("No analyses yet",
                        "Upload a packet capture to get a summary of its traffic and anything that stands out.")
        return
    with kit.card("pcap_list"):
        for record in records:
            title_col, open_col = st.columns([7, 1], vertical_alignment="center")
            current = " (open)" if record.id == open_id else ""
            size = pcap_data.size_words(record.payload.get("filesize_bytes"))
            title_col.html(
                f'<div class="tx-name">{_esc(record.title)}{_esc(current)}</div>'
                f'<p class="tx-muted">{_esc(_when(record.created_at))} &middot; {_esc(size)}</p>'
            )
            with open_col:
                kit.record_link(PAGE, record.id, "Open")


# ------------------------------------------------------------------ page


def render() -> None:
    """Upload and analyze, the open analysis, and past analyses."""
    kit.page_header("PCAP analysis", "Summarize a packet capture you upload.", area=Area.DEFENSE)
    tool_parts.tools_css()
    tool_parts.show_flash()
    available = routes.tshark_available()
    workspace = state.get_workspace()
    open_id = state.requested_record_id()
    record = workspace.get(RecordKind.PCAP_ANALYSES, open_id) if open_id else None
    running = False
    if available:
        kit.notice(PRIVACY_SENTENCE, tone=Tone.WARN, label="Privacy")
        tool_parts.follow_job(JOB_KIND)
        _finish()
        running = state.is_job_running(JOB_KIND)
        if running:
            tool_parts.running_panel(
                JOB_KIND, key="pcap", render_progress=_progress, cancel_label="Cancel analysis",
                cancelled_message="Analysis cancelled. Nothing was saved.",
            )
        elif record is None:
            _upload()
    else:
        kit.empty_state(
            "PCAP analysis is not available here",
            "This server does not have tshark installed, which the analysis needs. Saved analyses "
            "in this session can still be opened below.",
        )

    if open_id and record is None:
        kit.empty_state("That analysis is not in this session",
                        "Saved analyses live in this browser session's workspace. Import a workspace "
                        "file in Settings to bring earlier work back.")
    elif record is not None:
        _report(record)
        if available and not running:
            with st.expander("Analyze another capture", icon=":material/upload_file:"):
                _upload()
    _past(workspace.list(RecordKind.PCAP_ANALYSES), open_id)
