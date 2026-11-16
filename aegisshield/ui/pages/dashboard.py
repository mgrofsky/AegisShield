"""Dashboard: posture at a glance, recent threat models, and quick actions.

Built on ``posture_service.aggregate_posture``. There is no "audit
readiness" meter: nothing in the workspace could back one.
"""

from __future__ import annotations

import html
from typing import Any

import streamlit as st

from aegisshield.llm import get_llm
from aegisshield.pipeline.run import run_threat_model, threat_model_title
from aegisshield.pipeline.schemas import AppProfile, ThreatModelRequest
from aegisshield.services.posture_service import aggregate_posture, parse_highest_dread
from aegisshield.storage import RecordKind
from aegisshield.ui import kit, routes, state, tm_style
from aegisshield.ui.options import EXAMPLE_DESCRIPTION
from aegisshield.ui.posture_view import format_posture, relative_time
from aegisshield.ui.theme import Area, Tone

__all__ = ["SAMPLE_PROFILE", "add_sample_threat_model", "render"]

RECENT = 6
INTRO = ("AegisShield builds a STRIDE threat model of your application, maps each threat to "
         "MITRE ATT&CK, scores it with DREAD, and writes mitigations and test cases. Describe "
         "the application once and watch the agents work; everything stays in this browser "
         "session unless you export it.")

SAMPLE_PROFILE: dict[str, Any] = {
    "app_type": "Web application",
    "industry_sector": "Retail",
    "sensitive_data": "High",
    "internet_facing": "Yes",
    "num_employees": "101-1000",
    "technical_ability": "Medium",
    "compliance_requirements": ["PCI DSS v4.0"],
    "authentication": ["OAuth 2.0", "MFA (TOTP / Push)"],
}


class _Quiet:
    """A progress sink for the sample run, which nobody watches."""

    def set(self, record: dict[str, Any]) -> None:
        """Ignore the record."""

    def cancelled(self) -> bool:
        """The sample run is never cancelled."""
        return False


def add_sample_threat_model() -> None:
    """Run the mock pipeline once and save the result (mock mode only)."""
    settings = state.get_settings()
    if not settings.mock_llm:
        return
    request = ThreatModelRequest(app_profile=AppProfile(**SAMPLE_PROFILE),
                                 app_description=EXAMPLE_DESCRIPTION,
                                 addons=["mitigations", "dread", "test_cases"])
    result = run_threat_model(request, llm=get_llm(settings, None), settings=settings,
                              progress=_Quiet())
    profile = request.app_profile.model_dump()
    payload = {**result, "profile": profile, "description": request.app_description}
    workspace = state.get_workspace()
    workspace.add(RecordKind.THREAT_MODELS, threat_model_title(profile, EXAMPLE_DESCRIPTION), payload)
    state.save_workspace(workspace)
    state.flash("Sample threat model added. Open it from the list below.", "ok")


def _first_run(mock: bool) -> None:
    with kit.card("welcome"):
        kit.section("Start here")
        st.html(f'<p class="tm-intro">{html.escape(INTRO)}</p>')
        with st.container(horizontal=True):
            st.page_link(routes.page("threat_model_new"), label="New threat model",
                         icon=":material/add:")
            if mock:
                st.button("Try with sample data", key="dash_sample", type="primary",
                          on_click=add_sample_threat_model,
                          help="Mock mode: adds a sample threat model for an online checkout.")


def _urgent(cell_value: str, severity: str | None, scored: int) -> None:
    if severity not in ("critical", "high"):
        return
    noun = "threat" if scored == 1 else "threats"
    st.html(
        '<div class="tm-urgent" role="alert"><div>'
        '<div class="tm-urgent-lead">Needs attention now</div>'
        f'<div class="tm-urgent-title">{severity.capitalize()}-severity threat open: highest '
        f"DREAD risk is {html.escape(cell_value)}</div>"
        f'<div class="tm-urgent-meta">DREAD {html.escape(cell_value)}, {scored} {noun} scored</div>'
        "</div></div>")
    st.page_link(routes.page("threat_models"), label="Investigate", icon=":material/arrow_forward:")


def _recent() -> None:
    records = state.get_workspace().list(RecordKind.THREAT_MODELS)[:RECENT]
    kit.section("Recent threat models")
    if not records:
        kit.empty_state("No threat models yet", "Your threat models appear here once you run one.",
                        action_label="New threat model", action_page="threat_model_new")
        return
    for record in records:
        payload = record.payload
        profile = payload.get("profile") if isinstance(payload.get("profile"), dict) else {}
        top = parse_highest_dread(payload.get("dread_assessment_markdown"))
        threats = payload.get("threat_model") if isinstance(payload.get("threat_model"), list) else []
        with st.container(border=True, key=f"dash_row_{record.id}"):
            left, right = st.columns([5, 2], vertical_alignment="center")
            with left:
                kit.record_link("threat_model_detail", record.id, record.title)
                meta = ", ".join(str(v) for v in (profile.get("app_type"), profile.get("industry_sector"))
                                 if v)
                st.html(f'<div class="tm-row-meta">{html.escape(meta)}'
                        f'{", " if meta else ""}{len(threats)} threats, '
                        f"{html.escape(relative_time(record.created_at))}</div>")
            with right:
                if top.highest_score is not None:
                    st.html(f'<div style="text-align:right">DREAD {top.highest_score:.1f} '
                            f"{kit.severity_badge_html(top.severity)}</div>")
                else:
                    st.html(f'<div style="text-align:right">{kit.badge_html("Not scored")}</div>')
    st.page_link(routes.page("threat_models"), label="View all threat models",
                 icon=":material/arrow_forward:")


def _quick_actions() -> None:
    # The heading sits above the card, as "Recent threat models" does beside
    # it, so both columns open with a heading and then a card at one height.
    kit.section("Quick actions")
    with kit.card("quick_actions"):
        st.page_link(routes.page("threat_model_new"), label="New threat model", icon=":material/add:")
        st.page_link(routes.page("vulnerability_lookup"), label="Look up known vulnerabilities",
                     icon=":material/manage_search:")
        st.page_link(routes.page("policies"), label="Write security policies",
                     icon=":material/policy:")
        st.page_link(routes.page("threat_models"), label="All threat models",
                     icon=":material/list:")


def render() -> None:
    """The dashboard: first-run welcome, or posture, recent work, and actions."""
    tm_style.apply()
    kit.page_header("Dashboard", "Your threat models, lookups, and policies at a glance.",
                    area=Area.NEUTRAL)
    pending = state.consume_flash()
    if pending:
        kit.notice(pending[0], tone=Tone(pending[1]) if pending[1] in Tone else Tone.OK)
    workspace = state.get_workspace()
    snap = aggregate_posture(workspace)
    settings = state.get_settings()
    if snap.threat_model_count == 0 and not workspace.list(RecordKind.LOOKUPS):
        _first_run(settings.mock_llm)
    cells = format_posture(snap)
    _urgent(cells.dread.value, cells.dread.severity, snap.dread_threats_assessed)
    kit.section("Security posture")
    kit.stat_row([
        kit.Tile("Threat models", cells.threat_models.value, cells.threat_models.hint,
                 cells.threat_models.tone),
        kit.Tile("Highest open DREAD", cells.dread.value, cells.dread.hint, cells.dread.tone),
        kit.Tile("Last vulnerability lookup", cells.last_lookup.value, cells.last_lookup.hint,
                 cells.last_lookup.tone),
        kit.Tile("DREAD coverage", cells.coverage.value, cells.coverage.hint, cells.coverage.tone),
    ])
    # Three to one, the posture tiles' own grid: recent work under the first
    # three tiles, the quick actions under the fourth.
    main, side = st.columns([3, 1], gap="small")
    with main:
        _recent()
    with side:
        _quick_actions()
