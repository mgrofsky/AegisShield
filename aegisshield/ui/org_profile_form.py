"""The organization profile form, shown on the policies page.

Every field ``OrgProfile`` keeps. ``OrgProfile.from_dict`` is the only
validation path, so the form shows its sentence when a value is refused.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

from aegisshield.core.errors import ValidationError
from aegisshield.services import org_profile as op
from aegisshield.services.org_profile import OrgProfile
from aegisshield.ui import kit, state, tool_parts
from aegisshield.ui.theme import Tone

__all__ = ["REQUIRED_FIELDS", "load_profile", "missing_fields", "profile_form"]

# What policy generation needs. The service itself requires only the legal
# name; without an industry the prompt falls back to "technology", which
# would frame every policy for the wrong kind of organization.
REQUIRED_FIELDS = (("legal_name", "Legal name"), ("industry", "Industry"))
_MIN_LEADER_ROWS = 3


def load_profile() -> tuple[OrgProfile | None, str | None]:
    """The saved profile, or None; and the reason it could not be read, if any."""
    try:
        return OrgProfile.load_from(state.get_workspace()), None
    except ValidationError as exc:
        return None, str(exc)


def missing_fields(profile: OrgProfile | None) -> list[str]:
    """The labels of the required fields the profile does not set."""
    if profile is None:
        return [label for _, label in REQUIRED_FIELDS]
    return [label for name, label in REQUIRED_FIELDS if not getattr(profile, name)]


def _index(options: tuple[str, ...], value: str) -> int | None:
    return options.index(value) if value in options else None


def profile_form(profile: OrgProfile | None) -> None:
    """The form; saving validates through ``OrgProfile.from_dict``."""
    current = profile.to_dict() if profile else {}
    leaders = current.get("leadership") or []
    rows = min(op.MAX_LEADERS, max(_MIN_LEADER_ROWS, len(leaders) + 1))
    industries = op.KNOWN_INDUSTRIES
    industry = current.get("industry") or ""
    if industry and industry not in industries:
        industries = (*industries, industry)
    drivers = current.get("compliance_drivers") or []
    driver_options = tuple(dict.fromkeys([*op.KNOWN_COMPLIANCE_DRIVERS, *drivers]))

    with st.form("org_profile_form", border=False):
        kit.section("Organization identity")
        left, right = st.columns(2)
        legal = left.text_input("Legal name *", value=current.get("legal_name", ""),
                                max_chars=op.MAX_LEGAL_NAME_CHARS)
        dba = right.text_input("Doing-business-as or brand name", value=current.get("dba_name", ""),
                               max_chars=op.MAX_DBA_NAME_CHARS)
        chosen_industry = left.selectbox(
            "Industry *", industries, index=_index(industries, industry), accept_new_options=True,
            placeholder="Choose or type an industry",
            help="Policies are written for this kind of organization. Type your own if it is not listed.",
        )
        employees = right.number_input(
            "Employee count", min_value=1, max_value=op.MAX_EMPLOYEE_COUNT, step=1,
            value=current.get("employee_count"), placeholder="Optional",
        )

        kit.section("Leadership contacts", "Policies assign duties to these roles. Leave a name blank to skip a row.")
        contacts: list[dict[str, Any]] = []
        for index in range(rows):
            existing = leaders[index] if index < len(leaders) else {}
            role_col, name_col = st.columns([1, 3])
            role = role_col.selectbox(
                f"Role {index + 1}", op.KNOWN_LEADERSHIP_ROLES,
                index=_index(op.KNOWN_LEADERSHIP_ROLES, existing.get("role", "")) or 0,
                key=f"org_role_{index}", label_visibility="collapsed" if index else "visible",
            )
            name = name_col.text_input(
                f"Name {index + 1}", value=existing.get("name", ""), key=f"org_name_{index}",
                max_chars=op.MAX_LEADER_NAME_CHARS, placeholder="Name",
                label_visibility="collapsed" if index else "visible",
            )
            contacts.append({"role": role, "name": name})

        kit.section("Compliance and regulatory", "Select all that apply. You may also type a framework that is not listed.")
        chosen_drivers = st.multiselect(
            "Compliance drivers", driver_options, default=drivers, accept_new_options=True,
            max_selections=op.MAX_COMPLIANCE_DRIVERS, placeholder="For example SOC 2 or ISO 27001",
        )
        notes = st.text_area(
            "Regulatory notes", value=current.get("regulatory_notes", ""),
            max_chars=op.MAX_REGULATORY_NOTES_CHARS, height=110,
            help="Anything the policies should take into account, such as a regulator or a contract term.",
        )
        tool_parts.muted("* needed before policies can be generated.")
        submitted = st.form_submit_button("Save profile", type="primary")

    if submitted:
        data = {
            "legal_name": legal, "dba_name": dba, "industry": chosen_industry or "",
            "employee_count": employees, "leadership": contacts,
            "compliance_drivers": chosen_drivers, "regulatory_notes": notes,
        }
        try:
            saved = OrgProfile.from_dict(data)
        except ValidationError as exc:
            kit.notice(str(exc), tone=Tone.CRIT)
            return
        workspace = state.get_workspace()
        saved.save_to(workspace)
        state.save_workspace(workspace)
        state.flash("Profile saved.", "ok")
        st.rerun()
