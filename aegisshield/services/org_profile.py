"""The organization profile that policy generation writes for.

It holds only the fields the policy prompt reads (legal name, trading name,
industry, head count, leadership, compliance drivers, regulatory notes).
Address, website, and leadership email are left out because nothing here
uses them.

The profile round-trips through ``Workspace.org_profile`` as a plain dict
(``to_dict`` / ``from_dict``). ``from_dict`` is the one validation path for
both the settings form and an imported workspace, so text is sanitized and
capped the same way whichever way it arrives.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from aegisshield.core.errors import ValidationError
from aegisshield.core.text import sanitize_user_markdown, single_line
from aegisshield.storage.workspace import Record, Workspace

# Choices offered by the settings form. Visitors may also type
# a compliance driver or an industry that is not listed.
KNOWN_LEADERSHIP_ROLES: tuple[str, ...] = (
    "CEO",
    "COO",
    "CTO",
    "CISO",
    "CFO",
    "HR",
    "DPO",
    "Other",
)
KNOWN_COMPLIANCE_DRIVERS: tuple[str, ...] = (
    "SOC 2",
    "HIPAA",
    "PCI DSS",
    "GDPR",
    "ISO 27001",
    "NIST CSF",
    "CCPA",
    "FedRAMP",
)
KNOWN_INDUSTRIES: tuple[str, ...] = (
    "Technology",
    "Retail and e-commerce",
    "Financial services",
    "Insurance",
    "Healthcare",
    "Manufacturing",
    "Energy and utilities",
    "Telecommunications",
    "Education",
    "Government",
    "Professional services",
    "Media and entertainment",
    "Transportation and logistics",
    "Nonprofit",
    "Other",
)

# Caps on each text field's length, the leader count, and the head count
# range.
MAX_LEGAL_NAME_CHARS = 200
MAX_DBA_NAME_CHARS = 200
MAX_INDUSTRY_CHARS = 120
MAX_LEADERS = 20
MAX_LEADER_NAME_CHARS = 120
MAX_COMPLIANCE_DRIVERS = 25
MAX_DRIVER_CHARS = 120
MAX_REGULATORY_NOTES_CHARS = 2000
MAX_EMPLOYEE_COUNT = 10_000_000

_ROLE_BY_UPPER = {role.upper(): role for role in KNOWN_LEADERSHIP_ROLES}


@dataclass(frozen=True)
class LeadershipContact:
    """One named leader and the role the policies assign duties to."""

    role: str
    name: str


@dataclass(frozen=True)
class OrgProfile:
    """A validated organization profile. Build one with ``from_dict``."""

    legal_name: str
    dba_name: str = ""
    industry: str = ""
    employee_count: int | None = None
    leadership: tuple[LeadershipContact, ...] = ()
    compliance_drivers: tuple[str, ...] = ()
    regulatory_notes: str = ""

    @classmethod
    def from_dict(cls, data: object) -> OrgProfile:
        """Validate and sanitize a profile dict from the form or a workspace.

        Unknown keys are ignored. Raises ``ValidationError`` with a sentence
        that names the field when a value is missing, too long, or the wrong
        type.
        """
        if not isinstance(data, Mapping):
            raise ValidationError("The organization profile must be an object.")
        legal_name = _line(data.get("legal_name"), "Legal name", MAX_LEGAL_NAME_CHARS)
        if not legal_name:
            raise ValidationError("Legal name is required.")
        return cls(
            legal_name=legal_name,
            dba_name=_line(data.get("dba_name"), "Doing-business-as name", MAX_DBA_NAME_CHARS),
            industry=_line(data.get("industry"), "Industry", MAX_INDUSTRY_CHARS),
            employee_count=_employee_count(data.get("employee_count")),
            leadership=_leadership(data.get("leadership")),
            compliance_drivers=_drivers(data.get("compliance_drivers")),
            regulatory_notes=_notes(data.get("regulatory_notes")),
        )

    def to_dict(self) -> dict[str, Any]:
        """A JSON-safe dict in the shape ``from_dict`` reads."""
        return {
            "legal_name": self.legal_name,
            "dba_name": self.dba_name,
            "industry": self.industry,
            "employee_count": self.employee_count,
            "leadership": [{"role": c.role, "name": c.name} for c in self.leadership],
            "compliance_drivers": list(self.compliance_drivers),
            "regulatory_notes": self.regulatory_notes,
        }

    def save_to(self, workspace: Workspace) -> Record:
        """Store this profile as the workspace's organization profile."""
        return workspace.set_org_profile(self.legal_name, self.to_dict())

    @classmethod
    def load_from(cls, workspace: Workspace) -> OrgProfile | None:
        """The workspace's profile, or None when it has none.

        Raises ``ValidationError`` when the stored profile does not validate
        (for example, an edited workspace file).
        """
        record = workspace.org_profile
        if record is None:
            return None
        return cls.from_dict(record.payload)


def _line(value: object, label: str, limit: int) -> str:
    """One sanitized line, or "" for None. Too long or not text is an error."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValidationError(f"{label} must be text.")
    text = single_line(value, max(len(value), 1))
    if len(text) > limit:
        raise ValidationError(f"{label} must be at most {limit} characters.")
    return text


def _employee_count(value: object) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError("Employee count must be a whole number.")
    if not 1 <= value <= MAX_EMPLOYEE_COUNT:
        raise ValidationError(f"Employee count must be between 1 and {MAX_EMPLOYEE_COUNT:,}.")
    return value


def _leadership(value: object) -> tuple[LeadershipContact, ...]:
    if value is None:
        return ()
    if not isinstance(value, list | tuple):
        raise ValidationError("Leadership must be a list.")
    contacts: list[LeadershipContact] = []
    for item in value:
        if isinstance(item, LeadershipContact):
            item = {"role": item.role, "name": item.name}
        if not isinstance(item, Mapping):
            raise ValidationError("Each leadership entry must have a role and a name.")
        name = _line(item.get("name"), "Leader name", MAX_LEADER_NAME_CHARS)
        if not name:
            # A blank row in the form; the policy prompt has no use for it.
            continue
        role_text = item.get("role")
        role = _ROLE_BY_UPPER.get(role_text.strip().upper()) if isinstance(role_text, str) else None
        if role is None:
            raise ValidationError(
                "Leadership role must be one of " + ", ".join(KNOWN_LEADERSHIP_ROLES) + "."
            )
        contacts.append(LeadershipContact(role=role, name=name))
    if len(contacts) > MAX_LEADERS:
        raise ValidationError(f"List at most {MAX_LEADERS} leaders.")
    return tuple(contacts)


def _drivers(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list | tuple):
        raise ValidationError("Compliance drivers must be a list.")
    drivers: list[str] = []
    for item in value:
        text = _line(item, "Each compliance driver", MAX_DRIVER_CHARS)
        if text and text not in drivers:
            drivers.append(text)
    if len(drivers) > MAX_COMPLIANCE_DRIVERS:
        raise ValidationError(f"Choose at most {MAX_COMPLIANCE_DRIVERS} compliance drivers.")
    return tuple(drivers)


def _notes(value: object) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValidationError("Regulatory notes must be text.")
    text = sanitize_user_markdown(value)
    if len(text) > MAX_REGULATORY_NOTES_CHARS:
        raise ValidationError(
            f"Regulatory notes must be at most {MAX_REGULATORY_NOTES_CHARS:,} characters."
        )
    return text


__all__ = [
    "KNOWN_COMPLIANCE_DRIVERS",
    "KNOWN_INDUSTRIES",
    "KNOWN_LEADERSHIP_ROLES",
    "LeadershipContact",
    "OrgProfile",
]
