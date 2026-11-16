"""Organization profile validation: fields, limits, and the Workspace round trip."""

from __future__ import annotations

import pytest

from aegisshield.core.errors import ValidationError
from aegisshield.services import org_profile as op
from aegisshield.services.org_profile import LeadershipContact, OrgProfile
from aegisshield.storage.workspace import Workspace


def _form() -> dict:
    return {
        "legal_name": "Northwind Outfitters Inc.",
        "dba_name": "Northwind",
        "industry": "Retail and e-commerce",
        "employee_count": 240,
        "leadership": [
            {"role": "CEO", "name": "Dana Cruz", "email": "dana@example.com"},
            {"role": "CISO", "name": "Sam Patel"},
        ],
        "compliance_drivers": ["PCI DSS", "SOC 2"],
        "regulatory_notes": "Sells online in the US and the EU.",
        "website": "https://example.com",
        "plan": "enterprise",
    }


def test_round_trip_through_workspace() -> None:
    ws = Workspace()
    profile = OrgProfile.from_dict(_form())
    record = profile.save_to(ws)
    assert record.title == "Northwind Outfitters Inc."
    restored = Workspace.from_json(ws.to_json())
    assert OrgProfile.load_from(restored) == profile


def test_load_from_empty_workspace_is_none() -> None:
    assert OrgProfile.load_from(Workspace()) is None


def test_unknown_and_saas_fields_and_email_are_dropped() -> None:
    data = OrgProfile.from_dict(_form()).to_dict()
    assert set(data) == {
        "legal_name",
        "dba_name",
        "industry",
        "employee_count",
        "leadership",
        "compliance_drivers",
        "regulatory_notes",
    }
    assert data["leadership"][0] == {"role": "CEO", "name": "Dana Cruz"}


def test_minimal_profile_defaults() -> None:
    profile = OrgProfile.from_dict({"legal_name": "Acme"})
    assert profile == OrgProfile(legal_name="Acme")
    assert profile.to_dict()["employee_count"] is None


@pytest.mark.parametrize("value", [None, "", "   "])
def test_legal_name_required(value) -> None:
    with pytest.raises(ValidationError, match="Legal name is required"):
        OrgProfile.from_dict({"legal_name": value})


def test_not_a_mapping() -> None:
    with pytest.raises(ValidationError, match="must be an object"):
        OrgProfile.from_dict(["legal_name"])


def test_text_is_sanitized() -> None:
    profile = OrgProfile.from_dict(
        {
            "legal_name": "Acme\u202e Corp\x00\n Ltd",
            "industry": "Tech\u200bnology",
            "regulatory_notes": "Line one\r\nLine two\x07\u2066",
        }
    )
    assert profile.legal_name == "Acme Corp  Ltd"
    assert profile.industry == "Technology"
    assert profile.regulatory_notes == "Line one\nLine two"


@pytest.mark.parametrize(
    ("field", "limit"),
    [
        ("legal_name", op.MAX_LEGAL_NAME_CHARS),
        ("dba_name", op.MAX_DBA_NAME_CHARS),
        ("industry", op.MAX_INDUSTRY_CHARS),
    ],
)
def test_line_caps(field: str, limit: int) -> None:
    data = {"legal_name": "Acme", field: "x" * limit}
    assert getattr(OrgProfile.from_dict(data), field) == "x" * limit
    data[field] = "x" * (limit + 1)
    with pytest.raises(ValidationError, match=f"at most {limit} characters"):
        OrgProfile.from_dict(data)


def test_line_must_be_text() -> None:
    with pytest.raises(ValidationError, match="Industry must be text"):
        OrgProfile.from_dict({"legal_name": "Acme", "industry": 5})


def test_notes_cap_and_type() -> None:
    limit = op.MAX_REGULATORY_NOTES_CHARS
    assert OrgProfile.from_dict({"legal_name": "A", "regulatory_notes": "y" * limit})
    with pytest.raises(ValidationError, match="Regulatory notes must be at most"):
        OrgProfile.from_dict({"legal_name": "A", "regulatory_notes": "y" * (limit + 1)})
    with pytest.raises(ValidationError, match="Regulatory notes must be text"):
        OrgProfile.from_dict({"legal_name": "A", "regulatory_notes": ["x"]})


@pytest.mark.parametrize(("value", "expected"), [(None, None), ("", None), (" 42 ", 42), (1, 1)])
def test_employee_count_accepted(value, expected) -> None:
    assert OrgProfile.from_dict({"legal_name": "A", "employee_count": value}).employee_count == (
        expected
    )


@pytest.mark.parametrize("value", [0, -5, op.MAX_EMPLOYEE_COUNT + 1, True, 2.5, "lots"])
def test_employee_count_rejected(value) -> None:
    with pytest.raises(ValidationError, match="Employee count"):
        OrgProfile.from_dict({"legal_name": "A", "employee_count": value})


def test_invalid_leadership_role() -> None:
    data = {"legal_name": "A", "leadership": [{"role": "Overlord", "name": "Kim"}]}
    with pytest.raises(ValidationError, match="Leadership role must be one of"):
        OrgProfile.from_dict(data)


def test_role_is_normalized_and_blank_rows_skipped() -> None:
    profile = OrgProfile.from_dict(
        {
            "legal_name": "A",
            "leadership": [
                {"role": " ciso ", "name": "Kim"},
                {"role": "CEO", "name": "  "},
                LeadershipContact(role="CFO", name="Lee"),
            ],
        }
    )
    assert profile.leadership == (
        LeadershipContact(role="CISO", name="Kim"),
        LeadershipContact(role="CFO", name="Lee"),
    )


@pytest.mark.parametrize(
    ("leadership", "message"),
    [
        ("CEO", "Leadership must be a list"),
        (["CEO"], "Each leadership entry"),
        ([{"role": None, "name": "Kim"}], "Leadership role"),
        ([{"role": "CEO", "name": "k" * (op.MAX_LEADER_NAME_CHARS + 1)}], "Leader name"),
        ([{"role": "CEO", "name": f"n{i}"} for i in range(op.MAX_LEADERS + 1)], "at most 20"),
    ],
)
def test_leadership_rejected(leadership, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        OrgProfile.from_dict({"legal_name": "A", "leadership": leadership})


def test_too_many_compliance_drivers() -> None:
    drivers = [f"Framework {i}" for i in range(op.MAX_COMPLIANCE_DRIVERS + 1)]
    with pytest.raises(ValidationError, match="at most 25 compliance drivers"):
        OrgProfile.from_dict({"legal_name": "A", "compliance_drivers": drivers})


def test_overlong_compliance_driver() -> None:
    drivers = ["x" * (op.MAX_DRIVER_CHARS + 1)]
    with pytest.raises(ValidationError, match="Each compliance driver must be at most 120"):
        OrgProfile.from_dict({"legal_name": "A", "compliance_drivers": drivers})


def test_drivers_deduplicated_and_blank_dropped() -> None:
    profile = OrgProfile.from_dict(
        {"legal_name": "A", "compliance_drivers": ["GDPR", "", "GDPR", "Internal audit"]}
    )
    assert profile.compliance_drivers == ("GDPR", "Internal audit")


def test_drivers_must_be_a_list() -> None:
    with pytest.raises(ValidationError, match="Compliance drivers must be a list"):
        OrgProfile.from_dict({"legal_name": "A", "compliance_drivers": "GDPR"})


def test_option_lists_are_offered_not_defaults() -> None:
    assert "Healthcare" in op.KNOWN_INDUSTRIES
    assert op.KNOWN_INDUSTRIES[0] != "Healthcare"
    assert OrgProfile(legal_name="A").compliance_drivers == ()
    assert OrgProfile(legal_name="A").industry == ""


def test_invalid_stored_profile_raises_on_load() -> None:
    ws = Workspace()
    ws.set_org_profile("bad", {"legal_name": ""})
    with pytest.raises(ValidationError):
        OrgProfile.load_from(ws)
