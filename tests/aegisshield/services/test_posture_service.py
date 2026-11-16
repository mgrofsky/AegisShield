"""Posture aggregator tests, on a ``Workspace``.

The lookup cases check the last lookup's status, technology count, and
finish time.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegisshield.services.posture_service import (
    DreadSummary,
    PostureSnapshot,
    aggregate_posture,
    parse_highest_dread,
    severity_for_score,
)
from aegisshield.storage.workspace import RecordKind, Workspace

DREAD_TABLE_TWO_THREATS = """\
| ID | Damage Potential | Reproducibility | Exploitability | Affected Users | Discoverability | Risk Score |
|----|------------------|-----------------|----------------|----------------|-----------------|-------------|
| TC-S01 | 7 | 6 | 5 | 8 | 4 | 6.00 |
| TC-T01 | 9 | 7 | 6 | 9 | 5 | 7.20 |
"""

DREAD_TABLE_LOW = """\
| ID | Damage Potential | Reproducibility | Exploitability | Affected Users | Discoverability | Risk Score |
|----|------------------|-----------------|----------------|----------------|-----------------|-------------|
| TC-S01 | 2 | 2 | 2 | 2 | 2 | 2.00 |
"""

_counter = iter(range(10_000))


def _record(payload: dict[str, Any], created_at: str = "2026-06-14T09:00:00+00:00") -> dict:
    return {
        "id": f"r{next(_counter)}",
        "created_at": created_at,
        "title": "t",
        "payload": payload,
    }


def _workspace(
    threat_models: list[dict[str, Any]] | None = None,
    lookups: list[dict[str, Any]] | None = None,
) -> Workspace:
    return Workspace.from_dict(
        {
            "schema_version": 1,
            RecordKind.THREAT_MODELS.value: threat_models or [],
            RecordKind.LOOKUPS.value: lookups or [],
        }
    )


def _tm(dread_md: object = None) -> dict:
    payload: dict[str, Any] = {"threat_model": [], "description": "checkout"}
    if dread_md is not None:
        payload["dread_assessment_markdown"] = dread_md
    return _record(payload)


def _lookup(
    status: object = "complete",
    finished_at: object = "2026-06-14T09:30:00+00:00",
    tech_count: object = 4,
    created_at: str = "2026-06-14T09:00:00+00:00",
) -> dict:
    result = {
        "status": status,
        "finished_at": finished_at,
        "summary": {"tech_count": tech_count, "cve_count": 12},
    }
    return _record({"request": {"technologies": ["nginx 1.18"]}, "result": result}, created_at)


# parse_highest_dread ---------------------------------------------------------


def test_parse_highest_dread_returns_max_score_and_severity_label() -> None:
    summary = parse_highest_dread(DREAD_TABLE_TWO_THREATS)
    assert summary == DreadSummary(highest_score=7.20, severity="high", threats_assessed=2)


def test_parse_highest_dread_low_score_is_low_severity() -> None:
    summary = parse_highest_dread(DREAD_TABLE_LOW)
    assert summary.severity == "low"
    assert summary.highest_score == 2.00


def test_parse_highest_dread_empty_input_is_neutral() -> None:
    for empty in ("", None):
        summary = parse_highest_dread(empty)
        assert summary == DreadSummary(highest_score=None, severity=None, threats_assessed=0)


def test_parse_highest_dread_ignores_garbled_rows() -> None:
    garbled = (
        "| ID | ... |\n"
        "| not-a-tc-id | x | y | z | w | v | nope |\n"
        "| TC-S99 | 1 | 1 | 1 | 1 | 1 | 1.00 |\n"
    )
    summary = parse_highest_dread(garbled)
    assert summary.threats_assessed == 1
    assert summary.highest_score == 1.00


def test_parse_highest_dread_em_dash_id_is_accepted() -> None:
    md = "| ID | ... |\n|----|-----|\n| \u2014 | 5 | 5 | 5 | 5 | 5 | 5.00 |\n"
    summary = parse_highest_dread(md)
    assert summary.threats_assessed == 1
    assert summary.highest_score == 5.00


# Severity buckets ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "label"),
    [
        (10.0, "critical"),
        (8.0, "critical"),
        (7.99, "high"),
        (6.0, "high"),
        (5.99, "medium"),
        (4.0, "medium"),
        (3.99, "low"),
        (1.0, "low"),
    ],
)
def test_severity_buckets(score: float, label: str) -> None:
    assert severity_for_score(score) == label


# Any ID cell counts, not only TC ids ---------------------------------------------


def test_parse_highest_dread_accepts_any_id_cell() -> None:
    """The DREAD step keeps a model ID such as T-7 as given, rather than dropping it."""
    md = (
        "| T-7 | 9 | 9 | 9 | 9 | 9 | 9.00 |\n"
        "| - | 3 | 3 | 3 | 3 | 3 | 3.00 |\n"
        "|  | 4 | 4 | 4 | 4 | 4 | 4.00 |\n"
    )
    summary = parse_highest_dread(md)
    assert summary == DreadSummary(highest_score=9.0, severity="critical", threats_assessed=3)


def test_parse_highest_dread_ignores_header_and_separator() -> None:
    header_only = DREAD_TABLE_LOW.splitlines()[:2]
    assert parse_highest_dread("\n".join(header_only)).threats_assessed == 0


# aggregate_posture (on a Workspace) ----------------------------------------------


def test_aggregate_posture_counts_threat_models_and_dread_coverage() -> None:
    snapshot = aggregate_posture(
        _workspace([_tm(DREAD_TABLE_TWO_THREATS), _tm(None), _tm(DREAD_TABLE_LOW)])
    )
    assert snapshot.threat_model_count == 3
    assert snapshot.threat_models_with_dread == 2
    assert snapshot.coverage_pct == 67  # 2/3 rounded
    assert snapshot.dread_highest == 7.20
    assert snapshot.dread_severity == "high"
    assert snapshot.dread_threats_assessed == 3


def test_aggregate_posture_zero_models_is_zero_coverage_not_div_by_zero() -> None:
    snapshot = aggregate_posture(Workspace())
    assert snapshot == PostureSnapshot(
        threat_model_count=0,
        threat_models_with_dread=0,
        coverage_pct=0,
        dread_highest=None,
        dread_severity=None,
        dread_threats_assessed=0,
        last_lookup_status=None,
        last_lookup_tech_count=None,
        last_lookup_finished_at=None,
    )


def test_aggregate_posture_surfaces_last_lookup_fields() -> None:
    snapshot = aggregate_posture(_workspace(lookups=[_lookup()]))
    assert snapshot.last_lookup_status == "complete"
    assert snapshot.last_lookup_tech_count == 4
    assert snapshot.last_lookup_finished_at == "2026-06-14T09:30:00+00:00"


def test_aggregate_posture_running_lookup_falls_back_to_created_at() -> None:
    snapshot = aggregate_posture(_workspace(lookups=[_lookup(status="running", finished_at=None)]))
    assert snapshot.last_lookup_status == "running"
    assert snapshot.last_lookup_finished_at == "2026-06-14T09:00:00+00:00"


def test_aggregate_posture_reports_status_verbatim() -> None:
    snapshot = aggregate_posture(_workspace(lookups=[_lookup(status="Partial: NVD timed out")]))
    assert snapshot.last_lookup_status == "Partial: NVD timed out"


def test_aggregate_posture_uses_newest_lookup() -> None:
    old = _lookup(status="failed", tech_count=1, created_at="2026-06-13T09:00:00+00:00")
    new = _lookup(status="complete", tech_count=7, created_at="2026-06-14T12:00:00+00:00")
    snapshot = aggregate_posture(_workspace(lookups=[new, old]))
    assert snapshot.last_lookup_status == "complete"
    assert snapshot.last_lookup_tech_count == 7
    snapshot = aggregate_posture(_workspace(lookups=[old, new]))
    assert snapshot.last_lookup_tech_count == 7


def test_aggregate_posture_records_added_through_the_workspace_api() -> None:
    """Records added through the Workspace API: another way to build the input."""
    workspace = Workspace()
    workspace.add(
        RecordKind.THREAT_MODELS, "Checkout", {"dread_assessment_markdown": DREAD_TABLE_LOW}
    )
    workspace.add(
        RecordKind.LOOKUPS,
        "nginx",
        {
            "request": {},
            "result": {
                "status": "failed",
                "finished_at": "2026-06-14T12:00:00+00:00",
                "summary": {"tech_count": 2},
            },
        },
    )
    snapshot = aggregate_posture(workspace)
    assert snapshot.threat_model_count == 1
    assert snapshot.coverage_pct == 100
    assert snapshot.last_lookup_status == "failed"
    assert snapshot.last_lookup_tech_count == 2
    assert snapshot.last_lookup_finished_at == "2026-06-14T12:00:00+00:00"


# Defensive reads -----------------------------------------------------------------


def test_lookup_with_malformed_result_is_read_defensively() -> None:
    record = _record({"request": {}, "result": "not a dict"})
    snapshot = aggregate_posture(_workspace(lookups=[record]))
    assert snapshot.last_lookup_status is None
    assert snapshot.last_lookup_tech_count is None
    assert snapshot.last_lookup_finished_at == record["created_at"]


@pytest.mark.parametrize("tech_count", [True, "4", 4.0, None])
def test_tech_count_must_be_an_int(tech_count: object) -> None:
    snapshot = aggregate_posture(_workspace(lookups=[_lookup(tech_count=tech_count)]))
    assert snapshot.last_lookup_tech_count is None


def test_non_string_status_and_finished_at_are_ignored() -> None:
    snapshot = aggregate_posture(_workspace(lookups=[_lookup(status=3, finished_at=17)]))
    assert snapshot.last_lookup_status is None
    assert snapshot.last_lookup_finished_at == "2026-06-14T09:00:00+00:00"


def test_non_string_or_blank_dread_markdown_is_not_assessed() -> None:
    snapshot = aggregate_posture(_workspace([_tm({"x": 1}), _tm("   "), _tm(DREAD_TABLE_LOW)]))
    assert snapshot.threat_models_with_dread == 1
    assert snapshot.coverage_pct == 33


def test_unreadable_dread_markdown_counts_as_assessed_without_a_score() -> None:
    """A saved DREAD section counts toward coverage even with no readable table."""
    snapshot = aggregate_posture(_workspace([_tm("no table here")]))
    assert snapshot.threat_models_with_dread == 1
    assert snapshot.coverage_pct == 100
    assert snapshot.dread_highest is None
    assert snapshot.dread_threats_assessed == 0
