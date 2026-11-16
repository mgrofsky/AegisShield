"""The dashboard's at-a-glance security posture, computed from a visitor's workspace.

The dashboard needs four single-number reads: how many threat models are
saved, the highest DREAD risk score, the last vulnerability lookup, and the
share of threat models with a DREAD assessment. Keeping the math here keeps the page free of
markdown parsing and keeps the rules under unit tests.

The counts are read from ``Workspace`` records. The last passive
vulnerability lookup is reported with its status, how many technologies it
covered, and when it finished.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from aegisshield.storage.workspace import Record, RecordKind, Workspace

# A DREAD markdown row as ``dread_service.dread_json_to_markdown`` writes it:
#   | TC-S01 | 7 | 6 | 5 | 8 | 4 | 6.00 |
# Only the trailing risk score is needed. The ID cell may hold any text: the
# DREAD step writes the model's ID as given when it is not a TC- id, and a
# placeholder when there is none. The five integer columns keep header,
# separator, and garbled rows out.
_DREAD_SCORE_RE = re.compile(
    r"^\|[^|\n]*\|"  # ID column
    r"(?:\s*\d+\s*\|){5}"  # five integer DREAD columns
    r"\s*([0-9]+(?:\.[0-9]+)?)\s*\|\s*$",  # risk score (for example 6.00)
)

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

# Lower bound of each bucket, highest first. The score is the mean of five
# DREAD axes scored 1 to 10. The thresholds match the threat cards' tiers so
# the dashboard and the cards never disagree.
SEVERITY_BUCKETS: tuple[tuple[float, str], ...] = (
    (8.0, CRITICAL),
    (6.0, HIGH),
    (4.0, MEDIUM),
)


def severity_for_score(score: float) -> str:
    """The severity label for a DREAD risk score: critical, high, medium, or low."""
    for floor, label in SEVERITY_BUCKETS:
        if score >= floor:
            return label
    return LOW


@dataclass(frozen=True)
class DreadSummary:
    """The highest risk score in one DREAD table, its severity, and the row count."""

    highest_score: float | None
    severity: str | None
    threats_assessed: int


def parse_highest_dread(dread_md: str | None) -> DreadSummary:
    """Pull the highest risk score and threat count out of one DREAD table.

    Returns ``(None, None, 0)`` for empty or unreadable input rather than
    raising, so the dashboard can show a neutral cell.
    """
    if not dread_md:
        return DreadSummary(highest_score=None, severity=None, threats_assessed=0)

    highest: float | None = None
    count = 0
    for line in dread_md.splitlines():
        match = _DREAD_SCORE_RE.match(line.strip())
        if match is None:
            continue
        value = float(match.group(1))
        count += 1
        if highest is None or value > highest:
            highest = value

    severity = severity_for_score(highest) if highest is not None else None
    return DreadSummary(highest_score=highest, severity=severity, threats_assessed=count)


@dataclass(frozen=True)
class PostureSnapshot:
    """The four posture cells' numbers.

    ``last_lookup_finished_at`` is a UTC ISO 8601 string. While a lookup is
    still running it holds the time the lookup was saved, so the cell always
    has a time to show.
    """

    threat_model_count: int
    threat_models_with_dread: int
    coverage_pct: int  # 0 to 100 inclusive
    dread_highest: float | None
    dread_severity: str | None
    dread_threats_assessed: int
    last_lookup_status: str | None
    last_lookup_tech_count: int | None
    last_lookup_finished_at: str | None


def _dread_markdown(record: Record) -> str | None:
    value = record.payload.get("dread_assessment_markdown")
    return value if isinstance(value, str) and value.strip() else None


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _last_lookup(workspace: Workspace) -> tuple[str | None, int | None, str | None]:
    """Status, technology count, and finish time of the newest lookup record."""
    lookups = workspace.list(RecordKind.LOOKUPS)
    if not lookups:
        return None, None, None
    record = lookups[0]
    result = _as_dict(record.payload.get("result"))
    status = result.get("status")
    tech_count = _as_dict(result.get("summary")).get("tech_count")
    finished_at = result.get("finished_at")
    return (
        status if isinstance(status, str) and status else None,
        tech_count if isinstance(tech_count, int) and not isinstance(tech_count, bool) else None,
        finished_at if isinstance(finished_at, str) and finished_at else record.created_at,
    )


def aggregate_posture(workspace: Workspace) -> PostureSnapshot:
    """Combine a workspace's threat models and lookups into the posture snapshot.

    A threat model counts as assessed when its payload has a non-empty
    ``dread_assessment_markdown``. The last lookup is the newest
    ``RecordKind.LOOKUPS`` record; its status is reported as stored.
    """
    threat_models = workspace.list(RecordKind.THREAT_MODELS)
    total = len(threat_models)
    with_dread = 0
    overall_highest: float | None = None
    overall_severity: str | None = None
    overall_threats = 0

    for record in threat_models:
        dread_md = _dread_markdown(record)
        if dread_md is None:
            continue
        with_dread += 1
        summary = parse_highest_dread(dread_md)
        overall_threats += summary.threats_assessed
        if summary.highest_score is None:
            continue
        if overall_highest is None or summary.highest_score > overall_highest:
            overall_highest = summary.highest_score
            overall_severity = summary.severity

    coverage_pct = round((with_dread / total) * 100) if total else 0
    status, tech_count, finished_at = _last_lookup(workspace)

    return PostureSnapshot(
        threat_model_count=total,
        threat_models_with_dread=with_dread,
        coverage_pct=coverage_pct,
        dread_highest=overall_highest,
        dread_severity=overall_severity,
        dread_threats_assessed=overall_threats,
        last_lookup_status=status,
        last_lookup_tech_count=tech_count,
        last_lookup_finished_at=finished_at,
    )
