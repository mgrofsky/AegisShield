"""posture_view: the posture card cells and the relative time labels."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aegisshield.services.posture_service import PostureSnapshot
from aegisshield.ui.posture_view import NONE, Cell, format_posture, relative_time
from aegisshield.ui.theme import Tone

NOW = datetime(2026, 6, 14, 12, 0, 0, tzinfo=UTC)


def _ago(**delta: float) -> str:
    return (NOW - timedelta(**delta)).isoformat()


def _snap(**kw: object) -> PostureSnapshot:
    base: dict[str, object] = {
        "threat_model_count": 0,
        "threat_models_with_dread": 0,
        "coverage_pct": 0,
        "dread_highest": None,
        "dread_severity": None,
        "dread_threats_assessed": 0,
        "last_lookup_status": None,
        "last_lookup_tech_count": None,
        "last_lookup_finished_at": None,
    }
    base.update(kw)
    return PostureSnapshot(**base)  # type: ignore[arg-type]


# relative_time ---------------------------------------------------------


def test_relative_time_missing_or_unparseable_is_a_dash() -> None:
    assert NONE == "-"
    assert relative_time(None, NOW) == "-"
    assert relative_time("", NOW) == "-"
    assert relative_time("not-a-date", NOW) == "-"


def test_relative_time_sub_minute_is_just_now() -> None:
    assert relative_time(_ago(seconds=30), NOW) == "just now"


def test_relative_time_minutes_hours_days() -> None:
    assert relative_time(_ago(minutes=5), NOW) == "5m ago"
    assert relative_time(_ago(hours=3), NOW) == "3h ago"
    assert relative_time(_ago(days=4), NOW) == "4d ago"


def test_relative_time_older_than_a_week_is_the_date() -> None:
    assert relative_time(_ago(days=30), NOW) == "2026-05-15"


def test_relative_time_reads_z_suffix_and_naive_times_as_utc() -> None:
    assert relative_time("2026-06-14T11:55:00Z", NOW) == "5m ago"
    assert relative_time("2026-06-14T09:00:00", NOW) == "3h ago"


# format_posture --------------------------------------------------------


def test_empty_state_is_muted() -> None:
    cells = format_posture(_snap(), now=NOW)
    assert cells.threat_models == Cell("0", "No threat models yet", Tone.NEUTRAL)
    assert cells.dread == Cell("-", "No DREAD assessments yet", Tone.NEUTRAL, None)
    assert cells.last_lookup == Cell("-", "No lookups yet", Tone.NEUTRAL)
    assert cells.coverage == Cell("0%", "No threat models yet", Tone.NEUTRAL)


def test_populated_snapshot() -> None:
    cells = format_posture(_snap(
        threat_model_count=3, threat_models_with_dread=2, coverage_pct=67,
        dread_highest=7.2, dread_severity="high", dread_threats_assessed=4,
        last_lookup_status="complete", last_lookup_tech_count=5,
        last_lookup_finished_at=_ago(hours=2),
    ), now=NOW)
    assert cells.threat_models == Cell("3", "3 threat models on file", Tone.INFO)
    assert cells.dread == Cell("7.2", "High risk, 4 threats scored", Tone.CRIT, "high")
    assert cells.last_lookup == Cell("Complete", "5 technologies, 2h ago", Tone.OK)
    assert cells.coverage == Cell("67%", "2/3 threat models scored", Tone.WARN)


def test_one_threat_model_and_one_technology_are_singular() -> None:
    cells = format_posture(_snap(
        threat_model_count=1, threat_models_with_dread=1, coverage_pct=100,
        dread_highest=8.5, dread_severity="critical", dread_threats_assessed=1,
        last_lookup_status="complete", last_lookup_tech_count=1,
        last_lookup_finished_at=_ago(minutes=5),
    ), now=NOW)
    assert cells.threat_models.hint == "1 threat model on file"
    assert cells.dread.hint == "Critical risk, 1 threat scored"
    assert cells.dread.tone is Tone.CRIT
    assert cells.last_lookup.hint == "1 technology, 5m ago"


def test_medium_severity_is_warn_and_full_coverage_is_ok() -> None:
    cells = format_posture(_snap(
        threat_model_count=1, threat_models_with_dread=1, coverage_pct=100,
        dread_highest=5.0, dread_severity="medium", dread_threats_assessed=1,
        last_lookup_status="running", last_lookup_finished_at=NOW.isoformat(),
    ), now=NOW)
    assert cells.dread.tone is Tone.WARN
    assert cells.dread.severity == "medium"
    assert cells.dread.value == "5.0"
    assert cells.dread.hint == "Medium risk, 1 threat scored"
    assert cells.coverage == Cell("100%", "All threat models have DREAD", Tone.OK)
    assert cells.last_lookup.tone is Tone.INFO
    assert cells.last_lookup.value == "Running"
    # No technology count: the hint is the time alone.
    assert cells.last_lookup.hint == "just now"


def test_low_severity_is_ok_and_unknown_severity_is_info() -> None:
    low = format_posture(_snap(threat_model_count=1, dread_highest=2.0, dread_severity="low",
                               dread_threats_assessed=2), now=NOW)
    assert low.dread.tone is Tone.OK and low.dread.hint == "Low risk, 2 threats scored"
    odd = format_posture(_snap(threat_model_count=1, dread_highest=2.0, dread_severity=None,
                               dread_threats_assessed=2), now=NOW)
    assert odd.dread.tone is Tone.INFO and odd.dread.hint.startswith("Unknown risk")


def test_failed_lookup_is_crit_and_cancelled_is_warn() -> None:
    failed = format_posture(_snap(last_lookup_status="failed"), now=NOW)
    assert failed.last_lookup.tone is Tone.CRIT and failed.last_lookup.value == "Failed"
    assert failed.last_lookup.hint == "-"
    cancelled = format_posture(_snap(last_lookup_status="cancelled"), now=NOW)
    assert cancelled.last_lookup.tone is Tone.WARN
    other = format_posture(_snap(last_lookup_status="weird"), now=NOW)
    assert other.last_lookup.tone is Tone.INFO


def test_coverage_is_clamped_and_toned() -> None:
    high = format_posture(_snap(threat_model_count=2, threat_models_with_dread=2,
                                coverage_pct=250), now=NOW)
    assert high.coverage.value == "100%"
    neg = format_posture(_snap(threat_model_count=4, threat_models_with_dread=0,
                               coverage_pct=-5), now=NOW)
    assert neg.coverage.value == "0%" and neg.coverage.tone is Tone.CRIT
    assert neg.coverage.hint == "0/4 threat models scored"
    mid = format_posture(_snap(threat_model_count=5, threat_models_with_dread=2,
                               coverage_pct=40), now=NOW)
    assert mid.coverage.tone is Tone.WARN
    ok = format_posture(_snap(threat_model_count=5, threat_models_with_dread=4,
                              coverage_pct=80), now=NOW)
    assert ok.coverage.tone is Tone.OK
