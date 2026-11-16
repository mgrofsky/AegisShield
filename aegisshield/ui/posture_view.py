"""Words and tones for the dashboard's posture cells.

The "Last scan" cell is the last vulnerability lookup (this app does not
scan), a missing value reads "-", and hints join their parts with ", ".
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from aegisshield.services.posture_service import PostureSnapshot
from aegisshield.ui.theme import Tone

__all__ = ["Cell", "Posture", "format_posture", "relative_time"]

NONE = "-"

_STATUS_TONE = {
    "complete": Tone.OK, "succeeded": Tone.OK, "finished": Tone.OK,
    "running": Tone.INFO, "queued": Tone.INFO, "pending": Tone.INFO,
    "paused": Tone.WARN, "failed": Tone.CRIT, "cancelled": Tone.WARN, "canceled": Tone.WARN,
}
_SEVERITY_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
_SEVERITY_TONE = {"critical": Tone.CRIT, "high": Tone.CRIT, "medium": Tone.WARN, "low": Tone.OK}


def _parse(iso: str | None) -> datetime | None:
    if not iso:
        return None
    try:
        then = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return None
    return then if then.tzinfo else then.replace(tzinfo=UTC)


def relative_time(iso: str | None, now: datetime | None = None) -> str:
    """"just now", "5m ago", "3h ago", "4d ago", or the date; "-" when unknown."""
    then = _parse(iso)
    if then is None:
        return NONE
    now = now or datetime.now(UTC)
    seconds = round((now - then).total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    if seconds < 86400 * 7:
        return f"{seconds // 86400}d ago"
    return then.date().isoformat()


@dataclass(frozen=True)
class Cell:
    """One posture cell: the big value, a hint line, and a tone."""

    value: str
    hint: str
    tone: Tone
    severity: str | None = None


@dataclass(frozen=True)
class Posture:
    """The four cells in display order."""

    threat_models: Cell
    dread: Cell
    last_lookup: Cell
    coverage: Cell


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def format_posture(snap: PostureSnapshot, *, now: datetime | None = None) -> Posture:
    """The four cells for a posture snapshot."""
    count = snap.threat_model_count
    threat_models = Cell(
        str(count),
        "No threat models yet" if count == 0 else f"{_plural(count, 'threat model')} on file",
        Tone.NEUTRAL if count == 0 else Tone.INFO,
    )
    if snap.dread_highest is None:
        dread = Cell(NONE, "No DREAD assessments yet", Tone.NEUTRAL)
    else:
        label = _SEVERITY_LABEL.get(snap.dread_severity or "", "Unknown")
        dread = Cell(f"{snap.dread_highest:.1f}",
                     f"{label} risk, {_plural(snap.dread_threats_assessed, 'threat')} scored",
                     _SEVERITY_TONE.get(snap.dread_severity or "", Tone.INFO),
                     severity=snap.dread_severity)
    if not snap.last_lookup_status:
        last = Cell(NONE, "No lookups yet", Tone.NEUTRAL)
    else:
        status = snap.last_lookup_status
        when = relative_time(snap.last_lookup_finished_at, now)
        techs = snap.last_lookup_tech_count
        if isinstance(techs, int):
            noun = "technology" if techs == 1 else "technologies"
            hint = f"{techs} {noun}, {when}"
        else:
            hint = when
        last = Cell(status[:1].upper() + status[1:], hint,
                    _STATUS_TONE.get(status.lower(), Tone.INFO))
    pct = max(0, min(100, int(snap.coverage_pct)))
    if count == 0:
        coverage = Cell(f"{pct}%", "No threat models yet", Tone.NEUTRAL)
    else:
        hint = ("All threat models have DREAD" if snap.threat_models_with_dread == count
                else f"{snap.threat_models_with_dread}/{count} threat models scored")
        tone = Tone.OK if pct >= 80 else Tone.WARN if pct >= 40 else Tone.CRIT
        coverage = Cell(f"{pct}%", hint, tone)
    return Posture(threat_models, dread, last, coverage)
