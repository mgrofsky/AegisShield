"""Load the repo's NIST SP 800-53 Rev. 5 controls mapping.

``nist-sp-800-53-controls-mapping.json`` at the repo root (described in
``NIST-SP-800-53-CONTROLS.md``) records where the app's code lines up with an
800-53 control, with the files and functions that carry each one. It is the
maintainers' own description of this application, not an assessment, and not
a threat-to-control mapping: it has no STRIDE categories or threat fields, so
this module only loads it into typed records and groups them by family.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegisshield.core.errors import ValidationError

MAPPING_FILENAME = "nist-sp-800-53-controls-mapping.json"
# Located from this file (aegisshield/services/), never from the working directory.
DEFAULT_MAPPING_PATH = Path(__file__).resolve().parents[2] / MAPPING_FILENAME

_BAD_FILE = "The NIST SP 800-53 controls mapping could not be read."


@dataclass(frozen=True)
class Control:
    """One control and where the app's code carries it.

    ``scope`` is "application" for a safeguard in the app itself, or
    "capability" for a feature that helps a user's organization with its own
    work on the control.
    """

    control_id: str
    control_name: str
    family: str
    family_abbreviation: str
    implementation_status: str
    scope: str
    description: str
    primary_file: str
    files: tuple[str, ...]


@dataclass(frozen=True)
class ControlFamily:
    """A control family as the file summarizes it."""

    abbreviation: str
    name: str
    controls_count: int


@dataclass(frozen=True)
class ControlsMapping:
    """The whole file: framework, version, controls, and families."""

    framework: str
    version: str
    generated_date: str
    controls: tuple[Control, ...]
    families: tuple[ControlFamily, ...]

    def controls_by_family(self) -> dict[str, list[Control]]:
        """Controls grouped by family abbreviation, families in file order."""
        out: dict[str, list[Control]] = {f.abbreviation: [] for f in self.families}
        for control in self.controls:
            out.setdefault(control.family_abbreviation, []).append(control)
        return out

    def get(self, control_id: str) -> Control | None:
        """The control with ``control_id`` (for example ``"AC-3"``), or None."""
        wanted = control_id.strip().upper()
        return next((c for c in self.controls if c.control_id.upper() == wanted), None)


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _control(raw: dict[str, Any]) -> Control:
    locations = raw.get("implementation_locations")
    files = tuple(
        loc["file"]
        for loc in (locations if isinstance(locations, list) else [])
        if isinstance(loc, dict) and isinstance(loc.get("file"), str)
    )
    return Control(
        control_id=_text(raw.get("control_id")),
        control_name=_text(raw.get("control_name")),
        family=_text(raw.get("control_family")),
        family_abbreviation=_text(raw.get("control_family_abbreviation")),
        implementation_status=_text(raw.get("implementation_status")),
        scope=_text(raw.get("scope")),
        description=_text(raw.get("description")),
        primary_file=_text(raw.get("primary_file")),
        files=files,
    )


def parse_controls_mapping(data: object) -> ControlsMapping:
    """Build a ``ControlsMapping`` from the file's JSON values.

    Controls without a ``control_id`` are skipped. Raises ``ValidationError``
    when the top level or ``controls`` has the wrong type.
    """
    if not isinstance(data, dict) or not isinstance(data.get("controls", []), list):
        raise ValidationError(_BAD_FILE)
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    controls = tuple(
        _control(raw)
        for raw in data.get("controls", [])
        if isinstance(raw, dict) and _text(raw.get("control_id"))
    )
    raw_families = data.get("control_families")
    families = tuple(
        ControlFamily(
            abbreviation=abbr,
            name=_text(fam.get("name")),
            controls_count=_int(fam.get("controls_count")),
        )
        for abbr, fam in (raw_families.items() if isinstance(raw_families, dict) else [])
        if isinstance(fam, dict)
    )
    return ControlsMapping(
        framework=_text(meta.get("framework")),
        version=_text(meta.get("version")),
        generated_date=_text(meta.get("generated_date")),
        controls=controls,
        families=families,
    )


def load_controls_mapping(path: Path | None = None) -> ControlsMapping:
    """Read and parse the mapping file (default: the one at the repo root).

    Raises ``ValidationError`` with a fixed message when the file is
    missing, is not JSON, or has the wrong shape.
    """
    target = path or DEFAULT_MAPPING_PATH
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValidationError(_BAD_FILE) from None
    return parse_controls_mapping(data)
