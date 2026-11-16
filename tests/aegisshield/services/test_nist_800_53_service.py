"""Tests for the NIST SP 800-53 controls mapping loader."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from aegisshield.core.errors import ValidationError
from aegisshield.services import nist_800_53_service as svc


def test_default_path_is_the_repo_root_file() -> None:
    root = Path(__file__).resolve().parents[3]
    assert svc.DEFAULT_MAPPING_PATH == root / svc.MAPPING_FILENAME
    assert svc.DEFAULT_MAPPING_PATH.is_file()


def test_loads_the_committed_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # The working directory must not matter.
    monkeypatch.chdir(tmp_path)
    mapping = svc.load_controls_mapping()
    assert mapping.framework == "NIST SP 800-53 Rev. 5"
    assert len(mapping.controls) == 7
    assert [f.abbreviation for f in mapping.families] == ["IA", "SC", "SI", "RA", "PM"]
    si11 = mapping.get("si-11")
    assert si11 is not None
    assert si11.control_name == "Error Handling"
    assert si11.family == "System and Information Integrity"
    assert si11.implementation_status == "implemented"
    assert si11.scope == "application"
    assert "aegisshield/jobs/runner.py" in si11.files
    assert mapping.get("ZZ-1") is None


def test_family_counts_match_the_controls() -> None:
    mapping = svc.load_controls_mapping()
    grouped = mapping.controls_by_family()
    for family in mapping.families:
        assert len(grouped[family.abbreviation]) == family.controls_count, family.abbreviation
    assert sum(len(v) for v in grouped.values()) == len(mapping.controls)


def test_missing_file_raises_fixed_message(tmp_path: Path) -> None:
    with pytest.raises(ValidationError) as info:
        svc.load_controls_mapping(tmp_path / "nope.json")
    assert "nope" not in str(info.value)


def test_malformed_json_raises(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValidationError):
        svc.load_controls_mapping(path)


@pytest.mark.parametrize("data", [[], {"controls": "x"}])
def test_wrong_shape_raises(data: object) -> None:
    with pytest.raises(ValidationError):
        svc.parse_controls_mapping(data)


def test_tolerates_partial_records(tmp_path: Path) -> None:
    data = {
        "metadata": "not a dict",
        "controls": [
            "not a dict",
            {"control_name": "No id"},
            {
                "control_id": "XX-1",
                "control_family_abbreviation": "XX",
                "implementation_locations": [{"file": "a.py"}, {"file": 3}, "x"],
                "scope": ["not a string"],
            },
        ],
        "control_families": {"AC": {"name": "Access Control", "controls_count": True}, "BAD": 1},
    }
    path = tmp_path / "m.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    mapping = svc.load_controls_mapping(path)
    assert mapping.framework == ""
    assert [c.control_id for c in mapping.controls] == ["XX-1"]
    assert mapping.controls[0].files == ("a.py",)
    assert mapping.controls[0].scope == ""
    assert mapping.families[0].controls_count == 0
    # A control from a family the summary does not list still gets a group.
    assert mapping.controls_by_family() == {"AC": [], "XX": [mapping.controls[0]]}


def test_no_controls_or_families_is_empty() -> None:
    mapping = svc.parse_controls_mapping({})
    assert mapping.controls == ()
    assert mapping.families == ()
    assert mapping.controls_by_family() == {}


# -- The committed file's evidence must point at code that exists ------------

_ROOT = Path(__file__).resolve().parents[3]
_SCOPES = {"application", "capability"}


def _defined_names(path: Path) -> set[str]:
    """Top-level functions and classes, and ``Class.method`` for their methods."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    names.add(f"{node.name}.{item.name}")
    return names


def _raw_controls() -> list[dict]:
    return json.loads(svc.DEFAULT_MAPPING_PATH.read_text(encoding="utf-8"))["controls"]


def _evidence_problems(controls: list[dict], root: Path) -> list[str]:
    """Every evidence file, symbol, and test path that does not exist under ``root``."""
    problems: list[str] = []
    for control in controls:
        cid = control["control_id"]
        paths = [control["primary_file"], *control.get("tests", [])]
        for location in control["implementation_locations"]:
            path = root / location["file"]
            if not path.is_file():
                problems.append(f"{cid}: missing file {location['file']}")
                continue
            symbols = location.get("symbols", [])
            if symbols and path.suffix != ".py":
                problems.append(f"{cid}: symbols named in non-Python file {location['file']}")
                continue
            defined = _defined_names(path) if symbols else set()
            problems.extend(
                f"{cid}: {location['file']} has no {name}" for name in symbols if name not in defined
            )
        problems.extend(f"{cid}: missing file {p}" for p in paths if not (root / p).is_file())
    return problems


def test_every_evidence_path_and_name_exists() -> None:
    assert _evidence_problems(_raw_controls(), _ROOT) == []


def test_evidence_check_catches_a_renamed_function() -> None:
    controls = _raw_controls()
    controls[0]["implementation_locations"][0]["symbols"].append("no_such_function")
    controls[0]["implementation_locations"].append({"file": "gone.py", "symbols": ["x"]})
    controls[0]["tests"].append("tests/gone_test.py")
    problems = _evidence_problems(controls, _ROOT)
    cid = controls[0]["control_id"]
    assert f"{cid}: {controls[0]['implementation_locations'][0]['file']} has no no_such_function" in problems
    assert f"{cid}: missing file gone.py" in problems
    assert f"{cid}: missing file tests/gone_test.py" in problems


def test_committed_file_is_consistent() -> None:
    data = json.loads(svc.DEFAULT_MAPPING_PATH.read_text(encoding="utf-8"))
    controls = data["controls"]
    families = data["control_families"]
    assert data["metadata"]["total_controls"] == len(controls)
    assert data["metadata"]["control_families"] == len(families)
    assert {c["control_family_abbreviation"] for c in controls} == set(families)
    for control in controls:
        assert control["scope"] in _SCOPES, control["control_id"]
        assert control["implementation_locations"], control["control_id"]
        assert control["evidence"], control["control_id"]
        # Line numbers rot; evidence names functions and classes instead.
        assert "line_references" not in json.dumps(control), control["control_id"]
