"""Scans exist only when the operator turns them on and garak is found."""

from __future__ import annotations

import subprocess
import time

from aegisshield.aiscan import availability
from aegisshield.aiscan.availability import ScanState, garak_version, scan_availability
from aegisshield.config import get_settings
from tests.aegisshield.aiscan.garak_fakes import gone


def _settings(python: str | None, on: bool = True):
    env = {"AEGIS_AI_SCAN": "1" if on else ""}
    if python:
        env["AEGIS_GARAK_PYTHON"] = python
    return get_settings(env)


def test_off_by_default(fake_garak):
    assert scan_availability(get_settings({})).state is ScanState.OFF
    assert scan_availability(_settings(fake_garak.python, on=False)).state is ScanState.OFF
    assert fake_garak.calls() == []


def test_on_without_interpreter_is_not_found():
    got = scan_availability(_settings(None))
    assert got.state is ScanState.NOT_FOUND and not got.available


def test_found_reports_version_and_caches_it(fake_garak, monkeypatch):
    got = scan_availability(_settings(fake_garak.python))
    assert got.available and got.version == "0.17.1" and got.python == fake_garak.python
    calls = []
    real_run = subprocess.run
    monkeypatch.setattr(availability.subprocess, "run", lambda *a, **k: calls.append(a) or real_run(*a, **k))
    assert garak_version(fake_garak.python) == "0.17.1"
    assert calls == []  # asked once per process


def test_version_question_is_a_fixed_command(fake_garak, monkeypatch):
    """Its time limit is tested by ``test_a_child_holding_the_output_open_times_out_and_is_killed``."""
    seen = {}
    real_popen = subprocess.Popen

    def spy(command, **kwargs):
        seen.update(command=command, **kwargs)
        return real_popen(command, **kwargs)

    monkeypatch.setattr(availability.subprocess, "Popen", spy)
    assert garak_version(fake_garak.python) == "0.17.1"
    assert seen["command"][:3] == [fake_garak.python, "-I", "-c"]
    assert set(seen["env"]) == {"PATH"} and seen["start_new_session"] is True


def test_a_child_the_version_question_leaves_is_killed(fake_garak):
    fake_garak.configure(version_child="devnull")
    assert garak_version(fake_garak.python) == "0.17.1"
    assert gone(int((fake_garak.dir / "child.pid").read_text()))


def test_a_child_holding_the_output_open_times_out_and_is_killed(fake_garak, monkeypatch):
    monkeypatch.setattr(availability, "VERSION_TIMEOUT_SECONDS", 1)
    fake_garak.configure(version_child="pipe")
    start = time.monotonic()
    assert garak_version(fake_garak.python) is None
    assert time.monotonic() - start < 5
    assert gone(int((fake_garak.dir / "child.pid").read_text()))


def test_garak_missing_from_that_environment_is_not_found(fake_garak):
    fake_garak.configure(version=None)
    assert scan_availability(_settings(fake_garak.python)).state is ScanState.NOT_FOUND


def test_garbage_version_is_not_found(fake_garak):
    fake_garak.configure(version="<script>alert(1)</script>")
    assert scan_availability(_settings(fake_garak.python)).state is ScanState.NOT_FOUND


def test_relative_missing_or_non_executable_paths_are_not_found(tmp_path, fake_garak):
    plain = tmp_path / "plain"
    plain.write_text("")
    for path in ("python3", str(tmp_path / "nope"), str(plain)):
        assert scan_availability(_settings(path)).state is ScanState.NOT_FOUND


def test_timeout_and_os_errors_are_not_found(fake_garak, monkeypatch):
    def boom(*_a, **_k):
        raise OSError("cannot start")

    monkeypatch.setattr(availability.subprocess, "Popen", boom)
    assert garak_version(fake_garak.python) is None
