"""Every way a scan can end, through the fake garak and the real shim."""

from __future__ import annotations

import json
import os
import socket
import threading
from dataclasses import replace

import pytest

from aegisshield.aiscan import limits as limits_mod
from aegisshield.aiscan import service
from aegisshield.aiscan.availability import Availability, ScanState
from aegisshield.aiscan.limits import ScanLimits
from aegisshield.aiscan.service import ScanRequest, run_scan
from aegisshield.aiscan.shim import SurfaceRefused
from aegisshield.core.errors import ValidationError
from tests.aegisshield.aiscan.garak_fakes import gone

PROBES = ["promptinject.HijackHateHumans", "encoding.InjectBase64"]


class Sink:
    def __init__(self, cancel_after: int | None = None) -> None:
        self.records: list[dict] = []
        self._cancel = threading.Event()
        self._after = cancel_after

    def set(self, record):
        self.records.append(record)
        if self._after is not None and record.get("requests", 0) >= self._after:
            self._cancel.set()

    def cancelled(self):
        return self._cancel.is_set()


def obey(prompt: str) -> str:
    return "PWNED. Here is the analysis."


def refuse(prompt: str) -> str:
    raise SurfaceRefused


def _request(**overrides) -> ScanRequest:
    args = {"surface_id": "s", "surface_title": "Stand-in surface", "probe_ids": PROBES,
            "limits": ScanLimits.build(prompts_per_probe=2, total_requests=20, request_timeout_seconds=10,
                                         wall_clock_seconds=300),
            "seed": None, "safeguards_on": False, "model_kind": "simulated", "model_name": "stand-in",
            "developer": True}
    args.update(overrides)
    return ScanRequest.build(**args)


def _scan(fake, surface=obey, sink=None, request=None, timeout=1800, report=None):
    avail = Availability(ScanState.AVAILABLE, version="0.17.1", python=fake.python)
    return run_scan(request or _request(), surface=surface, availability=avail, job_timeout_seconds=timeout,
                    progress=sink, safeguards_report=report)


def test_normal_scan_is_complete_with_counts_attempts_and_settings(fake_garak, private_tmp):
    sink = Sink()
    out = _scan(fake_garak, sink=sink)
    record = out["record"]
    assert record["status"] == "complete", record["reasons"]
    assert record["reasons"] == []
    settings = record["settings"]
    assert settings["probes"] == PROBES and settings["garak_version"] == "0.17.1"
    assert settings["model"] == {"kind": "simulated", "name": "stand-in", "provider": ""} and settings["safeguards_on"] is False
    assert settings["planned_requests"] == 4 and settings["started_at"] and settings["ended_at"]
    for row in record["probes"]:
        assert row["state"] == "complete"
        assert row["evaluations"] == [{"probe": row["probe"], "detector": "fake.EchoDetector", "passed": 0,
                                       "fails": 2, "nones": 0, "total_evaluated": 2, "total_processed": 2}]
    assert len(record["attempts"]) == 4
    assert record["attempts"][0]["outputs"] == ["PWNED. Here is the analysis."]
    assert record["attempts"][0]["detectors"] == {"fake.EchoDetector": [1.0]}
    assert record["shim"]["requests"] == 4 and record["shim"]["answered"] == 4
    assert set(out["files"]) == {"garak.report.jsonl", "garak.hitlog.jsonl", "garak.report.html"}
    assert sink.records[-1]["requests"] == 4 and sink.records[-1]["request_limit"] == 20
    # Progress records carry counts and probe ids only, never prompt text.
    assert all("PWNED" not in json.dumps(r) for r in sink.records)
    assert private_tmp() == []  # the temporary directory is gone
    json.dumps(record, allow_nan=False)


def test_command_environment_config_and_cleanup(fake_garak, private_tmp, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-visitor-key-must-not-pass-123456")
    out = _scan(fake_garak)
    (call,) = fake_garak.calls()
    argv, env, config = call["argv"], call["env"], call["config"]
    assert argv[:3] == ["-m", "garak", "--config"] and argv[4:] == [
        "--spec", "probes.promptinject.HijackHateHumans,probes.encoding.InjectBase64", "--narrow_output"]
    token = env["REST_API_KEY"]
    assert len(token) >= 40 and [k for k, v in env.items() if token in v] == ["REST_API_KEY"]
    assert not any(token in a for a in argv) and token not in json.dumps(config)
    assert not any("sk-visitor" in v for v in env.values())
    assert not any("sk-visitor" in a for a in argv)
    expected = {"PATH", "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "HF_HUB_OFFLINE",
                "TRANSFORMERS_OFFLINE", "HF_DATASETS_OFFLINE", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy",
                "https_proxy", "NO_PROXY", "no_proxy", "PYTHONDONTWRITEBYTECODE", "REST_API_KEY"}
    assert set(env) - {"__CF_USER_TEXT_ENCODING", "LC_CTYPE"} == expected
    assert call["cwd"].endswith("/home") and env["HOME"] == call["cwd"]
    uri = config["plugins"]["generators"]["rest"]["RestGenerator"]["uri"]
    assert uri.startswith("http://127.0.0.1:") and uri.endswith("/generate")
    assert env["REST_API_KEY"] not in json.dumps(out["record"])
    assert all(env["REST_API_KEY"].encode() not in data for data in out["files"].values())
    port = int(uri.split(":")[2].split("/")[0])
    with pytest.raises(OSError), socket.create_connection(("127.0.0.1", port), timeout=1):
        pass  # the shim's port is released
    assert private_tmp() == []


def test_server_paths_are_replaced_in_downloads(fake_garak, private_tmp):
    out = _scan(fake_garak)
    report = out["files"]["garak.report.jsonl"].decode()
    assert service.SCAN_DIR_PLACEHOLDER in report
    assert str(fake_garak.dir) not in report and "/tmp/" not in report.replace("<scan directory>", "")


def test_refusing_surface_is_shown_as_refused_never_as_passed(fake_garak):
    record = _scan(fake_garak, surface=refuse)["record"]
    assert record["status"] == "complete"
    for row in record["probes"]:
        assert row["state"] == "all_refused" and row["refusals"] == 2
        assert row["evaluations"][0]["fails"] == 0
    (answer,) = record["attempts"][0]["outputs"]
    assert answer.startswith("[AegisShield scan ") and "refused this input" in answer
    assert record["shim"]["refusals"] == 4


def test_failing_surface_makes_the_scan_incomplete(fake_garak):
    def broken(prompt):
        raise RuntimeError("model down")

    record = _scan(fake_garak, surface=broken)["record"]
    assert record["status"] == "incomplete"
    assert {row["state"] for row in record["probes"]} == {"all_failed"}
    assert record["shim"]["failures"] == 4


def test_request_limit_reached_is_incomplete(fake_garak):
    # A probe that sends more prompts than planned runs into the shim's limit.
    fake_garak.configure(mode="overrun")
    record = _scan(fake_garak, request=_request(limits=ScanLimits.build(prompts_per_probe=2, total_requests=5,
                                                                                wall_clock_seconds=300)))[
        "record"]
    assert record["status"] == "incomplete"
    assert any("request limit" in r for r in record["reasons"])
    assert record["shim"]["limit_hits"] == 1 and record["shim"]["requests"] == 5
    states = {row["probe"]: row["state"] for row in record["probes"]}
    assert states == {"promptinject.HijackHateHumans": "complete", "encoding.InjectBase64": "incomplete"}
    row = record["probes"][1]
    assert row["missing_answers"] == 1 and "1 of 3 prompts got no answer" in row["reason"]


def test_slow_scan_is_killed_at_the_wall_clock_limit(fake_garak, private_tmp, monkeypatch):
    fake_garak.configure(mode="slow", sleep=30)
    clock = iter([0.0, 0.0] + [10_000.0] * 1000)
    monkeypatch.setattr(service, "run_garak", _with_clock(service.run_garak, lambda: next(clock)))
    record = _scan(fake_garak)["record"]
    assert record["status"] == "incomplete"
    assert record["settings"]["stopped"] == "time_limit"
    assert any("time limit" in r for r in record["reasons"])
    assert private_tmp() == []


def _with_clock(fn, clock):
    def run(**kwargs):
        return fn(clock=clock, **kwargs)
    return run


def test_cancel_kills_garak_and_marks_the_scan(fake_garak, private_tmp):
    fake_garak.configure(mode="hang")
    sink = Sink()
    timer = threading.Timer(0.5, sink._cancel.set)
    timer.start()
    record = _scan(fake_garak, sink=sink)["record"]
    assert record["status"] == "incomplete"
    assert record["settings"]["stopped"] == "cancelled"
    assert any("cancelled" in r for r in record["reasons"])
    assert private_tmp() == []


def test_wall_clock_is_kept_below_the_job_timeout(fake_garak):
    record = _scan(fake_garak, timeout=300)["record"]
    assert record["settings"]["limits"]["wall_clock_seconds"] == 300 - service.JOB_TIMEOUT_MARGIN_SECONDS


def test_a_child_garak_leaves_behind_is_killed_with_its_group(fake_garak):
    fake_garak.configure(mode="orphan")
    record = _scan(fake_garak)["record"]
    assert record["status"] == "complete", record["reasons"]
    assert gone(int((fake_garak.dir / "child.pid").read_text()))


def test_crash_is_failed(fake_garak):
    fake_garak.configure(mode="crash")
    record = _scan(fake_garak)["record"]
    assert record["status"] == "failed"
    assert "exit code 3" in record["reasons"][0]


def test_crash_after_completion_is_incomplete(fake_garak):
    fake_garak.configure(exit=2)
    record = _scan(fake_garak)["record"]
    assert record["status"] == "incomplete"
    assert any("exited with code 2" in r for r in record["reasons"])


def test_no_report_is_failed(fake_garak):
    fake_garak.configure(mode="no_report")
    out = _scan(fake_garak)
    assert out["record"]["status"] == "failed"
    assert out["record"]["reasons"] == ["garak wrote no report."]
    assert out["files"] == {}


def test_truncated_report_is_not_complete(fake_garak):
    fake_garak.configure(mode="truncated")
    record = _scan(fake_garak)["record"]
    assert record["status"] == "incomplete"
    assert any("no completion entry" in r for r in record["reasons"])


def test_missing_probe_is_incomplete(fake_garak):
    fake_garak.configure(mode="missing_probe")
    record = _scan(fake_garak)["record"]
    assert record["status"] == "incomplete"
    states = {row["probe"]: row["state"] for row in record["probes"]}
    assert states == {"promptinject.HijackHateHumans": "complete", "encoding.InjectBase64": "not_run"}


def test_probe_without_evaluations_is_incomplete(fake_garak):
    fake_garak.configure(mode="no_eval")
    record = _scan(fake_garak)["record"]
    assert record["status"] == "incomplete"
    assert {row["state"] for row in record["probes"]} == {"not_evaluated"}


def test_oversize_line_is_skipped_and_reported(fake_garak):
    fake_garak.configure(mode="oversize")
    record = _scan(fake_garak)["record"]
    assert record["status"] == "incomplete"
    assert record["report"]["oversize_lines"] == 1
    assert any("could not be read" in r for r in record["reasons"])


def test_garak_that_cannot_start_is_failed(fake_garak, tmp_path):
    avail = Availability(ScanState.AVAILABLE, version="0.17.1", python=str(tmp_path / "gone" / "python"))
    record = run_scan(_request(), surface=obey, availability=avail, job_timeout_seconds=1800)["record"]
    assert record["status"] == "failed" and record["reasons"] == ["garak could not be started."]


def test_an_executable_that_cannot_be_run_is_failed(fake_garak, tmp_path):
    """It passes the pre-start check but exec fails: the scan is failed.

    Started directly, the failed exec is reported at once ("could not be
    started"). Under a real ``prlimit`` (Linux) the wrapper itself starts and
    the exec inside it fails, so what the app can see is a process that
    exited without a report; that reason is the honest one there.
    """
    python = tmp_path / "python"
    python.write_text("#!/no/such/interpreter\n")
    python.chmod(0o755)
    avail = Availability(ScanState.AVAILABLE, version="0.17.1", python=str(python))
    record = run_scan(_request(), surface=obey, availability=avail, job_timeout_seconds=1800)["record"]
    assert record["status"] == "failed"
    assert record["reasons"] in (["garak could not be started."], ["garak wrote no report."])


@pytest.mark.parametrize("make", ["missing", "not_executable", "directory"])
def test_garak_that_cannot_start_under_prlimit_is_failed(fake_garak, tmp_path, monkeypatch, make):
    """On Linux ``prlimit`` can start while the interpreter it runs cannot,
    which would read as "garak wrote no report." The interpreter is checked
    before anything starts, so the reason is the same on every platform."""
    from aegisshield.aiscan import garak_run

    prlimit = tmp_path / "prlimit"
    prlimit.write_text('#!/bin/sh\nshift\nshift\nexec "$@"\n')
    prlimit.chmod(0o755)
    monkeypatch.setattr(garak_run.sys, "platform", "linux")
    monkeypatch.setattr(garak_run.shutil, "which", lambda name: str(prlimit) if name == "prlimit" else None)
    python = tmp_path / "python"
    if make == "not_executable":
        python.write_text("#!/bin/sh\n")
        python.chmod(0o644)
    elif make == "directory":
        python.mkdir()
    avail = Availability(ScanState.AVAILABLE, version="0.17.1", python=str(python))
    record = run_scan(_request(), surface=obey, availability=avail, job_timeout_seconds=1800)["record"]
    assert record["status"] == "failed" and record["reasons"] == ["garak could not be started."]


def test_unavailable_scans_raise_a_fixed_sentence():
    with pytest.raises(ValidationError, match="not available"):
        run_scan(_request(), surface=obey, availability=Availability(ScanState.OFF), job_timeout_seconds=1800)


def test_request_validation():
    with pytest.raises(ValidationError):
        _request(model_kind="other")
    with pytest.raises(ValidationError):
        _request(probe_ids=["dan.DanInTheWild"])
    with pytest.raises(ValidationError):
        _request(limits=ScanLimits.build(prompts_per_probe=20, total_requests=10))


def test_keyless_scans_have_lower_hard_maximums(fake_garak):
    for kind in ("simulated", "mock"):
        for limits in (ScanLimits.build(total_requests=61), ScanLimits.build(wall_clock_seconds=301)):
            with pytest.raises(ValidationError, match="Without a model key"):
                _request(model_kind=kind, limits=limits)
        assert _request(model_kind=kind, limits=ScanLimits.build(total_requests=60, wall_clock_seconds=300))
    real = _request(model_kind="real", limits=ScanLimits.build(total_requests=300, wall_clock_seconds=1500))
    assert real.limits.wall_clock_seconds == 1500
    # A request made without ``build`` is checked again when it runs.
    sneaked = replace(real, model_kind="simulated")
    with pytest.raises(ValidationError, match="Without a model key"):
        _scan(fake_garak, request=sneaked)
    assert fake_garak.calls() == []
    assert limits_mod.ERROR_KEYLESS in service.JOB_ERRORS


def test_stored_strings_are_redacted_and_capped(fake_garak, monkeypatch):
    monkeypatch.setattr(service, "MAX_STORED_TEXT_CHARS", 30)
    record = _scan(fake_garak, surface=lambda p: "sk-proj-abcdefghijklmnopqrstuvwxyz " + "x" * 100)["record"]
    answer = record["attempts"][0]["outputs"][0]
    assert answer.startswith("[redacted]") and len(answer) <= 30
    assert record["caps"]["texts_clipped"] > 0


def test_attempt_caps(fake_garak, monkeypatch):
    monkeypatch.setattr(service, "MAX_ATTEMPTS_PER_PROBE", 1)
    record = _scan(fake_garak)["record"]
    assert record["caps"]["attempts_in_report"] == 4 and record["caps"]["attempts_stored"] == 2
    monkeypatch.setattr(service, "MAX_STORED_ATTEMPTS", 1)
    assert len(_scan(fake_garak)["record"]["attempts"]) == 1


def test_safeguards_report_is_recorded_and_its_failure_tolerated(fake_garak):
    assert _scan(fake_garak, report=lambda: {"checks": 3})["record"]["safeguards"] == {"checks": 3}

    def broken():
        raise RuntimeError("x")

    assert _scan(fake_garak, report=broken)["record"]["safeguards"] is None


@pytest.mark.parametrize("summary,words", [
    (None, "no record of what they did"),
    ({"status": "unavailable", "not_checked": 0}, "did not run as on (status: unavailable)"),
    ({"status": "on", "not_checked": 2}, "2 safeguard checks could not run"),
])
def test_safeguards_chosen_on_that_did_not_all_run_make_the_scan_incomplete(fake_garak, summary, words):
    record = _scan(fake_garak, request=_request(safeguards_on=True), report=lambda: summary)["record"]
    assert record["status"] == "incomplete"
    assert any(words in r for r in record["reasons"])
    ok = _scan(fake_garak, request=_request(safeguards_on=True),
               report=lambda: {"status": "on", "not_checked": 0})["record"]
    assert ok["status"] == "complete"


def test_downloads_are_scrubbed_in_pieces_that_never_split_a_path_or_the_token():
    from aegisshield.aiscan.garak_run import GarakFiles, GarakRun

    token = "T" * 43
    line = f'{{"a": "/srv/scan-dir/report/x", "b": "Bearer {token}", "c": "/opt/genv/lib/garak"}}\n'
    data = (line * 3000).encode()  # far more than one piece
    run = GarakRun(True, 0, None, 1.0, GarakFiles(report=data, html=b"<p>" + data + b"</p>"))
    files = service.downloadable_files(run, token=token, workdir="/srv/scan-dir", python="/opt/genv/bin/python")
    for blob in files.values():
        text = blob.decode()
        assert token not in text and "/srv/scan-dir" not in text and "/opt/genv" not in text
        assert text.count(service.SCAN_DIR_PLACEHOLDER) == 3000
        assert text.count(service.GARAK_ENV_PLACEHOLDER) == 3000
    pieces = service._pieces("x" * (service.SCRUB_PIECE_CHARS * 2 + 5))
    assert [len(p) for p in pieces] == [service.SCRUB_PIECE_CHARS, service.SCRUB_PIECE_CHARS, 5]


def test_scrubbing_the_largest_download_does_not_stall_other_threads():
    from aegisshield.aiscan.garak_run import GarakFiles, GarakRun
    from aegisshield.aiscan.report import MAX_REPORT_BYTES
    from tests.aegisshield.stall import STALL_LIMIT_S, least_stall

    data = (b'{"x": "sk-' + b"a" * 40 + b' /srv/scan-dir"}\n') * (MAX_REPORT_BYTES // 64)
    run = GarakRun(True, 0, None, 1.0, GarakFiles(report=data[:MAX_REPORT_BYTES]))
    measured = least_stall(service.downloadable_files, run, token="t" * 43, workdir="/srv/scan-dir",
                           python="/opt/genv/bin/python", repeats=1)
    assert measured.stall < STALL_LIMIT_S


def test_progress_step_counts_the_probes_garak_has_started():
    from aegisshield.aiscan.garak_run import ReportTail

    sink = Sink()
    live = service._Progress(sink, _request(), planned=4)
    tail = ReportTail("/nonexistent")
    tail.current, tail.probes_seen = "encoding.InjectBase64", ["encoding.InjectBase64"]
    live.on_poll(tail)
    assert sink.records[-1]["step"] == 1 and sink.records[-1]["current"] == "encoding.InjectBase64"
    tail.current = "dan.Other"
    live.on_poll(tail)
    assert len(sink.records) == 2


def _record_waitable(monkeypatch) -> list[bool]:
    """Patch ``os.killpg`` to note whether the group leader was still
    unreaped (so its id still reserved) when its group was signalled."""
    from aegisshield.aiscan import garak_run

    seen: list[bool] = []
    real = os.killpg

    def killpg(pid: int, sig: int) -> None:
        try:
            os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
            seen.append(True)
        except ChildProcessError:
            seen.append(False)
        real(pid, sig)

    monkeypatch.setattr(garak_run.os, "killpg", killpg)
    return seen


@pytest.mark.skipif(not hasattr(os, "waitid"), reason="os.waitid is not on this platform")
def test_garak_is_reaped_only_after_its_group_is_signalled(fake_garak, monkeypatch):
    """Signalling the group after reaping garak left a window in which its id
    could be reused by another scan's garak, which leads its own group."""
    seen = _record_waitable(monkeypatch)
    assert _scan(fake_garak)["record"]["status"] == "complete"
    assert seen == [True]


@pytest.mark.skipif(not hasattr(os, "waitid"), reason="os.waitid is not on this platform")
@pytest.mark.parametrize("child", [None, "devnull"])
def test_the_version_question_is_reaped_only_after_its_group_is_signalled(fake_garak, monkeypatch, child):
    from aegisshield.aiscan.availability import garak_version

    if child:
        fake_garak.configure(version_child=child)
    seen = _record_waitable(monkeypatch)
    assert garak_version(fake_garak.python) == "0.17.1"
    assert seen == [True]


def test_without_waitid_exit_is_read_by_polling(fake_garak, monkeypatch):
    """Where the platform has no ``os.waitid`` the earlier behavior stays."""
    from aegisshield.aiscan import garak_run
    from aegisshield.aiscan.availability import garak_version

    monkeypatch.delattr(garak_run.os, "waitid", raising=False)
    assert _scan(fake_garak)["record"]["status"] == "complete"
    assert garak_version(fake_garak.python) == "0.17.1"
