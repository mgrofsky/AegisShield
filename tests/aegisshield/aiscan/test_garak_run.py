"""The garak command line, environment, and configuration are fixed, and the
configuration can only ever point at the loopback shim."""

from __future__ import annotations

import json
import os
import sys

import pytest

from aegisshield.aiscan import garak_run
from aegisshield.aiscan.garak_run import (
    ReportTail,
    build_command,
    build_config,
    build_env,
    shim_uri,
)
from aegisshield.aiscan.limits import ScanLimits
from aegisshield.core.errors import ValidationError


def test_uri_is_loopback_and_only_the_port_varies():
    assert shim_uri(8080) == "http://127.0.0.1:8080/generate"
    for bad in (0, 65536, -1, "8080", "1@evil.example", 80.0, True, None):
        with pytest.raises(ValueError):
            shim_uri(bad)  # type: ignore[arg-type]


def test_config_points_only_at_the_shim():
    config = build_config(port=4321, limits=ScanLimits.build(request_timeout_seconds=30), report_dir="/r", seed=5)
    text = json.dumps(config)
    rest = config["plugins"]["generators"]["rest"]["RestGenerator"]  # type: ignore[index]
    assert rest["uri"] == "http://127.0.0.1:4321/generate"
    assert text.count("http") == 1  # no other address anywhere in the file
    assert rest["headers"]["Authorization"] == "Bearer $KEY"
    assert rest["request_timeout"] == 30 + garak_run.REQUEST_TIMEOUT_MARGIN_SECONDS
    assert rest["skip_codes"] == [429] and rest["ratelimit_codes"] == []
    assert config["run"] == {"generations": 1, "soft_probe_prompt_cap": 5, "seed": 5}
    assert "seed" not in build_config(port=1, limits=ScanLimits(), report_dir="/r", seed=None)["run"]


def test_no_code_path_builds_a_config_with_another_address(monkeypatch):
    # The configuration takes the shim's port and nothing else that ends up
    # in an address; every keyword it accepts is listed here.
    import inspect

    params = set(inspect.signature(build_config).parameters)
    assert params == {"port", "limits", "report_dir", "seed"}
    with pytest.raises(ValueError):
        build_config(port="99@169.254.169.254", limits=ScanLimits(), report_dir="/r", seed=None)  # type: ignore[arg-type]


def test_command_is_a_fixed_argument_list():
    cmd = build_command("/opt/g/bin/python", "/tmp/x/run.yaml", ["encoding.InjectBase64",
                                                                "promptinject.HijackHateHumans"])
    assert cmd == ["/opt/g/bin/python", "-m", "garak", "--config", "/tmp/x/run.yaml", "--spec",
                   "probes.promptinject.HijackHateHumans,probes.encoding.InjectBase64", "--narrow_output"]
    with pytest.raises(ValidationError):
        build_command("/opt/g/bin/python", "/tmp/x/run.yaml", ["encoding.InjectBase64,dan.Dan"])


def test_environment_is_minimal_and_holds_the_token_only_in_rest_api_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-should-not-pass-0123456789")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "nope")
    env = build_env("/tmp/home", "tok123")
    assert "OPENAI_API_KEY" not in env and "AWS_SECRET_ACCESS_KEY" not in env
    assert [k for k, v in env.items() if "tok123" in v] == ["REST_API_KEY"]
    assert env["HOME"] == "/tmp/home"
    for name in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
        assert env[name].startswith("/tmp/home/")
    assert env["HF_HUB_OFFLINE"] == env["TRANSFORMERS_OFFLINE"] == env["HF_DATASETS_OFFLINE"] == "1"
    assert env["HTTPS_PROXY"] == garak_run.DEAD_PROXY and env["NO_PROXY"] == "127.0.0.1"


def test_prlimit_wraps_on_linux_only(monkeypatch):
    monkeypatch.setattr(garak_run.shutil, "which", lambda name: "/usr/bin/prlimit")
    monkeypatch.setattr(garak_run.sys, "platform", "linux")
    assert garak_run._limited(["p"]) == ["/usr/bin/prlimit", f"--cpu={garak_run.GARAK_CPU_SECONDS}", "--", "p"]
    monkeypatch.setattr(garak_run.sys, "platform", "darwin")
    assert garak_run._limited(["p"]) == ["p"]


def test_config_file_is_private(tmp_path):
    path = garak_run.write_config(str(tmp_path), {"a": 1})
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"


def test_report_tail_names_the_probe_running(tmp_path):
    path = tmp_path / "r.jsonl"
    tail = ReportTail(str(path))
    tail.poll()  # no file yet
    assert tail.current is None
    attempt = {"entry_type": "attempt", "probe_classname": "encoding.InjectBase64"}
    path.write_text(json.dumps({"entry_type": "init"}) + "\n" + json.dumps(attempt) + "\n" + '{"entry_type": "att')
    tail.poll()
    assert tail.current == "encoding.InjectBase64"
    with path.open("a") as fh:
        fh.write('empt", "probe_classname": "promptinject.HijackHateHumans"}\nnot json "attempt"\n')
    tail.poll()
    assert tail.current == "promptinject.HijackHateHumans"
    assert tail.probes_seen == ["encoding.InjectBase64", "promptinject.HijackHateHumans"]


def test_report_tail_skips_a_line_longer_than_it_reads(tmp_path, monkeypatch):
    monkeypatch.setattr(garak_run, "MAX_LINE_BYTES", 10)
    path = tmp_path / "r.jsonl"
    path.write_text("x" * 100)
    tail = ReportTail(str(path))
    tail.poll()
    assert tail._offset == 40


def test_report_tail_skips_lines_it_cannot_read(tmp_path):
    path = tmp_path / "r.jsonl"
    lines = [
        '{"entry_type": "attempt", "seq": ' + "9" * 5000 + "}",  # past Python's integer digit limit
        '["attempt"]',  # valid JSON, not an object
        '"attempt"',
        json.dumps({"entry_type": "attempt", "probe_classname": "encoding.InjectBase64"}),
    ]
    path.write_text("\n".join(lines) + "\n")
    tail = ReportTail(str(path))
    tail.poll()
    assert tail.current == "encoding.InjectBase64" and tail.probes_seen == ["encoding.InjectBase64"]


def test_runnable_reads_a_bare_name_from_path(tmp_path) -> None:
    """A bare interpreter name is looked up on PATH; a path must be an
    executable file."""
    assert garak_run._runnable("sh")
    assert not garak_run._runnable("no-such-garak-python-here")
    assert not garak_run._runnable(str(tmp_path))
    assert not garak_run._runnable(str(tmp_path / "missing"))


def test_a_zombie_reads_as_gone_on_linux_only() -> None:
    """A killed child nobody reaps stays a zombie and still answers signal 0;
    on Linux its state in /proc says it is dead. Read with a fake /proc."""
    from tests.aegisshield.aiscan.garak_fakes import alive

    me = os.getpid()
    zombie = lambda pid: f"{pid} (odd ) name) Z 1 1 1 0 -1"  # noqa: E731
    running = lambda pid: f"{pid} (python) S 1 1 1 0 -1"  # noqa: E731
    assert not alive(me, platform="linux", read_stat=zombie)
    assert not alive(me, platform="linux", read_stat=lambda pid: f"{pid} (x) X 1")
    assert alive(me, platform="linux", read_stat=running)
    assert alive(me, platform="linux", read_stat=lambda pid: None)
    assert alive(me, platform="linux", read_stat=lambda pid: "garbled")
    assert alive(me, platform="darwin", read_stat=zombie)
    if sys.platform.startswith("linux"):  # pragma: no cover - the real /proc
        assert alive(me)
