"""Run garak as a subprocess against the scan's shim.

- The command is a fixed argument list (no shell): the operator's garak
  interpreter, ``-m garak``, the configuration file this module wrote, the
  probe spec built only from ids checked against ``probes.PROBES``, and
  ``--narrow_output``.
- The configuration points garak's REST generator at
  ``http://127.0.0.1:<port>/generate`` and nowhere else; the only value
  that varies in that address is the shim's port, an integer.
- The environment is minimal: ``PATH``, ``HOME`` and the three ``XDG_*_HOME``
  variables inside the scan's private temporary directory, the offline flags
  (``HF_HUB_OFFLINE``, ``TRANSFORMERS_OFFLINE``, ``HF_DATASETS_OFFLINE``), a
  proxy setting that points every outside address at a closed loopback port
  (so a probe that tries to download fails at once instead of reaching the
  network), and the shim's bearer token in ``REST_API_KEY`` and nowhere else.
  The visitor's model key never reaches the subprocess.
- The working directory is the temporary directory. garak runs in its own
  process group, so a stop kills garak and anything it started.
- On Linux with ``prlimit`` on PATH, garak runs under a CPU-time limit (see
  ``GARAK_CPU_SECONDS``).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from aegisshield.aiscan.limits import ScanLimits
from aegisshield.aiscan.probes import check_probe_ids
from aegisshield.aiscan.report import MAX_LINE_BYTES, MAX_REPORT_BYTES
from aegisshield.aiscan.shim import LIMIT_STATUS, LOOPBACK, ROUTE

logger = logging.getLogger(__name__)

REPORT_PREFIX = "garak"
CONFIG_NAME = "run.yaml"
LOG_NAME = "garak.out"
# garak waits this much longer than the shim for each answer, so the shim's
# fixed timeout answer always arrives first and garak never gives up on a
# request the shim is still answering.
REQUEST_TIMEOUT_MARGIN_SECONDS = 15
POLL_SECONDS = 0.2
# A closed port on the loopback address: every proxied request fails at once.
DEAD_PROXY = "http://127.0.0.1:9"
# Each of the other files garak writes (hit log, HTML summary) is kept for
# download up to this size.
MAX_EXTRA_FILE_BYTES = 8 * 1024 * 1024
# CPU seconds garak may use, under prlimit on Linux. A scan spends nearly all
# its time waiting on the shim; this only stops a runaway process, so it is
# the longest a scan may run at all.
GARAK_CPU_SECONDS = 1500

ERROR_PORT = "The shim's port must be a whole number from 1 to 65535."


@dataclass(frozen=True)
class GarakFiles:
    """What garak wrote, read back with size limits."""

    report: bytes | None = None
    report_truncated: bool = False
    hitlog: bytes | None = None
    html: bytes | None = None


@dataclass(frozen=True)
class GarakRun:
    """How the garak process ended, and what it wrote."""

    started: bool
    exit_code: int | None
    stopped: str | None  # "time_limit", "cancelled", or None
    seconds: float
    files: GarakFiles = field(default_factory=GarakFiles)


def shim_uri(port: int) -> str:
    """The only address garak is ever given: the shim on the loopback address."""
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        raise ValueError(ERROR_PORT)
    return f"http://{LOOPBACK}:{port}{ROUTE}"


def build_config(*, port: int, limits: ScanLimits, report_dir: str, seed: int | None) -> dict[str, object]:
    """garak's run configuration as plain values (written as JSON, which YAML reads)."""
    run: dict[str, object] = {
        "generations": limits.generations,
        "soft_probe_prompt_cap": limits.prompts_per_probe,
    }
    if seed is not None:
        run["seed"] = seed
    return {
        "system": {"parallel_attempts": 1, "parallel_requests": False, "lite": True},
        "run": run,
        "plugins": {
            "target_type": "rest",
            "generators": {"rest": {"RestGenerator": {
                "uri": shim_uri(port),
                "method": "post",
                # garak puts REST_API_KEY in place of $KEY.
                "headers": {"Authorization": "Bearer $KEY", "Content-Type": "application/json"},
                "req_template_json_object": {"prompt": "$INPUT"},
                "response_json": True,
                "response_json_field": "text",
                "request_timeout": limits.request_timeout_seconds + REQUEST_TIMEOUT_MARGIN_SECONDS,
                # Past the request limit the shim answers LIMIT_STATUS; garak
                # records no answer and goes on, instead of backing off.
                "ratelimit_codes": [],
                "skip_codes": [LIMIT_STATUS],
                "verify_ssl": True,
            }}},
        },
        "reporting": {"report_dir": report_dir, "report_prefix": REPORT_PREFIX},
    }


def build_command(python: str, config_path: str, probe_ids: Sequence[str]) -> list[str]:
    """The fixed argument list. Probe ids are checked against the list again here."""
    spec = ",".join(f"probes.{pid}" for pid in check_probe_ids(probe_ids))
    return [python, "-m", "garak", "--config", config_path, "--spec", spec, "--narrow_output"]


def build_env(home: str, token: str) -> dict[str, str]:
    """The subprocess environment: nothing from this process but ``PATH``."""
    return {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": home,
        "XDG_CONFIG_HOME": os.path.join(home, "config"),
        "XDG_DATA_HOME": os.path.join(home, "data"),
        "XDG_CACHE_HOME": os.path.join(home, "cache"),
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_DATASETS_OFFLINE": "1",
        "HTTP_PROXY": DEAD_PROXY,
        "HTTPS_PROXY": DEAD_PROXY,
        "http_proxy": DEAD_PROXY,
        "https_proxy": DEAD_PROXY,
        "NO_PROXY": LOOPBACK,
        "no_proxy": LOOPBACK,
        "PYTHONDONTWRITEBYTECODE": "1",
        "REST_API_KEY": token,
    }


def _runnable(python: str) -> bool:
    """True when ``python`` names an executable file (a bare name: one on PATH).

    Checked before starting, because under ``prlimit`` a missing interpreter
    would start ``prlimit`` and then exit with no report, which would read as
    garak running and writing nothing rather than not starting.
    """
    path = python if os.sep in python else shutil.which(python)
    return path is not None and os.path.isfile(path) and os.access(path, os.X_OK)


def _limited(command: list[str]) -> list[str]:
    """``command`` under ``prlimit --cpu`` on Linux when ``prlimit`` is on PATH."""
    prlimit = shutil.which("prlimit") if sys.platform.startswith("linux") else None
    if prlimit is None:
        return command
    return [prlimit, f"--cpu={GARAK_CPU_SECONDS}", "--", *command]


def write_config(directory: str, config: dict[str, object]) -> str:
    """Write the configuration file (mode 0600) and return its path."""
    path = os.path.join(directory, CONFIG_NAME)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2)
    return path


def _read_capped(path: str, limit: int) -> tuple[bytes | None, bool]:
    """Up to ``limit`` bytes of ``path``, and whether there was more."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
    except OSError:
        return None, False
    return data[:limit], len(data) > limit


def read_files(report_dir: str) -> GarakFiles:
    """The report, hit log, and HTML summary garak wrote, each size-capped."""
    report, cut = _read_capped(os.path.join(report_dir, f"{REPORT_PREFIX}.report.jsonl"), MAX_REPORT_BYTES)
    hitlog, _ = _read_capped(os.path.join(report_dir, f"{REPORT_PREFIX}.hitlog.jsonl"), MAX_EXTRA_FILE_BYTES)
    html, _ = _read_capped(os.path.join(report_dir, f"{REPORT_PREFIX}.report.html"), MAX_EXTRA_FILE_BYTES)
    return GarakFiles(report=report, report_truncated=cut, hitlog=hitlog, html=html)


class ReportTail:
    """Follows the report while garak writes it, to name the probe running.

    Reads only whole new lines, each up to the parser's line limit, and only
    the ``probe_classname`` of attempt entries.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._offset = 0
        self.current: str | None = None
        self.probes_seen: list[str] = []

    def poll(self) -> None:
        """Read what garak appended since the last poll."""
        try:
            with open(self._path, "rb") as fh:
                fh.seek(self._offset)
                chunk = fh.read(4 * MAX_LINE_BYTES)
        except OSError:
            return
        end = chunk.rfind(b"\n")
        if end < 0:
            if len(chunk) >= 4 * MAX_LINE_BYTES:
                self._offset += len(chunk)  # one line longer than any we read; skip it
            return
        self._offset += end + 1
        for line in chunk[: end + 1].splitlines():
            if b'"attempt"' not in line or len(line) > MAX_LINE_BYTES:
                continue
            try:
                entry = json.loads(line.decode("utf-8"))
            # ValueError covers bad JSON, bad UTF-8, and an integer longer
            # than Python's digit limit.
            except (ValueError, RecursionError):
                continue
            if not isinstance(entry, dict):
                continue
            name = entry.get("probe_classname")
            if entry.get("entry_type") == "attempt" and isinstance(name, str) and len(name) <= 200:
                self.current = name
                if name not in self.probes_seen:
                    self.probes_seen.append(name)


def exited(proc: subprocess.Popen[bytes]) -> bool:
    """True once ``proc`` has exited, without reaping it where the platform
    has ``os.waitid``: until it is reaped its id cannot be reused, so the
    group it leads can be signalled safely (``kill_group``) and then reaped.
    Elsewhere this polls, which reaps, as before."""
    if proc.returncode is not None:
        return True
    if not hasattr(os, "waitid"):
        return proc.poll() is not None
    try:
        return os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is not None
    except ChildProcessError:  # pragma: no cover - reaped by someone else
        return proc.poll() is not None


def kill_group(proc: subprocess.Popen[bytes]) -> None:
    """Kill garak's process group: garak, if it still runs, and anything it
    started. The group may already be gone; that is not an error."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        # No group left (or, on macOS, only exited members): garak itself
        # may still need killing when it could not be signalled as a group.
        if proc.poll() is None:
            proc.kill()


def run_garak(
    *,
    python: str,
    probe_ids: Sequence[str],
    limits: ScanLimits,
    port: int,
    token: str,
    workdir: str,
    seed: int | None = None,
    should_stop: Callable[[], bool] = lambda: False,
    on_poll: Callable[[ReportTail], None] | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> GarakRun:
    """Run garak in ``workdir`` (a private temporary directory) until it ends,
    the wall-clock limit passes, or ``should_stop`` returns True.

    Never raises for what garak does; a process that cannot start returns
    ``started=False``.
    """
    home = os.path.join(workdir, "home")
    report_dir = os.path.join(workdir, "report")
    os.mkdir(home, 0o700)
    os.mkdir(report_dir, 0o700)
    config = build_config(port=port, limits=limits, report_dir=report_dir, seed=seed)
    command = _limited(build_command(python, write_config(workdir, config), probe_ids))
    began = clock()
    deadline = began + limits.wall_clock_seconds
    stopped: str | None = None
    if not _runnable(python):
        logger.warning("garak could not be started kind=not_executable")
        return GarakRun(started=False, exit_code=None, stopped=None, seconds=0.0)
    with open(os.path.join(workdir, LOG_NAME), "wb") as log:
        try:
            proc = subprocess.Popen(  # noqa: S603 - fixed argument list, no shell
                command,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                env=build_env(home, token),
                cwd=home,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            logger.warning("garak could not be started kind=%s", type(exc).__name__)
            return GarakRun(started=False, exit_code=None, stopped=None, seconds=0.0)
        tail = ReportTail(os.path.join(report_dir, f"{REPORT_PREFIX}.report.jsonl"))
        try:
            while not exited(proc):
                if should_stop():
                    stopped = "cancelled"
                    break
                if clock() >= deadline:
                    stopped = "time_limit"
                    break
                tail.poll()
                if on_poll is not None:
                    on_poll(tail)
                time.sleep(POLL_SECONDS)
        finally:
            # Always, however garak ended: a child it started can outlive it.
            kill_group(proc)
            proc.wait()
    if stopped:
        logger.info("garak stopped reason=%s", stopped)
    return GarakRun(started=True, exit_code=proc.returncode, stopped=stopped, seconds=clock() - began,
                    files=read_files(report_dir))
