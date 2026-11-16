"""The fake garak interpreter the scan and page tests share (see ``fake_garak.py``)."""

from __future__ import annotations

import json
import os
import signal
import stat
import sys
import time
from collections.abc import Callable
from pathlib import Path

FAKE = Path(__file__).resolve().parent / "fake_garak.py"


class FakeGarak:
    """A fake garak interpreter in its own directory, and its call log."""

    def __init__(self, directory: Path) -> None:
        self.dir = directory
        self.python = str(directory / "python")
        self.configure()

    def configure(self, **config: object) -> FakeGarak:
        """Set the fake's behavior (``mode``, ``version``, ``exit``, ``sleep``, ``prompt``)."""
        settings = {"version": "0.17.1", **config}
        (self.dir / "config.json").write_text(json.dumps(settings))
        return self

    def calls(self) -> list[dict]:
        """Every garak call so far, oldest first."""
        log = self.dir / "calls.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]


def install(directory: Path) -> FakeGarak:
    """Put a fake garak interpreter in ``directory`` (created) and return it."""
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "python"
    target.write_text(f"#!{sys.executable}\n" + FAKE.read_text())
    target.chmod(target.stat().st_mode | stat.S_IXUSR)
    return FakeGarak(directory)


def _proc_stat(pid: int) -> str | None:
    """The text of ``/proc/<pid>/stat``, or None when it cannot be read."""
    try:
        return Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None


def alive(pid: int, *, platform: str | None = None,
          read_stat: Callable[[int], str | None] = _proc_stat) -> bool:
    """True while ``pid`` is a running process.

    On Linux a killed child whose parent never reaps it stays a zombie, and
    in a container whose first process does not reap orphans it still
    answers signal 0. A zombie is dead, so it reads as gone there, from its
    state in ``/proc/<pid>/stat``. macOS keeps the signal-0 answer alone.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover - a reused pid owned by someone else
        return True
    if not (platform or sys.platform).startswith("linux"):
        return True
    text = read_stat(pid)
    if text is None or ")" not in text:
        return True  # unreadable: keep the signal-0 answer
    # The command name sits in parentheses and may hold spaces or ")", so
    # the state is the first field after the last ")".
    fields = text.rsplit(")", 1)[1].split()
    return not (fields and fields[0] in ("Z", "X"))


def gone(pid: int, within: float = 3.0) -> bool:
    """True when ``pid`` ends within ``within`` seconds; kills it if not."""
    end = time.monotonic() + within
    while alive(pid) and time.monotonic() < end:
        time.sleep(0.05)
    still = alive(pid)
    if still:
        os.kill(pid, signal.SIGKILL)
    return not still
