"""Whether scans can run here: on, off, or garak not found.

Scans exist only when the operator sets ``AEGIS_AI_SCAN`` and
``AEGIS_GARAK_PYTHON`` names a Python interpreter whose environment has garak
installed. garak never lives in the app's own environment, so it is found
through that explicit path, never on PATH or by import.

The interpreter is asked for garak's version once per process, with a
timeout, from the package's metadata (0.04 s, where ``-m garak --version``
takes about 0.3 s), and the answer is cached by interpreter path. The cache
holds only the operator's configuration, never visitor data. The question
runs in its own process group, which is killed when it ends, however it
ends, so nothing the interpreter starts outlives it.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from enum import StrEnum

from aegisshield.aiscan.garak_run import exited, kill_group
from aegisshield.config import Settings

logger = logging.getLogger(__name__)

VERSION_TIMEOUT_SECONDS = 10
# How often the version question checks whether it has finished.
_VERSION_POLL_SECONDS = 0.02
_VERSION_CODE = "import importlib.metadata as m; print(m.version('garak'))"
_VERSION_RE = re.compile(r"[0-9][0-9A-Za-z.+\-]{0,39}")

_cache: dict[str, str | None] = {}
_cache_lock = threading.Lock()


class ScanState(StrEnum):
    """Whether scans can run."""

    AVAILABLE = "available"
    OFF = "off"
    NOT_FOUND = "not_found"


@dataclass(frozen=True)
class Availability:
    """The answer to "can scans run here", with garak's version when they can.

    ``python`` is the operator's interpreter path; it is used to start garak
    and is never shown to a visitor or stored in a scan record.
    """

    state: ScanState
    version: str | None = None
    python: str | None = None

    @property
    def available(self) -> bool:
        """True when a scan can be started."""
        return self.state is ScanState.AVAILABLE


def _ask_version(python: str) -> str | None:
    """garak's version from ``python``'s environment, or None on any failure."""
    if not os.path.isabs(python) or not os.path.isfile(python) or not os.access(python, os.X_OK):
        logger.warning("AEGIS_GARAK_PYTHON is not an absolute path to an executable file")
        return None
    try:
        proc = subprocess.Popen(  # noqa: S603 - fixed argument list, no shell
            [python, "-I", "-c", _VERSION_CODE],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": os.defpath},
            start_new_session=True,
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("could not ask for the garak version kind=%s", type(exc).__name__)
        return None
    with proc:
        # The output is read on a helper thread, and the process is not
        # reaped until its group has been signalled (``exited``), so its id
        # cannot be reused by another process group in between.
        chunks: list[bytes] = []
        out = proc.stdout
        assert out is not None  # stdout=PIPE above
        reader = threading.Thread(target=lambda: chunks.append(out.read()), name="aegis-garak-version",
                                  daemon=True)
        reader.start()
        deadline = time.monotonic() + VERSION_TIMEOUT_SECONDS
        while (reader.is_alive() or not exited(proc)) and time.monotonic() < deadline:
            time.sleep(_VERSION_POLL_SECONDS)
        finished = not reader.is_alive() and exited(proc)
        # Always, however it ended: a child it started can outlive it (and
        # hold its output open).
        kill_group(proc)
        reader.join(_VERSION_POLL_SECONDS * 50)
        proc.wait()
        if not finished:
            logger.warning("could not ask for the garak version kind=TimeoutExpired")
            return None
    text = b"".join(chunks).decode("utf-8", "replace").strip()
    if proc.returncode != 0 or not _VERSION_RE.fullmatch(text):
        logger.warning("garak was not found by AEGIS_GARAK_PYTHON code=%s", proc.returncode)
        return None
    return text


def garak_version(python: str) -> str | None:
    """garak's version for ``python``, asked once per process and cached."""
    with _cache_lock:
        if python in _cache:
            return _cache[python]
    version = _ask_version(python)
    with _cache_lock:
        _cache.setdefault(python, version)
        return _cache[python]


def clear_cache() -> None:
    """Forget cached versions (for tests, and after the operator changes garak)."""
    with _cache_lock:
        _cache.clear()


def scan_availability(settings: Settings) -> Availability:
    """Whether scans are on, off, or on but garak was not found."""
    if not settings.ai_scan:
        return Availability(ScanState.OFF)
    python = settings.garak_python
    version = garak_version(python) if python else None
    if version is None:
        return Availability(ScanState.NOT_FOUND)
    return Availability(ScanState.AVAILABLE, version=version, python=python)
