"""Where a ``Workspace`` lives between page runs.

``MappingStore`` is the default: the page passes ``st.session_state``, so each
visitor's work stays in their own session and disappears with it.
``FileStore`` is only for a single-user, self-hosted install with
``AEGIS_DATA_DIR`` set; it is never used by default.
"""

from __future__ import annotations

import contextlib
import logging
import os
import tempfile
import threading
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from aegisshield.config import Settings
from aegisshield.core.errors import WorkspaceError
from aegisshield.storage.workspace import MAX_WORKSPACE_BYTES, Workspace

logger = logging.getLogger(__name__)

DEFAULT_SESSION_KEY = "aegis_workspace"
WORKSPACE_FILENAME = "workspace.json"


@runtime_checkable
class WorkspaceStore(Protocol):
    """Loads and saves one workspace."""

    def load(self) -> Workspace:
        """The stored workspace, or a new empty one."""
        ...

    def save(self, workspace: Workspace) -> None:
        """Store ``workspace``, replacing what was there."""
        ...


class MappingStore:
    """Keeps the workspace object in a mutable mapping under ``key``."""

    def __init__(self, mapping: MutableMapping[str, Any], key: str = DEFAULT_SESSION_KEY) -> None:
        self._mapping = mapping
        self._key = key

    def load(self) -> Workspace:
        """The workspace in the mapping; a new one is created and stored if absent."""
        current = self._mapping.get(self._key)
        if not isinstance(current, Workspace):
            current = Workspace()
            self._mapping[self._key] = current
        return current

    def save(self, workspace: Workspace) -> None:
        """Put ``workspace`` in the mapping."""
        self._mapping[self._key] = workspace


class FileStore:
    """Keeps the workspace as a JSON file readable only by its owner (mode 0600)."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def load(self) -> Workspace:
        """The workspace in the file, or a new one if the file does not exist."""
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return Workspace()
        if size > MAX_WORKSPACE_BYTES:
            raise WorkspaceError(f"The workspace file is larger than {MAX_WORKSPACE_BYTES // (1024 * 1024)} MB.")
        return Workspace.from_json(self.path.read_bytes())

    def save(self, workspace: Workspace) -> None:
        """Write the workspace atomically: a temporary file, then a rename."""
        data = workspace.to_json()
        directory = self.path.parent
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        # mkstemp creates the file with mode 0600 in the same directory, so
        # the rename below is atomic and the file is never readable by others.
        fd, tmp_name = tempfile.mkstemp(prefix=".workspace-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.path)
        # BaseException so an interrupt mid-write also removes the temporary
        # file; the exception is always raised again.
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_name)
            raise


def file_store_from_settings(settings: Settings) -> FileStore | None:
    """A ``FileStore`` under ``settings.data_dir``, or None when it is not set."""
    if settings.data_dir is None:
        return None
    return FileStore(settings.data_dir / WORKSPACE_FILENAME)


SHARED_WORKSPACE_WARNING = (
    "AEGIS_DATA_DIR is set: every visitor of this app reads and writes the same workspace "
    "file. Use it only for a single-user install."
)
# Process-wide and public: whether the warning above was logged. Streamlit
# reruns the app script on every interaction, so the guard keeps it to one.
_shared_warning_logged = False
_shared_warning_lock = threading.Lock()


def warn_if_shared_workspace(settings: Settings) -> bool:
    """Log ``SHARED_WORKSPACE_WARNING`` once per process when ``data_dir`` is set.

    Returns True on the call that logged it.
    """
    global _shared_warning_logged
    if settings.data_dir is None:
        return False
    with _shared_warning_lock:
        if _shared_warning_logged:
            return False
        _shared_warning_logged = True
    logger.warning(SHARED_WORKSPACE_WARNING)
    return True
