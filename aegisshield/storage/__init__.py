"""Per-visitor storage for saved work."""

from aegisshield.storage.stores import (
    FileStore,
    MappingStore,
    WorkspaceStore,
    file_store_from_settings,
    warn_if_shared_workspace,
)
from aegisshield.storage.workspace import Record, RecordKind, Workspace

__all__ = [
    "FileStore",
    "MappingStore",
    "Record",
    "RecordKind",
    "Workspace",
    "WorkspaceStore",
    "file_store_from_settings",
    "warn_if_shared_workspace",
]
