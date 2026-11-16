import os
import stat

import pytest

from aegisshield.config import Settings
from aegisshield.core.errors import WorkspaceError
from aegisshield.storage import stores as stores_mod
from aegisshield.storage.stores import (
    DEFAULT_SESSION_KEY,
    FileStore,
    MappingStore,
    WorkspaceStore,
    file_store_from_settings,
)
from aegisshield.storage.workspace import MAX_WORKSPACE_BYTES, RecordKind, Workspace


def test_mapping_store_creates_and_keeps_workspace():
    session = {}
    store = MappingStore(session)
    assert isinstance(store, WorkspaceStore)
    ws = store.load()
    assert session[DEFAULT_SESSION_KEY] is ws
    assert store.load() is ws
    other = Workspace()
    store.save(other)
    assert store.load() is other


def test_mapping_store_replaces_wrong_type():
    session = {"k": "not a workspace"}
    assert isinstance(MappingStore(session, "k").load(), Workspace)


def test_mapping_stores_are_isolated():
    a, b = {}, {}
    MappingStore(a).load().add(RecordKind.LOOKUPS, "mine", {})
    assert MappingStore(b).load().list(RecordKind.LOOKUPS) == []


def test_file_store_missing_file(tmp_path):
    assert FileStore(tmp_path / "none.json").load().to_dict() == Workspace().to_dict()


def test_file_store_round_trip_and_mode(tmp_path):
    path = tmp_path / "sub" / "workspace.json"
    store = FileStore(path)
    ws = Workspace()
    ws.add(RecordKind.THREAT_MODELS, "tm", {"threat_model": []})
    store.save(ws)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert store.load().to_dict() == ws.to_dict()
    assert [p.name for p in path.parent.iterdir()] == ["workspace.json"]


def test_file_store_atomic_on_failure(tmp_path, monkeypatch):
    path = tmp_path / "workspace.json"
    store = FileStore(path)
    first = Workspace()
    first.add(RecordKind.LOOKUPS, "kept", {})
    store.save(first)
    before = path.read_bytes()

    def fail_replace(_src, _dst):
        raise OSError("disk full")

    monkeypatch.setattr(stores_mod.os, "replace", fail_replace)
    second = Workspace()
    second.add(RecordKind.LOOKUPS, "lost", {})
    with pytest.raises(OSError):
        store.save(second)
    assert path.read_bytes() == before
    assert [p.name for p in tmp_path.iterdir()] == ["workspace.json"]


def test_file_store_rejects_oversized_file(tmp_path):
    path = tmp_path / "workspace.json"
    with open(path, "wb") as handle:
        handle.truncate(MAX_WORKSPACE_BYTES + 1)
    with pytest.raises(WorkspaceError):
        FileStore(path).load()


def test_file_store_rejects_bad_file(tmp_path):
    path = tmp_path / "workspace.json"
    path.write_bytes(b"{nope")
    with pytest.raises(WorkspaceError):
        FileStore(str(path)).load()


def test_file_store_only_when_data_dir_set(tmp_path):
    assert file_store_from_settings(Settings()) is None
    store = file_store_from_settings(Settings(data_dir=tmp_path))
    assert isinstance(store, FileStore)
    assert store.path == tmp_path / "workspace.json"
    assert not os.path.exists(store.path)


def test_shared_workspace_warning_is_logged_once(monkeypatch, caplog, tmp_path):
    from aegisshield.config import Settings
    from aegisshield.storage import stores

    monkeypatch.setattr(stores, "_shared_warning_logged", False)
    with caplog.at_level("WARNING", logger="aegisshield.storage.stores"):
        assert stores.warn_if_shared_workspace(Settings()) is False
        assert stores.warn_if_shared_workspace(Settings(data_dir=tmp_path)) is True
        assert stores.warn_if_shared_workspace(Settings(data_dir=tmp_path)) is False
    messages = [r.getMessage() for r in caplog.records]
    assert messages == [stores.SHARED_WORKSPACE_WARNING]
    assert "every visitor" in messages[0]


def test_app_frame_logs_the_shared_workspace_warning(monkeypatch, tmp_path):
    from streamlit.testing.v1 import AppTest

    from aegisshield.storage import stores

    calls = []
    monkeypatch.setattr(stores, "_shared_warning_logged", False)
    monkeypatch.setattr(stores.logger, "warning", lambda msg, *a: calls.append(msg))
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AEGIS_MOCK_LLM", "1")

    def app():
        from aegisshield.ui.app import run

        run()

    at = AppTest.from_function(app, default_timeout=30).run()
    at.run()
    assert calls == [stores.SHARED_WORKSPACE_WARNING]
