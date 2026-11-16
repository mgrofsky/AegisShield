import json
from datetime import datetime

import pytest

from aegisshield.core.errors import WorkspaceError
from aegisshield.storage import workspace as ws_mod
from aegisshield.storage.workspace import (
    MAX_WORKSPACE_BYTES,
    PAYLOAD_KEYS,
    SCHEMA_VERSION,
    Record,
    RecordKind,
    Workspace,
)


def filled():
    ws = Workspace()
    ws.set_org_profile("Example Store", {"legal_name": "Example Store LLC", "leadership": []})
    ws.add(RecordKind.THREAT_MODELS, "Checkout", {"threat_model": [{"Threat Type": "Spoofing"}]})
    ws.add("policies", "Access control", {"policy_key": "access", "body_markdown": "# A"})
    ws.add(RecordKind.LOOKUPS, "nginx 1.25", {"request": {}, "result": {"nvd": []}})
    ws.add(RecordKind.PCAP_ANALYSES, "capture.pcap", {"filename": "capture.pcap", "result": {}})
    ws.add(RecordKind.AI_SCANS, "Scan", {"status": "complete", "probes": [], "attempts": []})
    return ws


def test_record_fields():
    rec = Workspace().add(RecordKind.THREAT_MODELS, " Title\ntwo\u202e ", {"a": 1})
    assert len(rec.id) >= 20
    assert datetime.fromisoformat(rec.created_at).utcoffset().total_seconds() == 0
    assert rec.title == "Title two"
    assert rec.payload == {"a": 1}


def test_add_get_list_delete():
    ws = Workspace()
    first = ws.add(RecordKind.THREAT_MODELS, "one", {})
    second = ws.add(RecordKind.THREAT_MODELS, "two", {})
    assert ws.get("threat_models", first.id) == first
    assert ws.get(RecordKind.POLICIES, first.id) is None
    assert [r.title for r in ws.list(RecordKind.THREAT_MODELS)] == ["two", "one"]
    assert ws.delete(RecordKind.THREAT_MODELS, first.id) is True
    assert ws.delete(RecordKind.THREAT_MODELS, first.id) is False
    assert ws.list(RecordKind.THREAT_MODELS) == [second]
    with pytest.raises(ValueError):
        ws.add("unknown_kind", "x", {})


def test_list_sorts_by_time_not_insertion():
    ws = Workspace()
    bucket = ws._items[RecordKind.POLICIES]
    old = Record("a", "2026-01-01T00:00:00+00:00", "old", {})
    new = Record("b", "2026-06-01T00:00:00+00:00", "new", {})
    naive = Record("c", "2026-03-01T00:00:00", "naive", {})
    bucket.update({"b": new, "a": old, "c": naive})
    assert [r.title for r in ws.list(RecordKind.POLICIES)] == ["new", "naive", "old"]


def test_org_profile():
    ws = Workspace()
    rec = ws.set_org_profile("Org", {"legal_name": "X"})
    assert ws.org_profile is rec
    ws.clear_org_profile()
    assert ws.org_profile is None


@pytest.mark.parametrize("payload", [["list"], "text", {"bad": {1, 2}}, {"f": float("nan")}])
def test_payload_must_be_json_object(payload):
    with pytest.raises(WorkspaceError):
        Workspace().add(RecordKind.LOOKUPS, "x", payload)


def test_round_trip():
    ws = filled()
    data = ws.to_json()
    assert isinstance(data, bytes)
    loaded = Workspace.from_json(data)
    assert loaded.to_dict() == ws.to_dict()
    assert loaded.org_profile == ws.org_profile
    for kind in RecordKind:
        assert loaded.list(kind) == ws.list(kind)
    assert json.loads(data)["schema_version"] == SCHEMA_VERSION


def test_empty_round_trip_and_minimal_file():
    assert Workspace.from_json(Workspace().to_json()).to_dict() == Workspace().to_dict()
    loaded = Workspace.from_json(b'{"schema_version": 1}')
    assert loaded.org_profile is None and loaded.list(RecordKind.LOOKUPS) == []


def _doc(**changes):
    data = filled().to_dict()
    data.update(changes)
    return json.dumps(data).encode()


def _record(**changes):
    rec = {"id": "abc", "created_at": "2026-11-13T00:00:00+00:00", "title": "t", "payload": {}}
    rec.update(changes)
    return rec


@pytest.mark.parametrize(
    "data",
    [
        b"\xff\xfe not utf-8",
        b"{not json",
        b"[]",
        b'"text"',
        _doc(extra_key=1),
        _doc(schema_version=2),
        _doc(schema_version=True),
        json.dumps({"threat_models": []}).encode(),
        _doc(threat_models={}),
        _doc(policies=["not a record"]),
        _doc(policies=[{**_record(), "extra": 1}]),
        _doc(policies=[{k: v for k, v in _record().items() if k != "title"}]),
        _doc(policies=[_record(id="")]),
        _doc(policies=[_record(id="x" * 65)]),
        _doc(policies=[_record(id=5)]),
        _doc(policies=[_record(created_at=5)]),
        _doc(policies=[_record(created_at="yesterday")]),
        _doc(policies=[_record(title=None)]),
        _doc(policies=[_record(payload=[])]),
        _doc(policies=[_record(), _record()]),
        _doc(org_profile="text"),
        b"[" * 100_000 + b"]" * 100_000,
    ],
)
def test_rejects_bad_files(data):
    with pytest.raises(WorkspaceError):
        Workspace.from_json(data)


def test_rejects_non_bytes():
    with pytest.raises(WorkspaceError):
        Workspace.from_json("{}")  # type: ignore[arg-type]


def test_size_cap_checked_before_parsing(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("parsed an oversized file")

    monkeypatch.setattr(ws_mod.json, "loads", boom)
    with pytest.raises(WorkspaceError) as info:
        Workspace.from_json(b" " * (MAX_WORKSPACE_BYTES + 1))
    assert f"{MAX_WORKSPACE_BYTES // (1024 * 1024)} MB" in str(info.value)


def test_to_json_refuses_oversized(monkeypatch):
    monkeypatch.setattr(ws_mod, "MAX_WORKSPACE_BYTES", 100)
    ws = Workspace()
    ws.add(RecordKind.LOOKUPS, "big", {"blob": "x" * 200})
    with pytest.raises(WorkspaceError):
        ws.to_json()


def test_titles_cleaned_on_load():
    data = _doc(policies=[_record(title="Bad\u202etitle\nhere")])
    (rec,) = Workspace.from_json(data).list(RecordKind.POLICIES)
    assert rec.title == "Badtitle here"


def test_payload_keys_documented_for_every_kind():
    assert set(PAYLOAD_KEYS) == {*RecordKind, "org_profile"}
    assert "attack_tree_code" in PAYLOAD_KEYS[RecordKind.THREAT_MODELS]


def test_rename_keeps_id_time_and_payload() -> None:
    ws = Workspace()
    record = ws.add(RecordKind.THREAT_MODELS, "Old", {"a": 1})
    renamed = ws.rename(RecordKind.THREAT_MODELS, record.id, "  New\ntitle  ")
    assert renamed is not None
    assert (renamed.id, renamed.created_at, renamed.payload) == (record.id, record.created_at, {"a": 1})
    assert renamed.title == "New title"
    assert ws.get(RecordKind.THREAT_MODELS, record.id) == renamed
    assert ws.rename(RecordKind.THREAT_MODELS, "missing", "x") is None


# ------------------------------------------------- limits on what comes in


def _payload_doc(payload: object) -> bytes:
    return _doc(policies=[_record(payload=payload)])


@pytest.mark.parametrize(
    ("payload", "words"),
    [
        ({"body_markdown": "x" * (ws_mod.MAX_STRING_CHARS + 1)}, "characters"),
        ({"k" * (ws_mod.MAX_STRING_CHARS + 1): 1}, "characters"),
        ({"rows": list(range(ws_mod.MAX_LIST_ITEMS + 1))}, "items"),
        ({"a": None, **{f"k{i}": i for i in range(ws_mod.MAX_LIST_ITEMS)}}, "items"),
    ],
)
def test_import_refuses_values_over_the_limits(payload, words):
    with pytest.raises(WorkspaceError) as info:
        Workspace.from_json(_payload_doc(payload))
    assert words in str(info.value)


def test_import_refuses_deep_nesting():
    deep: object = "leaf"
    for _ in range(ws_mod.MAX_DEPTH):
        deep = [deep]
    with pytest.raises(WorkspaceError) as info:
        Workspace.from_json(_payload_doc({"a": deep}))
    assert "nested" in str(info.value)


def test_import_accepts_values_at_the_limits():
    shallow: object = "leaf"
    for _ in range(ws_mod.MAX_DEPTH - 2):
        shallow = [shallow]
    payload = {"s": "x" * ws_mod.MAX_STRING_CHARS, "rows": list(range(ws_mod.MAX_LIST_ITEMS)), "d": shallow}
    (record,) = Workspace.from_json(_payload_doc(payload)).list(RecordKind.POLICIES)
    assert record.payload == payload


def test_import_refuses_too_many_records():
    records = [_record(id=f"r{i}") for i in range(ws_mod.MAX_RECORDS + 1)]
    with pytest.raises(WorkspaceError) as info:
        Workspace.from_json(_doc(lookups=records))
    assert "records" in str(info.value)


def test_container_count_checked_before_parsing(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("parsed a file with too many containers")

    monkeypatch.setattr(ws_mod.json, "loads", boom)
    with pytest.raises(WorkspaceError) as info:
        Workspace.from_json(b"[" * (ws_mod.MAX_CONTAINERS + 1))
    assert "lists and objects" in str(info.value)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {1, 2}, b"x", (1,)])
def test_save_refuses_values_that_are_not_json(value):
    with pytest.raises(WorkspaceError):
        Workspace().add(RecordKind.LOOKUPS, "x", {"v": value})


def test_save_refuses_non_string_keys():
    with pytest.raises(WorkspaceError):
        Workspace().add(RecordKind.LOOKUPS, "x", {"v": {1: "a"}})


def test_save_refuses_a_string_over_the_limit():
    """A save is held to the import limits, so whatever is saved can be imported again."""
    with pytest.raises(WorkspaceError):
        Workspace().add(RecordKind.LOOKUPS, "x", {"v": ["y" * (ws_mod.MAX_STRING_CHARS + 1)]})


def test_a_real_threat_model_round_trips_well_inside_the_limits():
    from tests.aegisshield.ui.tm_records import mock_payload

    ws = Workspace()
    for index in range(20):
        ws.add(RecordKind.THREAT_MODELS, f"Model {index}", mock_payload())
    data = ws.to_json()
    assert len(data) < MAX_WORKSPACE_BYTES / 10
    assert data.count(b"[") + data.count(b"{") < ws_mod.MAX_CONTAINERS / 10
    assert len(Workspace.from_json(data).list(RecordKind.THREAT_MODELS)) == 20


def _fill(unit: bytes, budget: int) -> bytes:
    """A JSON workspace whose one payload list is ``unit`` repeated to ``budget`` bytes."""
    head = b'{"schema_version": 1, "lookups": [{"id": "a", "created_at": "2026-01-01T00:00:00+00:00", '
    head += b'"title": "t", "payload": {"v": ['
    tail = b"0]}}]}"
    return head + unit * ((budget - len(head) - len(tail)) // len(unit)) + tail


@pytest.mark.parametrize(
    "unit",
    [b"0,", b"1e5,", b'"",', b"{},", b"[[]],"],
    ids=["ints", "floats", "strings", "objects", "nested"],
)
def test_the_largest_hostile_import_does_not_stall_other_threads(unit):
    """At the byte cap, parsing the smallest JSON values (or refusing them)
    never blocks a second thread for anywhere near the bound."""
    from tests.aegisshield.stall import STALL_LIMIT_S, least_stall

    data = _fill(unit, MAX_WORKSPACE_BYTES)
    assert len(data) <= MAX_WORKSPACE_BYTES

    def attempt() -> None:
        try:
            Workspace.from_json(data)
        except WorkspaceError:
            pass

    run = least_stall(attempt)
    assert run.stall < STALL_LIMIT_S * 0.8, run


def test_a_workspace_that_would_not_import_is_not_saved():
    """to_json refuses what from_json would refuse, so a saved file always loads."""
    many = Workspace()
    for index in range(ws_mod.MAX_RECORDS + 1):
        many.add(RecordKind.LOOKUPS, f"l{index}", {})
    with pytest.raises(WorkspaceError, match="records"):
        many.to_json()
    dense = Workspace()
    for index in range(3):
        dense.add(RecordKind.LOOKUPS, f"d{index}", {"t": "[" * 40_000})
    with pytest.raises(WorkspaceError, match="brackets"):
        dense.to_json()
    fine = Workspace()
    for index in range(ws_mod.MAX_RECORDS):
        fine.add(RecordKind.LOOKUPS, f"l{index}", {"t": "[" * 100})
    assert len(Workspace.from_json(fine.to_json()).list(RecordKind.LOOKUPS)) == ws_mod.MAX_RECORDS


def test_the_largest_ai_scan_record_round_trips_inside_the_limits():
    """A scan record at every cap the scan service applies saves and loads again."""
    from aegisshield.aiscan import service

    text = "\U0001f600" * service.MAX_STORED_TEXT_CHARS  # four bytes each in UTF-8
    attempt = {"probe": "promptinject.HijackHateHumans", "seq": 0, "evaluated": True, "prompt": text,
               "outputs": [text] * service.MAX_OUTPUTS_PER_ATTEMPT,
               "detectors": {"promptinject.AttackRogueString": [1.0, 0.0, None]}}
    record = {"status": "complete", "attempts": [attempt] * service.MAX_STORED_ATTEMPTS, "probes": []}
    ws = Workspace()
    ws.add(RecordKind.AI_SCANS, "Largest scan", record)
    data = ws.to_json()
    assert len(data) < MAX_WORKSPACE_BYTES / 3
    assert data.count(b"[") + data.count(b"{") < 1_000
    assert Workspace.from_json(data).list(RecordKind.AI_SCANS)[0].payload == record
