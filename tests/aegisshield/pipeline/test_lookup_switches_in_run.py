"""A threat-model run honors the same lookup switches as the vulnerability
lookup page (``lookup_switches.source_disabled``): offline mode calls no
source, and each ``AEGIS_DISABLE_*`` flag skips only its own source. Every
outgoing connection is refused and recorded, so a call that slipped through
would show up even if the fakes missed it."""

from __future__ import annotations

import socket

import pytest

from aegisshield.llm.mock import MockLLM
from aegisshield.pipeline import agentic_threat_model as atm
from aegisshield.pipeline import workflow_service as ws
from tests.aegisshield.pipeline.test_run import (
    _PULSE,
    FakeSink,
    _lookup_fakes,
    _lookup_request,
    _run,
    _settings,
)


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> dict[str, list]:
    """Count calls into the fake NVD and OTX clients, and refuse all sockets."""
    seen: dict[str, list] = {"nvd": [], "otx": [], "socket": []}

    def nvd(cpe):  # noqa: ANN001, ANN202
        seen["nvd"].append(cpe)
        return []

    pulses = _PULSE
    _lookup_fakes(monkeypatch, nvd, pulses)
    from aegisshield.pipeline import otx_service

    real_otx = otx_service.BoundedOTXv2

    class CountingOTX(real_otx):  # type: ignore[misc, valid-type]
        def search_pulses(self, query, max_results=0):  # noqa: ANN001, ANN201
            seen["otx"].append(query)
            return super().search_pulses(query, max_results)

    monkeypatch.setattr(otx_service, "BoundedOTXv2", CountingOTX)

    def refuse(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        seen["socket"].append(args[:1])
        raise OSError("network refused in tests")

    monkeypatch.setattr(socket.socket, "connect", lambda self, *a: refuse(*a))
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    for name in ("AEGIS_OFFLINE", "AEGIS_DISABLE_NVD", "AEGIS_DISABLE_OTX"):
        monkeypatch.delenv(name, raising=False)
    return seen


def _stages(sink: FakeSink) -> dict[str, tuple[str, str | None]]:
    return {s["id"]: (s["status"], s.get("reason")) for s in sink.last["stages"]}


def _run_with_keys(sink: FakeSink, *, offline: bool = False) -> dict:
    return _run(_lookup_request(["nginx"]), sink, settings=_settings(offline=offline),
                nvd_api_key="test-nvd-key", otx_api_key="test-otx-key")


@pytest.mark.parametrize("how", ["settings", "environment"])
def test_offline_calls_no_source_and_says_so(calls, monkeypatch, how) -> None:
    if how == "environment":
        monkeypatch.setenv("AEGIS_OFFLINE", "1")
    sink = FakeSink()
    _run_with_keys(sink, offline=how == "settings")
    assert calls == {"nvd": [], "otx": [], "socket": []}
    stages = _stages(sink)
    assert stages["nvd"] == ("fallback", ws.REASON_NVD_OFF)
    assert stages["otx"] == ("fallback", ws.REASON_OTX_OFF)


def test_disable_nvd_skips_only_nvd(calls, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_DISABLE_NVD", "1")
    sink = FakeSink()
    _run_with_keys(sink)
    assert calls["nvd"] == [] and calls["otx"] and calls["socket"] == []
    stages = _stages(sink)
    assert stages["nvd"] == ("fallback", ws.REASON_NVD_DISABLED)
    assert stages["otx"][0] == "done"


def test_disable_otx_skips_only_otx(calls, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_DISABLE_OTX", "true")
    sink = FakeSink()
    _run_with_keys(sink)
    assert calls["otx"] == [] and calls["nvd"] and calls["socket"] == []
    stages = _stages(sink)
    assert stages["otx"] == ("fallback", ws.REASON_OTX_DISABLED)
    assert stages["nvd"][0] == "done"


def test_the_agentic_path_calls_no_source_offline(calls, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_OFFLINE", "1")
    notes: list[str] = []

    def on_progress(record):  # noqa: ANN001, ANN202
        lead = record.get("lead") if isinstance(record, dict) else None
        if isinstance(lead, dict) and lead.get("note"):
            notes.append(lead["note"])

    atm.orchestrate_threat_model(
        llm=MockLLM(), settings=_settings(offline=False),
        nvd_api_key="test-nvd-key", otx_api_key="test-otx-key",
        app_details=_lookup_request(["nginx"]).app_profile.model_dump(),
        app_description="An online checkout service with a card payment provider.",
        on_progress=on_progress,
    )
    assert calls == {"nvd": [], "otx": [], "socket": []}
    assert notes and notes[0] == "Planning the run"


def test_the_agentic_note_names_a_source_only_when_it_is_on(monkeypatch) -> None:
    details = {"selected_technologies": {"nginx": "cpe"}}
    monkeypatch.delenv("AEGIS_OFFLINE", raising=False)
    monkeypatch.setenv("AEGIS_DISABLE_OTX", "1")
    note = atm.gathering_note(nvd_api_key="k", otx_api_key="k", app_details=details,
                              settings=_settings(offline=False))
    assert note == "Gathering threat intel (NVD) and planning the run"
