"""Request handling and failure close-out of ``aegisshield.pipeline.run``.

These call ``run_threat_model`` directly with a fake progress sink and
``MockLLM``. The app has no database, HTTP layer, auth, or queue, so none of
those are tested here.
"""

from __future__ import annotations

import base64
import copy
import json
from types import SimpleNamespace

import pydantic
import pytest
from requests.exceptions import RequestException

from aegisshield.config import Settings
from aegisshield.core.errors import LLMError, LLMResponseError, ValidationError
from aegisshield.jobs.runner import (
    ERROR_GENERIC,
    ERROR_UNREADABLE,
    ERROR_UPSTREAM,
    plain_error,
)
from aegisshield.llm.mock import MOCK_IMAGE_DESCRIPTION, MOCK_THREAT_MODEL, MockLLM
from aegisshield.pipeline import run as run_module
from aegisshield.pipeline import workflow_service
from aegisshield.pipeline.run import close_failed_progress, run_threat_model, threat_model_title
from aegisshield.pipeline.schemas import ThreatModelRequest
from aegisshield.pipeline.workflow_service import REASON_ADDON_FAILED

_FAKE_WORKFLOW = {
    "threat_model": [
        {
            "Threat Type": "Spoofing",
            "Scenario": "Worker-shape test scenario",
            "Assumptions": [],
            "Potential Impact": "Worker-shape test impact",
            "MITRE ATT&CK Keywords": ["test"],
        }
    ],
    "improvement_suggestions": ["Add architecture details"],
    "threat_model_markdown": "tm",
    "mitre_attack_markdown": "mitre",
    "nvd_vulnerabilities_markdown": "",
    "otx_data_markdown": "",
    "attack_tree_code": "graph LR; A-->B",
    "mitre_data": [],
    "detected_patterns": ["GenAI"],
    "pattern_source": "user",
}

_PAYLOAD = {
    "app_profile": {
        "app_type": "Web application",
        "industry_sector": "Information Technology",
        "sensitive_data": "High",
        "internet_facing": "Yes",
    },
    "app_description": "An app description used by the async-job tests.",
}

_ADDONS = ["mitigations", "dread", "test_cases"]


class FakeSink:
    """A progress sink that keeps a deep copy of every record it is given."""

    def __init__(self, cancel: bool = False) -> None:
        self.records: list[dict] = []
        self.cancel = cancel

    def set(self, record: dict) -> None:
        self.records.append(copy.deepcopy(record))

    def cancelled(self) -> bool:
        return self.cancel

    @property
    def last(self) -> dict:
        return self.records[-1]


def _request(**overrides) -> ThreatModelRequest:
    payload = json.loads(json.dumps(_PAYLOAD))
    payload.update(overrides)
    return ThreatModelRequest.model_validate(payload)


def _settings(**overrides) -> Settings:
    base = {"mock_llm": True, "offline": True}
    base.update(overrides)
    return Settings(**base)


def _run(request: ThreatModelRequest, sink: FakeSink, settings: Settings | None = None, **keys):
    return run_threat_model(
        request,
        llm=MockLLM(),
        settings=settings or _settings(),
        progress=sink,
        **keys,
    )


def _stages(record: dict) -> dict[str, dict]:
    return {s["id"]: s for s in record["stages"]}


# Add-ons inside the job -------------------------------------------------------


def test_job_with_addons_runs_all_eleven_stages_offline() -> None:
    sink = FakeSink()
    result = _run(_request(addons=_ADDONS), sink)

    progress = sink.last
    # The record's ``current`` is not checked here: completion is reported by
    # the job status, not by the progress record.
    assert progress["office"] is True
    assert len(progress["stages"]) == 11
    assert all(s["status"] in {"done", "fallback"} for s in progress["stages"])
    assert {s["id"] for s in progress["stages"] if s["status"] == "fallback"} == {"nvd", "otx"}
    assert progress["total"] == 11 and progress["step"] == 11
    deck = progress["deck"]
    expected_threats = len(MOCK_THREAT_MODEL["threat_model"])
    assert deck["v"] == 1 and len(deck["threats"]) == expected_threats and deck["live"] is None

    for key in (
        "mitigations_markdown",
        "dread_assessment",
        "dread_assessment_markdown",
        "test_cases_markdown",
    ):
        assert key in result, key


def test_job_without_addons_leaves_them_to_the_browser() -> None:
    sink = FakeSink()
    result = _run(_request(), sink)

    byid = {s["id"]: s["status"] for s in sink.last["stages"]}
    assert byid["mitigations"] == byid["dread"] == byid["test_cases"] == "queued"
    assert sink.last["total"] == 8
    assert "mitigations_markdown" not in result


def test_addon_that_raises_leaves_the_job_complete(monkeypatch) -> None:
    def boom(*_args, **_kwargs):
        raise RuntimeError("upstream exploded")

    monkeypatch.setattr(workflow_service, "generate_test_cases", boom)
    sink = FakeSink()
    result = _run(_request(addons=_ADDONS), sink)

    stage = _stages(sink.last)["test_cases"]
    assert stage["status"] == "error"
    assert stage["reason"] == REASON_ADDON_FAILED
    assert stage["reason"] == "This step did not finish. You can run it again from the results."
    assert "test_cases_markdown" not in result
    assert "mitigations_markdown" in result


def test_agentic_path_ignores_addons(monkeypatch) -> None:
    seen: dict = {}
    real = run_module.orchestrate_threat_model

    def spy(**kwargs):
        seen.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(run_module, "orchestrate_threat_model", spy)
    sink = FakeSink()
    _run(_request(addons=_ADDONS), sink, settings=_settings(agentic=True))

    assert seen, "the agentic path did not run"
    assert "addons" not in seen
    assert sink.last.get("agentic") is True
    assert "deck" not in sink.last
    # mitigations_markdown is not checked: the agentic sections' keys pass
    # through to the result on purpose (tested in test_pipeline_guards.py).


# Failure close-out ------------------------------------------------------------


def _fail_in_stride(monkeypatch, exc: Exception) -> tuple[FakeSink, BaseException]:
    def boom(*_args, **_kwargs):
        raise exc

    monkeypatch.setattr(workflow_service, "generate_threat_model", boom)
    sink = FakeSink()
    with pytest.raises(type(exc)) as excinfo:
        _run(_request(addons=_ADDONS), sink)
    return sink, excinfo.value


def test_failed_job_marks_working_stage_error_with_plain_text(monkeypatch) -> None:
    sink, exc = _fail_in_stride(
        monkeypatch,
        LLMError("JSON completion failed: AccessDeniedException arn:aws:iam::123"),
    )
    assert plain_error(exc) == ERROR_UPSTREAM
    assert plain_error(exc) == "The AI service did not answer. Try again in a minute."
    progress = sink.last
    stride = _stages(progress)["stride"]
    assert stride["status"] == "error"
    assert stride["reason"] == "The AI service did not answer. Try again in a minute."
    assert not any(s["status"] == "working" for s in progress["stages"])
    assert progress["deck"]["live"] is None
    assert "AccessDenied" not in json.dumps(sink.records)


def test_unreadable_answer_gets_plain_text(monkeypatch) -> None:
    # The threat model service raises LLMResponseError for an answer of the
    # wrong shape; it must read as unreadable, like a JSON decode error.
    sink, exc = _fail_in_stride(monkeypatch, LLMResponseError("'threat_model' must be a list"))
    assert plain_error(exc) == ERROR_UNREADABLE
    assert _stages(sink.last)["stride"]["reason"] == (
        "The AI returned an answer that could not be read. Try again."
    )

    sink, exc = _fail_in_stride(monkeypatch, json.JSONDecodeError("Expecting value", "x", 0))
    assert plain_error(exc) == "The AI returned an answer that could not be read. Try again."
    assert _stages(sink.last)["stride"]["reason"] == ERROR_UNREADABLE


def test_agentic_failure_keeps_its_roster_and_gets_plain_text(monkeypatch) -> None:
    def boom(**kwargs):
        kwargs["on_progress"]({"agentic": True, "agents": [{"id": "stride", "status": "working"}]})
        raise RuntimeError("orchestrator broke")

    monkeypatch.setattr(run_module, "orchestrate_threat_model", boom)
    sink = FakeSink()
    with pytest.raises(RuntimeError) as excinfo:
        _run(_request(), sink, settings=_settings(agentic=True))
    assert plain_error(excinfo.value) == ERROR_GENERIC
    assert plain_error(excinfo.value) == "The task could not be completed. Try again."
    # The run writes the opening record first (before the safeguards build
    # their rails); the agentic roster record is then left as the
    # orchestrator wrote it.
    assert sink.records[0]["agentic"] is True and sink.records[0]["step"] == 0
    assert sink.records[1:] == [{"agentic": True, "agents": [{"id": "stride", "status": "working"}]}]


def test_close_failed_progress_edge_shapes() -> None:
    close = close_failed_progress
    assert close(None, "x") is None
    assert close({"step": 0, "total": 1, "current": "running"}, "x") is None
    assert close({"office": True, "current": "stride"}, "x") == {"office": True, "current": "stride"}
    closed = close(
        {"office": True, "stages": [{"id": "a", "status": "done"}, "junk"], "deck": {"live": {"x": 1}}},
        "plain",
    )
    assert closed["stages"] == [{"id": "a", "status": "done"}, "junk"]
    assert closed["deck"] == {"live": None}


# Lookups through the run ------------------------------------------------------

_PULSE = [{"name": "Report", "modified": "2025-01-01T00:00:00", "public": 1}]


def _lookup_fakes(monkeypatch, nvd, pulses) -> None:
    """Fake ``nvdlib`` and ``OTXv2`` under the real lookups. ``nvd(cpe)``
    gives a list of entries or an exception; ``pulses`` a list or an exception."""

    def search_cve(cpeName, key=None, **_k):
        value = nvd(cpeName)
        if isinstance(value, BaseException):
            raise value
        return value

    class FakeOTX:
        def __init__(self, _key):
            pass

        def search_pulses(self, _query, max_results=0):
            if isinstance(pulses, BaseException):
                raise pulses
            return {"results": pulses}

    fake_nvdlib = SimpleNamespace(
        searchCPE=lambda cpeMatchString, key=None, **_k: [
            SimpleNamespace(cpeName=cpeMatchString, deprecated=False)
        ],
        searchCVE=search_cve,
    )
    monkeypatch.setattr("aegisshield.pipeline.nvd_service.nvdlib", fake_nvdlib)
    monkeypatch.setattr("aegisshield.pipeline.otx_service.BoundedOTXv2", FakeOTX)
    monkeypatch.setattr(workflow_service, "LOOKUP_MAX_RETRIES", 1)
    monkeypatch.setattr(workflow_service, "LOOKUP_RETRY_BASE_DELAY_S", 0)


def _lookup_request(techs) -> ThreatModelRequest:
    payload = json.loads(json.dumps(_PAYLOAD))
    payload["app_profile"]["selected_technologies"] = {t: f"cpe:2.3:a:x:{t}:" for t in techs}
    payload["app_profile"]["selected_versions"] = dict.fromkeys(techs, "1.0")
    payload["addons"] = _ADDONS
    return ThreatModelRequest.model_validate(payload)


def _lookup_run(request: ThreatModelRequest, sink: FakeSink) -> dict:
    return _run(
        request,
        sink,
        settings=_settings(offline=False),
        nvd_api_key="test-nvd-key",
        otx_api_key="test-otx-key",
    )


def test_a_job_failing_between_stages_after_a_lookup_failed(monkeypatch) -> None:
    """The record the page reads when a lookup failed and the run then
    stopped with no stage working: the lookup is error, nothing is working."""
    _lookup_fakes(monkeypatch, lambda _cpe: RequestException("down"), _PULSE)

    def boom(**_kw):
        raise RuntimeError("prompt builder died")

    monkeypatch.setattr(workflow_service, "create_threat_model_prompt", boom)
    sink = FakeSink()
    with pytest.raises(RuntimeError):
        _lookup_run(_lookup_request(["nginx"]), sink)
    stages = {s["id"]: s["status"] for s in sink.last["stages"]}
    assert stages["nvd"] == "error" and stages["otx"] == "done"
    assert "working" not in stages.values()


def test_a_huge_score_does_not_fail_the_job(monkeypatch) -> None:
    entry = SimpleNamespace(
        id="CVE-2024-1111", score=["V31", 10**400, "HIGH"], published="2024-01-01T00:00:00",
        descriptions=[SimpleNamespace(value="d")],
    )
    _lookup_fakes(monkeypatch, lambda _cpe: [entry], _PULSE)
    sink = FakeSink()
    result = _lookup_run(_lookup_request(["nginx"]), sink)
    assert "CVE-2024-1111" in result["nvd_vulnerabilities_markdown"]
    assert sink.last["deck"]["lookups"]["nvd"][0]["top"] == [{"id": "CVE-2024-1111", "score": None}]


# Titles (threat_model_title and its word-boundary clip) -----------------------


def test_threat_model_title_uses_no_em_dash_and_word_boundary_clip() -> None:
    """The stored title must not carry em or en dashes and a long description
    must clip on a word boundary, never mid-word."""
    profile = {"app_type": "Web application", "industry_sector": "Retail"}
    description = (
        "A small business management application designed for local retail "
        "stores with an Angular frontend, Flask backend, and MySQL database "
        "storing customer records"
    )
    title = threat_model_title(profile, description)

    assert chr(0x2014) not in title  # em dash
    assert chr(0x2013) not in title  # en dash
    assert title.startswith("Web application: Retail. ")
    # Clipped (description is long) and ends on the "..." marker, not mid-word.
    assert title.endswith("...")
    assert not title.endswith("My...")


def test_threat_model_title_edge_cases() -> None:
    # No industry: just the app type, no dangling separator.
    assert threat_model_title({"app_type": "API"}, "Short desc") == "API. Short desc"
    # No description: app type + industry, no trailing punctuation.
    assert (
        threat_model_title({"app_type": "Web application", "industry_sector": "Retail"}, "")
        == "Web application: Retail"
    )
    # Empty everything: safe default.
    assert threat_model_title({}, "") == "Threat model"


def test_threat_model_title_short_snippet_is_unchanged() -> None:
    # A snippet under the 120-character limit is kept as is.
    assert threat_model_title({"app_type": "API"}, "short") == "API. short"


def test_threat_model_title_no_space_still_clips_with_marker() -> None:
    # One 200-character word has no space to clip on: it is still clipped
    # with the marker, to at most 120 characters.
    title = threat_model_title({"app_type": "API"}, "a" * 200)
    snippet = title.removeprefix("API. ")
    assert snippet.endswith("...")
    assert len(snippet) <= 120


# Request handling --------------------------------------------------------------


def _capture_workflow(monkeypatch, result: dict | None = None) -> dict:
    captured: dict = {}

    def fake_workflow(**kwargs):
        captured.update(kwargs)
        return dict(result or _FAKE_WORKFLOW)

    monkeypatch.setattr(run_module, "run_threat_model_workflow", fake_workflow)
    return captured


def test_threat_model_success(monkeypatch) -> None:
    captured = _capture_workflow(
        monkeypatch,
        {
            **_FAKE_WORKFLOW,
            "nvd_vulnerabilities_markdown": "nvd",
            "otx_data_markdown": "otx",
            "detected_patterns": [],
            "pattern_source": "none",
        },
    )
    settings = _settings()
    llm = MockLLM()
    body = run_threat_model(_request(), llm=llm, settings=settings, progress=FakeSink())
    assert body["threat_model_markdown"] == "tm"
    assert body["attack_tree_code"] == "graph LR; A-->B"
    # The workflow gets the settings (the model comes from them) and the
    # client, not a model id.
    assert captured["settings"] is settings
    # The client the workflow gets is the safeguards' wrapper around this one.
    assert captured["llm"]._inner is llm
    assert "detected_patterns" in body
    assert "pattern_source" in body


def test_threat_model_request_carries_no_model_name() -> None:
    # The request has no model field at all, so a visitor cannot pick one:
    # the model comes from Settings.
    with pytest.raises(pydantic.ValidationError):
        _request(model_name="gpt-5.4")


def test_result_passes_the_workflow_answer_through(monkeypatch) -> None:
    # The result carries the workflow's answer as the saved record shows it.
    _capture_workflow(monkeypatch)
    body = _run(_request(), FakeSink())
    assert body["detected_patterns"] == ["GenAI"]
    assert body["threat_model"][0]["Threat Type"] == "Spoofing"
    profile = _request().app_profile.model_dump()
    assert threat_model_title(profile, _PAYLOAD["app_description"]).startswith("Web application")


# Request handling: the description and diagram before the workflow runs.


def test_description_is_sanitized_before_the_workflow(monkeypatch) -> None:
    captured = _capture_workflow(monkeypatch)
    raw = "  A checkout\r\nservice\x00 with\u200b hidden characters.  "
    _run(_request(app_description=raw), FakeSink())
    assert captured["app_description"] == "A checkout\nservice with hidden characters."


def test_diagram_analysis_is_appended_to_the_description(monkeypatch) -> None:
    captured = _capture_workflow(monkeypatch)
    png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16).decode()
    _run(_request(architecture_image_base64=png), FakeSink())
    assert captured["app_description"] == (
        f"{_PAYLOAD['app_description']}\n\nArchitecture Diagram Analysis:\n{MOCK_IMAGE_DESCRIPTION}"
    )


def test_bad_diagram_fails_before_the_workflow_runs(monkeypatch) -> None:
    captured = _capture_workflow(monkeypatch)
    not_an_image = base64.b64encode(b"GIF89a not allowed").decode()
    sink = FakeSink()
    with pytest.raises(ValidationError):
        _run(_request(architecture_image_base64=not_an_image), sink)
    assert captured == {}
    assert sink.records == []
