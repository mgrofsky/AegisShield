"""Job-level behavior of ``run_threat_model`` through the job runner: the
agentic flag off, office progress surviving completion, the agentic roster,
a failure through the runner, and lookup errors on a job that completes.
"""

from __future__ import annotations

import json
import logging
import time
from types import SimpleNamespace
from typing import Any

import pytest
from requests.exceptions import RequestException

from aegisshield.config import Settings
from aegisshield.jobs.runner import ERROR_GENERIC, JobRunner, JobSnapshot, JobStatus
from aegisshield.llm.mock import MockLLM
from aegisshield.pipeline import nvd_service, otx_service, run, workflow_service
from aegisshield.pipeline.run import run_threat_model
from aegisshield.pipeline.schemas import ThreatModelRequest

PROFILE: dict[str, Any] = {
    "app_type": "Web application",
    "industry_sector": "Retail",
    "sensitive_data": "Payment card data",
    "internet_facing": "Yes",
    "authentication": ["OAuth2"],
}
DESCRIPTION = "An online checkout service where shoppers pay with saved cards and coupons."
SECRET = "sk-" + "live-" + "Zq9X" * 6


def _request(**overrides: Any) -> ThreatModelRequest:
    data: dict[str, Any] = {"app_profile": dict(PROFILE), "app_description": DESCRIPTION}
    data.update(overrides)
    return ThreatModelRequest(**data)


def _run_job(fn: Any) -> JobSnapshot:
    runner = JobRunner(max_concurrent_jobs=1, job_timeout_seconds=60)
    job_id = runner.submit(fn, kind="threat_model")
    for _ in range(1000):
        snap = runner.snapshot(job_id)
        assert snap is not None
        if snap.done:
            return snap
        time.sleep(0.01)
    raise AssertionError("job did not finish")


def _job(request: ThreatModelRequest, settings: Settings | None = None, **keys: Any) -> JobSnapshot:
    return _run_job(
        lambda progress: run_threat_model(
            request, llm=MockLLM(), settings=settings or Settings(), progress=progress, **keys
        )
    )


def test_agentic_flag_off_keeps_linear_path_and_no_roster() -> None:
    snap = _job(_request())
    assert snap.status is JobStatus.COMPLETE
    assert snap.progress.get("agentic") is not True
    assert snap.progress.get("office") is True
    assert snap.result is not None and snap.result["threat_model_markdown"].startswith("| ID |")


def test_default_job_keeps_office_stage_progress_through_completion() -> None:
    snap = _job(_request())
    progress = snap.progress
    assert progress.get("office") is True
    assert progress.get("agentic") is not True
    assert progress.get("current") == "complete"
    by_id = {s["id"]: s["status"] for s in progress["stages"]}
    for sid in ("serialize", "stride", "mitre_load", "mitre_map", "attack_tree", "markdown"):
        assert by_id[sid] == "done"
    # No keys: the lookups are skipped, not done; no add-ons were asked for.
    assert by_id["nvd"] == by_id["otx"] == "fallback"
    assert {by_id[a] for a in ("mitigations", "dread", "test_cases")} == {"queued"}


def test_agentic_job_populates_roster_and_matches_linear_shape() -> None:
    snap = _job(_request(), Settings(agentic=True))
    assert snap.status is JobStatus.COMPLETE
    result = snap.result or {}
    for key in run.CORE_RESULT_KEYS + ("detected_patterns", "pattern_source"):
        assert key in result, key
    progress = snap.progress
    assert progress["agentic"] is True and progress["current"] == "complete"
    assert progress["lead"]["status"] == "done"
    agents = progress["agents"]
    assert [a["id"] for a in agents] == [
        "stride", "mitre", "dread", "mitigations", "test_cases", "teammate", "rebuttal"
    ]
    assert all(a["status"] == "done" for a in agents)
    assert all(isinstance(a["started_at"], float) and isinstance(a["finished_at"], float) for a in agents)


def test_runner_records_failure_when_the_workflow_raises(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def boom(**_kwargs: Any) -> dict:
        raise RuntimeError("simulated model outage")

    monkeypatch.setattr(run, "run_threat_model_workflow", boom)
    with caplog.at_level(logging.WARNING, logger="aegisshield.jobs.runner"):
        snap = _job(_request())
    assert snap.status is JobStatus.FAILED
    assert snap.error == ERROR_GENERIC
    assert "simulated model outage" in caplog.text
    assert "RuntimeError" in caplog.text


def _lookup_fakes(monkeypatch: pytest.MonkeyPatch, nvd: Any, pulses: Any) -> None:
    def search_cve(cpeName: str, key: Any = None, **_k: Any) -> Any:  # noqa: N803
        value = nvd(cpeName)
        if isinstance(value, BaseException):
            raise value
        return value

    class FakeOTX:
        def __init__(self, _key: str) -> None:
            pass

        def search_pulses(self, _query: str, max_results: int = 0) -> Any:
            if isinstance(pulses, BaseException):
                raise pulses
            return {"results": pulses}

    monkeypatch.setattr(
        nvd_service.nvdlib,
        "searchCPE",
        lambda cpeMatchString, key=None, **_k: [  # noqa: N803
            SimpleNamespace(cpeName=cpeMatchString, deprecated=False)
        ],
    )
    monkeypatch.setattr(nvd_service.nvdlib, "searchCVE", search_cve)
    monkeypatch.setattr(otx_service, "BoundedOTXv2", FakeOTX)
    monkeypatch.setattr(workflow_service, "LOOKUP_MAX_RETRIES", 1)
    monkeypatch.setattr(workflow_service, "LOOKUP_RETRY_BASE_DELAY_S", 0.0)


def _lookup_request(techs: list[str]) -> ThreatModelRequest:
    profile = dict(
        PROFILE,
        selected_technologies={t: f"cpe:2.3:a:x:{t}:" for t in techs},
        selected_versions=dict.fromkeys(techs, "1.0"),
    )
    return _request(app_profile=profile, addons=["mitigations", "dread", "test_cases"])


def test_a_lookup_stage_error_on_a_job_that_completes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every NVD lookup fails: the job completes, the stage ends error with the
    fixed reason through the final complete record, the add-ons run, and no
    upstream text reaches the answer."""
    _lookup_fakes(
        monkeypatch, lambda _cpe: RequestException(f"403 apiKey={SECRET}"), RuntimeError(SECRET)
    )
    snap = _job(_lookup_request(["nginx", "Redis"]), nvd_api_key="k1", otx_api_key="k2")
    assert snap.status is JobStatus.COMPLETE and snap.error is None
    assert snap.progress["current"] == "complete"
    stages = {s["id"]: (s["status"], s.get("reason")) for s in snap.progress["stages"]}
    assert stages["nvd"] == ("error", "The NVD lookup did not finish.")
    assert stages["otx"] == ("error", "The OTX lookup did not finish.")
    assert all(stages[a][0] == "done" for a in ("mitigations", "dread", "test_cases"))
    lookups = snap.progress["deck"]["lookups"]
    assert lookups["nvd_total"] == {
        "checked": 2, "returned": 0, "used": 0, "failed": 2, "unknown": 0
    }
    assert SECRET not in json.dumps({"p": snap.progress, "r": snap.result, "e": snap.error})
