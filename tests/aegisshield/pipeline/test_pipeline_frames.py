"""The progress record contract, end to end.

Runs the whole linear pipeline through ``run_threat_model`` against the
app's ``MockLLM`` with streaming on, stubbed NVD and OTX lookups, and
all three add-ons, captures every record passed to the progress sink, and
checks each against the structural expectations the recorded run in
``tests/fixtures/live_progress_frames.json.gz`` meets (``record_shape``). The captured sequence is saved as
``tests/fixtures/pipeline_mock_frames.json.gz`` for the page to replay; the test
fails when a run no longer matches it. Regenerate it after an intended change
with ``AEGIS_REGEN_FIXTURES=1``.
"""

from __future__ import annotations

import copy
import gzip
import json
import os
from types import SimpleNamespace
from typing import Any

import pytest

from aegisshield.config import Settings
from aegisshield.llm.mock import MockLLM
from aegisshield.pipeline import nvd_service, otx_service, workflow_service
from aegisshield.pipeline.run import run_threat_model
from aegisshield.pipeline.schemas import ThreatModelRequest
from tests.aegisshield.pipeline.record_shape import (
    FIXTURES,
    STAGE_IDS,
    check_agentic,
    check_lookups,
    check_office,
    load_json,
)

# Gzipped: the capture is about 650 KB of JSON.
FRAMES_FIXTURE = FIXTURES / "pipeline_mock_frames.json.gz"

def _frames_text() -> str:
    with gzip.open(FRAMES_FIXTURE, "rt", encoding="utf-8") as fh:
        return fh.read()


# Each read of the run clock moves it on by this much, so streamed updates
# cross the 1/3 second coalescing window and the capture has live frames.
CLOCK_STEP_S = 0.1

PROFILE = {
    "app_type": "Web application",
    "industry_sector": "Retail",
    "sensitive_data": "Payment card data",
    "internet_facing": "Yes",
    "compliance_requirements": ["PCI DSS"],
    "technical_ability": "Medium",
    "authentication": ["OAuth2", "MFA"],
    "selected_technologies": {
        "nginx": "cpe:2.3:a:f5:nginx:",
        "PostgreSQL": "cpe:2.3:a:postgresql:postgresql:",
        "Redis": "cpe:2.3:a:redis:redis:",
    },
    "selected_versions": {"nginx": "1.24.0", "PostgreSQL": "15.4", "Redis": "7.2.4"},
}
DESCRIPTION = (
    "An online checkout service for a retail store. Shoppers sign in, keep saved cards with "
    "the payment provider, apply coupons, and place orders. Staff issue refunds from an "
    "admin console."
)

_CVES = {
    "nginx": [
        ("CVE-2023-44487", ["V31", 7.5, "HIGH"], "2023-10-10T14:15:10.883"),
        ("CVE-2025-23419", ["V31", 5.3, "MEDIUM"], "2025-02-05T18:15:32.000"),
    ],
    "postgresql": [
        ("CVE-2024-10979", ["V31", 8.8, "HIGH"], "2024-11-14T13:15:04.000"),
        ("CVE-2024-7348", ["V31", 7.5, "HIGH"], "2024-08-08T13:15:12.000"),
        ("CVE-2024-10978", ["V31", 4.2, "MEDIUM"], "2024-11-14T13:15:04.000"),
    ],
}

_PULSES = [
    {
        "name": "Card skimming scripts on online stores",
        "description": "Injected scripts copy card numbers from checkout forms.",
        "modified": "2026-10-02T08:00:00.000",
        "public": 1,
        "TLP": "white",
        "adversary": "",
        "malware_families": ["Magecart"],
    },
    {
        "name": "Credential stuffing against retail accounts",
        "description": "Reused passwords tried at scale against shopper logins.",
        "modified": "2026-09-14T12:30:00.000",
        "public": 1,
        "TLP": "white",
        "adversary": "",
        "malware_families": [],
    },
    {
        "name": "Private report that must be filtered out",
        "description": "Not public.",
        "modified": "2026-09-01T00:00:00.000",
        "public": 0,
    },
]


class SteppingClock:
    """A run clock that moves on by a fixed step at every read."""

    def __init__(self, step: float) -> None:
        self.now = 1000.0
        self.step = step

    def __call__(self) -> float:
        self.now += self.step
        return self.now


class RecordingSink:
    """A progress sink that keeps a JSON copy of every record."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def set(self, record: dict[str, Any]) -> None:
        self.records.append(json.loads(json.dumps(record)))

    def cancelled(self) -> bool:
        return False


def _cpe_search(cpeMatchString: str, key: str) -> list[SimpleNamespace]:  # noqa: N803
    if ":redis:" in cpeMatchString:
        return []
    return [SimpleNamespace(cpeName=cpeMatchString, deprecated=False)]


def _cve_search(cpeName: str, key: str, limit: int | None = None) -> list[SimpleNamespace]:  # noqa: N803
    product = cpeName.split(":")[4]
    return [
        SimpleNamespace(
            id=cve,
            score=score,
            published=published,
            descriptions=[SimpleNamespace(value=f"A flaw in {product} ({cve}).")],
            metrics=None,
        )
        for cve, score, published in _CVES[product]
    ]


class _FakeOtx:
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def search_pulses(self, query: str, max_results: int) -> dict[str, Any]:
        return {"results": copy.deepcopy(_PULSES)}


@pytest.fixture
def stubbed_lookups(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nvd_service.nvdlib, "searchCPE", _cpe_search)
    monkeypatch.setattr(nvd_service.nvdlib, "searchCVE", _cve_search)
    monkeypatch.setattr(otx_service, "BoundedOTXv2", _FakeOtx)


def capture_run(monkeypatch: pytest.MonkeyPatch, *, agentic: bool = False) -> tuple[list, dict]:
    """One full run on the mock; returns (records, result)."""
    monkeypatch.setattr(workflow_service, "_monotonic", SteppingClock(CLOCK_STEP_S))
    request = ThreatModelRequest(
        app_profile=PROFILE,
        app_description=DESCRIPTION,
        addons=["mitigations", "dread", "test_cases"],
        agentic=agentic,
    )
    sink = RecordingSink()
    result = run_threat_model(
        request,
        llm=MockLLM(chunk_size=40),
        settings=Settings(),
        progress=sink,
        nvd_api_key="test-nvd-key",
        otx_api_key="test-otx-key",
    )
    return sink.records, result


def _status(record: dict, stage_id: str) -> str:
    return next(s["status"] for s in record["stages"] if s["id"] == stage_id)


def test_source_fixtures_meet_the_shape_checks() -> None:
    """The checks themselves accept every frame of the recorded run."""
    run = load_json("live_progress_frames.json.gz")
    for i, frame in enumerate(run["frames"]):
        check_office(f"frames[{i}]", frame["progress"])
    check_office("mock", load_json("deck_mock_record.json")["progress"])
    check_lookups("lookups", load_json("deck_lookups_record.json")["lookups"])


def test_every_record_of_a_mock_run_has_the_contract_shape(
    monkeypatch: pytest.MonkeyPatch, stubbed_lookups: None
) -> None:
    records, result = capture_run(monkeypatch)

    assert len(records) > 40
    for i, record in enumerate(records):
        check_office(f"records[{i}]", record)
        assert "deck" in record

    # The same keys the recorded run's frames carry, at every level.
    source = load_json("live_progress_frames.json.gz")["frames"][-1]["progress"]
    final = records[-1]
    assert set(final) == set(source)
    assert set(final["deck"]) - {"lookups"} == set(source["deck"])
    assert [set(s) for s in final["stages"]] == [set(s) for s in source["stages"]]
    assert [(s["id"], s["name"], s["term"], s["phase"]) for s in final["stages"]] == [
        (s["id"], s["name"], s["term"], s["phase"]) for s in source["stages"]
    ]

    # Every stage ran, the lookups filled the deck, and the deck matches the result.
    assert final["step"] == final["total"] == 11
    assert all(_status(final, sid) == "done" for sid in STAGE_IDS)
    lookups = final["deck"]["lookups"]
    assert [e["state"] for e in lookups["nvd"]] == ["found", "found", "unknown"]
    assert lookups["nvd_total"] == {
        "checked": 3,
        "returned": 5,
        "used": 5,
        "failed": 0,
        "unknown": 1,
    }
    assert lookups["nvd"][1]["top"][0] == {"id": "CVE-2024-10979", "score": 8.8}
    assert lookups["otx"]["state"] == "found" and lookups["otx"]["returned"] == 2
    deck = final["deck"]
    ids = [t["ID"] for t in result["threat_model"]]
    assert [t["id"] for t in deck["threats"]] == ids
    assert set(deck["techniques"]) == set(ids)
    assert set(deck["fixes"]) == set(ids)
    assert set(deck["scores"]) == set(ids)
    assert set(deck["tests"]) == {"TC-S01", "TC-T01"}
    assert deck["live"] is None

    # Streaming wrote live frames for the model stages.
    live_stages = {r["deck"]["live"]["stage"] for r in records if r["deck"]["live"]}
    assert {"stride", "mitre_map", "attack_tree", "mitigations", "dread", "test_cases"} <= (
        live_stages
    )


def test_captured_sequence_matches_the_saved_fixture(
    monkeypatch: pytest.MonkeyPatch, stubbed_lookups: None
) -> None:
    records, result = capture_run(monkeypatch)
    # The same envelope as the recorded live_progress_frames.json.gz: seen is
    # the record's run time (the deck's t), status the job status the page
    # would have read with it.
    frames = [
        {
            "seen": record["deck"]["t"],
            "status": "complete" if i == len(records) - 1 else "running",
            "progress": record,
        }
        for i, record in enumerate(records)
    ]
    saved = {
        "note": (
            "Every progress record one linear run wrote, in order, in the recorded run's "
            "frame envelope (seen, status, progress): aegisshield.pipeline."
            "run_threat_model on MockLLM (40 character chunks, streaming on), stubbed NVD "
            "and OTX answers for an online retail checkout service, all three add-ons, and "
            f"a run clock that moves {CLOCK_STEP_S} s at every read. Written by "
            "tests/aegisshield/pipeline/test_pipeline_frames.py; regenerate with "
            "AEGIS_REGEN_FIXTURES=1."
        ),
        "frames": frames,
        "final": {"status": "complete", "error": None, "result_keys": sorted(result)},
    }
    if os.environ.get("AEGIS_REGEN_FIXTURES") == "1":
        with FRAMES_FIXTURE.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as fh:
            fh.write((json.dumps(saved, indent=1) + "\n").encode("utf-8"))
    expected = json.loads(_frames_text())
    assert expected == saved


def test_agentic_records_have_the_roster_shape(
    monkeypatch: pytest.MonkeyPatch, stubbed_lookups: None
) -> None:
    records, result = capture_run(monkeypatch, agentic=True)
    assert records
    for i, record in enumerate(records):
        check_agentic(f"records[{i}]", record)
    assert records[-1]["lead"]["status"] == "done"
    assert result["agentic"] is True


def test_the_saved_fixture_is_ascii_and_uses_the_source_envelope() -> None:
    text = _frames_text()
    assert text.isascii()
    saved = json.loads(text)
    source = load_json("live_progress_frames.json.gz")
    assert set(saved) == set(source)
    for frame in saved["frames"]:
        assert set(frame) == set(source["frames"][0])
        check_office("saved", frame["progress"])
    assert saved["frames"][-1]["progress"]["current"] == "complete"
