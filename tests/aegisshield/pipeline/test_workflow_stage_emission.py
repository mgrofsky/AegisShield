"""Locks the live-office stage emission contract for the linear workflow.

The office view binds one worker desk to each real pipeline stage. The backend
is the single source of truth for that stage list (``THREAT_MODEL_STAGES``) and
must EMIT a per-stage progress event (queued -> working -> done) through
``on_progress`` as the engine crosses each stage it owns (1-8). These tests pin:

  * the canonical list shape (ids, order, phase clusters),
  * that an attached ``on_progress`` sees every backend stage reach working then
    done, in canonical order,
  * that the emitted progress carries ``office: True`` (NOT ``agentic: True``,
    so the linear-path no-roster assertion does not regress),
  * that a missing/throwing callback never breaks the run.
"""

from __future__ import annotations

from aegisshield.config import Settings
from aegisshield.pipeline import workflow_service
from aegisshield.pipeline.catalog_service import CatalogEntry
from aegisshield.pipeline.nvd_service import NvdItem, NvdLookup

_APP_DETAILS = {
    "app_type": "Web application",
    "industry_sector": "Retail",
    "authentication": ["OAuth2"],
    "internet_facing": "Yes",
    "sensitive_data": "Payment card data",
}
_DESCRIPTION = "An online retail checkout service exposing order APIs over the internet."

# The eight stage ids this backend workflow owns and emits directly, in order.
_BACKEND_IDS = [
    "serialize",
    "nvd",
    "otx",
    "stride",
    "mitre_load",
    "mitre_map",
    "attack_tree",
    "markdown",
]


class StubLLM:
    """Answers every model call offline: one threat, T1059, a tiny tree."""

    def chat_json(self, *, system, user, model, max_tokens=16000, on_text=None) -> dict:
        return {
            "threat_model": [
                {
                    "Threat Type": "Spoofing",
                    "Scenario": "Test",
                    "Assumptions": [],
                    "Potential Impact": "High",
                    "MITRE ATT&CK Keywords": ["execute", "command"],
                }
            ],
            "improvement_suggestions": [],
        }

    def chat_text(self, *, system, user, model, max_tokens=8192, on_text=None) -> str:
        if "Candidate Techniques" in user:
            return '{"technique_id": "T1059"}'
        return "graph LR; A-->B"

    def describe_image(self, *, image_bytes, media_type, prompt, model, max_tokens=4096) -> str:
        raise AssertionError("the workflow never describes an image")


def _stub_engine(monkeypatch) -> StubLLM:
    """Replace every external call so the workflow runs offline and fast."""
    fake_catalog = [
        CatalogEntry(
            framework="ATT&CK",
            domain="enterprise",
            technique_id="T1059",
            stix_id="attack-pattern--cmd",
            name="Command and Scripting Interpreter",
            tactic="Execution",
            description="Adversaries execute commands.",
        )
    ]
    monkeypatch.setattr(
        workflow_service,
        "catalog_for_app_type",
        lambda *_args, **_kwargs: fake_catalog,
    )
    return StubLLM()


def _run(llm, on_progress=None) -> dict:
    return workflow_service.run_threat_model_workflow(
        llm=llm,
        settings=Settings(),
        nvd_api_key=None,
        otx_api_key=None,
        app_details=_APP_DETAILS,
        app_description=_DESCRIPTION,
        on_progress=on_progress,
    )


def test_canonical_stage_list_shape() -> None:
    stages = workflow_service.THREAT_MODEL_STAGES
    # Eleven stages: the eight backend stages plus the three add-on desks.
    assert [s["id"] for s in stages] == _BACKEND_IDS + [
        "mitigations",
        "dread",
        "test_cases",
    ]
    # Every entry carries the keys the frontend builds desks from.
    for s in stages:
        assert set(s) == {"id", "label", "phase", "name", "term"}
        assert s["label"] and s["name"] and s["term"]
    # Phase clusters group desks into readable rows.
    phases = {s["id"]: s["phase"] for s in stages}
    assert phases["serialize"] == "enrichment"
    assert phases["stride"] == "modeling"
    assert phases["mitigations"] == "scoring"
    assert phases["test_cases"] == "validation"


def test_workflow_emits_each_backend_stage_in_order(monkeypatch) -> None:
    llm = _stub_engine(monkeypatch)
    events: list[dict] = []

    _run(llm, on_progress=events.append)

    assert events, "office must emit at least the reveal frame"

    # Reveal frame: office flagged on, every stage queued, before any work.
    first = events[0]
    assert first["office"] is True
    assert "agentic" not in first  # linear path must not look agentic
    assert first["current"] == "running"
    assert all(s["status"] == "queued" for s in first["stages"])
    # The full canonical roster is present from frame one so the floor is stable.
    assert [s["id"] for s in first["stages"]] == [
        s["id"] for s in workflow_service.THREAT_MODEL_STAGES
    ]

    # For each backend stage, the first event that shows it working must precede
    # the first event that shows it done, and the stages must reach working in
    # canonical order.
    def first_index(stage_id: str, status: str) -> int:
        for i, ev in enumerate(events):
            byid = {s["id"]: s["status"] for s in ev["stages"]}
            if byid.get(stage_id) == status:
                return i
        return -1

    # No NVD or OTX key: those two are skipped (fallback) with a reason and
    # never read done. Every other backend stage goes working then done.
    ran_ids = [sid for sid in _BACKEND_IDS if sid not in ("nvd", "otx")]
    working_order = []
    for sid in ran_ids:
        wi = first_index(sid, "working")
        di = first_index(sid, "done")
        assert wi != -1, f"stage {sid} never emitted working"
        assert di != -1, f"stage {sid} never emitted done"
        assert wi <= di, f"stage {sid} reported done before working"
        working_order.append((wi, sid))

    assert [sid for _, sid in sorted(working_order)] == ran_ids
    for sid in ("nvd", "otx"):
        assert first_index(sid, "done") == -1
        assert first_index(sid, "working") == -1

    # The final frame has every backend stage resolved; the three add-on desks
    # stay queued (the page runs them after the job when no add-ons are named).
    last = {s["id"]: s["status"] for s in events[-1]["stages"]}
    for sid in ran_ids:
        assert last[sid] == "done"
    assert last["nvd"] == "fallback"
    assert last["otx"] == "fallback"
    for sid in ("mitigations", "dread", "test_cases"):
        assert last[sid] == "queued"


def test_workflow_runs_without_on_progress(monkeypatch) -> None:
    llm = _stub_engine(monkeypatch)
    # No callback attached: the linear path must run exactly as before.
    result = _run(llm)
    assert result["threat_model"]


def test_throwing_callback_does_not_break_run(monkeypatch) -> None:
    llm = _stub_engine(monkeypatch)

    def boom(_progress):
        raise RuntimeError("callback blew up")

    result = _run(llm, on_progress=boom)
    assert result["threat_model"]


def test_office_progress_attaches_detail_only_to_current_stage() -> None:
    statuses = workflow_service._stage_seed()
    statuses["nvd"] = workflow_service._WORKING

    frame = workflow_service._office_progress(statuses, "nvd", "Checking Python 3.13")

    # Shape is unchanged: still office-flagged, never agentic.
    assert frame["office"] is True
    assert "agentic" not in frame
    byid = {s["id"]: s for s in frame["stages"]}
    # Detail rides ONLY the current stage; every other stage carries None.
    assert byid["nvd"]["detail"] == "Checking Python 3.13"
    for sid, s in byid.items():
        if sid != "nvd":
            assert s["detail"] is None


def test_office_progress_detail_defaults_none() -> None:
    statuses = workflow_service._stage_seed()
    frame = workflow_service._office_progress(statuses, "running")
    assert all(s["detail"] is None for s in frame["stages"])


def test_emitter_detail_sets_working_and_emits_detail() -> None:
    events: list[dict] = []
    emitter = workflow_service._StageEmitter(events.append)

    emitter.detail("nvd", "Checking Python 3.13")

    assert events, "detail() must emit a frame"
    last = events[-1]
    byid = {s["id"]: s for s in last["stages"]}
    # The stage is now WORKING (idempotent) and carries the detail string.
    assert byid["nvd"]["status"] == "working"
    assert byid["nvd"]["detail"] == "Checking Python 3.13"
    assert last["current"] == "nvd"


def test_nvd_loop_emits_per_tech_checking_then_count(monkeypatch) -> None:
    # The count comes from the lookup that ``lookup_nvd`` returns.
    def item(cve_id):
        return NvdItem(id=cve_id, score=["V31", 7.5, "HIGH"], published="2024-01-01", description="d")

    nvd_returns = {
        "cpe:python": NvdLookup(returned=2, items=[item("CVE-2024-0001"), item("CVE-2024-0002")]),
        "cpe:nginx": NvdLookup(returned=0),
    }

    def fake_lookup_nvd(*, cpe_prefix, **_kwargs):
        return nvd_returns[cpe_prefix]

    monkeypatch.setattr(workflow_service, "lookup_nvd", fake_lookup_nvd)

    events: list[dict] = []
    emitter = workflow_service._StageEmitter(events.append)
    app_details = dict(_APP_DETAILS)
    app_details["selected_technologies"] = {"Python": "cpe:python", "nginx": "cpe:nginx"}
    app_details["selected_versions"] = {"Python": "3.13", "nginx": "1.25"}

    workflow_service.gather_enrichment(
        nvd_api_key="test-nvd-key",
        otx_api_key=None,
        app_details=app_details,
        app_description=_DESCRIPTION,
        settings=Settings(),
        emitter=emitter,
    )

    # Collect the nvd-stage detail strings, in emission order.
    nvd_details = [
        detail
        for detail in (
            next((s["detail"] for s in e["stages"] if s["id"] == "nvd" and s["detail"]), None)
            for e in events
        )
        if detail
    ]
    assert "Checking Python 3.13" in nvd_details
    assert "Python: NVD returned 2, 2 passed on" in nvd_details
    assert "Checking nginx 1.25" in nvd_details
    assert "nginx: NVD returned none" in nvd_details
    # "Checking" precedes the count for Python.
    assert nvd_details.index("Checking Python 3.13") < nvd_details.index("Python: NVD returned 2, 2 passed on")
