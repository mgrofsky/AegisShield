"""What the lookups show in the live deck: ``progress.deck.lookups``.

The linear path writes what each lookup gave into the deck as it arrives:
per technology, how many NVD returned and how many were passed on, with up to
five ids; for OTX, how many reports passed the filter and how many were
passed on, with their titles. Display only: nothing here reaches the prompt or
the result, and no exception text reaches the record.
"""

from __future__ import annotations

import json
import math
from typing import Any

import pytest

from aegisshield.config import Settings
from aegisshield.pipeline import workflow_service
from aegisshield.pipeline.live_deck import LiveDeck
from aegisshield.pipeline.nvd_service import NvdItem, NvdLookup, nvd_text
from aegisshield.pipeline.otx_service import OtxLookup, otx_text

_APP = {
    "app_type": "Web application",
    "industry_sector": "Retail",
    "authentication": ["OAuth2"],
    "internet_facing": "Yes",
    "sensitive_data": "Payment card data",
}
_DESCRIPTION = "An online retail checkout service exposing payment APIs over the internet."
# a key-like string, built here so no scanner reads it as a real key
_LEAK = "sk-" + "live-" + "Q7f2" * 6


class Clock:
    def __init__(self, step: float = 0.0) -> None:
        self.now = 100.0
        self.step = step

    def __call__(self) -> float:
        self.now += self.step
        return self.now


def _items(n: int, start: int = 1000, score: Any = None) -> list[NvdItem]:
    return [
        NvdItem(
            id=f"CVE-2026-{start + i}",
            score=["V31", 9.0 - i * 0.5, "HIGH"] if score is None else score,
            published="2026-01-01",
            description="text",
        )
        for i in range(n)
    ]


def _otx(n: int = 10, returned: int = 37) -> OtxLookup:
    pulses = [
        {"name": f"Report {i}", "modified": f"2025-0{1 + i % 9}-02T10:11:12.000", "public": 1}
        for i in range(n)
    ]
    return OtxLookup(state="found", returned=returned, pulses=pulses)


def _run(
    monkeypatch,
    nvd: dict[str, Any],
    otx: Any = None,
    *,
    nvd_key: str | None = "key",
    otx_key: str | None = "otx-key",
    emitter: Any = "new",
    clock: Clock | None = None,
) -> tuple[list[dict], Any]:
    """Run the enrichment with fake lookups. A value that is an Exception is raised."""

    def fake_nvd(*, api_key: str, cpe_prefix: str, version: str, config: Any) -> NvdLookup:
        value = nvd[cpe_prefix]
        if isinstance(value, BaseException):
            raise value
        return value

    def fake_otx(**_kw: Any) -> OtxLookup:
        if isinstance(otx, BaseException):
            raise otx
        return otx

    monkeypatch.setattr(workflow_service, "lookup_nvd", fake_nvd)
    monkeypatch.setattr(workflow_service, "lookup_otx", fake_otx)
    events: list[dict] = []
    if emitter == "new":
        emitter = workflow_service._StageEmitter(events.append, clock or Clock(0.5))
    details = dict(_APP)
    details["selected_technologies"] = {tech: tech for tech in nvd}
    details["selected_versions"] = {tech: f"{i + 1}.0" for i, tech in enumerate(nvd)}
    bundle = workflow_service.gather_enrichment(
        nvd_api_key=nvd_key,
        otx_api_key=otx_key,
        app_details=details,
        app_description=_DESCRIPTION,
        settings=Settings(),
        emitter=emitter,
    )
    return events, bundle


def _stage(record: dict, sid: str) -> dict:
    return next(s for s in record["stages"] if s["id"] == sid)


def _lookups(events: list[dict]) -> dict:
    return events[-1]["deck"]["lookups"]


# -- shape -----------------------------------------------------------------


def test_the_record_shape(monkeypatch) -> None:
    events, _ = _run(
        monkeypatch,
        {"PostgreSQL": NvdLookup(returned=50, items=_items(10)), "nginx": NvdLookup(returned=0)},
        _otx(),
    )
    lookups = _lookups(events)
    assert set(lookups) == {"nvd", "nvd_more", "nvd_total", "otx"}
    assert lookups["nvd_total"] == {"checked": 2, "returned": 50, "used": 10, "failed": 0, "unknown": 0}
    pg, ng = lookups["nvd"]
    assert set(pg) == {"tech", "version", "state", "returned", "used", "top", "t"}
    assert (pg["tech"], pg["version"], pg["state"], pg["returned"], pg["used"]) == ("PostgreSQL", "1.0", "found", 50, 10)
    assert pg["top"] == [{"id": f"CVE-2026-{1000 + i}", "score": 9.0 - i * 0.5} for i in range(5)]
    assert (ng["state"], ng["returned"], ng["used"], ng["top"]) == ("none", 0, 0, [])
    assert isinstance(pg["t"], float) and pg["t"] <= ng["t"]
    assert lookups["nvd_more"] == 0
    otx = lookups["otx"]
    assert set(otx) == {"sector", "state", "returned", "used", "at_least", "reports", "t"}
    assert (otx["sector"], otx["state"], otx["returned"], otx["used"], otx["at_least"]) == ("Retail", "found", 37, 10, False)
    assert otx["reports"][0] == {"title": "Report 0", "date": "2025-01-02"}
    assert len(otx["reports"]) == 10
    json.dumps(events[-1], allow_nan=False)


def test_bounds(monkeypatch) -> None:
    nvd = {f"tech{i:02d}": NvdLookup(returned=99999, items=_items(10)) for i in range(30)}
    events, _ = _run(monkeypatch, nvd, _otx(n=40, returned=10**9))
    lookups = _lookups(events)
    assert len(lookups["nvd"]) == 25 and lookups["nvd_more"] == 5
    assert [e["tech"] for e in lookups["nvd"]] == [f"tech{i:02d}" for i in range(25)]
    assert all(len(e["top"]) == 5 for e in lookups["nvd"])
    assert all(e["returned"] == 9999 and e["used"] == 10 for e in lookups["nvd"])
    assert len(lookups["otx"]["reports"]) == 10
    # ``used`` stays the true count passed on; only the listed titles are capped
    assert lookups["otx"]["returned"] == 9999 and lookups["otx"]["used"] == 40


def test_bounds_on_the_deck_directly() -> None:
    deck = LiveDeck(lambda: 1.0)
    deck.add_nvd_lookup("x", "1", "found", -5, 10**6, [])
    deck.set_otx_lookup("s", "found", math.nan, -1, [])
    lookups = deck.as_dict()["lookups"]
    assert (lookups["nvd"][0]["returned"], lookups["nvd"][0]["used"]) == (0, 9999)
    assert (lookups["otx"]["returned"], lookups["otx"]["used"]) == (0, 0)
    deck.add_nvd_lookup("x", "1", "maybe", 1, 1, [])
    assert deck.as_dict()["lookups"]["nvd"][1]["state"] == "failed"


def test_no_lookups_key_until_a_lookup_answers() -> None:
    deck = LiveDeck(lambda: 1.0)
    assert "lookups" not in deck.as_dict()
    deck.set_otx_lookup("Retail", "off", 0, 0, [])
    assert deck.as_dict()["lookups"] == {
        "nvd": [],
        "nvd_more": 0,
        "nvd_total": {"checked": 0, "returned": 0, "used": 0, "failed": 0, "unknown": 0},
        "otx": {"sector": "Retail", "state": "off", "returned": 0, "used": 0, "at_least": False, "reports": [], "t": 1.0},
    }


# -- cleaning --------------------------------------------------------------

_BIDI = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"


def test_cleaning_of_titles_and_names(monkeypatch) -> None:
    word = "A" * 600
    hostile_tech = f"<img src=x onerror=alert(1)>\x00\x07{_BIDI}Post\u202egres"
    pulses = [
        {"name": f"<script>alert(1)</script>\x1b[31m{_BIDI}Ransom\u202eware", "modified": "2025-01-01", "public": 1},
        {"name": word, "modified": "2025-01-01", "public": 1},
        {"name": f"Report about {word}", "modified": "2025-01-01", "public": 1},
    ]
    nvd = {hostile_tech: NvdLookup(returned=1, items=_items(1)), word: NvdLookup(returned=0)}
    events, _ = _run(monkeypatch, nvd, OtxLookup(state="found", returned=3, pulses=pulses))
    lookups = _lookups(events)
    first, long_tech = lookups["nvd"]
    assert first["tech"] == "<img src=x onerror=alert(1)>Postgres"
    assert len(long_tech["tech"]) <= 60 and long_tech["tech"].endswith("...")
    titles = [r["title"] for r in lookups["otx"]["reports"]]
    assert titles[0] == "<script>alert(1)</script>[31mRansomware"
    assert all(len(t) <= 120 for t in titles)
    assert titles[1] == "A" * 117 + "..."
    assert titles[2] == "Report about..."
    strings = [e["tech"] for e in lookups["nvd"]] + titles + [lookups["otx"]["sector"]]
    for ch in _BIDI + "\x00\x07\x1b":
        assert not any(ch in s for s in strings)


def test_cleaning_of_version_and_sector() -> None:
    deck = LiveDeck(lambda: 1.0)
    deck.add_nvd_lookup("t", f"1.0\u2066{'9' * 50}", "none", 0, 0, [])
    deck.set_otx_lookup(f"Ret\u202eail\x00{' x' * 60}", "none", 0, 0, [])
    lookups = deck.as_dict()["lookups"]
    assert len(lookups["nvd"][0]["version"]) <= 30 and "\u2066" not in lookups["nvd"][0]["version"]
    assert lookups["otx"]["sector"].startswith("Retail x") and len(lookups["otx"]["sector"]) <= 60


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        ("CVE-2024-1234", True),
        ("CVE-2024-1234567", True),
        ("CVE-2024-123", False),
        ("CVE-2024-12345678", False),
        ("cve-2024-1234", False),
        ("CVE-24-1234", False),
        (" CVE-2024-1234", False),
        ("CVE-2024-1234\n", False),
        ("CVE-2024-1234<script>", False),
        ("javascript:alert(1)", False),
        (20241234, False),
        (None, False),
        ("N/A", False),
    ],
)
def test_the_id_pattern(value: Any, kept: bool) -> None:
    deck = LiveDeck(lambda: 1.0)
    deck.add_nvd_lookup("t", "1", "found", 1, 1, [(value, None)])
    top = deck.as_dict()["lookups"]["nvd"][0]["top"]
    assert top == ([{"id": value, "score": None}] if kept else [])


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (["V31", 8.8, "HIGH"], 8.8),
        (("V2", 5, "MEDIUM"), 5.0),
        (["V40", 10.0, "CRITICAL"], 10.0),
        (["V31", 0.0, "NONE"], 0.0),
        ([None, None, None], None),
        (["V31", 11.0, "HIGH"], None),
        (["V31", -1, "LOW"], None),
        (["V31", math.nan, "HIGH"], None),
        (["V31", math.inf, "HIGH"], None),
        (["V31", True, "HIGH"], None),
        (["V31", "8.8", "HIGH"], None),
        (7.5, 7.5),
        (True, None),
        ("N/A", None),
        ({"score": 8.8}, None),
        ([], None),
    ],
)
def test_the_score(score: Any, expected: Any) -> None:
    deck = LiveDeck(lambda: 1.0)
    deck.add_nvd_lookup("t", "1", "found", 1, 1, [("CVE-2024-1234", score)])
    assert deck.as_dict()["lookups"]["nvd"][0]["top"][0]["score"] == expected


@pytest.mark.parametrize(
    ("modified", "date"),
    [
        ("2025-03-02T10:11:12.000", "2025-03-02"),
        ("2025-03-02", "2025-03-02"),
        ("2025-13-40T00:00:00", None),
        ("March 2, 2025", None),
        ("2025-03-02<b>", None),
        ("", None),
        (None, None),
        (20250302, None),
    ],
)
def test_report_dates(monkeypatch, modified: Any, date: Any) -> None:
    pulses = [{"name": "R", "modified": modified, "public": 1}]
    events, _ = _run(monkeypatch, {}, OtxLookup(state="found", returned=1, pulses=pulses), nvd_key=None)
    assert _lookups(events)["otx"]["reports"] == [{"title": "R", "date": date}]


# -- states and stage status -----------------------------------------------


def test_every_nvd_state_and_a_partly_failed_step_reads_done(monkeypatch) -> None:
    nvd = {
        "a": NvdLookup(returned=3, items=_items(3)),
        "b": NvdLookup(returned=0),
        "c": RuntimeError(f"401 for apiKey={_LEAK}"),
    }
    events, _ = _run(monkeypatch, nvd, None, otx_key=None)
    states = [(e["tech"], e["state"], e["returned"], e["used"]) for e in _lookups(events)["nvd"]]
    assert states == [("a", "found", 3, 3), ("b", "none", 0, 0), ("c", "failed", 0, 0)]
    nvd_stage = _stage(events[-1], "nvd")
    assert nvd_stage["status"] == "done" and nvd_stage["reason"] is None


def test_a_wholly_failed_nvd_step_is_an_error_with_the_fixed_reason(monkeypatch) -> None:
    nvd = {"a": RuntimeError(f"boom {_LEAK}"), "b": TimeoutError("https://services.nvd.nist.gov/?key=" + _LEAK)}
    events, bundle = _run(monkeypatch, nvd, _otx())
    nvd_stage = _stage(events[-1], "nvd")
    assert nvd_stage["status"] == "error"
    assert nvd_stage["reason"] == "The NVD lookup did not finish."
    assert [e["state"] for e in _lookups(events)["nvd"]] == ["failed", "failed"]
    # the job carries on: OTX ran and the bundle is as it always was
    assert _stage(events[-1], "otx")["status"] == "done"
    assert bundle.nvd_vulnerabilities == {}


@pytest.mark.parametrize(
    ("otx", "state", "status", "reason"),
    [
        (OtxLookup(state="off"), "off", "fallback", "OTX is switched off (offline mode)"),
        (OtxLookup(state="none", returned=0), "none", "done", None),
        (OtxLookup(state="none", returned=4), "none", "done", None),
        (RuntimeError(f"OTX search failed: {_LEAK}"), "failed", "error", "The OTX lookup did not finish."),
    ],
)
def test_every_otx_state(monkeypatch, otx: Any, state: str, status: str, reason: Any) -> None:
    events, _ = _run(monkeypatch, {}, otx, nvd_key=None)
    entry = _lookups(events)["otx"]
    assert entry["state"] == state
    assert entry["used"] == 0 and entry["reports"] == []
    stage = _stage(events[-1], "otx")
    assert (stage["status"], stage["reason"]) == (status, reason)


def test_found_otx_state(monkeypatch) -> None:
    events, _ = _run(monkeypatch, {}, _otx(3, 3), nvd_key=None)
    assert _lookups(events)["otx"]["state"] == "found"


def test_no_exception_text_reaches_progress(monkeypatch) -> None:
    nvd = {
        "a": RuntimeError(f"NVD search failed: 403 Forbidden apiKey={_LEAK} https://services.nvd.nist.gov"),
        "b": NvdLookup(returned=1, items=_items(1)),
    }
    events, _ = _run(monkeypatch, nvd, RuntimeError(f"OTX search failed: X-OTX-API-KEY {_LEAK}"))
    dumped = json.dumps(events)
    for leak in (_LEAK, "apiKey", "403", "Forbidden", "https://", "RuntimeError", "search failed", "X-OTX"):
        assert leak not in dumped


def test_no_keys_still_skips_both_steps_and_writes_no_lookups(monkeypatch) -> None:
    events, _ = _run(monkeypatch, {"a": NvdLookup(returned=1, items=_items(1))}, _otx(), nvd_key=None, otx_key=None)
    assert _stage(events[-1], "nvd")["status"] == "fallback"
    assert _stage(events[-1], "nvd")["reason"] == "No NVD API key configured"
    assert _stage(events[-1], "otx")["reason"] == "No OTX API key configured"
    assert all("lookups" not in e["deck"] for e in events)


# -- timing ----------------------------------------------------------------


def test_each_answer_is_written_when_it_arrives_even_while_writes_coalesce(monkeypatch) -> None:
    clock = Clock(0.0)  # time stands still: every coalesced write would be dropped
    nvd = {
        "a": NvdLookup(returned=2, items=_items(2)),
        "b": RuntimeError("down"),
        "c": NvdLookup(returned=0),
    }
    emitter = workflow_service._StageEmitter(None, clock)
    events: list[dict] = []
    emitter._on_progress = events.append
    emitter._last_write = clock.now
    emitter._backoff_until = clock.now + 999
    _run(monkeypatch, nvd, _otx(), emitter=emitter)
    seen = [len(e["deck"].get("lookups", {}).get("nvd", [])) for e in events]
    for n in (1, 2, 3):
        assert n in seen
    # the first frame with each entry is written before the next product is checked
    details = [_stage(e, "nvd")["detail"] for e in events]
    assert details[seen.index(1)] == "a: NVD returned 2, 2 passed on"
    assert details[seen.index(1) + 1] == "Checking b 2.0"
    assert details[seen.index(2)] == "b: lookup did not finish"
    assert details[seen.index(3)] == "c: NVD returned none"
    otx_first = next(i for i, e in enumerate(events) if (e["deck"].get("lookups") or {}).get("otx"))
    assert _stage(events[otx_first], "otx")["status"] == "done"


def test_the_detail_lines_carry_both_numbers(monkeypatch) -> None:
    """The stage detail line names both numbers, not just "found 7 CVEs"."""
    events, _ = _run(monkeypatch, {"Python": NvdLookup(returned=70, items=_items(7))}, _otx())
    details = [d for d in (_stage(e, "nvd")["detail"] for e in events) if d]
    assert details == ["Checking Python 1.0", "Python: NVD returned 70, 7 passed on"]
    otx_details = [d for d in (_stage(e, "otx")["detail"] for e in events) if d]
    assert otx_details == ["Fetching Retail sector pulses"]


# -- display only ----------------------------------------------------------


def test_the_prompt_inputs_are_what_the_text_builders_give(monkeypatch) -> None:
    pg = NvdLookup(returned=50, items=_items(10))
    otx = _otx()
    nvd = {"PostgreSQL": pg, "nginx": NvdLookup(returned=0), "bad": RuntimeError("x")}
    events, with_deck = _run(monkeypatch, nvd, otx)
    _, without = _run(monkeypatch, nvd, otx, emitter=None)
    assert with_deck.nvd_vulnerabilities == without.nvd_vulnerabilities == {
        "PostgreSQL 1.0": nvd_text(pg, tech="PostgreSQL", category="Web application", version="1.0"),
        "nginx 2.0": "No vulnerabilities found",
    }
    assert with_deck.otx_vulnerabilities == without.otx_vulnerabilities == otx_text(otx, "Retail")


def test_the_agentic_path_passes_no_emitter() -> None:
    import inspect

    from aegisshield.pipeline import agentic_threat_model

    source = inspect.getsource(agentic_threat_model)
    call = source[source.index("enrichment = gather_enrichment(") :]
    call = call[: call.index(")") + 1]
    assert "emitter" not in call


def test_the_agentic_path_without_an_emitter_writes_nothing(monkeypatch) -> None:
    events, bundle = _run(monkeypatch, {"a": NvdLookup(returned=1, items=_items(1))}, _otx(), emitter=None)
    assert events == []
    assert list(bundle.nvd_vulnerabilities) == ["a 1.0"]
