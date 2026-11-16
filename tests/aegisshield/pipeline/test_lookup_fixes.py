"""Fixes to what the lookups show, found in a review of the lookup record.

These run the real ``nvd_service`` and ``otx_service`` against a fake
``nvdlib`` and a fake ``OTXv2`` (one layer below ``lookup_nvd`` and
``lookup_otx``, which test_lookup_record.py replaces), so the sort, the CPE
step, and the record run together.
"""

from __future__ import annotations

import json
import logging
import math
from types import SimpleNamespace
from typing import Any

import pytest

from aegisshield.config import Settings
from aegisshield.core.errors import IntelLookupError
from aegisshield.pipeline import live_deck, nvd_service, otx_service, workflow_service
from aegisshield.pipeline.live_deck import LiveDeck, cvss, lookup_count, lookup_text


def _search_nvd(api_key, cpe_prefix, version, tech, category, config):  # noqa: ANN001, ANN202
    """``lookup_nvd`` then ``nvd_text``, as the threat-model run composes them."""
    lookup = nvd_service.lookup_nvd(api_key, cpe_prefix, version, config)
    return nvd_service.nvd_text(lookup, tech=tech, category=category, version=version)

_APP = {
    "app_type": "Web application",
    "industry_sector": "Retail",
    "authentication": ["OAuth2"],
    "internet_facing": "Yes",
    "sensitive_data": "Payment card data",
}
_DESCRIPTION = "An online retail checkout service exposing payment APIs over the internet."
NOCPE = "nocpe"


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        self.now += 0.5
        return self.now


def cve(n: int, score: Any = None, published: str = "2024-01-01T00:00:00.000") -> SimpleNamespace:
    return SimpleNamespace(
        id=f"CVE-2024-{10000 + n}",
        score=["V31", 5.0, "MEDIUM"] if score is None else score,
        published=published,
        descriptions=[SimpleNamespace(value=f"entry {n}")],
    )


def pulse(n: int, modified: str = "2025-06-01T00:00:00.000", **extra: Any) -> dict[str, Any]:
    return {"name": f"Report {n}", "modified": modified, "public": 1, **extra}


def _fakes(monkeypatch, techs: dict[str, Any], pulses: Any) -> None:
    """``techs`` maps a cpe prefix to a list of entries, an exception, or NOCPE."""

    def search_cpe(cpeMatchString: str, key: Any = None, **_k: Any) -> list[Any]:
        prefix = cpeMatchString.rsplit(":", 2)[0] + ":"
        if techs.get(prefix) == NOCPE:
            return []
        return [SimpleNamespace(cpeName=prefix, deprecated=False)]

    def search_cve(cpeName: str, key: Any = None, **_k: Any) -> Any:
        value = techs[cpeName]
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

    monkeypatch.setattr(nvd_service, "nvdlib", SimpleNamespace(searchCPE=search_cpe, searchCVE=search_cve))
    monkeypatch.setattr(otx_service, "BoundedOTXv2", FakeOTX)
    # retry settings are module constants, not Settings fields
    monkeypatch.setattr(workflow_service, "LOOKUP_MAX_RETRIES", 1)
    monkeypatch.setattr(workflow_service, "LOOKUP_RETRY_BASE_DELAY_S", 0.0)


def _run(
    monkeypatch,
    techs: dict[str, tuple[str, Any]],
    pulses: Any = None,
    *,
    emitter: bool = True,
    otx_key: str | None = "otx-key",
) -> tuple[list[dict], Any]:
    """``techs`` maps a technology name to (version, what NVD gives)."""
    _fakes(monkeypatch, {f"cpe:2.3:a:x:{t}:": v for t, (_ver, v) in techs.items()}, pulses or [pulse(1)])
    events: list[dict] = []
    details = dict(_APP)
    details["selected_technologies"] = {t: f"cpe:2.3:a:x:{t}:" for t in techs}
    details["selected_versions"] = {t: ver for t, (ver, _v) in techs.items()}
    bundle = workflow_service.gather_enrichment(
        nvd_api_key="nvd-key",
        otx_api_key=otx_key,
        app_details=details,
        app_description=_DESCRIPTION,
        settings=Settings(),
        emitter=workflow_service._StageEmitter(events.append, Clock()) if emitter else None,
    )
    return events, bundle


def _stage(record: dict, sid: str) -> dict:
    return next(s for s in record["stages"] if s["id"] == sid)


def _lookups(events: list[dict]) -> dict:
    return events[-1]["deck"]["lookups"]


def _details(events: list[dict], sid: str = "nvd") -> list[str]:
    out: list[str] = []
    for e in events:
        d = _stage(e, sid)["detail"]
        if d and (not out or out[-1] != d):
            out.append(d)
    return out


# -- item 1 through the real service: sort, CPE step, and record together --


def test_mixed_versions_and_an_unscored_entry_through_the_real_service(monkeypatch) -> None:
    entries = (
        [cve(i, ["V2", 10.0, "HIGH"]) for i in range(6)]
        + [cve(10 + i, ["V30", 9.8, "CRITICAL"]) for i in range(6)]
        + [cve(20 + i, ["V31", 2.0 + i / 10, "LOW"]) for i in range(10)]
        + [cve(40, [None, None, None])]
    )
    events, bundle = _run(monkeypatch, {"PostgreSQL": ("15.4", entries)})
    (entry,) = _lookups(events)["nvd"]
    assert (entry["state"], entry["returned"], entry["used"]) == ("found", 23, 10)
    assert [t["score"] for t in entry["top"]] == [10.0] * 5
    text = bundle.nvd_vulnerabilities["PostgreSQL 15.4"]
    assert text.count("CVSS Score: ['V2', 10.0, 'HIGH']") == 6
    assert text.count("CVSS Score: ['V30', 9.8, 'CRITICAL']") == 4
    assert _stage(events[-1], "nvd")["status"] == "done"


def test_an_entry_with_no_score_no_longer_loses_the_technology(monkeypatch) -> None:
    events, bundle = _run(monkeypatch, {"PostgreSQL": ("15.4", [cve(1), cve(2, [None, None, None]), cve(3)])})
    (entry,) = _lookups(events)["nvd"]
    assert (entry["state"], entry["returned"], entry["used"]) == ("found", 3, 3)
    assert [t["id"] for t in entry["top"]][-1] == "CVE-2024-10002"
    assert _stage(events[-1], "nvd")["status"] == "done"
    assert "CVE ID: CVE-2024-10002" in bundle.nvd_vulnerabilities["PostgreSQL 15.4"]


# -- item 2: no CPE is its own answer; failures speak about our side ------


def test_no_cpe_raises_its_own_type(monkeypatch) -> None:
    _fakes(monkeypatch, {"cpe:": NOCPE}, [])
    config = nvd_service.NvdSearchConfig(max_retries=1, base_delay_seconds=0.0)
    with pytest.raises(nvd_service.NoCpeMatch) as caught:
        nvd_service.lookup_nvd("key", "cpe:", "1.0", config)
    # still an upstream error, so every other caller is unchanged
    assert isinstance(caught.value, IntelLookupError)
    # the message is a fixed sentence; it does not quote the CPE prefix
    with pytest.raises(IntelLookupError, match="NVD has no entry for this product and version"):
        _search_nvd("key", "cpe:", "1.0", "t", "c", config)


def test_what_is_recorded_when_no_cpe_matches(monkeypatch) -> None:
    events, bundle = _run(monkeypatch, {"PostgreSQL": ("15.4", [cve(i) for i in range(12)]), "nginx": ("9.9.9", NOCPE)})
    pg, ng = _lookups(events)["nvd"]
    assert (pg["state"], pg["returned"], pg["used"]) == ("found", 12, 10)
    assert ng == {**ng, "tech": "nginx", "version": "9.9.9", "state": "unknown", "returned": 0, "used": 0, "top": []}
    assert _stage(events[-1], "nvd")["status"] == "done"
    assert "nginx 9.9.9" not in bundle.nvd_vulnerabilities
    assert _details(events)[-1] == "nginx: NVD has no entry"


def test_no_cpe_for_every_technology_is_an_answer_not_a_failure(monkeypatch) -> None:
    events, bundle = _run(monkeypatch, {"PostgreSQL": ("15.4", NOCPE), "nginx": ("1.24.0", NOCPE)})
    assert [e["state"] for e in _lookups(events)["nvd"]] == ["unknown", "unknown"]
    nvd = _stage(events[-1], "nvd")
    assert (nvd["status"], nvd["reason"]) == ("done", None)
    assert bundle.nvd_vulnerabilities == {}


def test_unknown_is_signalled_by_type_not_by_message(monkeypatch) -> None:
    raised = {
        "a": IntelLookupError("No CPE found for a version 1"),
        "b": nvd_service.NoCpeMatch("anything at all"),
    }

    def fake(*, api_key: str, cpe_prefix: str, version: str, config: Any) -> Any:
        raise raised[cpe_prefix.split(":")[-2]]

    monkeypatch.setattr(workflow_service, "lookup_nvd", fake)
    events, _ = _run(monkeypatch, {"a": ("1", []), "b": ("1", [])})
    assert [e["state"] for e in _lookups(events)["nvd"]] == ["failed", "unknown"]


def test_a_wholly_failed_step_says_the_lookup_did_not_finish(monkeypatch) -> None:
    events, _ = _run(monkeypatch, {"a": ("1", RuntimeError("x")), "b": ("2", RuntimeError("y"))}, RuntimeError("z"))
    assert (_stage(events[-1], "nvd")["status"], _stage(events[-1], "nvd")["reason"]) == ("error", "The NVD lookup did not finish.")
    assert (_stage(events[-1], "otx")["status"], _stage(events[-1], "otx")["reason"]) == ("error", "The OTX lookup did not finish.")
    assert "did not answer" not in json.dumps(events)


def test_failed_and_unknown_together_is_not_wholly_failed(monkeypatch) -> None:
    events, _ = _run(monkeypatch, {"a": ("1", RuntimeError("x")), "b": ("2", NOCPE)})
    assert _stage(events[-1], "nvd")["status"] == "done"


# -- item 3: totals over every technology ----------------------------------


def _thirty(fail: range) -> dict[str, tuple[str, Any]]:
    return {
        f"Tech{i:02d}": (f"{i}.0", RuntimeError("down") if i in fail else [cve(i * 60 + j) for j in range(40)])
        for i in range(30)
    }


def test_totals_count_every_technology_listed_or_not(monkeypatch) -> None:
    events, _ = _run(monkeypatch, _thirty(range(0)))
    lk = _lookups(events)
    assert len(lk["nvd"]) == 25 and lk["nvd_more"] == 5
    assert lk["nvd_total"] == {"checked": 30, "returned": 1200, "used": 300, "failed": 0, "unknown": 0}


def test_totals_when_the_listed_ones_fail_and_the_rest_answer(monkeypatch) -> None:
    events, bundle = _run(monkeypatch, _thirty(range(25)))
    lk = _lookups(events)
    assert lk["nvd_total"] == {"checked": 30, "returned": 200, "used": 50, "failed": 25, "unknown": 0}
    assert _stage(events[-1], "nvd")["status"] == "done"
    assert len(bundle.nvd_vulnerabilities) == 5


def test_totals_count_failures_among_unlisted_technologies(monkeypatch) -> None:
    techs = _thirty(range(25, 30))
    techs["Tech29"] = ("29.0", NOCPE)
    events, _ = _run(monkeypatch, techs)
    assert _lookups(events)["nvd_total"] == {"checked": 30, "returned": 1000, "used": 250, "failed": 4, "unknown": 1}


def test_totals_are_capped_and_running(monkeypatch) -> None:
    deck = LiveDeck(lambda: 1.0)
    deck.add_nvd_lookup("a", "1", "found", 9999, 10, [])
    assert deck.as_dict()["lookups"]["nvd_total"]["returned"] == 9999
    deck.add_nvd_lookup("b", "1", "found", 5000, 10, [])
    total = deck.as_dict()["lookups"]["nvd_total"]
    assert total == {"checked": 2, "returned": 9999, "used": 20, "failed": 0, "unknown": 0}


# -- item 4: display code can never stop a run -----------------------------


@pytest.mark.parametrize(
    "value",
    [10**400, -(10**400), ["V31", 10**400, "HIGH"], ("V31", 10**400), float("nan"), float("inf"), True, "9", None, [], {}, object()],
    ids=lambda v: type(v).__name__,
)
def test_cvss_and_lookup_count_never_raise(value: Any) -> None:
    assert cvss(value) is None
    assert lookup_count(value) in (0, 9999)
    assert lookup_count(10**400) == 9999


def test_the_huge_score_input_goes_through_and_builds_the_same_prompt_inputs(monkeypatch) -> None:
    entries = [cve(1, ["V31", 10**400, "HIGH"]), cve(2)]
    events, with_deck = _run(monkeypatch, {"PostgreSQL": ("15.4", entries)})
    _, without = _run(monkeypatch, {"PostgreSQL": ("15.4", entries)}, emitter=False)
    assert with_deck == without
    assert "CVE-2024-10001" in with_deck.nvd_vulnerabilities["PostgreSQL 15.4"]
    (entry,) = _lookups(events)["nvd"]
    assert entry["top"][0] == {"id": "CVE-2024-10001", "score": None}
    json.dumps(events, allow_nan=False)


@pytest.mark.parametrize("method", ["add_nvd_lookup", "set_otx_lookup"])
def test_a_deck_method_that_raises_does_not_stop_the_run(monkeypatch, caplog, method: str) -> None:
    def broken(*_a: Any, **_k: Any) -> None:
        raise ValueError("display broke")

    techs = {"PostgreSQL": ("15.4", [cve(i) for i in range(3)]), "nginx": ("1.24.0", [])}
    _, without = _run(monkeypatch, techs)
    monkeypatch.setattr(LiveDeck, method, broken)
    with caplog.at_level(logging.WARNING, logger="aegisshield.pipeline.workflow_service"):
        events, bundle = _run(monkeypatch, techs)
    assert bundle == without
    assert _stage(events[-1], "nvd")["status"] == "done"
    assert _stage(events[-1], "otx")["status"] == "done"
    assert any("display" in r.getMessage().lower() for r in caplog.records if r.levelno == logging.WARNING)


# -- item 10: OTX wording facts in the record ------------------------------


def test_otx_at_its_search_limit_is_flagged(monkeypatch) -> None:
    events, _ = _run(monkeypatch, {}, [pulse(i) for i in range(100)])
    otx = _lookups(events)["otx"]
    assert (otx["returned"], otx["used"], otx["at_least"]) == (100, 10, True)
    events, _ = _run(monkeypatch, {}, [pulse(i) for i in range(99)])
    assert _lookups(events)["otx"]["at_least"] is False


def test_the_offline_switch_skips_the_otx_step(monkeypatch) -> None:
    _fakes(monkeypatch, {}, [pulse(1)])
    events: list[dict] = []
    details = {**_APP, "selected_technologies": {}, "selected_versions": {}}
    bundle = workflow_service.gather_enrichment(
        nvd_api_key=None,
        otx_api_key="otx-key",
        app_details=details,
        app_description=_DESCRIPTION,
        settings=Settings(offline=True),
        emitter=workflow_service._StageEmitter(events.append, Clock()),
    )
    otx = _stage(events[-1], "otx")
    assert (otx["status"], otx["reason"]) == ("fallback", "OTX is switched off (offline mode)")
    assert _lookups(events)["otx"]["state"] == "off"
    # the prompt text is the sentinel it always was
    assert bundle.otx_vulnerabilities == "OTX threat intelligence disabled (offline mode)"


# -- item 11: the stage detail line carries both numbers ------------------


def test_the_detail_lines_carry_both_numbers(monkeypatch) -> None:
    events, _ = _run(
        monkeypatch,
        {
            "PostgreSQL": ("15.4", [cve(i) for i in range(50)]),
            "Redis": ("7.2", []),
            "X": ("1", NOCPE),
            "Y": ("1", RuntimeError("down")),
        },
    )
    assert _details(events) == [
        "Checking PostgreSQL 15.4",
        "PostgreSQL: NVD returned 50, 10 passed on",
        "Checking Redis 7.2",
        "Redis: NVD returned none",
        "Checking X 1",
        "X: NVD has no entry",
        "Checking Y 1",
        "Y: lookup did not finish",
    ]
    assert not any("CVEs" in d for d in _details(events))


# -- item 12: cleaning -----------------------------------------------------


@pytest.mark.parametrize("digits", ["\uff12\uff10\uff12\uff14-\uff11\uff12\uff13\uff14", "\u0662\u0660\u0662\u0664-\u0661\u0662\u0663\u0664", "2024-\u0661\u0662\u0663\u0664"])
def test_the_id_pattern_takes_ascii_digits_only(digits: str) -> None:
    assert live_deck.cve_id(f"CVE-{digits}") is None


def test_lookup_strings_lose_invisible_and_line_controls() -> None:
    invisible = "".join(chr(c) for c in range(0x200B, 0x2010)) + "\u061c\u2028\u2029\ufeff\x7f"
    c1 = "".join(chr(c) for c in range(0x80, 0xA0))
    assert lookup_text(f"Post{invisible}gre{c1}SQL", 60) == "PostgreSQL"
    assert lookup_text("Redis\nCluster\tEdition", 60) == "Redis Cluster Edition"
    assert lookup_text("a\u202eb\u2066c", 60) == "abc"
    deck = LiveDeck(lambda: 1.0)
    deck.add_nvd_lookup(f"n\u200bginx{c1}", "1.\u20280", "none", 0, 0, [])
    deck.set_otx_lookup("Ret\ufeffail", "found", 1, 1, [(f"Title\n{invisible}one", "2025-01-01")])
    lk = deck.as_dict()["lookups"]
    assert (lk["nvd"][0]["tech"], lk["nvd"][0]["version"]) == ("nginx", "1.0")
    assert (lk["otx"]["sector"], lk["otx"]["reports"][0]["title"]) == ("Retail", "Title one")


def test_the_cvss_number_is_finite_for_ordinary_values() -> None:
    assert cvss(["V31", 8.8, "HIGH"]) == 8.8 and cvss(7) == 7.0 and math.isfinite(cvss(("V2", 10, "X")) or 0)


# -- the visitor's keys never leave the lookup -----------------------------

_NVD_KEY = "sk-test-SENTINEL-nvd-key-123456"
_OTX_KEY = "SENTINEL-otx-key-abcdef"
_KEYS = (_NVD_KEY, _OTX_KEY)


def _leaky_fakes(monkeypatch, step: str) -> None:
    """nvdlib and OTXv2 that fail with the key in the message. ``step`` picks
    the NVD call that fails: the CPE step or the CVE search."""

    def search_cpe(cpeMatchString: str, key: Any = None, **_k: Any) -> list[Any]:
        if step == "cpe":
            raise RuntimeError(f"401 Unauthorized for apiKey={key}")
        return [SimpleNamespace(cpeName=cpeMatchString, deprecated=False)]

    def search_cve(cpeName: str, key: Any = None, **_k: Any) -> Any:
        raise RuntimeError(f"403 Forbidden https://services.nvd.nist.gov/?apiKey={key}")

    class LeakyOTX:
        def __init__(self, key: str) -> None:
            self.key = key

        def search_pulses(self, _query: str, max_results: int = 0) -> Any:
            raise RuntimeError(f"OTX search failed: X-OTX-API-KEY {self.key}")

    monkeypatch.setattr(nvd_service, "nvdlib", SimpleNamespace(searchCPE=search_cpe, searchCVE=search_cve))
    monkeypatch.setattr(otx_service, "BoundedOTXv2", LeakyOTX)
    monkeypatch.setattr(workflow_service, "LOOKUP_MAX_RETRIES", 1)
    monkeypatch.setattr(workflow_service, "LOOKUP_RETRY_BASE_DELAY_S", 0.0)


def _no_key_in(text: str) -> None:
    for key in _KEYS:
        assert key not in text


@pytest.mark.parametrize("step", ["cpe", "cve"])
def test_a_key_in_an_upstream_error_reaches_no_message_record_or_log(monkeypatch, caplog, step: str) -> None:
    _leaky_fakes(monkeypatch, step)
    config = nvd_service.NvdSearchConfig(max_retries=1, base_delay_seconds=0.0)
    raised: list[BaseException] = []
    events: list[dict] = []
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(IntelLookupError) as nvd_caught:
            nvd_service.lookup_nvd(_NVD_KEY, "cpe:2.3:a:x:postgresql:", "15.4", config)
        raised.append(nvd_caught.value)
        with pytest.raises(IntelLookupError) as otx_caught:
            otx_service.lookup_otx(_OTX_KEY, "Retail", 30, 10, 1, 0.0)
        raised.append(otx_caught.value)
        details = {
            **_APP,
            "selected_technologies": {"PostgreSQL": "cpe:2.3:a:x:postgresql:", "nginx": "cpe:2.3:a:x:nginx:"},
            "selected_versions": {"PostgreSQL": "15.4", "nginx": "1.24.0"},
        }
        workflow_service.gather_enrichment(
            nvd_api_key=_NVD_KEY,
            otx_api_key=_OTX_KEY,
            app_details=details,
            app_description=_DESCRIPTION,
            settings=Settings(),
            emitter=workflow_service._StageEmitter(events.append, Clock()),
        )
    # the cause still holds the key (kept for debugging); the messages do not
    assert _NVD_KEY in str(raised[0].__cause__) and _OTX_KEY in str(raised[1].__cause__)
    for exc in raised:
        _no_key_in(str(exc))
        _no_key_in(repr(exc.args))
    assert events
    assert _stage(events[-1], "nvd")["status"] == "error"
    assert _stage(events[-1], "otx")["status"] == "error"
    _no_key_in(json.dumps(events))
    assert caplog.records
    formatter = logging.Formatter()
    for record in caplog.records:
        _no_key_in(record.getMessage())
        _no_key_in(formatter.format(record))
    _no_key_in(caplog.text)


def test_offline_otx_makes_no_client_call(monkeypatch) -> None:
    calls: list[str] = []

    class Spy:
        def __init__(self, key: str) -> None:
            calls.append("init")

        def search_pulses(self, *_a: Any, **_k: Any) -> Any:
            calls.append("search")
            return {"results": [pulse(1)]}

    monkeypatch.setattr(otx_service, "BoundedOTXv2", Spy)
    lookup = otx_service.lookup_otx(_OTX_KEY, "Retail", 30, 10, 1, 0.0, offline=True)
    assert lookup.state == "off"
    assert calls == []
