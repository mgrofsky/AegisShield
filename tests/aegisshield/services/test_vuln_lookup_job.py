"""One lookup job: states, budgets, feeds once per job, wording, the result.

Also covers the job entry point ``run_lookup``.
"""

from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace

import pytest
import requests

from aegisshield.config import Settings
from aegisshield.core.errors import ValidationError
from aegisshield.services import (
    eol_service,
    epss_service,
    exploitdb_service,
    kev_service,
    vuln_lookup,
)
from aegisshield.services.exploitdb_service import ExploitRef
from aegisshield.services.kev_service import KevRecord
from aegisshield.services.vuln_lookup import (
    DetectedTech,
    NvdAnswer,
    NvdLookupError,
)

pytestmark = pytest.mark.usefixtures("lookup_no_network")

SETTINGS = Settings()


def _exact(fn):
    def lookup(*args):
        return NvdAnswer(list(fn(*args)), exact_version=True)

    return lookup


def _cve(cve_id: str, score: float | None, severity: str | None = "MEDIUM", **extra) -> dict:
    return {
        "cve_id": cve_id,
        "cvss_score": score,
        "severity": severity,
        "published": "2024-01-01",
        "description": "",
        "references": [],
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        **extra,
    }


def _t(name: str, version: str | None, source: str = "selected", distro: bool = False) -> dict:
    return {"name": name, "version": version, "source": source, "distro": distro}


def _kev(cve_id: str) -> KevRecord:
    return KevRecord(cve_id, "v", "p", "n", "2024-01-02", "d", "Patch", "2024-01-16", "Unknown")


# -- States -------------------------------------------------------------------------


def test_every_state_is_reachable_and_correctly_labeled(monkeypatch, quiet_feeds) -> None:
    def fake_nvd(name, version, api_key):
        if name == "PHP":
            return [_cve("CVE-2024-0002", 9.8, "CRITICAL"), _cve("CVE-2024-0001", 7.5, "HIGH")]
        if name == "jQuery":
            return []
        if name == "WordPress":
            raise NvdLookupError("network", "could not reach NVD")
        if name == "Drupal":
            raise NvdLookupError("nvd", "NVD lookup failed: 503")
        raise AssertionError(f"unexpected lookup for {name}")

    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(fake_nvd))
    techs = [
        _t("PHP", "8.2.35"),
        _t("jQuery", "3.6.0"),
        _t("WordPress", "6.4.2"),
        _t("Drupal", "10.1.0"),
        _t("Debian", "12"),
        _t("MySQL", None),
    ]
    out = vuln_lookup.lookup(techs, settings=SETTINGS)
    entries, cves = out.entries, out.cves
    by_name = {e["name"]: e for e in entries}
    assert [e["name"] for e in entries] == [t["name"] for t in techs]

    php = by_name["PHP"]
    assert (php["state"], php["reason"]) == ("vulnerabilities_found", None)
    assert (php["cve_count"], php["critical_count"], php["high_count"]) == (2, 1, 1)
    assert php["kev_count"] is None  # KEV off: unknown, not zero
    assert [c["cve_id"] for c in cves[0]] == ["CVE-2024-0002", "CVE-2024-0001"]

    jq = by_name["jQuery"]
    assert (jq["state"], jq["reason"], jq["cve_count"]) == ("checked_none_found", None, 0)
    assert (by_name["WordPress"]["state"], by_name["WordPress"]["reason"]) == ("not_checked", "lookup_failed")
    assert by_name["WordPress"]["failed_source"] == "network"
    assert by_name["Drupal"]["failed_source"] == "nvd"
    assert by_name["Debian"]["reason"] == "product_not_recognized"
    assert by_name["MySQL"]["reason"] == "no_version"
    for name in ("WordPress", "Drupal", "Debian", "MySQL"):
        assert by_name[name]["cve_count"] is None
        assert by_name[name]["kev_count"] is None
    assert set(php) == {
        "name", "version", "lookup_version", "product", "product_name", "source", "state", "reason",
        "failed_source", "cve_count", "critical_count", "high_count", "kev_count", "nvd_truncated", "eol", "note", "description",
    }
    assert php["product"] == "php:php"
    assert by_name["MySQL"]["product"] == "oracle:mysql"
    assert by_name["Debian"]["product"] is None
    assert php["product_name"] == "PHP"
    assert by_name["Debian"]["product_name"] is None
    for entry in entries:
        assert entry["description"] == vuln_lookup.describe(entry)


def test_at_most_fifteen_lookups_the_rest_are_over_budget(monkeypatch, quiet_feeds) -> None:
    looked: list[str] = []
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: looked.append(v) or []))
    techs = [_t("PHP", f"8.0.{i}") for i in range(20)] + [_t("MySQL", None)]
    entries = vuln_lookup.lookup(techs, settings=SETTINGS).entries
    assert len(looked) == vuln_lookup.MAX_LOOKUPS == 15
    assert [e["state"] for e in entries[:15]] == ["checked_none_found"] * 15
    assert [(e["state"], e["reason"]) for e in entries[15:20]] == [("not_checked", "over_budget")] * 5
    assert entries[20]["reason"] == "no_version"


def test_the_time_budget_stops_lookups(monkeypatch, quiet_feeds) -> None:
    clock = {"now": 1000.0}
    monkeypatch.setattr(vuln_lookup.time, "monotonic", lambda: clock["now"])

    def slow_nvd(name, version, api_key):
        clock["now"] += 100.0
        return []

    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(slow_nvd))
    entries = vuln_lookup.lookup([_t("PHP", f"8.0.{i}") for i in range(1, 5)], settings=SETTINGS).entries
    assert vuln_lookup.LOOKUP_BUDGET_SECONDS == 300.0
    assert [(e["state"], e["reason"]) for e in entries] == [
        ("checked_none_found", None),
        ("checked_none_found", None),
        ("checked_none_found", None),
        ("not_checked", "over_budget"),
    ]


def test_a_lookup_that_runs_past_the_deadline_is_abandoned(monkeypatch, quiet_feeds) -> None:
    release = threading.Event()

    def stuck_nvd(name, version, api_key):
        release.wait(5)
        return []

    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(stuck_nvd))
    monkeypatch.setattr(vuln_lookup, "MIN_LOOKUP_SECONDS", 0.05)
    try:
        entries = vuln_lookup.lookup(
            [_t("PHP", "8.0.1")], settings=SETTINGS, deadline=vuln_lookup._Deadline(0.3)
        ).entries
    finally:
        release.set()
    assert [(e["state"], e["reason"]) for e in entries] == [("not_checked", "over_budget")]


def test_lookup_works_with_no_nvd_key_and_never_asks_otx_without_one(monkeypatch, quiet_feeds) -> None:
    keys: list[str] = []
    listed = SimpleNamespace(cpeName="cpe:2.3:a:f5:nginx:1.27.5:*:*:*:*:*:*:*", deprecated=False, deprecatedBy=[])
    monkeypatch.setattr(vuln_lookup, "_nvd_search_cpe", lambda match, key: keys.append(key) or [listed])
    monkeypatch.setattr(vuln_lookup, "_nvd_search_cve", lambda name, key: keys.append(key) or [])
    monkeypatch.setattr(vuln_lookup, "otx_lookup", lambda *a: pytest.fail("no OTX key, no OTX call"))
    entries = vuln_lookup.lookup([_t("nginx", "1.27.5")], settings=SETTINGS).entries
    assert keys == ["", ""]
    assert entries[0]["state"] == "checked_none_found"


def test_kev_unavailable_is_not_reported_as_not_exploited(monkeypatch, quiet_feeds) -> None:
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: [_cve("CVE-2024-0001", 7.5, "HIGH")]))
    out = vuln_lookup.lookup([_t("PHP", "8.2.35")], settings=SETTINGS)
    assert out.entries[0]["kev_count"] is None
    assert "known-exploited status unknown" in vuln_lookup.describe(out.entries[0])
    row = vuln_lookup.describe_cve(out.entries[0], out.cves[0][0])
    assert "known-exploited status unknown" in row
    assert "known exploited (CISA KEV)" not in row


def test_end_of_life_is_carried_when_known(monkeypatch) -> None:
    for name in ("KEV", "EPSS", "EXPLOITDB"):
        monkeypatch.setenv(f"AEGIS_DISABLE_{name}", "1")
    eol_service.seed_cache_for_tests("php", [{"cycle": "7.4", "eol": "2022-11-28", "latest": "7.4.33"}])
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: []))
    entries = vuln_lookup.lookup([_t("PHP", "7.4.3")], settings=SETTINGS).entries
    assert entries[0]["eol"] == {
        "is_eol": True,
        "cycle": "7.4",
        "eol": "2022-11-28",
        "url": "https://endoflife.date/php",
    }
    assert vuln_lookup.describe(entries[0]).endswith("; this release is past end of life.")


# -- Versions in the job --------------------------------------------------------------


def test_a_distribution_build_is_looked_up_upstream_and_noted(monkeypatch, quiet_feeds) -> None:
    asked: list[str] = []

    def nvd(name, version, key):
        asked.append(version)
        return NvdAnswer([_cve("CVE-2024-0001", 7.5, "HIGH")], exact_version=True)

    monkeypatch.setattr(vuln_lookup, "nvd_lookup", nvd)
    entries = vuln_lookup.lookup(
        [_t("nginx", "1.18.0-0ubuntu1"), _t("Apache", "2.4.69", distro=True)], settings=SETTINGS
    ).entries
    assert asked == ["1.18.0", "2.4.69"]
    for entry in entries:
        assert entry["state"] == "vulnerabilities_found"
        assert entry["note"] == vuln_lookup.DISTRO_NOTE
    assert (entries[0]["version"], entries[0]["lookup_version"]) == ("1.18.0-0ubuntu1", "1.18.0")


def test_only_an_answer_carries_the_distribution_note(monkeypatch, quiet_feeds) -> None:
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: []))
    entries = vuln_lookup.lookup(
        [_t("PHP", "7.4.3 (Ubuntu)"), _t("Acme Widget", "1.2.3", distro=True), _t("jQuery", None, distro=True)],
        settings=SETTINGS,
    ).entries
    assert [(e["state"], e["note"]) for e in entries] == [
        ("checked_none_found", vuln_lookup.DISTRO_NOTE),
        ("not_checked", None),
        ("not_checked", None),
    ]


@pytest.mark.parametrize("raw", ["6.4.2~beta1", "6.4.2 beta1", "10.0.0-M1", "1.2.3-0.rc1.el9", "6.4.2 [rc1]", "6.4.2 (beta)"])
def test_a_pre_release_is_never_looked_up_as_the_release(monkeypatch, quiet_feeds, raw) -> None:
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", lambda *a: pytest.fail("pre-release looked up"))
    entries = vuln_lookup.lookup([_t("WordPress", raw)], settings=SETTINGS).entries
    assert (entries[0]["state"], entries[0]["reason"]) == ("not_checked", "version_not_recognized")


def test_version_not_recognized_reaches_the_result(monkeypatch, quiet_feeds) -> None:
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", lambda n, v, k: NvdAnswer([], exact_version=False))
    entries = vuln_lookup.lookup([_t("PHP", "8.2"), _t("WordPress", "6.5.0-beta1")], settings=SETTINGS).entries
    assert [(e["state"], e["reason"]) for e in entries] == [
        ("not_checked", "version_not_recognized"),
        ("not_checked", "version_not_recognized"),
    ]
    assert "does not recognize this version" in entries[0]["description"]


# -- Known exploited first, one cap ------------------------------------------------------


def test_a_known_exploited_cve_with_a_middling_score_still_gets_a_row(monkeypatch, quiet_feeds) -> None:
    rows = [_cve(f"CVE-2024-{i:04d}", 9.0 + i / 100, "CRITICAL") for i in range(20)]
    rows.append(_cve("CVE-2023-7777", 5.4, "MEDIUM"))
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", lambda n, v, k: NvdAnswer(rows, True))
    monkeypatch.delenv("AEGIS_DISABLE_KEV")
    kev_service.seed_cache_for_tests({"CVE-2023-7777": _kev("CVE-2023-7777")})
    out = vuln_lookup.lookup([_t("nginx", "1.18.0")], settings=SETTINGS)
    assert out.entries[0]["cve_count"] == 21 and out.entries[0]["kev_count"] == 1
    kept = out.cves[0]
    assert len(kept) == vuln_lookup.MAX_CVE_ROWS == 10
    assert kept[0]["cve_id"] == "CVE-2023-7777" and kept[0]["known_exploited"] is True
    assert kept[0]["severity"] == "high"
    scores = [c["cvss_score"] for c in kept[1:]]
    assert scores == sorted(scores, reverse=True)


# -- Feeds once per job ---------------------------------------------------------------------


def test_a_stale_kev_cache_and_dead_feeds_are_unknown_with_one_attempt_each(monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_DISABLE_EOL", "1")
    kev_service.seed_cache_for_tests({"CVE-2024-0001": _kev("CVE-2024-0001")})
    monkeypatch.setattr(kev_service, "_cache_built_at", time.time() - 25 * 3600)
    attempts: dict[str, int] = {}

    def dead(url, *args, **kwargs):
        host = url.split("/")[2]
        attempts[host] = attempts.get(host, 0) + 1
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(requests, "get", dead)
    monkeypatch.setattr(epss_service, "_http_get", lambda params, timeout: dead(epss_service.EPSS_API_URL))
    monkeypatch.setattr(
        vuln_lookup, "nvd_lookup", lambda n, v, k: NvdAnswer([_cve(f"CVE-2024-{i:04d}", 5.0) for i in range(30)], True)
    )
    techs = [_t(name, "1.0.0") for name in ("nginx", "PHP", "jQuery", "WordPress")]
    started = time.monotonic()
    out = vuln_lookup.lookup(techs, settings=SETTINGS)
    assert time.monotonic() - started < 5
    assert attempts == {"www.cisa.gov": 1, "gitlab.com": 1, "api.first.org": 1}
    for index, entry in enumerate(out.entries):
        assert entry["kev_count"] is None
        assert all(c["known_exploited"] is None for c in out.cves[index])
        assert all("epss" not in c for c in out.cves[index])
        assert "exploitdb" in out.extras[index]["errors"]


def test_epss_is_one_request_for_the_whole_job(monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_DISABLE_KEV", "1")
    monkeypatch.setenv("AEGIS_DISABLE_EOL", "1")
    monkeypatch.setenv("AEGIS_DISABLE_EXPLOITDB", "1")
    rows = {
        "nginx": [_cve("CVE-2024-0001", 9.8, "CRITICAL"), _cve("CVE-2024-0002", 5.0)],
        "PHP": [_cve("CVE-2024-0003", 7.5, "HIGH"), _cve("CVE-2024-0001", 9.8, "CRITICAL")],
    }
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: rows[n]))
    requests_made: list[dict] = []

    def epss(params, timeout):
        requests_made.append(params)
        return {
            "data": [
                {"cve": "CVE-2024-0001", "epss": "0.9", "percentile": "0.99"},
                {"cve": "CVE-2024-0003", "epss": "0.1", "percentile": "0.5"},
            ]
        }

    monkeypatch.setattr(epss_service, "_http_get", epss)
    out = vuln_lookup.lookup([_t("nginx", "1.18.0"), _t("PHP", "8.2.35")], settings=SETTINGS)
    assert len(requests_made) == 1
    assert requests_made[0]["cve"] == "CVE-2024-0001,CVE-2024-0002,CVE-2024-0003"
    assert out.cves[0][0]["epss"] == pytest.approx(0.9)
    assert "epss" not in out.cves[0][1]  # unscored: absent, not zero
    assert out.cves[1][1]["epss"] == pytest.approx(0.1)


def test_an_epss_failure_leaves_every_row_unscored(monkeypatch, quiet_feeds) -> None:
    monkeypatch.delenv("AEGIS_DISABLE_EPSS")
    monkeypatch.setattr(epss_service, "_http_get", lambda params, timeout: (_ for _ in ()).throw(RuntimeError("x")))
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: [_cve("CVE-2024-0001", 5.0)]))
    out = vuln_lookup.lookup([_t("nginx", "1.18.0")], settings=SETTINGS)
    assert "epss" not in out.cves[0][0]


def test_a_kev_load_that_does_not_finish_in_time_is_unknown(monkeypatch, quiet_feeds) -> None:
    release = threading.Event()

    def stuck(*_a, **_k):
        release.wait(5)
        return {}

    monkeypatch.setattr(kev_service, "catalog_snapshot", stuck)
    monkeypatch.setattr(vuln_lookup, "FEED_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: [_cve("CVE-2024-0001", 5.0)]))
    try:
        out = vuln_lookup.lookup([_t("nginx", "1.18.0")], settings=SETTINGS)
    finally:
        release.set()
    assert out.entries[0]["kev_count"] is None
    assert out.cves[0][0]["known_exploited"] is None


def test_an_exploitdb_load_that_does_not_finish_in_time_is_unavailable(monkeypatch, quiet_feeds) -> None:
    release = threading.Event()
    monkeypatch.setattr(exploitdb_service, "index_available", lambda **_k: release.wait(5))
    monkeypatch.setattr(vuln_lookup, "EXPLOITDB_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: [_cve("CVE-2024-0001", 5.0)]))
    try:
        out = vuln_lookup.lookup([_t("nginx", "1.18.0")], settings=SETTINGS)
    finally:
        release.set()
    assert out.extras[0]["errors"]["exploitdb"] == "ExploitDB index unavailable."


def test_exploits_are_found_once_the_index_loads(monkeypatch, quiet_feeds) -> None:
    monkeypatch.delenv("AEGIS_DISABLE_EXPLOITDB")
    exploitdb_service.seed_cache_for_tests(
        {"CVE-2024-0001": [ExploitRef("1", "PoC", "remote", "linux", "2024-02-01", "u")]}
    )
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: [_cve("CVE-2024-0001", 5.0)]))
    out = vuln_lookup.lookup([_t("nginx", "1.18.0")], settings=SETTINGS)
    assert out.extras[0]["exploits"][0]["edb_id"] == "1"


def test_feeds_are_not_loaded_when_nothing_is_looked_up(monkeypatch) -> None:
    monkeypatch.setattr(kev_service, "catalog_snapshot", lambda *a, **k: pytest.fail("no KEV load"))
    monkeypatch.setattr(exploitdb_service, "index_available", lambda **k: pytest.fail("no ExploitDB load"))
    entries = vuln_lookup.lookup([_t("Debian", "12"), _t("nginx", None)], settings=SETTINGS).entries
    assert [e["state"] for e in entries] == ["not_checked", "not_checked"]


def test_settings_offline_makes_every_lookup_a_switched_off_failure(monkeypatch) -> None:
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", lambda *a: pytest.fail("NVD is switched off"))
    entries = vuln_lookup.lookup([_t("nginx", "1.18.0")], settings=Settings(offline=True)).entries
    assert (entries[0]["reason"], entries[0]["failed_source"]) == ("lookup_failed", "disabled")
    assert "switched off on this deployment" in entries[0]["description"]


def test_call_within_raises_what_the_call_raised() -> None:
    def boom():
        raise KeyError("x")

    with pytest.raises(KeyError):
        vuln_lookup.call_within(boom, 1.0)
    assert vuln_lookup.call_within(lambda: 3, 1.0) == (True, 3)


def test_deadline_respects_a_cap() -> None:
    cap = vuln_lookup._Deadline(1.0)
    assert vuln_lookup._Deadline(100.0, cap=cap).at == cap.at
    assert 0.0 < cap.remaining() <= 1.0


# -- Wording ----------------------------------------------------------------------------------


def _entry(**overrides) -> dict:
    base = vuln_lookup._entry(_t("PHP", "8.2.35"), state="checked_none_found")
    base.update(overrides)
    return base


def test_describe_states_in_plain_words() -> None:
    describe = vuln_lookup.describe
    assert describe(
        _entry(state="vulnerabilities_found", cve_count=3, critical_count=1, high_count=2, kev_count=1)
    ) == "PHP 8.2.35: 3 known vulnerabilities in NVD (1 critical, 2 high, 1 known exploited)."
    assert describe(
        _entry(state="vulnerabilities_found", cve_count=1, critical_count=0, high_count=0, kev_count=0)
    ) == "PHP 8.2.35: 1 known vulnerability in NVD (0 critical, 0 high, 0 known exploited)."
    assert describe(_entry(cve_count=0)) == (
        "PHP 8.2.35: checked against NVD, no known vulnerabilities listed for this version."
    )
    assert describe(_entry(state="not_checked", reason="no_version", version=None)) == (
        "PHP: no version was given, so it was not checked."
    )
    assert describe(_entry(state="not_checked", reason="product_not_recognized")) == (
        "PHP 8.2.35: not checked; this product is not in the lookup catalog."
    )
    assert describe(_entry(state="not_checked", reason="over_budget")) == (
        "PHP 8.2.35: not checked; this lookup reached its limit."
    )
    assert describe(_entry(state="not_checked", reason="cancelled")) == (
        "PHP 8.2.35: not checked; the lookup was cancelled."
    )
    assert describe(_entry(state="not_checked", reason="something_new")) == "PHP 8.2.35: not checked."
    for source, text in (
        ("nvd", "NVD returned an error"),
        ("network", "the network request to NVD failed"),
        ("disabled", "vulnerability lookups are switched off on this deployment"),
        (None, "the lookup failed"),
    ):
        assert describe(
            _entry(state="not_checked", reason="lookup_failed", failed_source=source)
        ) == f"PHP 8.2.35: not checked; {text}."


def test_describe_cve_row() -> None:
    entry = _entry(state="vulnerabilities_found")
    assert vuln_lookup.describe_cve(
        entry, _cve("CVE-2024-0001", 9.8, "critical", known_exploited=True, epss=0.97123)
    ) == (
        "CVE-2024-0001 in PHP 8.2.35; CVSS 9.8; known exploited (CISA KEV); EPSS 97.1%; "
        "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"
    )
    assert vuln_lookup.describe_cve(entry, _cve("CVE-2024-0002", None, None, known_exploited=False)) == (
        "CVE-2024-0002 in PHP 8.2.35; no CVSS score yet; https://nvd.nist.gov/vuln/detail/CVE-2024-0002"
    )


def test_rows_cap_cves_and_grade_severity(monkeypatch, quiet_feeds) -> None:
    rows = [_cve(f"CVE-2024-{i:04d}", float(i) / 2, "HIGH") for i in range(1, 15)]
    rows[0]["severity"] = "weird"
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: rows if n == "Apache" else []))
    result = vuln_lookup.run_lookup([_t("Apache", "2.4.69"), _t("PHP", "8.2.35")], settings=SETTINGS)
    nvd_rows = [r for r in result["rows"] if r["source"] == "nvd"]
    assert len(nvd_rows) == 10
    assert nvd_rows[0]["finding"].startswith("CVE-2024-0014 in Apache 2.4.69; CVSS 7.0")
    assert {r["severity"] for r in nvd_rows} == {"high"}
    tech_rows = [r for r in result["rows"] if r["source"] == "lookup"]
    assert [r["technology"] for r in tech_rows] == ["Apache 2.4.69", "PHP 8.2.35"]
    assert {r["severity"] for r in tech_rows} == {"info"}
    assert vuln_lookup._cve_severity({"severity": "weird"}) == "info"


# -- run_lookup ---------------------------------------------------------------------------------


class _Sink:
    def __init__(self, cancel_after: int | None = None) -> None:
        self.records: list[dict] = []
        self._cancel_after = cancel_after

    def set(self, record: dict) -> None:
        self.records.append(dict(record))

    def cancelled(self) -> bool:
        return self._cancel_after is not None and len(self.records) >= self._cancel_after


def test_run_lookup_returns_the_documented_shape(monkeypatch, quiet_feeds) -> None:
    monkeypatch.setattr(
        vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: [_cve("CVE-2024-0001", 9.8, "CRITICAL")] if n == "PHP" else [])
    )
    sink = _Sink()
    result = vuln_lookup.run_lookup(
        [DetectedTech("PHP", "8.2.35", "tech_list", "PHP 8.2.35"), {"name": "nginx", "version": "1.27.5"}, {"name": "Debian"}],
        settings=SETTINGS,
        progress=sink,
    )
    assert set(result) == {"status", "started_at", "finished_at", "technologies", "rows", "summary"}
    assert result["status"] == "complete"
    assert result["started_at"] <= result["finished_at"]
    php, nginx, debian = result["technologies"]
    assert php["source"] == "tech_list" and nginx["source"] == "selected"
    assert php["cves"][0]["cve_id"] == "CVE-2024-0001"
    assert set(php) >= {"cves", "exploits", "otx_pulses", "errors", "state", "description"}
    assert debian["cves"] == [] and debian["errors"] == {}
    assert result["summary"] == {
        "tech_count": 3,
        "checked_count": 2,
        "not_checked_count": 1,
        "cve_count": 1,
        "critical_count": 1,
        "high_count": 0,
        "kev_count": None,  # KEV off: unknown
        "exploit_count": None,  # ExploitDB off: unknown
        "eol_count": 0,
    }
    # Per-technology progress, then the end.
    messages = [r["message"] for r in sink.records]
    assert messages == [
        "Looking up PHP 8.2.35 (1 of 3)",
        "Looking up nginx 1.27.5 (2 of 3)",
        "Looking up Debian (3 of 3)",
        "Lookup finished",
    ]
    assert [r["done"] for r in sink.records] == [0, 1, 2, 3]
    assert {r["total"] for r in sink.records} == {3}
    json.dumps(result)  # JSON-ready, for the workspace


def test_an_unknown_kev_count_stays_unknown_in_the_overall_summary(monkeypatch, quiet_feeds) -> None:
    """One unknown KEV count keeps the total unknown; it must not read as zero."""
    monkeypatch.delenv("AEGIS_DISABLE_KEV")
    kev_service.seed_cache_for_tests({"CVE-2024-0001": _kev("CVE-2024-0001")})
    calls = {"n": 0}

    def flaky_snapshot(*a, **k):
        calls["n"] += 1
        return None

    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: [_cve("CVE-2024-0001", 9.8, "CRITICAL")]))
    known = vuln_lookup.run_lookup([_t("nginx", "1.18.0"), _t("PHP", "8.2.35")], settings=SETTINGS)
    assert known["summary"]["kev_count"] == 2
    monkeypatch.setattr(kev_service, "catalog_snapshot", flaky_snapshot)
    unknown = vuln_lookup.run_lookup([_t("nginx", "1.18.0"), _t("PHP", "8.2.35")], settings=SETTINGS)
    assert calls["n"] == 1  # loaded once per job
    assert unknown["summary"]["kev_count"] is None


def test_nothing_checked_means_unknown_totals_not_zero(quiet_feeds) -> None:
    result = vuln_lookup.run_lookup([_t("Debian", "12"), _t("nginx", None)], settings=SETTINGS)
    summary = result["summary"]
    assert summary["checked_count"] == 0
    for key in ("cve_count", "critical_count", "high_count", "kev_count", "exploit_count"):
        assert summary[key] is None, key


def test_an_unavailable_exploitdb_makes_the_exploit_total_unknown(monkeypatch, quiet_feeds) -> None:
    monkeypatch.delenv("AEGIS_DISABLE_EXPLOITDB")
    monkeypatch.setattr(exploitdb_service, "index_available", lambda **k: False)
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: [_cve("CVE-2024-0001", 5.0)]))
    result = vuln_lookup.run_lookup([_t("nginx", "1.18.0")], settings=SETTINGS)
    assert result["summary"]["exploit_count"] is None


def test_eol_count_counts_releases_past_end_of_life(monkeypatch, quiet_feeds) -> None:
    monkeypatch.delenv("AEGIS_DISABLE_EOL")
    eol_service.seed_cache_for_tests("php", [{"cycle": "7.4", "eol": "2022-11-28"}])
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: []))
    result = vuln_lookup.run_lookup([_t("PHP", "7.4.3")], settings=SETTINGS)
    assert result["summary"]["eol_count"] == 1


def test_cancel_stops_the_job_and_marks_the_rest(monkeypatch, quiet_feeds) -> None:
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: []))
    sink = _Sink(cancel_after=1)
    result = vuln_lookup.run_lookup(
        [_t("PHP", "8.2.35"), _t("nginx", "1.27.5"), _t("jQuery", "3.6.0")], settings=SETTINGS, progress=sink
    )
    assert result["status"] == "cancelled"
    assert [(t["state"], t["reason"]) for t in result["technologies"]] == [
        ("checked_none_found", None),
        ("not_checked", "cancelled"),
        ("not_checked", "cancelled"),
    ]
    assert sink.records[-1]["message"] == "Lookup cancelled"


def test_a_progress_sink_without_cancel_is_fine(monkeypatch, quiet_feeds) -> None:
    records: list[dict] = []
    sink = SimpleNamespace(set=records.append)
    result = vuln_lookup.run_lookup([_t("Debian", "12")], settings=SETTINGS, progress=sink)
    assert result["status"] == "complete" and records


def test_keys_never_reach_the_result_or_the_progress(monkeypatch, quiet_feeds) -> None:
    nvd_key, otx_key = "nvd-secret-123456", "otx-secret-654321"

    def nvd(name, version, api_key):
        assert api_key == nvd_key
        raise NvdLookupError("nvd", f"bad key {api_key}")

    def otx(name, api_key):
        raise RuntimeError(f"otx refused {api_key}")

    monkeypatch.setattr(vuln_lookup, "nvd_lookup", nvd)
    monkeypatch.setattr(vuln_lookup, "otx_lookup", otx)
    sink = _Sink()
    result = vuln_lookup.run_lookup(
        [_t("nginx", "1.18.0")], nvd_api_key=nvd_key, otx_api_key=otx_key, settings=SETTINGS, progress=sink
    )
    text = json.dumps(result) + json.dumps(sink.records)
    assert nvd_key not in text and otx_key not in text
    assert set(result["technologies"][0]["errors"]) == {"nvd", "otx"}


def test_run_lookup_cleans_and_deduplicates_input(quiet_feeds) -> None:
    result = vuln_lookup.run_lookup(
        [
            {"name": "Debian", "version": "12"},
            {"name": "debian", "version": "12"},
            {"name": "bad\u202ename"},
            {"name": ""},
            {"name": "Acme", "version": "1.0\n2", "source": 7},
            "not a technology",
        ],
        settings=SETTINGS,
    )
    techs = result["technologies"]
    assert [(t["name"], t["version"], t["source"]) for t in techs] == [
        ("Debian", "12", "selected"),
        ("Acme", None, "selected"),
    ]


def test_run_lookup_refuses_too_many_technologies() -> None:
    with pytest.raises(ValidationError):
        vuln_lookup.run_lookup(
            [_t(f"Tech{i}", None) for i in range(vuln_lookup.MAX_TECHNOLOGIES + 1)], settings=SETTINGS
        )
