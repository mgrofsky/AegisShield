"""The per-technology lookup: product mapping, NVD, KEV, EPSS, ExploitDB, EOL, OTX.

No network: every NVD seam and feed is stubbed.
"""

from __future__ import annotations

import json
import re
import sys
import time
from types import SimpleNamespace

import pytest
import requests

from aegisshield.config import Settings
from aegisshield.data import data_path
from aegisshield.services import (
    eol_service,
    epss_service,
    exploitdb_service,
    kev_service,
    vuln_lookup,
)
from aegisshield.services.exploitdb_service import ExploitRef
from aegisshield.services.kev_service import KevRecord
from aegisshield.services.tech_products import product_for
from aegisshield.services.vuln_lookup import DetectedTech, FeedAvailability, NvdAnswer

pytestmark = pytest.mark.usefixtures("lookup_no_network")


def _exact(fn):
    """Wrap a stub that returns CVE rows as an answer for a listed version."""

    def lookup(*args):
        return NvdAnswer(list(fn(*args)), exact_version=True)

    return lookup


def _tech(name: str, version: str | None) -> DetectedTech:
    return DetectedTech(name=name, version=version, source="tech", raw=name)


def _cve(cve_id: str, score: float | None, severity: str | None = "MEDIUM") -> dict:
    return {
        "cve_id": cve_id,
        "cvss_score": score,
        "severity": severity,
        "published": "2024-01-01",
        "description": "",
        "references": [],
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def _cpe(name: str, deprecated_by: str | None = None):
    return SimpleNamespace(
        cpeName=name,
        deprecated=deprecated_by is not None,
        deprecatedBy=[SimpleNamespace(cpeName=deprecated_by)] if deprecated_by else [],
    )


def _kev(cve_id: str) -> KevRecord:
    return KevRecord(cve_id, "F5", "nginx", "x", "2024-01-02", "x", "Patch", "2024-01-16", "Unknown")


# -- Mapping file ---------------------------------------------------------------

PRODUCT_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9 .]{0,39}")


def test_mapping_file_is_valid_and_complete() -> None:
    products = json.loads(data_path("tech_cpe_map.json").read_text())["products"]
    assert len(products) >= 30
    seen_names: set[str] = set()
    for entry in products:
        assert entry["vendor"] and entry["product"], entry
        assert entry["names"], entry
        assert entry["from"].startswith(("wizard_catalog", "nvd_cpe_dictionary_")), entry
        # The one canonical name shown for the product; the only product text
        # that reaches a threat-model description, so plain characters only.
        assert PRODUCT_NAME_RE.fullmatch(entry.get("product_name") or ""), entry
        for name in entry["names"]:
            assert name.lower() not in seen_names, f"duplicate name {name}"
            seen_names.add(name.lower())


def test_product_for_resolves_names_case_insensitively() -> None:
    ref = product_for("Apache HTTP Server")
    assert (ref.vendor, ref.product) == ("apache", "http_server")
    assert product_for("apache") == ref
    assert ref.name == "Apache HTTP Server"
    assert product_for("Microsoft-IIS").name == "Microsoft IIS"
    assert product_for("NGINX").product == "nginx"
    assert product_for("Debian") is None
    assert product_for("") is None
    assert product_for(None) is None
    # Left out on purpose: X-AspNet-Version reports a runtime build number NVD
    # cannot match, so a lookup would say "none found" falsely.
    assert product_for("Microsoft ASP.NET") is None


def test_mapping_pairs_confirmed_against_the_nvd_dictionary() -> None:
    mysql = product_for("MySQL")
    assert (mysql.vendor, mysql.product) == ("oracle", "mysql")
    assert ("mysql", "mysql") in mysql.accepted
    nginx = product_for("nginx")
    assert nginx.accepted[0] == ("f5", "nginx") and ("nginx", "nginx") in nginx.accepted
    express = product_for("Express")
    assert (express.vendor, express.product) == ("openjsf", "express")
    httpd = product_for("httpd")
    assert (httpd.vendor, httpd.product) == ("apache", "http_server")


# -- NVD: product check and CPE choice -------------------------------------------


def _nvd(monkeypatch, cpe_results: list, cve_rows: list) -> list[str]:
    used: list[str] = []
    monkeypatch.setattr(vuln_lookup, "_nvd_search_cpe", lambda m, k: cpe_results)
    monkeypatch.setattr(vuln_lookup, "_nvd_search_cve", lambda name, k: used.append(name) or cve_rows)
    return used


def test_nvd_lookup_searches_with_the_mapped_product_and_rejects_a_wrong_one(monkeypatch) -> None:
    searched: dict[str, str] = {}

    def fake_cpe(match_string, api_key):
        searched["cpe"] = match_string
        return [
            _cpe("cpe:2.3:a:apache:tomcat:2.4.49:*:*:*:*:*:*:*"),
            _cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
        ]

    def fake_cve(cpe_name, api_key):
        searched["cve"] = cpe_name
        return []

    monkeypatch.setattr(vuln_lookup, "_nvd_search_cpe", fake_cpe)
    monkeypatch.setattr(vuln_lookup, "_nvd_search_cve", fake_cve)
    answer = vuln_lookup.nvd_lookup("Apache HTTP Server", "2.4.49", "")
    assert answer == NvdAnswer([], exact_version=True)
    assert searched["cpe"] == "cpe:2.3:a:apache:http_server:2.4.49:*"
    assert searched["cve"] == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"


def test_nvd_lookup_never_uses_a_cpe_for_another_product(monkeypatch) -> None:
    used = _nvd(monkeypatch, [_cpe("cpe:2.3:a:nginx_ui:nginx_ui:1.18.0:*:*:*:*:*:*:*")], [])
    vuln_lookup.nvd_lookup("nginx", "1.18.0", "")
    assert used == ["cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"]


def test_nvd_lookup_follows_a_deprecated_name(monkeypatch) -> None:
    used = _nvd(
        monkeypatch,
        [
            _cpe(
                "cpe:2.3:a:jquery:jquery:3.6:*:*:*:*:*:*:*",
                deprecated_by="cpe:2.3:a:jquery:jquery:3.6.0:*:*:*:*:*:*:*",
            )
        ],
        [],
    )
    vuln_lookup.nvd_lookup("jQuery", "3.6", "")
    assert used == ["cpe:2.3:a:jquery:jquery:3.6.0:*:*:*:*:*:*:*"]


def test_nvd_lookup_skips_short_and_malformed_cpe_names(monkeypatch) -> None:
    used = _nvd(monkeypatch, [_cpe("cpe:2.3:a"), _cpe("cpe:2.3:a:f5:nginx")], [])
    assert vuln_lookup.nvd_lookup("nginx", "1.18.0", "").exact_version is False
    assert used == ["cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"]


def test_nvd_lookup_does_not_look_up_an_unmapped_or_unversioned_technology() -> None:
    nothing = NvdAnswer([], exact_version=False)
    assert vuln_lookup.nvd_lookup("Debian", "12", "key") == nothing
    assert vuln_lookup.nvd_lookup("nginx", None, "key") == nothing
    assert vuln_lookup.nvd_lookup("nginx", "1.2 3", "key") == nothing


def test_nvd_lookup_converts_cve_objects(monkeypatch) -> None:
    cve = SimpleNamespace(
        id="CVE-2021-41773",
        score=["V31", 7.5, "HIGH"],
        descriptions=[SimpleNamespace(value="Path traversal")],
        references=[SimpleNamespace(url="https://example.com/a")],
        published="2021-10-05T09:15:07.593",
    )
    _nvd(monkeypatch, [], [cve])
    assert vuln_lookup.nvd_lookup("Apache", "2.4.49", "").cves == [
        {
            "cve_id": "CVE-2021-41773",
            "cvss_score": 7.5,
            "cvss_version": "3.1",
            "severity": "HIGH",
            "published": "2021-10-05",
            "description": "Path traversal",
            "references": ["https://example.com/a"],
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        }
    ]


@pytest.mark.parametrize(
    ("error", "source"),
    [
        (requests.exceptions.ConnectionError("no route"), "network"),
        (requests.exceptions.Timeout("slow"), "network"),
        (requests.exceptions.HTTPError("503 Server Error"), "nvd"),
        (LookupError("Invalid cpeName"), "nvd"),
    ],
)
def test_nvd_lookup_says_whether_nvd_or_the_network_failed(monkeypatch, error, source) -> None:
    def fail(*_args):
        raise error

    monkeypatch.setattr(vuln_lookup, "_nvd_search_cpe", fail)
    with pytest.raises(vuln_lookup.NvdLookupError) as caught:
        vuln_lookup.nvd_lookup("nginx", "1.18.0", "")
    assert caught.value.source == source
    # Fixed wording: the upstream text is not repeated (it can quote the request).
    assert str(error) not in str(caught.value)


@pytest.mark.parametrize("flag", ["AEGIS_DISABLE_NVD", "AEGIS_OFFLINE"])
def test_nvd_lookup_switched_off_is_a_failure_not_an_empty_answer(monkeypatch, flag) -> None:
    monkeypatch.setenv(flag, "1")
    with pytest.raises(vuln_lookup.NvdLookupError) as caught:
        vuln_lookup.nvd_lookup("nginx", "1.18.0", "key")
    assert caught.value.source == "disabled"


def test_settings_offline_switches_nvd_off_too(quiet_feeds) -> None:
    finding = vuln_lookup.enrich_tech(
        _tech("nginx", "1.18.0"), feeds=FeedAvailability(), settings=Settings(offline=True)
    )
    assert (finding.nvd_status, finding.nvd_failed_source) == ("lookup_failed", "disabled")


def test_nvd_search_passes_a_short_delay_only_with_a_key(monkeypatch) -> None:
    calls: list[dict] = []
    fake_nvdlib = SimpleNamespace(
        searchCPE=lambda **kw: calls.append(kw) or [],
        searchCVE=lambda **kw: calls.append(kw) or [],
    )
    monkeypatch.setitem(sys.modules, "nvdlib", fake_nvdlib)
    vuln_lookup._default_nvd_search_cpe("cpe:2.3:a:f5:nginx:1.18.0:*", "")
    vuln_lookup._default_nvd_search_cve("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*", "secret")
    assert calls[0] == {"cpeMatchString": "cpe:2.3:a:f5:nginx:1.18.0:*"}
    # isVulnerable: without it NVD also returns CVEs in OTHER products that
    # merely list this one as the platform they run on.
    assert calls[1] == {
        "cpeName": "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*",
        "isVulnerable": True,
        "key": "secret",
        "delay": 0.6,
        "limit": vuln_lookup.MAX_NVD_RESULTS,
    }


def test_cve_search_always_asks_only_for_cves_where_the_product_is_vulnerable(monkeypatch) -> None:
    calls: list[dict] = []
    monkeypatch.setitem(sys.modules, "nvdlib", SimpleNamespace(searchCVE=lambda **kw: calls.append(kw) or []))
    vuln_lookup._default_nvd_search_cve("cpe:2.3:a:apache:http_server:2.4.69:*:*:*:*:*:*:*", "")
    assert calls == [
        {"cpeName": "cpe:2.3:a:apache:http_server:2.4.69:*:*:*:*:*:*:*", "isVulnerable": True,
         "limit": vuln_lookup.MAX_NVD_RESULTS}
    ]


def test_a_full_page_of_cves_is_marked_truncated_and_the_page_says_so(monkeypatch, quiet_feeds) -> None:
    rows = [SimpleNamespace(id=f"CVE-2020-{1000 + i}", score=["V31", 5.0, "MEDIUM"], published="2020-01-01")
            for i in range(vuln_lookup.MAX_NVD_RESULTS)]
    _nvd(monkeypatch, [], rows)
    answer = vuln_lookup.nvd_lookup("Apache", "2.4.49", "")
    assert answer.truncated is True
    _nvd(monkeypatch, [], rows[:-1])
    assert vuln_lookup.nvd_lookup("Apache", "2.4.49", "").truncated is False
    _nvd(monkeypatch, [], rows)
    entry = vuln_lookup.lookup([{"name": "Apache", "version": "2.4.49", "source": "typed"}]).entries[0]
    assert entry["nvd_truncated"] is True and entry["cve_count"] == vuln_lookup.MAX_NVD_RESULTS
    from aegisshield.ui.pages import vulnerability_lookup as page

    assert "more than" in page.truncated_line(entry) and "2,000" in page.truncated_line(entry)
    assert page.truncated_line({"nvd_truncated": False}) is None


def test_a_cve_scored_only_under_cvss_4_keeps_its_score_and_severity(monkeypatch) -> None:
    v4_only = SimpleNamespace(
        id="CVE-2025-0001",
        score=[None, None, None],
        metrics=SimpleNamespace(
            cvssMetricV40=[SimpleNamespace(cvssData=SimpleNamespace(baseScore=9.3, baseSeverity="CRITICAL"))]
        ),
        descriptions=[],
        references=[],
        published="2025-02-01T00:00:00.000",
    )
    unscored = SimpleNamespace(
        id="CVE-2025-0002", score=[None, None, None], metrics=SimpleNamespace(),
        descriptions=[], references=[], published="2025-02-02T00:00:00.000",
    )
    _nvd(monkeypatch, [], [unscored, v4_only])
    rows = vuln_lookup.nvd_lookup("nginx", "1.27.5", "").cves
    assert [(r["cve_id"], r["cvss_score"], r["severity"]) for r in rows] == [
        ("CVE-2025-0001", 9.3, "CRITICAL"),
        ("CVE-2025-0002", None, None),
    ]
    assert [r["cvss_version"] for r in rows] == ["4.0", None]


@pytest.mark.parametrize(("label", "expected"), [("V31", "3.1"), ("V30", "3.0"), ("V2", "2.0"), ("V9", None)])
def test_each_cve_row_says_which_cvss_version_its_score_is(monkeypatch, label, expected) -> None:
    cve = SimpleNamespace(id="CVE-2024-0009", score=[label, 5.0, "MEDIUM"], descriptions=[], references=[], published="")
    _nvd(monkeypatch, [], [cve])
    assert vuln_lookup.nvd_lookup("nginx", "1.27.5", "").cves[0]["cvss_version"] == expected


# -- "Checked, none found" must be earned ------------------------------------------


def _status(version: str) -> tuple[str, int]:
    finding = vuln_lookup.enrich_tech(
        _tech("Apache HTTP Server", version), nvd_api_key="", feeds=FeedAvailability()
    )
    return finding.nvd_status, finding.cve_total


@pytest.mark.parametrize("version", ["1.2.3+x", "1.2 3", "1.2(3)", "1.2;3"])
def test_nothing_unsafe_is_ever_sent_in_a_cpe(quiet_feeds, version) -> None:
    finding = vuln_lookup.enrich_tech(_tech("nginx", version), nvd_api_key="", feeds=FeedAvailability())
    assert finding.nvd_status == "version_not_recognized"


def test_none_found_needs_an_exact_dictionary_entry(monkeypatch, quiet_feeds) -> None:
    _nvd(monkeypatch, [_cpe("cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*")], [])
    assert _status("2.4.62") == ("checked", 0)


def test_no_dictionary_entry_and_no_vulnerabilities_is_not_recognized(monkeypatch, quiet_feeds) -> None:
    _nvd(monkeypatch, [], [])
    assert _status("2.4.99") == ("version_not_recognized", 0)


def test_no_dictionary_entry_but_range_matches_still_count_as_found(monkeypatch, quiet_feeds) -> None:
    cve = SimpleNamespace(id="CVE-2024-0001", score=["V31", 7.5, "HIGH"], descriptions=[], references=[], published="")
    used = _nvd(monkeypatch, [], [cve])
    assert _status("2.4.99") == ("checked", 1)
    assert used == ["cpe:2.3:a:apache:http_server:2.4.99:*:*:*:*:*:*:*"]


@pytest.mark.parametrize("version", ["2", "2.4"])
def test_a_short_version_is_never_checked_even_with_an_exact_entry(monkeypatch, quiet_feeds, version) -> None:
    cve = SimpleNamespace(id="CVE-2024-0001", score=["V31", 7.5, "HIGH"], descriptions=[], references=[], published="")
    _nvd(monkeypatch, [], [cve])
    assert _status(version) == ("version_not_recognized", 0)
    _nvd(monkeypatch, [_cpe(f"cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*")], [cve])
    assert _status(version) == ("version_not_recognized", 0)
    _nvd(monkeypatch, [_cpe(f"cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*")], [])
    assert _status(version) == ("version_not_recognized", 0)


def test_an_entry_that_exists_only_as_an_update_variant_is_not_exact(monkeypatch, quiet_feeds) -> None:
    used = _nvd(
        monkeypatch,
        [
            _cpe("cpe:2.3:a:apache:http_server:6.4.2:beta1:*:*:*:*:*:*"),
            _cpe("cpe:2.3:a:apache:http_server:6.4.2:rc1:*:*:*:*:*:*"),
        ],
        [],
    )
    assert _status("6.4.2") == ("version_not_recognized", 0)
    assert used == ["cpe:2.3:a:apache:http_server:6.4.2:*:*:*:*:*:*:*"]
    _nvd(monkeypatch, [_cpe("cpe:2.3:a:apache:http_server:6.4.2:-:*:*:*:*:*:*")], [])
    assert _status("6.4.2") == ("checked", 0)
    _nvd(
        monkeypatch,
        [
            _cpe(
                "cpe:2.3:a:apache:http_server:6.4.2:*:*:*:*:*:*:*",
                deprecated_by="cpe:2.3:a:apache:http_server:6.4.2:beta1:*:*:*:*:*:*",
            )
        ],
        [],
    )
    assert _status("6.4.2") == ("version_not_recognized", 0)


def test_the_release_entry_wins_over_update_variants(monkeypatch, quiet_feeds) -> None:
    used = _nvd(
        monkeypatch,
        [
            _cpe("cpe:2.3:a:apache:http_server:2.4.62:beta:*:*:*:*:*:*"),
            _cpe("cpe:2.3:a:apache:http_server:2.4.62:rc1:*:*:*:*:*:*"),
            _cpe("cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*"),
        ],
        [],
    )
    assert _status("2.4.62") == ("checked", 0)
    assert used == ["cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*"]


def test_a_deprecated_entry_is_followed_only_to_an_accepted_pair(monkeypatch, quiet_feeds) -> None:
    used = _nvd(
        monkeypatch,
        [_cpe("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", deprecated_by="cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*")],
        [],
    )
    finding = vuln_lookup.enrich_tech(_tech("nginx", "1.18.0"), nvd_api_key="", feeds=FeedAvailability())
    assert used == ["cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"]
    assert finding.nvd_status == "checked"
    used = _nvd(
        monkeypatch,
        [_cpe("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*", deprecated_by="cpe:2.3:a:someone:else:1.18.0:*:*:*:*:*:*:*")],
        [],
    )
    finding = vuln_lookup.enrich_tech(_tech("nginx", "1.18.0"), nvd_api_key="", feeds=FeedAvailability())
    assert used == ["cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"]
    assert finding.nvd_status == "version_not_recognized"


# -- Per-technology status, sort, counts -------------------------------------------


def test_enrich_tech_sorts_by_score_before_cutting_and_counts_everything(monkeypatch, quiet_feeds) -> None:
    rows = [_cve(f"CVE-2024-{i:04d}", float(i) / 4, "LOW") for i in range(1, 29)]
    rows.insert(0, _cve("CVE-2024-9001", None))
    rows.insert(5, _cve("CVE-2024-9002", None))
    rows[-1]["severity"] = "CRITICAL"
    rows[-2]["severity"] = "HIGH"
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: rows))
    finding = vuln_lookup.enrich_tech(_tech("nginx", "1.18.0"), nvd_api_key="")
    kept = finding.cves
    assert len(kept) == vuln_lookup.MAX_CVES_PER_TECH == 25
    scores = [c["cvss_score"] for c in kept]
    assert scores == sorted(scores, reverse=True)
    assert kept[0]["cve_id"] == "CVE-2024-0028"
    summary = finding.to_dict()["summary"]
    assert (summary["cve_count"], summary["critical_count"], summary["high_count"]) == (30, 1, 1)
    assert finding.nvd_status == "checked"


def test_sort_cves_puts_missing_scores_last() -> None:
    rows = [_cve("A", None), _cve("B", 2.0), _cve("C", 9.8), _cve("D", 0.0)]
    assert [c["cve_id"] for c in vuln_lookup.sort_cves(rows)] == ["C", "B", "D", "A"]


def test_enrich_tech_statuses(monkeypatch, quiet_feeds) -> None:
    enrich = vuln_lookup.enrich_tech
    assert enrich(_tech("nginx", None), nvd_api_key="").nvd_status == "no_version"
    assert enrich(_tech("Debian", "12"), nvd_api_key="").nvd_status == "product_not_recognized"
    assert enrich(_tech("nginx", "1.18.0"), nvd_api_key="", deadline=0.0).nvd_status == "over_budget"

    def failing(*_args):
        raise vuln_lookup.NvdLookupError("network", "connection refused")

    monkeypatch.setattr(vuln_lookup, "nvd_lookup", failing)
    failed = enrich(_tech("nginx", "1.18.0"), nvd_api_key="")
    assert (failed.nvd_status, failed.nvd_failed_source) == ("lookup_failed", "network")
    assert failed.errors["nvd"] == "connection refused"

    def crashing(*_args):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(vuln_lookup, "nvd_lookup", crashing)
    crashed = enrich(_tech("nginx", "1.18.0"), nvd_api_key="")
    assert (crashed.nvd_status, crashed.nvd_failed_source) == ("lookup_failed", "nvd")

    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: []))
    clean = enrich(_tech("nginx", "1.18.0"), nvd_api_key="")
    assert clean.nvd_status == "checked"
    assert clean.to_dict()["summary"]["cve_count"] == 0


def test_a_failure_message_never_carries_the_nvd_key(monkeypatch, quiet_feeds) -> None:
    key = "nvd-key-0123456789"

    def failing(name, version, api_key):
        raise vuln_lookup.NvdLookupError("nvd", f"NVD said no to {api_key}")

    monkeypatch.setattr(vuln_lookup, "nvd_lookup", failing)
    finding = vuln_lookup.enrich_tech(_tech("nginx", "1.18.0"), nvd_api_key=key)
    assert key not in json.dumps(finding.to_dict())


# -- KEV: unavailable is unknown, never "not exploited" ----------------------------


def test_kev_unavailable_is_reported_as_unknown(monkeypatch, quiet_feeds) -> None:
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: [_cve("CVE-2024-0001", 5.0)]))
    finding = vuln_lookup.enrich_tech(_tech("nginx", "1.18.0"), nvd_api_key="")
    assert finding.cves[0]["known_exploited"] is None
    assert "kev" in finding.errors
    assert finding.to_dict()["summary"]["kev_count"] is None


def test_kev_available_marks_exploited_and_raises_severity(monkeypatch, quiet_feeds) -> None:
    monkeypatch.delenv("AEGIS_DISABLE_KEV")
    kev_service.seed_cache_for_tests({"CVE-2024-0001": _kev("CVE-2024-0001"), "CVE-2024-0003": _kev("CVE-2024-0003")})
    monkeypatch.setattr(
        vuln_lookup,
        "nvd_lookup",
        _exact(
            lambda n, v, k: [
                _cve("CVE-2024-0001", 5.0, "MEDIUM"),
                _cve("CVE-2024-0002", 9.0, "CRITICAL"),
                _cve("CVE-2024-0003", 9.8, "CRITICAL"),
            ]
        ),
    )
    finding = vuln_lookup.enrich_tech(_tech("nginx", "1.18.0"), nvd_api_key="")
    by_id = {c["cve_id"]: c for c in finding.cves}
    assert by_id["CVE-2024-0001"]["known_exploited"] is True
    assert by_id["CVE-2024-0001"]["severity"] == "high"
    assert by_id["CVE-2024-0001"]["kev_marker"] == "Known Exploited (CISA KEV)"
    assert by_id["CVE-2024-0003"]["severity"] == "critical"  # never lowered
    assert by_id["CVE-2024-0002"]["known_exploited"] is False
    assert finding.to_dict()["summary"]["kev_count"] == 2
    assert "kev" not in finding.errors


def test_kev_catalog_snapshot_reports_a_failed_download(monkeypatch) -> None:
    calls: list[str] = []

    def down(url, timeout=None):
        calls.append(url)
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(kev_service.requests, "get", down)
    config = kev_service.KevConfig(max_retries=1, base_delay_seconds=0.0, timeout_seconds=1.0)
    assert kev_service.catalog_snapshot(config) is None
    assert len(calls) == 1
    kev_service.seed_cache_for_tests({})
    assert kev_service.catalog_snapshot(config) == {}
    monkeypatch.setenv("AEGIS_DISABLE_KEV", "1")
    assert kev_service.catalog_snapshot(config) is None


def test_a_down_feed_is_fetched_a_bounded_number_of_times(monkeypatch) -> None:
    """KEV and ExploitDB are downloaded at most once per job, not once per
    CVE, and EPSS is not retried after its first failure."""
    hits: dict[str, int] = {}

    def down(url, *args, **kwargs):
        host = url.split("/")[2]
        hits[host] = hits.get(host, 0) + 1
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(requests, "get", down)
    monkeypatch.setattr(epss_service, "_http_get", lambda params, timeout: down(epss_service.EPSS_API_URL))
    monkeypatch.setattr(
        vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: [_cve(f"CVE-2024-{i:04d}", 5.0) for i in range(40)])
    )
    feeds = vuln_lookup.probe_feeds()
    assert feeds == FeedAvailability(kev=None, exploitdb=False, epss=True)
    for name in ("nginx", "PHP", "jQuery"):
        finding = vuln_lookup.enrich_tech(_tech(name, "1.0.0"), nvd_api_key="", feeds=feeds)
        assert finding.cves[0]["known_exploited"] is None
        assert "exploitdb" in finding.errors
    assert feeds.epss is False
    assert hits["www.cisa.gov"] == 1
    assert hits["gitlab.com"] == 1
    assert hits["api.first.org"] == 1
    assert hits["endoflife.date"] == 3  # one per product, cached after that


def test_exploitdb_and_eol_honor_the_offline_switches(monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_OFFLINE", "1")
    assert exploitdb_service.find_for_cve("CVE-2024-0001") == []
    assert exploitdb_service.index_available() is False
    assert eol_service.check_eol("nginx", "1.18.0") is None
    monkeypatch.delenv("AEGIS_OFFLINE")
    offline = Settings(offline=True)
    assert exploitdb_service.index_available(settings=offline) is False
    assert eol_service.check_eol("nginx", "1.18.0", settings=offline) is None


@pytest.mark.parametrize("value", ["true", "yes", "on"])
def test_exploitdb_and_eol_flags_accept_every_true_value(monkeypatch, value) -> None:
    # Every true spelling counts, not only "1".
    monkeypatch.setenv("AEGIS_DISABLE_EXPLOITDB", value)
    monkeypatch.setenv("AEGIS_DISABLE_EOL", value)
    assert exploitdb_service.index_available() is False
    assert eol_service.check_eol("nginx", "1.18.0") is None


def test_each_source_records_its_own_failure_and_the_rest_still_run(monkeypatch) -> None:
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: [_cve("CVE-2024-0001", 5.0)]))

    def boom(*_args, **_kwargs):
        raise RuntimeError("source down")

    monkeypatch.setattr(exploitdb_service, "find_for_cve", boom)
    monkeypatch.setattr(epss_service, "fetch_scores", boom)
    monkeypatch.setattr(eol_service, "check_eol", boom)
    monkeypatch.setattr(vuln_lookup, "otx_lookup", boom)
    feeds = FeedAvailability()  # no KEV snapshot: unknown
    finding = vuln_lookup.enrich_tech(
        _tech("nginx", "1.18.0"), nvd_api_key="", otx_api_key="otx-key", feeds=feeds
    )
    assert set(finding.errors) == {"kev", "exploitdb", "epss", "eol", "otx"}
    assert "source down" not in json.dumps(finding.errors)
    assert finding.nvd_status == "checked"
    assert finding.cve_total == 1
    assert finding.kev_total is None
    assert feeds.epss is False


def test_exploit_references_and_epss_attach_to_the_kept_cves(monkeypatch, quiet_feeds) -> None:
    monkeypatch.delenv("AEGIS_DISABLE_EXPLOITDB")
    monkeypatch.delenv("AEGIS_DISABLE_EPSS")
    exploitdb_service.seed_cache_for_tests(
        {
            "CVE-2024-0001": [
                ExploitRef("1", "PoC", "remote", "linux", "2024-02-01", "https://www.exploit-db.com/exploits/1")
            ]
        }
    )
    monkeypatch.setattr(
        epss_service,
        "_http_get",
        lambda params, timeout: {"data": [{"cve": "CVE-2024-0001", "epss": "0.5", "percentile": "0.9"}]},
    )
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: [_cve("CVE-2024-0001", 5.0)]))
    finding = vuln_lookup.enrich_tech(_tech("nginx", "1.18.0"), nvd_api_key="")
    assert finding.exploits[0]["cve_id"] == "CVE-2024-0001"
    assert finding.cves[0]["epss"] == pytest.approx(0.5)
    assert "exploitdb" not in finding.errors and "epss" not in finding.errors
    assert finding.to_dict()["summary"]["exploit_count"] == 1


def test_epss_switched_off_mid_job_is_reported(monkeypatch, quiet_feeds) -> None:
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: [_cve("CVE-2024-0001", 5.0)]))
    finding = vuln_lookup.enrich_tech(
        _tech("nginx", "1.18.0"), feeds=FeedAvailability(kev={}, exploitdb=None, epss=False)
    )
    assert finding.errors["epss"] == "EPSS scores unavailable."


# -- OTX --------------------------------------------------------------------------


def test_otx_is_asked_only_with_a_key(monkeypatch, quiet_feeds) -> None:
    asked: list[tuple[str, str]] = []
    monkeypatch.setattr(vuln_lookup, "otx_lookup", lambda name, key: asked.append((name, key)) or [{"id": "p1"}])
    no_key = vuln_lookup.enrich_tech(_tech("nginx", None), feeds=FeedAvailability())
    assert asked == [] and no_key.otx_pulses == []
    with_key = vuln_lookup.enrich_tech(_tech("nginx", None), otx_api_key="otx", feeds=FeedAvailability())
    assert asked == [("nginx", "otx")] and with_key.otx_pulses == [{"id": "p1"}]


@pytest.mark.parametrize("flag", ["AEGIS_DISABLE_OTX", "AEGIS_OFFLINE"])
def test_otx_honors_its_disable_flag(monkeypatch, quiet_feeds, flag) -> None:
    """OTX is not asked when its flag is set, even with a key given."""
    monkeypatch.setenv(flag, "1")

    def no_otx(*_args):
        raise AssertionError("OTX is switched off")

    monkeypatch.setattr(vuln_lookup, "otx_lookup", no_otx)
    finding = vuln_lookup.enrich_tech(_tech("nginx", None), otx_api_key="otx", feeds=FeedAvailability())
    assert finding.otx_pulses == []
    assert "switched off" in finding.errors["otx"]


def test_otx_honors_settings_offline(monkeypatch, quiet_feeds) -> None:
    monkeypatch.setattr(vuln_lookup, "otx_lookup", lambda *a: pytest.fail("OTX is switched off"))
    finding = vuln_lookup.enrich_tech(
        _tech("nginx", None), otx_api_key="otx", feeds=FeedAvailability(), settings=Settings(offline=True)
    )
    assert "otx" in finding.errors


def test_default_otx_lookup_shapes_pulses(monkeypatch) -> None:
    searched: dict = {}

    class FakeOTX:
        def __init__(self, key) -> None:
            searched["key"] = key

        def search_pulses(self, query, max_results):
            searched["query"] = (query, max_results)
            return {
                "results": [
                    {"id": "abc", "name": "Pulse", "TLP": "white", "modified": "2024", "tags": ["t"]},
                    {"name": "No id"},
                    "junk",
                ]
            }

    from aegisshield.core import otx

    monkeypatch.setattr(otx, "BoundedOTXv2", FakeOTX)
    pulses = vuln_lookup._default_otx_lookup("nginx", "otx-key")
    assert searched == {"key": "otx-key", "query": ("nginx", 10)}
    assert pulses[0] == {
        "id": "abc", "name": "Pulse", "tlp": "white", "modified": "2024", "tags": ["t"],
        "url": "https://otx.alienvault.com/pulse/abc",
    }
    assert pulses[1]["url"] is None and len(pulses) == 2
    assert vuln_lookup._default_otx_lookup("nginx", "") == []


# -- End of life ----------------------------------------------------------------------


def test_eol_matches_a_cycle_on_a_dot_boundary_only() -> None:
    eol_service.seed_cache_for_tests(
        "thing",
        [{"cycle": "1", "eol": "2020-01-01", "latest": "1.9"}, {"cycle": "10", "eol": False, "latest": "10.4"}],
    )
    assert eol_service.check_eol("thing", "10.2").cycle == "10"
    assert eol_service.check_eol("thing", "1.9").is_eol is True
    assert eol_service.check_eol("thing", "7.0") is None
    assert eol_service.check_eol("thing").cycle == "10"


def test_a_letter_suffixed_version_matches_its_cycle() -> None:
    eol_service.seed_cache_for_tests(
        "openssl",
        [
            {"cycle": "3.0", "eol": "2026-09-07", "latest": "3.0.15"},
            {"cycle": "1.1.1", "eol": "2023-09-11", "latest": "1.1.1w"},
            {"cycle": "1.1.0", "eol": "2019-09-11", "latest": "1.1.0l"},
        ],
    )
    status = eol_service.check_eol("openssl", "1.1.1w")
    assert status.cycle == "1.1.1" and status.is_eol is True
    assert eol_service.check_eol("openssl", "1.1.10") is None
    assert eol_service.check_eol("openssl", "3.0.15").cycle == "3.0"


def test_the_longest_matching_cycle_wins() -> None:
    eol_service.seed_cache_for_tests("thing", [{"cycle": "1", "eol": False}, {"cycle": "1.2", "eol": "2020-01-01"}])
    assert eol_service.check_eol("thing", "1.2.3").cycle == "1.2"


def test_eol_field_shapes() -> None:
    eol_service.seed_cache_for_tests(
        "shapes",
        [
            {"cycle": "1", "eol": True, "support": False},
            {"cycle": "2", "eol": "someday", "support": "2030-01-01", "latest": 2.5},
            {"cycle": "3", "eol": "2999-01-01", "support": True},
        ],
    )
    one = eol_service.check_eol("shapes", "1.0")
    assert (one.eol, one.is_eol, one.support_until) == ("true", True, None)
    two = eol_service.check_eol("shapes", "2.0")
    assert (two.eol, two.is_eol, two.support_until, two.latest) == ("someday", False, "2030-01-01", "2.5")
    three = eol_service.check_eol("shapes", "3.1").to_dict()
    assert three["is_eol"] is False and three["url"] == "https://endoflife.date/shapes"
    # Every cycle past end of life and no version: the first one.
    eol_service.seed_cache_for_tests("old", [{"cycle": "1", "eol": True}, {"cycle": "2", "eol": True}])
    assert eol_service.check_eol("old").cycle == "1"
    assert eol_service.check_eol("") is None


def test_eol_fetch_caches_answers_but_not_failures(monkeypatch) -> None:
    calls: list[str] = []

    class _Resp:
        def __init__(self, status, body) -> None:
            self.status_code, self._body = status, body

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise requests.exceptions.HTTPError(str(self.status_code))

        def json(self):
            return self._body

    answers = {
        "https://endoflife.date/api/nginx.json": _Resp(200, [{"cycle": "1.18", "eol": False}, "junk"]),
        "https://endoflife.date/api/nope.json": _Resp(404, None),
        "https://endoflife.date/api/broken.json": _Resp(500, None),
        "https://endoflife.date/api/odd.json": _Resp(200, {"not": "a list"}),
    }

    def fake_get(url, timeout=None):
        calls.append(url)
        return answers[url]

    monkeypatch.setattr(eol_service.requests, "get", fake_get)
    assert eol_service.check_eol("nginx", "1.18.0").cycle == "1.18"
    assert eol_service.check_eol("nginx", "1.18.1").cycle == "1.18"
    assert eol_service.check_eol("nope", "1.0") is None
    assert eol_service.check_eol("broken", "1.0") is None
    assert eol_service.check_eol("odd", "1.0") is None
    assert eol_service.check_eol("broken", "1.0") is None
    assert eol_service.check_eol("odd", "1.0") is None
    assert eol_service.check_eol("nope", "1.0") is None
    # an answer (a list, or 404 for an unknown product) is cached; a failure
    # (an error status, a network error, or an unreadable body) is asked again
    assert calls.count("https://endoflife.date/api/nginx.json") == 1
    assert calls.count("https://endoflife.date/api/nope.json") == 1
    assert calls.count("https://endoflife.date/api/broken.json") == 2
    assert calls.count("https://endoflife.date/api/odd.json") == 2


def test_eol_network_errors_are_not_cached(monkeypatch) -> None:
    calls: list[str] = []

    def down(url, timeout=None):
        calls.append(url)
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(eol_service.requests, "get", down)
    assert eol_service.check_eol("nginx", "1.0") is None
    assert eol_service.check_eol("nginx", "1.0") is None
    assert len(calls) == 2 and eol_service._cache == {}


def test_the_eol_cache_is_bounded_and_drops_the_oldest(monkeypatch) -> None:
    class _Resp:
        status_code = 200

        def raise_for_status(self) -> None:
            return None

        def json(self):
            return [{"cycle": "1", "eol": False}]

    monkeypatch.setattr(eol_service.requests, "get", lambda url, timeout=None: _Resp())
    limit = eol_service.MAX_CACHE_ENTRIES
    for i in range(limit + 25):
        eol_service.check_eol(f"product-{i}", "1.0")
    assert len(eol_service._cache) == limit
    assert "product-0" not in eol_service._cache and f"product-{limit + 24}" in eol_service._cache


def test_an_expired_eol_answer_is_asked_again(monkeypatch) -> None:
    eol_service.seed_cache_for_tests("nginx", [{"cycle": "1", "eol": False}])
    stamp, cycles = eol_service._cache["nginx"]
    eol_service._cache["nginx"] = (stamp - eol_service.CACHE_TTL_SECONDS - 1, cycles)
    monkeypatch.setattr(eol_service.requests, "get", lambda url, timeout=None: (_ for _ in ()).throw(
        requests.exceptions.ConnectionError("down")))
    assert eol_service.check_eol("nginx", "1.0") is None
    assert "nginx" not in eol_service._cache


@pytest.mark.parametrize(
    "name", ["../admin", "a/b", "php?x=1", "php#frag", "-php", "a" * 65, "php..x", "caf\u00e9"]
)
def test_an_unsafe_product_slug_is_never_requested_or_cached(monkeypatch, name) -> None:
    monkeypatch.setattr(eol_service.requests, "get", lambda *a, **k: pytest.fail("requested"))
    assert eol_service.check_eol(name, "1.0") is None
    assert eol_service._cache == {}


def test_a_typed_name_with_spaces_becomes_a_safe_slug(monkeypatch) -> None:
    asked: list[str] = []

    class _Resp:
        status_code = 404

    monkeypatch.setattr(eol_service.requests, "get", lambda url, timeout=None: asked.append(url) or _Resp())
    assert eol_service.check_eol("Node.js Server 2", "1.0") is None
    assert asked == ["https://endoflife.date/api/node.js-server-2.json"]


def test_end_of_life_uses_the_mapped_slug(monkeypatch, quiet_feeds) -> None:
    monkeypatch.delenv("AEGIS_DISABLE_EOL")
    eol_service.seed_cache_for_tests("apache-http-server", [{"cycle": "2.4", "eol": False}])
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", _exact(lambda n, v, k: []))
    finding = vuln_lookup.enrich_tech(_tech("Apache", "2.4.62"), feeds=FeedAvailability())
    assert finding.eol["cycle"] == "2.4"


# -- ExploitDB index --------------------------------------------------------------------

_CSV = (
    "id,file,description,date_published,author,type,platform,port,date_added,date_updated,"
    "verified,codes\n"
    "1,a.py,Checkout RCE,2024-02-01,x,remote,linux,,,,1,CVE-2024-0001;OSVDB-1\n"
    "2,b.py,No codes,2024-02-01,x,local,linux,,,,1,\n"
    ",c.py,No id,2024-02-01,x,local,linux,,,,1,CVE-2024-0002\n"
    "3,d.py,Two,2024-03-01,x,webapps,php,,,,1,cve-2024-0001;CVE-2024-0003\n"
)



def test_exploitdb_index_downloads_once_and_answers_case_insensitively(monkeypatch) -> None:
    calls: list[str] = []

    class _Resp:
        text = _CSV

        def raise_for_status(self) -> None:
            return None

    monkeypatch.setattr(exploitdb_service.requests, "get", lambda url, timeout=None: calls.append(url) or _Resp())
    assert exploitdb_service.index_available() is True
    refs = exploitdb_service.find_for_cve("cve-2024-0001")
    assert [r.edb_id for r in refs] == ["1", "3"]
    assert refs[0].to_dict()["url"] == "https://www.exploit-db.com/exploits/1"
    assert exploitdb_service.find_for_cve("CVE-2024-0002") == []
    assert exploitdb_service.find_for_cve("") == []
    assert calls == [exploitdb_service.EXPLOITDB_CSV_URL]


def test_exploitdb_failed_download_is_unavailable(monkeypatch) -> None:
    def down(*a, **k):
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(exploitdb_service.requests, "get", down)
    assert exploitdb_service.index_available() is False


def test_exploitdb_backs_off_after_a_failed_download(monkeypatch) -> None:
    calls: list[str] = []
    now = [1_000_000.0]

    class _Resp:
        text = _CSV

        def raise_for_status(self) -> None:
            return None

    def down(url, timeout=None):
        calls.append(url)
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(exploitdb_service.time, "time", lambda: now[0])
    monkeypatch.setattr(exploitdb_service.requests, "get", down)
    assert exploitdb_service.index_available() is False
    assert exploitdb_service.find_for_cve("CVE-2024-0001") == []
    assert exploitdb_service.index_available() is False
    assert len(calls) == 1  # no second download while backing off
    now[0] += exploitdb_service.RETRY_AFTER_FAILURE_SECONDS + 1
    monkeypatch.setattr(exploitdb_service.requests, "get", lambda url, timeout=None: calls.append(url) or _Resp())
    assert exploitdb_service.index_available() is True
    assert len(calls) == 2


def test_exploitdb_an_empty_catalog_is_not_downloaded_again(monkeypatch) -> None:
    calls: list[str] = []

    class _Resp:
        text = "id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes\n"

        def raise_for_status(self) -> None:
            return None

    monkeypatch.setattr(exploitdb_service.requests, "get", lambda url, timeout=None: calls.append(url) or _Resp())
    assert exploitdb_service.index_available() is True
    assert exploitdb_service.find_for_cve("CVE-2024-0001") == []
    assert len(calls) == 1


def test_kev_snapshot_older_than_a_day_is_unknown(monkeypatch) -> None:
    kev_service.seed_cache_for_tests({"CVE-2024-0001": _kev("CVE-2024-0001")})
    monkeypatch.setattr(kev_service, "_cache_built_at", time.time() - 25 * 3600)
    monkeypatch.setattr(
        kev_service.requests, "get", lambda *a, **k: (_ for _ in ()).throw(requests.exceptions.Timeout())
    )
    config = kev_service.KevConfig(max_retries=1, base_delay_seconds=0.0, timeout_seconds=1.0)
    assert kev_service.catalog_snapshot(config) is None


def test_a_kev_cache_under_a_day_old_is_used_when_the_feed_is_down(monkeypatch) -> None:
    kev_service.seed_cache_for_tests({"CVE-2024-0001": _kev("CVE-2024-0001")})
    monkeypatch.setattr(kev_service, "_cache_built_at", time.time() - 7 * 3600)
    calls = []
    monkeypatch.setattr(
        kev_service.requests,
        "get",
        lambda *a, **k: calls.append(1) or (_ for _ in ()).throw(requests.exceptions.Timeout()),
    )
    config = kev_service.KevConfig(max_retries=1, base_delay_seconds=0.0, timeout_seconds=1.0)
    assert set(kev_service.catalog_snapshot(config)) == {"CVE-2024-0001"}
    assert calls == [1]
    monkeypatch.setattr(kev_service, "_cache_built_at", time.time() - 60)
    assert set(kev_service.catalog_snapshot(config)) == {"CVE-2024-0001"}
    assert calls == [1]
