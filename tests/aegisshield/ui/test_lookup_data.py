"""The lookup page's data helpers: input parsing, defensive reads, filters, exports."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from aegisshield.jobs.runner import JobStatus
from aegisshield.services import exploitdb_service
from aegisshield.ui import lookup_data as ld
from aegisshield.ui.tool_parts import elapsed_words


def test_catalog_names_are_the_mapping_files_products_sorted() -> None:
    names = ld.catalog_names()
    assert "Apache HTTP Server" in names and "nginx" in names
    assert list(names) == sorted(names, key=str.lower)


def test_picked_strips_a_v_prefix_and_blank_versions() -> None:
    techs = ld.picked_technologies([("nginx", " v1.25.3 "), ("Redis", "  ")])
    assert [(t.name, t.version, t.source) for t in techs] == [
        ("nginx", "1.25.3", "selected"), ("Redis", None, "selected"),
    ]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", []),
        ('[{"name": "nginx", "version": "1.25.3"}]', [("nginx", "1.25.3")]),
        ('{"nginx": "1.25.3", "PHP": "8.2.1"}', [("nginx", "1.25.3"), ("PHP", "8.2.1")]),
        ("Server: nginx/1.25.3 OpenSSL/3.0.13", [("nginx", "1.25.3"), ("OpenSSL", "3.0.13")]),
        ("nginx 1.25.3\nMicrosoft IIS\n# comment", [("nginx", "1.25.3"), ("Microsoft IIS", None)]),
        ("nginx 1.25.3\nnginx/1.25.3", [("nginx", "1.25.3")]),
        ("[not json", [("[not json", None)]),
    ],
)
def test_parse_pasted_accepts_every_format(raw, expected) -> None:
    assert [(t.name, t.version) for t in ld.parse_pasted(raw)] == expected


def test_lookup_title_names_the_first_three() -> None:
    techs = ld.picked_technologies([(n, "1.0.0") for n in ("a", "b", "c", "d", "e")])
    assert ld.lookup_title(techs) == "a, b, c and 2 more"
    assert ld.lookup_title([]) == "Lookup"


def test_safe_url_keeps_only_source_links() -> None:
    ref = exploitdb_service.ExploitRef("1", "t", "x", "p", "d", "https://www.exploit-db.com/exploits/1")
    assert ld.safe_url(ref.url) == ref.url
    assert ld.safe_url("https://endoflife.date/nginx") == "https://endoflife.date/nginx"
    for bad in ("javascript:alert(1)", "https://evil.example/", "https://nvd.nist.gov/vuln/detail/x\"onclick", 5):
        assert ld.safe_url(bad) is None


def test_summary_value_never_shows_unknown_as_zero() -> None:
    assert ld.summary_value({"cve_count": None}, "cve_count") == "Not checked"
    assert ld.summary_value({"cve_count": 0}, "cve_count") == "0"
    assert ld.summary_value({"cve_count": True}, "cve_count") == "Not checked"
    assert ld.summary_value("junk", "cve_count") == "Not checked"


def test_reads_tolerate_a_tampered_result() -> None:
    junk = {"technologies": ["x", {"name": 5, "state": "weird", "cves": "no", "exploits": [1],
                                  "errors": {"kev": "x", "zzz": "y"}},
                             {"name": "n", "cves": [7, {"cve_id": "bad id", "cvss_score": "9", "kev": "x",
                                                        "known_exploited": "yes", "severity": "LOL"}]}]}
    assert ld.state_label(junk["technologies"][1]) == "Not checked"
    assert ld.not_checked(junk) == [": not checked.", "n: not checked."]
    assert ld.source_gaps(junk) == [ld._SOURCE_GAPS["kev"], ld._NO_EPSS]
    (row,) = ld.cve_rows(junk)
    assert row.url is None and row.score is None and row.known_exploited is None and row.severity == "None"
    assert ld.cve_rows(None) == [] and ld.not_checked("x") == []


def _row(**kw) -> ld.CveRow:
    base = {"tech_index": 0, "technology": "t", "cve_id": "CVE-2024-0001", "url": None, "score": None, "cvss_version": "",
                "severity": "None", "known_exploited": False, "kev_due": "", "epss": None, "epss_percentile": None,
                "exploits": (), "exploits_known": True, "published": "", "description": ""}
    return ld.CveRow(**{**base, **kw})


def test_filter_and_sort_rows() -> None:
    a = _row(cve_id="A", score=5.0, severity="Medium", epss=0.5, published="2024-01-01")
    b = _row(cve_id="B", score=9.8, severity="Critical", published="2023-01-01", exploits=(("EDB-1", None),))
    c = _row(cve_id="C", score=None, severity="High", known_exploited=True, epss=0.9, published="2025-01-01")
    ids = lambda rows: [r.cve_id for r in rows]  # noqa: E731
    assert ids(ld.filter_rows([a, b, c])) == ["C", "B", "A"]
    assert ids(ld.filter_rows([a, b, c], sort="CVSS score")) == ["B", "A", "C"]
    assert ids(ld.filter_rows([a, b, c], sort="EPSS probability")) == ["C", "A", "B"]
    assert ids(ld.filter_rows([a, b, c], sort="Published")) == ["C", "A", "B"]
    assert ids(ld.filter_rows([a, b, c], kev_only=True)) == ["C"]
    assert ids(ld.filter_rows([a, b, c], exploit_only=True)) == ["B"]
    assert ids(ld.filter_rows([a, b, c], severities=["Medium"])) == ["A"]
    assert b.has_exploit and not a.has_exploit


def test_csv_has_a_row_for_a_technology_without_cves_and_neutralizes_formulas() -> None:
    result = {"technologies": [{"name": "@SUM(1)", "version": None, "state": "not_checked",
                                "description": "-x", "cves": []}]}
    lines = ld.to_csv(result).decode().splitlines()
    assert lines[0].startswith("technology,state,detail,cve_id")
    assert lines[1].startswith("'@SUM(1),Not checked,'-x,")


def test_elapsed_words() -> None:
    snap = SimpleNamespace(started_at=100.0, created_at=90.0, status=JobStatus.RUNNING)
    assert elapsed_words(snap, now=112.4) == "12 s"
    assert elapsed_words(snap, now=284.0) == "3 min 4 s"
    assert elapsed_words(SimpleNamespace(started_at=None, created_at=90.0), now=95.0) == "5 s"


def _entry(state="vulnerabilities_found", errors=None, eol=None, cves=None):
    return {"name": "nginx", "version": "1.25.3", "state": state, "errors": errors or {}, "eol": eol,
            "cves": cves if cves is not None else [{"cve_id": "CVE-2024-0001"}], "exploits": []}


def test_eol_value_is_unknown_unless_every_looked_up_answer_came_back() -> None:
    assert ld.eol_value({"technologies": [_entry(state="not_checked")]}) == "Not checked"
    assert ld.eol_value({"technologies": [_entry(errors={"eol": "x"})]}) == "Not checked"
    assert ld.eol_value({"technologies": [_entry(eol={"is_eol": True}), _entry(eol={"is_eol": False})]}) == "1"
    assert ld.eol_value({"technologies": [_entry(eol=None)]}) == "0"
    assert ld.eol_value(None) == "Not checked"


def test_failed_exploitdb_makes_exploits_unknown_in_rows_and_csv() -> None:
    result = {"technologies": [_entry(errors={"exploitdb": "ExploitDB index unavailable."})]}
    (row,) = ld.cve_rows(result)
    assert row.exploits_known is False
    assert ",unknown," in ld.to_csv(result).decode()
    (row,) = ld.cve_rows({"technologies": [_entry()]})
    assert row.exploits_known is True


def test_gaps_name_silent_epss_and_otx_not_asked() -> None:
    result = {"technologies": [_entry()]}
    assert ld.source_gaps(result, {"otx_requested": False}) == [ld._NO_EPSS, ld._NO_OTX]
    scored = {"technologies": [_entry(cves=[{"cve_id": "CVE-2024-0001", "epss": 0.1}])]}
    assert ld.source_gaps(scored, {"otx_requested": True}) == []
    assert ld.source_gaps({"technologies": [_entry(cves=[])]}) == []
