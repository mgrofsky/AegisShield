"""Tests for the JSON, HTML, and SARIF exporters.

The exporters take the job result. Includes tests for DREAD joined by
threat ID, escaped markdown and Mermaid, and the optional NIST CSF and vulnerability lookup sections.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

from aegisshield.services.export_service import (
    _dread_scores,
    _dread_to_level,
    _parse_dread_scores,
    _stable_fingerprint,
    assign_missing_ids,
    csf_section_html,
    format_count,
    markdown_html,
    safe_link,
    to_html_report,
    to_json_bytes,
    to_json_report,
    to_sarif,
    vuln_section_html,
)

FIXTURES = Path(__file__).parent / "fixtures" / "exports"

SAMPLE_THREATS = [
    {
        "ID": "TC-S01",
        "Threat Type": "Spoofing",
        "Scenario": "Attacker reuses session cookie.",
        "Assumptions": [],
        "Potential Impact": "Account takeover",
        "MITRE ATT&CK Keywords": ["session", "credentials"],
    },
    {
        "ID": "TC-T01",
        "Threat Type": "Tampering",
        "Scenario": "Attacker modifies API request bodies.",
        "Assumptions": [],
        "Potential Impact": "Data integrity loss",
        "MITRE ATT&CK Keywords": ["api"],
    },
]

SAMPLE_MITRE = [
    {
        "threat": SAMPLE_THREATS[0],
        "mitre_techniques": [
            {
                "name": "Valid Accounts",
                "description": "Use of valid credentials.",
                "id": "attack-pattern--valid-acct",
                "technique_id": "T1078",
                "framework": "ATT&CK",
                "tactic": "Initial Access",
            }
        ],
    },
    # The second threat has no mapped technique, to exercise the STRIDE rule.
    {"threat": SAMPLE_THREATS[1], "mitre_techniques": []},
]

# The DREAD table the pipeline renders: keyed by threat ID, risk score last.
SAMPLE_DREAD_MD = (
    "| ID | Damage Potential | Reproducibility | Exploitability | Affected Users "
    "| Discoverability | Risk Score |\n"
    "|----|----|----|----|----|----|----|\n"
    "| TC-S01 | 9 | 9 | 8 | 9 | 9 | 8.80 |\n"
    "| TC-T01 | 3 | 2 | 4 | 2 | 3 | 2.80 |\n"
)
PROFILE = {"app_type": "Web application", "industry_sector": "Retail"}
DESCRIPTION = "An online retail checkout service."


def _result(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "threat_model": copy.deepcopy(SAMPLE_THREATS),
        "improvement_suggestions": ["Add MFA"],
        "threat_model_markdown": "tm",
        "attack_tree_code": "graph LR; A-->B",
        "mitre_attack_markdown": "### MITRE\n- T1078",
        "nvd_vulnerabilities_markdown": "",
        "otx_data_markdown": "",
        "mitre_data": copy.deepcopy(SAMPLE_MITRE),
        "detected_patterns": [],
        "pattern_source": "description",
        "mitigations_markdown": "### Mitigations\n- Rotate session keys",
        "dread_assessment_markdown": SAMPLE_DREAD_MD,
        "test_cases_markdown": "",
    }
    base.update(overrides)
    return base


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def job() -> dict[str, Any]:
    """A realistic job result, request, CSF mapping, and lookup (online retail checkout)."""
    request = _load("request.json")
    return {
        "result": _load("job_result.json"),
        "profile": request["app_profile"],
        "description": request["app_description"],
        "nist_csf": _load("nist_csf.json"),
        "vuln_lookup": _load("vuln_lookup.json"),
    }


def _results_by_threat(sarif: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        r["properties"]["threatId"]: r
        for r in sarif["runs"][0]["results"]
        if "threatId" in r["properties"]
    }


# --- JSON -------------------------------------------------------------------


def test_to_json_report_round_trips() -> None:
    report = to_json_report(_result(), PROFILE, DESCRIPTION)
    decoded = json.loads(to_json_bytes(report).decode("utf-8"))
    assert decoded["schema_version"] == "1"
    assert decoded["threat_model"] == SAMPLE_THREATS
    assert "generated_at" in decoded
    assert decoded["app_profile"] == PROFILE
    assert decoded["app_description"] == DESCRIPTION


def test_to_json_report_has_stable_schema_for_a_sparse_result() -> None:
    report = to_json_report({"threat_model": "not a list"}, None, "")
    assert report["threat_model"] == []
    assert report["mitre_data"] == []
    assert report["dread_assessment"] is None
    assert report["test_cases_markdown"] == ""
    assert report["nist_csf"] is None
    assert report["vulnerability_lookup"] is None
    assert report["app_profile"] == {}


def test_to_json_report_includes_optional_sections(job: dict[str, Any]) -> None:
    report = to_json_report(
        job["result"],
        job["profile"],
        job["description"],
        nist_csf=job["nist_csf"],
        vuln_lookup=job["vuln_lookup"],
    )
    decoded = json.loads(to_json_bytes(report))
    assert decoded["dread_assessment"]["Risk Assessment"][0]["ID"] == "TC-S01"
    assert decoded["nist_csf"]["mappings"][0]["threat_id"] == "TC-S01"
    assert decoded["vulnerability_lookup"]["summary"]["kev_count"] is None


def test_to_json_report_accepts_dataclass_csf_rows() -> None:
    @dataclasses.dataclass
    class Row:
        threat_id: str
        categories: list[str]

    report = to_json_report(_result(), PROFILE, DESCRIPTION, nist_csf={"mappings": [Row("TC-S01", [])]})
    decoded = json.loads(to_json_bytes(report))
    assert decoded["nist_csf"]["mappings"] == [{"threat_id": "TC-S01", "categories": []}]


# --- HTML -------------------------------------------------------------------


class _Collect(HTMLParser):
    """Records every start tag and attribute so tests can look for injected markup."""

    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


def _tags(html_doc: str) -> list[tuple[str, dict[str, str | None]]]:
    parser = _Collect()
    parser.feed(html_doc)
    return parser.tags


def _assert_no_active_markup(html_doc: str) -> None:
    for tag, attrs in _tags(html_doc):
        assert tag not in {"script", "iframe", "object", "embed", "img", "svg"}, tag
        assert not any(name.startswith("on") for name in attrs), (tag, attrs)
        href = attrs.get("href") or ""
        assert not href.lower().startswith("javascript:"), href


def test_to_html_report_is_well_formed() -> None:
    html_doc = to_html_report(_result(), PROFILE, DESCRIPTION)
    assert _tags(html_doc)
    assert "<title>" in html_doc
    assert "Spoofing" in html_doc
    assert "Tampering" in html_doc
    # No external assets; the document is self-contained.
    assert "http://" not in html_doc.lower()
    assert "https://cdn" not in html_doc.lower()


def test_to_html_report_escapes_html_in_app_description() -> None:
    html_doc = to_html_report(_result(), PROFILE, "<script>alert(1)</script>")
    assert "<script>alert(1)</script>" not in html_doc
    assert "&lt;script&gt;" in html_doc
    _assert_no_active_markup(html_doc)


def test_to_html_report_has_general_header_and_csp(job: dict[str, Any]) -> None:
    html_doc = to_html_report(job["result"], job["profile"], job["description"])
    assert "Threat Modeling Report" in html_doc
    assert "Content-Security-Policy" in html_doc
    assert "default-src 'none'" in html_doc
    assert "badge" not in html_doc
    # No en or em dashes in the generated copy.
    assert not re.search("[\u2013\u2014]", html_doc)


def test_to_html_report_renders_the_realistic_result(job: dict[str, Any]) -> None:
    html_doc = to_html_report(job["result"], job["profile"], job["description"])
    for text in ("TC-S01", "TC-E01", "Session binding at checkout", "Risk Score", "Django"):
        assert text in html_doc
    # Core sections always appear, optional ones only when given.
    assert "NIST CSF 2.0 Mapping" not in html_doc
    assert "Vulnerability Lookup" not in html_doc


@pytest.mark.parametrize(
    "field",
    [
        "mitigations_markdown",
        "dread_assessment_markdown",
        "test_cases_markdown",
        "mitre_attack_markdown",
        "nvd_vulnerabilities_markdown",
        "otx_data_markdown",
    ],
)
def test_to_html_report_escapes_model_markdown(field: str) -> None:
    payload = (
        "Intro <script>alert(1)</script>\n\n"
        "<img src=x onerror=alert(2)>\n\n"
        '<div onclick="alert(3)">raw html block</div>\n\n'
        "[click](javascript:alert(4)) ![pixel](https://tracker.example/p.png)\n\n"
        "[ref][1] ![refimg][2] ![<script>alt</script>](https://tracker.example/a.png)\n\n"
        "[1]: javascript:alert(5)\n[2]: file:///etc/hosts\n\n"
        "```html\n<script>alert(6)</script>\n```"
    )
    html_doc = to_html_report(_result(**{field: payload}), PROFILE, DESCRIPTION)
    _assert_no_active_markup(html_doc)
    assert "&lt;script&gt;" in html_doc
    assert "tracker.example" not in html_doc
    assert "/etc/hosts" not in html_doc


def test_to_html_report_escapes_threat_and_profile_fields() -> None:
    threats = [
        {
            "ID": "<b>TC-S01</b>",
            "Threat Type": "<script>alert('type')</script>",
            "Scenario": "<img src=x onerror=alert(1)>",
            "Assumptions": [{"Assumption": "<script>a</script>", "Role": "<i>r</i>"}, "<u>s</u>"],
            "Potential Impact": "<svg onload=alert(1)>",
        }
    ]
    profile = {
        "app_type": "</title><script>alert(1)</script>",
        "industry_sector": "<img src=x onerror=alert(1)>",
        "authentication": ["<script>x</script>"],
        "selected_technologies": {"<script>t</script>": "cpe"},
        "selected_versions": {"<script>t</script>": "<b>1</b>"},
    }
    html_doc = to_html_report(
        _result(threat_model=threats, improvement_suggestions=["<img src=x onerror=alert(2)>"]),
        profile,
        DESCRIPTION,
    )
    _assert_no_active_markup(html_doc)
    assert "&lt;/title&gt;&lt;script&gt;" in html_doc


def test_to_html_report_attack_tree_cannot_inject_markup() -> None:
    tree = 'graph TD\n A["</pre><script>alert(1)</script>"] --> B["<img src=x onerror=alert(2)>"]'
    html_doc = to_html_report(_result(attack_tree_code=tree), PROFILE, DESCRIPTION)
    _assert_no_active_markup(html_doc)
    assert "&lt;/pre&gt;&lt;script&gt;" in html_doc
    assert html_doc.count("<pre>") == html_doc.count("</pre>") == 1


def test_to_html_report_shows_no_data_for_empty_sections() -> None:
    html_doc = to_html_report(
        _result(threat_model=[], attack_tree_code="", mitigations_markdown=""), {}, ""
    )
    assert "No threats were identified." in html_doc
    assert "No data." in html_doc
    assert "No description given." in html_doc


def test_to_html_report_includes_optional_sections(job: dict[str, Any]) -> None:
    html_doc = to_html_report(
        job["result"],
        job["profile"],
        job["description"],
        nist_csf=job["nist_csf"],
        vuln_lookup=job["vuln_lookup"],
    )
    assert "NIST CSF 2.0 Mapping" in html_doc
    assert "PR.AA (Protect)" in html_doc
    assert "Vulnerability Lookup" in html_doc
    assert "CVE-2023-36053" in html_doc
    assert '<a href="https://nvd.nist.gov/vuln/detail/CVE-2023-36053">' in html_doc
    assert "Redis was not checked because no version was given." in html_doc


# --- shared section renderers -------------------------------------------------


def test_format_count_never_turns_unknown_into_zero() -> None:
    assert format_count(None) == "unknown"
    assert format_count(0) == "0"
    assert format_count(3) == "3"
    assert format_count(2.0) == "2"
    assert format_count(True) == "unknown"
    assert format_count("5") == "unknown"


def test_vuln_section_renders_none_counts_as_unknown(job: dict[str, Any]) -> None:
    html_doc = vuln_section_html(job["vuln_lookup"])
    summary = re.search(r'<table class="kv">(.*?)</table>', html_doc, re.S)
    assert summary is not None
    assert "Known exploited (KEV)</td><td class=\"v\">unknown" in summary.group(1)
    assert "Public exploits</td><td class=\"v\">0" in summary.group(1)
    # PostgreSQL: checked, zero CVEs, unknown KEV count.
    assert "CVEs: 0 &middot; Critical: 0 &middot; High: 0 &middot; Known exploited: unknown" in html_doc
    # Redis: not checked, so every count is unknown.
    assert "CVEs: unknown &middot; Critical: unknown" in html_doc
    # Per-CVE KEV flags: False is No, None is unknown.
    assert "<td>No</td>" in html_doc
    assert "<td>unknown</td>" in html_doc
    assert "The KEV feed could not be loaded." in html_doc
    assert "Supported (release 4.2, end of life 2026-04-30)" in html_doc
    assert "1.2%" in html_doc


def test_vuln_section_escapes_user_and_third_party_text() -> None:
    lookup = {
        "status": "cancelled",
        "technologies": [
            {
                "name": "<script>alert(1)</script>",
                "version": "<img src=x onerror=alert(2)>",
                "description": "<b>desc</b>",
                "note": "<i>note</i>",
                "eol": {"is_eol": True, "cycle": "1", "url": "javascript:alert(3)"},
                "cves": [
                    {
                        "cve_id": "<script>CVE</script>",
                        "url": "javascript:alert(4)",
                        "description": "<img src=x onerror=alert(5)>" + "x" * 400,
                        "severity": "<b>HIGH</b>",
                        "cvss_score": "9",
                        "known_exploited": True,
                    },
                    "not a cve",
                ],
                "exploits": [
                    {"cve_id": "CVE-2024-0001", "title": "<script>exp</script>", "url": "javascript:x"},
                    "not an exploit",
                ],
                "errors": {"<nvd>": "<script>e</script>"},
            },
            "not a technology",
        ],
        "summary": {"tech_count": 1, "kev_count": None},
    }
    html_doc = vuln_section_html(lookup)
    _assert_no_active_markup(html_doc)
    assert "<a " not in html_doc
    assert "did not finish (status: cancelled)" in html_doc
    assert "End of life (release 1)" in html_doc
    assert "<td>Yes</td>" in html_doc
    assert "x" * 400 not in html_doc
    assert "CVE-2024-0001: &lt;script&gt;exp&lt;/script&gt;" in html_doc


def test_vuln_section_handles_missing_and_empty_input() -> None:
    assert vuln_section_html(None) == ""
    assert "No technologies were looked up." in vuln_section_html({"status": "complete"})


def test_csf_section_accepts_dicts_and_dataclasses(job: dict[str, Any]) -> None:
    @dataclasses.dataclass
    class Cat:
        id: str
        name: str
        function_id: str
        function_name: str

    @dataclasses.dataclass
    class Mapping_:
        threat_id: str | None
        threat_type: str
        scenario: str
        technique_id: str | None
        categories: list[Cat]

    rows = [Mapping_("TC-S01", "Spoofing", "<script>x</script>", None, [Cat("PR.AA", "n", "PR", "Protect")])]
    html_doc = csf_section_html({"mappings": rows, "coverage": job["nist_csf"]["coverage"]})
    _assert_no_active_markup(html_doc)
    assert "PR.AA (Protect)" in html_doc
    assert "Coverage by Function" in html_doc
    assert csf_section_html(None) == ""
    assert csf_section_html({"mappings": "bad", "coverage": None}) == ""


def test_markdown_html_drops_images_and_unsafe_links() -> None:
    rendered = markdown_html("![alt text](file:///etc/hosts) [x](javascript:alert(1)) <b>raw</b>")
    assert "<img" not in rendered
    assert "alt text" in rendered
    assert "href" not in rendered and "javascript" not in rendered  # the link is reduced to its text
    assert "&lt;b&gt;raw&lt;/b&gt;" in rendered
    assert markdown_html(None) == ""


def test_safe_link_allows_only_web_urls() -> None:
    assert safe_link("https://example.com/a?b=1&c=2", "x") == '<a href="https://example.com/a?b=1&amp;c=2">x</a>'
    assert safe_link("javascript:alert(1)", "<x>") == "&lt;x&gt;"
    assert safe_link(None, "y") == "y"


def test_assign_missing_ids_follows_the_pipeline_rule() -> None:
    threats = [
        {"Threat Type": "Spoofing"},
        {"Threat Type": "Spoofing"},
        {"Threat Type": "Information Disclosure"},
        {"ID": "TC-X09", "Threat Type": "Tampering"},
        {"Threat Type": "Something else"},
        "not a threat",
    ]
    assert assign_missing_ids(threats) == ["TC-S01", "TC-S02", "TC-I01", "TC-X09", "TC-X01", ""]
    assert "ID" not in threats[0]


# --- SARIF ------------------------------------------------------------------


def test_to_sarif_basic_shape() -> None:
    sarif = to_sarif(_result(), PROFILE, DESCRIPTION, tool_version="9.9.9")
    assert sarif["version"] == "2.1.0"
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "AegisShield"
    assert driver["version"] == "9.9.9"
    rule_ids = {r["id"] for r in driver["rules"]}
    assert "T1078" in rule_ids
    assert "AEGIS.STRIDE.Tampering" in rule_ids
    assert sarif["runs"][0]["properties"] == {"appType": "Web application", "industrySector": "Retail"}


def test_to_sarif_results_carry_fingerprint_and_rule() -> None:
    sarif = to_sarif(_result())
    results = sarif["runs"][0]["results"]
    assert len(results) == len(SAMPLE_THREATS)
    assert "T1078" in {r["ruleId"] for r in results}
    fingerprints = {r["fingerprints"]["aegisshield/v1"] for r in results}
    assert len(fingerprints) == len(SAMPLE_THREATS)


def test_dread_score_maps_to_sarif_level() -> None:
    assert _dread_to_level(9) == "error"
    assert _dread_to_level(8) == "error"
    assert _dread_to_level(6) == "warning"
    assert _dread_to_level(5) == "warning"
    assert _dread_to_level(2) == "note"
    assert _dread_to_level("not-a-number") == "warning"  # default
    assert _dread_to_level(None) == "warning"
    assert _dread_to_level(True) == "warning"


def test_to_sarif_uses_dread_high_score() -> None:
    sarif = to_sarif(_result())
    spoofing_fp = _stable_fingerprint(SAMPLE_THREATS[0])
    spoofing_result = next(
        r for r in sarif["runs"][0]["results"] if r["fingerprints"]["aegisshield/v1"] == spoofing_fp
    )
    assert spoofing_result["level"] == "error"  # DREAD risk score 8.8 in the fixture


def test_to_sarif_joins_dread_by_threat_id_not_scenario() -> None:
    """Scores join by threat ID; joined by scenario, every level read "warning"."""
    by_id = _results_by_threat(to_sarif(_result()))
    assert by_id["TC-S01"]["level"] == "error"
    assert by_id["TC-S01"]["properties"]["dreadScore"] == 8.8
    assert by_id["TC-T01"]["level"] == "note"
    assert by_id["TC-T01"]["properties"]["dreadScore"] == 2.8


def test_to_sarif_prefers_structured_dread_assessment() -> None:
    assessment = {
        "Risk Assessment": [
            {"ID": "TC-T01", "Damage Potential": 9, "Reproducibility": 9, "Exploitability": 9,
             "Affected Users": 9, "Discoverability": 9},
            {"ID": "TC-S01", "Damage Potential": "bad"},
            "not a row",
        ]
    }
    by_id = _results_by_threat(to_sarif(_result(dread_assessment=assessment)))
    assert by_id["TC-T01"]["level"] == "error"  # structured 9.0 beats the markdown 2.8
    assert by_id["TC-S01"]["level"] == "error"  # unreadable row: markdown 8.8 stays


def test_to_sarif_derives_missing_threat_ids_for_the_dread_join() -> None:
    threats = [{k: v for k, v in t.items() if k != "ID"} for t in SAMPLE_THREATS]
    by_id = _results_by_threat(to_sarif(_result(threat_model=threats, mitre_data=[])))
    assert by_id["TC-S01"]["level"] == "error"
    assert by_id["TC-T01"]["level"] == "note"
    assert {r["ruleId"] for r in by_id.values()} == {"AEGIS.UNKNOWN"}


def test_to_sarif_without_dread_defaults_to_warning() -> None:
    sarif = to_sarif(_result(dread_assessment_markdown=""))
    assert {r["level"] for r in sarif["runs"][0]["results"]} == {"warning"}
    assert all("dreadScore" not in r["properties"] for r in sarif["runs"][0]["results"])


def test_parse_dread_scores_skips_header_and_short_rows() -> None:
    scores = _parse_dread_scores(SAMPLE_DREAD_MD + "| short | row |\nnot a table\n|  | 1 | 2 | 3 | 4 | 5 | 6 |\n")
    assert scores == {"TC-S01": 8.8, "TC-T01": 2.8}
    assert _dread_scores({"dread_assessment": "not a dict"}) == {}


def test_to_sarif_help_uri_points_to_attack_for_attack_rule() -> None:
    rules = {r["id"]: r for r in to_sarif(_result())["runs"][0]["tool"]["driver"]["rules"]}
    assert urlparse(rules["T1078"]["helpUri"]).hostname == "attack.mitre.org"


def test_to_sarif_help_uri_points_to_atlas_for_atlas_rule() -> None:
    atlas_mitre = [
        {
            "threat": SAMPLE_THREATS[0],
            "mitre_techniques": [
                {
                    "name": "LLM Prompt Injection",
                    "description": "x",
                    "id": "AML.T0051",
                    "technique_id": "AML.T0051",
                    "framework": "ATLAS",
                    "tactic": "Initial Access",
                }
            ],
        }
    ]
    sarif = to_sarif(_result(mitre_data=atlas_mitre, threat_model=[SAMPLE_THREATS[0]]))
    rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert urlparse(rules["AML.T0051"]["helpUri"]).hostname == "atlas.mitre.org"


def test_to_sarif_cleans_untrusted_text_and_rule_ids() -> None:
    threat = {
        "ID": "TC-T01",
        "Threat Type": "Tam\u202epering </x>",
        "Scenario": "Bad\x00 text\u200b here",
        "Potential Impact": "",
    }
    mitre = [
        {"threat": threat, "mitre_techniques": [{"technique_id": "../../evil", "name": "x"}]},
        "not an entry",
    ]
    sarif = to_sarif(_result(threat_model=[threat], mitre_data=mitre))
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "AEGIS.STRIDE.Tamperingx"
    assert result["message"]["text"] == "Bad text here"
    assert "\u202e" not in json.dumps(sarif, ensure_ascii=False)


def test_to_sarif_message_for_threat_without_text() -> None:
    sarif = to_sarif(_result(threat_model=[{"ID": "TC-X01"}], mitre_data=[]))
    assert sarif["runs"][0]["results"][0]["message"]["text"] == "AegisShield threat without scenario text."


def test_to_sarif_adds_csf_categories_and_cve_results(job: dict[str, Any]) -> None:
    sarif = to_sarif(
        job["result"],
        job["profile"],
        job["description"],
        nist_csf=job["nist_csf"],
        vuln_lookup=job["vuln_lookup"],
    )
    results = sarif["runs"][0]["results"]
    by_id = _results_by_threat(sarif)
    assert len(by_id) == 6
    assert "PR.AA" in by_id["TC-S01"]["properties"]["nistCsf"]
    # Realistic DREAD: Repudiation scores 4.8 (note), the rest 5.6 to 7.4 (warning).
    assert by_id["TC-R01"]["level"] == "note"
    assert by_id["TC-I01"]["level"] == "warning"
    cves = [r for r in results if r["ruleId"].startswith("CVE-")]
    assert [r["ruleId"] for r in cves] == ["CVE-2023-36053", "CVE-2023-41164"]
    assert cves[0]["level"] == "error"
    assert cves[0]["properties"]["technology"] == "Django"
    assert cves[0]["properties"]["knownExploited"] is False
    assert "knownExploited" not in cves[1]["properties"]
    rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["CVE-2023-36053"]["helpUri"].startswith("https://nvd.nist.gov/")


@pytest.mark.parametrize(
    ("cve", "level"),
    [
        ({"severity": "LOW"}, "note"),
        ({"severity": "MEDIUM"}, "warning"),
        ({"severity": "LOW", "known_exploited": True}, "error"),
        ({}, "warning"),
    ],
)
def test_to_sarif_cve_levels(cve: dict[str, Any], level: str) -> None:
    lookup = {
        "technologies": [
            {"name": "nginx", "version": "1.0", "cves": [{"cve_id": "CVE-2024-0001", "url": "javascript:x", **cve}]},
            {"name": "skip", "cves": ["bad", {"cve_id": "not-a-cve"}]},
            "bad",
        ]
    }
    sarif = to_sarif(_result(threat_model=[], mitre_data=[]), vuln_lookup=lookup)
    (result,) = sarif["runs"][0]["results"]
    assert result["level"] == level
    assert "helpUri" not in sarif["runs"][0]["tool"]["driver"]["rules"][0]


def test_sarif_is_valid_json_and_parses(job: dict[str, Any]) -> None:
    sarif = to_sarif(job["result"], job["profile"], job["description"], vuln_lookup=job["vuln_lookup"])
    serialized = json.dumps(sarif)
    assert json.loads(serialized) == sarif


@pytest.mark.parametrize(
    ("threats", "expected"),
    [
        ([], 0),
        ([SAMPLE_THREATS[0]], 1),
        (SAMPLE_THREATS, 2),
    ],
)
def test_to_sarif_result_count_matches_threats(threats: list[dict[str, Any]], expected: int) -> None:
    sarif = to_sarif(_result(threat_model=threats, mitre_data=[]))
    assert len(sarif["runs"][0]["results"]) == expected
