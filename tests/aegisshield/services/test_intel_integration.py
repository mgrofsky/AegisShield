"""The services fed each other's real output, not hand-written shapes.

A real ``run_lookup`` result (NVD stubbed) and a real ``csf_report`` go
through every exporter, and the same lookup is stored in a ``Workspace``
for ``aggregate_posture``.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from pypdf import PdfReader

from aegisshield.config import Settings
from aegisshield.services import vuln_lookup
from aegisshield.services.export_service import (
    to_html_report,
    to_json_bytes,
    to_json_report,
    to_sarif,
)
from aegisshield.services.nist_csf_service import csf_report
from aegisshield.services.posture_service import aggregate_posture
from aegisshield.services.report_service import generate_pdf_bytes
from aegisshield.services.vuln_lookup import NvdAnswer
from aegisshield.storage import RecordKind, Workspace

pytestmark = pytest.mark.usefixtures("lookup_no_network", "quiet_feeds")

FIXTURES = Path(__file__).parent / "fixtures" / "exports"


def _cve(cve_id: str, score: float, severity: str) -> dict:
    return {
        "cve_id": cve_id, "cvss_score": score, "severity": severity, "published": "2024-01-01",
        "description": "Checkout <script>alert(1)</script> flaw", "references": [],
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


@pytest.fixture
def lookup_result(monkeypatch) -> dict:
    def nvd(name, version, key):
        if name == "PHP":
            return NvdAnswer([_cve("CVE-2024-0001", 9.8, "CRITICAL"), _cve("CVE-2024-0002", 5.0, "MEDIUM")], True)
        return NvdAnswer([], True)

    monkeypatch.setattr(vuln_lookup, "nvd_lookup", nvd)
    return vuln_lookup.run_lookup(
        [
            {"name": "PHP", "version": "8.2.35"},  # found; KEV off, so known-exploited unknown
            {"name": "nginx", "version": "1.27.5"},  # checked, none found
            {"name": "<b>Acme</b> Widget", "version": None},  # not checked
        ],
        settings=Settings(),
    )


@pytest.fixture
def job() -> tuple[dict, dict, str]:
    request = json.loads((FIXTURES / "request.json").read_text())
    result = json.loads((FIXTURES / "job_result.json").read_text())
    return result, request["app_profile"], request["app_description"]


def test_the_lookup_result_has_the_unknowns_the_exporters_must_show(lookup_result) -> None:
    php, nginx, acme = lookup_result["technologies"]
    assert (php["state"], php["kev_count"]) == ("vulnerabilities_found", None)
    assert nginx["state"] == "checked_none_found"
    assert (acme["state"], acme["cve_count"]) == ("not_checked", None)
    assert lookup_result["summary"]["kev_count"] is None
    assert lookup_result["summary"]["exploit_count"] is None


def test_json_export_carries_the_real_lookup_and_csf(job, lookup_result) -> None:
    result, profile, description = job
    csf = csf_report(result["threat_model"], result["mitre_data"])
    report = to_json_report(result, profile, description, nist_csf=csf, vuln_lookup=lookup_result)
    data = json.loads(to_json_bytes(report))
    text = json.dumps(data)
    assert "CVE-2024-0001" in text
    assert csf["mappings"] and csf["mappings"][0]["threat_id"] in text


def test_html_export_shows_unknown_never_zero_and_escapes(job, lookup_result) -> None:
    result, profile, description = job
    csf = csf_report(result["threat_model"], result["mitre_data"])
    page = to_html_report(result, profile, description, nist_csf=csf, vuln_lookup=lookup_result)
    assert "CVE-2024-0001" in page
    assert "unknown" in page.lower()
    assert "<b>Acme</b>" not in page and "&lt;b&gt;Acme&lt;/b&gt;" in page
    assert "<script>alert(1)</script>" not in page
    assert php_description(lookup_result) in page.replace("&#x27;", "'")
    assert csf["mappings"][0]["categories"][0]["id"] in page  # the real CSF section rendered


def php_description(lookup_result: dict) -> str:
    return lookup_result["technologies"][0]["description"].split(" (")[0]


def test_sarif_lists_the_lookup_cves_and_csf(job, lookup_result) -> None:
    result, profile, description = job
    csf = csf_report(result["threat_model"], result["mitre_data"])
    sarif = to_sarif(result, profile, description, nist_csf=csf, vuln_lookup=lookup_result)
    text = json.dumps(sarif)
    assert sarif["version"] == "2.1.0"
    assert "CVE-2024-0001" in text and "CVE-2024-0002" in text
    assert "PR.AA" in text  # CSF categories from the real mapping ride on the threats


def test_pdf_renders_the_real_lookup(job, lookup_result) -> None:
    result, profile, description = job
    csf = csf_report(result["threat_model"], result["mitre_data"])
    pdf = generate_pdf_bytes(result, profile, description, nist_csf=csf, vuln_lookup=lookup_result)
    text = " ".join(page.extract_text() for page in PdfReader(io.BytesIO(pdf)).pages)
    assert "CVE-2024-0001" in text
    assert "unknown" in text.lower()


def test_posture_reads_the_stored_lookup(job, lookup_result) -> None:
    result, profile, description = job
    workspace = Workspace()
    workspace.add(RecordKind.THREAT_MODELS, "Checkout", {"profile": profile, "description": description, **result})
    workspace.add(
        RecordKind.LOOKUPS,
        "Checkout stack",
        {"request": {"technologies": ["PHP 8.2.35", "nginx 1.27.5", "Acme Widget"]}, "result": lookup_result},
    )
    snapshot = aggregate_posture(workspace)
    assert snapshot.last_lookup_status == "complete"
    assert snapshot.last_lookup_tech_count == 3
    assert snapshot.last_lookup_finished_at == lookup_result["finished_at"]


@pytest.fixture
def otx_lookup_result(monkeypatch) -> dict:
    """A real run_lookup with an OTX key, the pulse source stubbed with
    hostile strings (names, tags, and a javascript: URL)."""
    monkeypatch.setattr(vuln_lookup, "nvd_lookup", lambda name, version, key: NvdAnswer([], True))

    def otx(name, key):
        return [
            {"id": "p1", "name": "Checkout <img src=x onerror=alert(1)> skimmer", "tlp": "white",
             "modified": "2026-10-02T11:00:00", "tags": ["magecart", "<b>card</b>", *[f"t{i}" for i in range(9)]],
             "url": "https://otx.alienvault.com/pulse/p1"},
            {"id": None, "name": "No link", "tlp": None, "modified": None, "tags": None,
             "url": "javascript:alert(2)"},
            "junk",
        ]

    monkeypatch.setattr(vuln_lookup, "otx_lookup", otx)
    return vuln_lookup.run_lookup([{"name": "nginx", "version": "1.27.5"}], settings=Settings(),
                                  otx_api_key="otx-test-key")


def test_every_export_carries_the_lookups_otx_reports_escaped(job, otx_lookup_result) -> None:
    result, profile, description = job
    pulses = otx_lookup_result["technologies"][0]["otx_pulses"]
    assert pulses and pulses[0]["id"] == "p1"

    data = json.loads(to_json_bytes(to_json_report(result, profile, description,
                                                   vuln_lookup=otx_lookup_result)))
    assert data["vulnerability_lookup"]["technologies"][0]["otx_pulses"][0]["name"].startswith("Checkout")
    assert "otx-test-key" not in json.dumps(data)

    page = to_html_report(result, profile, description, vuln_lookup=otx_lookup_result)
    assert "AlienVault OTX reports that mention it" in page
    assert '<a href="https://otx.alienvault.com/pulse/p1">Checkout &lt;img' in page
    assert "<img src=x" not in page and "<b>card</b>" not in page and "&lt;b&gt;card&lt;/b&gt;" in page
    assert "TLP white" in page and "updated 2026-10-02" in page
    assert "t5, ..." in page and "t6" not in page  # eight tags, then "..."
    assert "javascript:" not in page and "<li>No link</li>" in page

    pdf = generate_pdf_bytes(result, profile, description, vuln_lookup=otx_lookup_result)
    text = " ".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf)).pages)
    assert "AlienVault OTX reports that mention it" in text and "skimmer" in text
