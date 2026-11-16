"""Tests for the PDF report.

The app makes one PDF report, so the escaping assertions all run against
``generate_pdf_bytes``. The report header is general: it carries no industry
badge for any sector.

Escaping is checked on the XHTML from ``build_report_html`` (PDF content
streams are compressed, so a byte search of the PDF proves nothing) and on
the text pypdf extracts from the rendered PDF.
"""

from __future__ import annotations

import io
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest
from pypdf import PdfReader

from aegisshield.core.errors import AegisError
from aegisshield.services import pdf_render, report_service
from aegisshield.services.report_service import (
    LOGO_PATH,
    _logo_base64,
    _parse_mermaid_graph,
    build_report_html,
    generate_pdf_bytes,
    render_attack_tree,
    render_pdf,
    render_test_cases,
)

FIXTURES = Path(__file__).parent / "fixtures" / "exports"

SMOKE_PROFILE = {
    "app_type": "Web application",
    "industry_sector": "IT",
    "sensitive_data": "High",
    "internet_facing": "Yes",
    "num_employees": "11-100",
    "authentication": ["MFA"],
    "compliance_requirements": ["SOC 2"],
    "selected_technologies": {"Python": "cpe:2.3:a:python:python:"},
    "selected_versions": {"Python": "3.12.*"},
}


def _smoke_result(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "threat_model": [],
        "improvement_suggestions": ["<img src=x onerror=alert(1)>"],
        "attack_tree_code": "graph LR; A-->B",
        "mitre_attack_markdown": "### Test",
        "nvd_vulnerabilities_markdown": "- CVE",
        "otx_data_markdown": "- Pulse",
        "mitigations_markdown": "| A | B | C |",
        "dread_assessment_markdown": "| T | S |",
        "test_cases_markdown": "```gherkin\nGiven x\nWhen y\nThen z\n```",
    }
    base.update(overrides)
    return base


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def job() -> dict[str, Any]:
    request = _load("request.json")
    return {
        "result": _load("job_result.json"),
        "profile": request["app_profile"],
        "description": request["app_description"],
        "nist_csf": _load("nist_csf.json"),
        "vuln_lookup": _load("vuln_lookup.json"),
    }


def _pdf_text(pdf: bytes) -> str:
    return "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(pdf)).pages)


class _Collect(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


def _assert_no_injected_markup(html_doc: str) -> None:
    parser = _Collect()
    parser.feed(html_doc)
    for tag, attrs in parser.tags:
        assert tag not in {"script", "iframe", "object", "embed", "svg", "link"}, tag
        assert not any(name.startswith("on") for name in attrs), (tag, attrs)
        if tag == "img":
            assert (attrs.get("src") or "").startswith("data:image/png;base64,"), attrs


# --- smoke ------------------------------------------------------------------


def test_generate_pdf_bytes_smoke() -> None:
    pdf = generate_pdf_bytes(
        _smoke_result(), SMOKE_PROFILE, "<script>alert(1)</script>Secure app"
    )
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 100


def test_generate_pdf_bytes_realistic_result_with_optional_sections(job: dict[str, Any]) -> None:
    pdf = generate_pdf_bytes(
        job["result"],
        job["profile"],
        job["description"],
        nist_csf=job["nist_csf"],
        vuln_lookup=job["vuln_lookup"],
    )
    assert pdf.startswith(b"%PDF")
    text = _pdf_text(pdf)
    for expected in (
        "Threat Modeling Report",
        "TC-S01",
        "Compromise checkout",
        "Session binding at checkout",
        "NIST CSF 2.0 Mapping",
        "Vulnerability Lookup",
        "CVE-2023-36053",
        "unknown",
    ):
        assert expected in text, expected


def test_generate_pdf_bytes_minimal_result() -> None:
    pdf = generate_pdf_bytes({}, None, "")
    text = _pdf_text(pdf)
    assert "No threats were identified." in text
    assert "No attack tree generated." in text
    assert "Mitigations" not in text  # skipped add-ons leave no empty header


# --- general header (no industry badge) --------------------------------------


def test_report_header_is_general_for_every_industry(job: dict[str, Any]) -> None:
    for sector in ("Retail", "Financial", "Information Technology", "Government", ""):
        profile = {**job["profile"], "industry_sector": sector}
        html_doc = build_report_html(job["result"], profile, job["description"], logo_base64="")
        assert "Threat Modeling Report" in html_doc
        assert "badge" not in html_doc
        assert "45 CFR" not in html_doc
        assert "Security Rule" not in html_doc


def test_report_html_has_no_dashes(job: dict[str, Any]) -> None:
    html_doc = build_report_html(
        job["result"], job["profile"], job["description"],
        nist_csf=job["nist_csf"], vuln_lookup=job["vuln_lookup"], logo_base64="",
    )
    assert not re.search("[\u2013\u2014]", html_doc)


# --- escaping ----------------------------------------------------------------


HOSTILE_RESULT = {
    "threat_model": [
        {
            "ID": "<script>xss</script>",
            "Threat Type": "Tampering<img src=x onerror=alert(1)>",
            "Scenario": "<script>alert('scenario')</script>",
            "Assumptions": [{"Assumption": "<b>a</b>", "Role": "<i>r</i>", "Condition": "<u>c</u>"}],
            "Potential Impact": "<svg onload=alert(1)>",
        }
    ],
    "improvement_suggestions": ["<img src=x onerror=alert(2)>"],
    "attack_tree_code": 'graph TD\n A["<script>tree</script>"] --> B["<img src=x onerror=alert(3)>"]',
    "mitre_attack_markdown": "<script>alert('mitre')</script>",
    "nvd_vulnerabilities_markdown": "<img src=x onerror=alert(4)>",
    "otx_data_markdown": '<div onclick="alert(5)">raw block</div>',
    "mitigations_markdown": "| ID | M |\n|---|---|\n| <script>m</script> | ![x](file:///etc/hosts) |",
    "dread_assessment_markdown": "<iframe src=javascript:alert(6)></iframe>",
    "test_cases_markdown": "<script>pre</script>\n```gherkin\nGiven <script>g</script>\n```\n<b>post</b>",
}
HOSTILE_PROFILE = {
    "app_type": "<script>alert('app')</script>",
    "industry_sector": "<img src=x onerror=alert(7)>",
    "authentication": "<b>single string</b>",
    "selected_technologies": ["<script>t</script>"],
}


def test_build_report_html_escapes_model_and_user_text() -> None:
    html_doc = build_report_html(
        HOSTILE_RESULT, HOSTILE_PROFILE, "<script>alert(1)</script>Secure app", logo_base64="AAAA"
    )
    _assert_no_injected_markup(html_doc)
    assert "<script>" not in html_doc
    assert "onerror=" not in html_doc.replace("onerror=alert", "")  # only as escaped text
    assert "&lt;script&gt;xss&lt;/script&gt;" in html_doc
    assert "/etc/hosts" not in html_doc


def test_generate_pdf_shows_hostile_text_as_literal_text() -> None:
    pdf = generate_pdf_bytes(HOSTILE_RESULT, HOSTILE_PROFILE, "<script>alert(1)</script>Secure app")
    assert pdf.startswith(b"%PDF")
    assert b"<script>xss</script>" not in pdf
    text = _pdf_text(pdf)
    # Escaped markup is drawn as the characters the model wrote.
    assert "<script>xss</script>" in text
    assert "<script>tree</script>" in text
    assert "<script>alert(1)</script>Secure app" in text


def _image_count(pdf: bytes) -> int:
    return sum(len(page.images) for page in PdfReader(io.BytesIO(pdf)).pages)


def test_pdf_embeds_the_logo(job: dict[str, Any]) -> None:
    pdf = generate_pdf_bytes(job["result"], job["profile"], job["description"])
    assert len(PdfReader(io.BytesIO(pdf)).pages[0].images) == 1


def test_pdf_renderer_refuses_local_files_and_network() -> None:
    """Raw markup that reached the renderer still cannot read a file or fetch a URL."""
    for src in (str(LOGO_PATH), LOGO_PATH.as_uri(), "https://tracker.example/p.png"):
        pdf = render_pdf(f'<html><body><p>x</p><img src="{src}" /></body></html>')
        assert _image_count(pdf) == 0, src
    logo = _logo_base64()
    pdf = render_pdf(f'<html><body><img src="data:image/png;base64,{logo}" /></body></html>')
    assert _image_count(pdf) == 1


# --- attack tree ---------------------------------------------------------------


def test_attack_tree_renders_as_outline(job: dict[str, Any]) -> None:
    html_doc = render_attack_tree(job["result"]["attack_tree_code"])
    assert "tree-root" in html_doc
    assert "Compromise checkout" in html_doc
    assert "TC-S01 Replay a stolen session" in html_doc


def test_attack_tree_falls_back_to_escaped_source() -> None:
    html_doc = render_attack_tree('graph TD\n A["<script>only a node</script>"]')
    assert html_doc.startswith('<pre class="code-block">')
    assert "&lt;script&gt;only a node&lt;/script&gt;" in html_doc
    assert "No attack tree generated." in render_attack_tree("   ")


def test_attack_tree_handles_cycles_and_multi_targets() -> None:
    labels, children, roots = _parse_mermaid_graph("flowchart LR\nA --> B & C\nB --> A\nC --> D")
    assert children["A"] == ["B", "C"]
    assert roots == ["A", "B", "C"]  # every node is a target, so all sources are roots
    html_doc = render_attack_tree("flowchart LR\nA --> B & C\nB --> A\nC --> D")
    assert "(see above)" in html_doc
    assert labels["D"] == "D"


# --- test cases ----------------------------------------------------------------


def test_render_test_cases_highlights_gherkin_and_keeps_prose() -> None:
    html_doc = render_test_cases(
        "## TC-S01\n```gherkin\nFeature: F\n  Scenario Outline: S\n    Given a <b>\nplain line\n```\ntrailing **note**"
    )
    assert '<span class="gherkin-kw gherkin-scenario-outline">Scenario Outline</span>' in html_doc
    assert "&lt;b&gt;" in html_doc
    assert "plain&nbsp;line" in html_doc
    assert "<strong>note</strong>" in html_doc
    assert "<h2>TC-S01</h2>" in html_doc
    assert render_test_cases("  ") == ""
    assert render_test_cases("no fences here") == "<p>no fences here</p>\n"


# --- logo and errors ----------------------------------------------------------


def test_logo_is_found_relative_to_the_package(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    assert LOGO_PATH.parent.name == "brand" and LOGO_PATH.name == "logo-light.png"
    assert LOGO_PATH.is_file()
    assert _logo_base64().startswith("iVBOR")  # PNG signature in base64


def test_missing_logo_renders_without_image(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _logo_base64(tmp_path / "missing.png") == ""
    monkeypatch.setattr(report_service, "_logo_base64", lambda: "")
    assert "<img" not in build_report_html({}, {}, "")


def test_pdf_error_status_raises_plain_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class Status:
        err = 1

    monkeypatch.setattr(pdf_render.pisa, "CreatePDF", lambda *a, **k: Status())
    with pytest.raises(AegisError, match="could not be generated"):
        generate_pdf_bytes({}, {}, "")


def test_pdf_renderer_exception_raises_plain_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: Any, **kwargs: Any) -> None:
        raise ValueError("parser failure with internal detail")

    monkeypatch.setattr(pdf_render.pisa, "CreatePDF", boom)
    with pytest.raises(AegisError, match="could not be generated") as info:
        generate_pdf_bytes({}, {}, "")
    assert "internal detail" not in str(info.value)
    assert isinstance(info.value.__cause__.__cause__, ValueError)
