"""Policy catalog and generation: the catalog contract, citations, generating
each policy, and the PDF."""

from __future__ import annotations

import pytest

from aegisshield.config import Settings
from aegisshield.core.errors import LLMError, ValidationError
from aegisshield.llm.mock import MOCK_POLICY, MockLLM
from aegisshield.services import pdf_render, policy_catalog, policy_service
from aegisshield.services.org_profile import KNOWN_COMPLIANCE_DRIVERS, OrgProfile

SETTINGS = Settings(architect_model="gpt-5.4", worker_model="gpt-5.4", mock_llm=True)

_REQUIRED_KEYS = {"key", "title", "summary", "csf_baseline", "prompt_outline"}
_GENERIC_KEYS = [
    "information_security_policy",
    "access_control_policy",
    "data_protection_policy",
    "incident_response_policy",
    "risk_management_policy",
    "vendor_management_policy",
]
_NEW_KEYS = [
    "sensitive_data_handling_policy",
    "breach_notification_policy",
    "connected_device_security_policy",
]


class RecordingLLM:
    """Records ``chat_text`` calls and answers with fixed text."""

    def __init__(self, answer: str = "## Purpose\n\nText.") -> None:
        self.answer = answer
        self.calls: list[dict] = []

    def chat_text(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs.get("on_text"):
            kwargs["on_text"](self.answer)
        return self.answer


class FailingLLM:
    def chat_text(self, **kwargs):
        raise LLMError("The AI service did not answer.")


def _profile(**overrides) -> dict:
    data = {
        "legal_name": "Northwind Outfitters Inc.",
        "dba_name": "Northwind",
        "industry": "Retail and e-commerce",
        "employee_count": 240,
        "leadership": [
            {"role": "CEO", "name": "Dana Cruz"},
            {"role": "CISO", "name": "Sam Patel"},
        ],
        "compliance_drivers": ["PCI DSS", "SOC 2"],
        "regulatory_notes": "Sells online in the US and the EU.",
    }
    data.update(overrides)
    return data


# -- Catalog contract ---------------------------------------------------------


def test_catalog_keys_are_general() -> None:
    keys = frozenset(entry["key"] for entry in policy_catalog.get_catalog())
    assert keys == frozenset(_GENERIC_KEYS + _NEW_KEYS)


@pytest.mark.parametrize("entry", policy_catalog.get_catalog(), ids=lambda e: e["key"])
def test_every_entry_has_required_keys(entry: dict) -> None:
    assert _REQUIRED_KEYS.issubset(entry.keys())
    assert isinstance(entry["csf_baseline"], list) and entry["csf_baseline"]
    assert entry["title"] and entry["summary"] and entry["prompt_outline"]
    # Citations stay internal; a page that renders an entry shows no framework list.
    assert set(entry) == _REQUIRED_KEYS
    assert "CFR" not in repr(entry) and "Art." not in repr(entry)


@pytest.mark.parametrize("entry", policy_catalog.get_catalog(), ids=lambda e: e["key"])
def test_every_csf_baseline_id_resolves(entry: dict) -> None:
    mappings = policy_service.resolve_csf_mappings(entry)
    assert [m["id"] for m in mappings] == entry["csf_baseline"]
    assert all(m["name"] and m["function_name"] for m in mappings)


@pytest.mark.parametrize("entry", policy_catalog.get_catalog(), ids=lambda e: e["key"])
def test_prompt_outline_formats_cleanly(entry: dict) -> None:
    # The crash class: a placeholder the service does not supply raises KeyError.
    prompt = policy_service.build_prompt(entry, OrgProfile.from_dict(_profile()))
    assert prompt
    assert "{" not in prompt and "}" not in prompt
    assert "Northwind Outfitters Inc." in prompt


@pytest.mark.parametrize("entry", policy_catalog.CATALOG, ids=lambda e: e["key"])
def test_citation_drivers_are_known_options(entry: dict) -> None:
    for driver, citations in entry["citations_by_driver"].items():
        assert driver in KNOWN_COMPLIANCE_DRIVERS
        assert citations and all(isinstance(c, str) and c for c in citations)


def test_get_catalog_returns_a_copy() -> None:
    catalog = policy_catalog.get_catalog()
    catalog[0]["title"] = "changed"
    catalog[0]["csf_baseline"].append("XX.YY")
    assert policy_catalog.get_catalog()[0]["title"] == "Information Security Policy"
    assert "XX.YY" not in policy_catalog.get_entry("information_security_policy")["csf_baseline"]


def test_get_entry_unknown_is_none() -> None:
    assert policy_catalog.get_entry("nope") is None


def test_unknown_csf_id_is_skipped(caplog) -> None:
    entry = {"csf_baseline": ["GV.OC", "ZZ.ZZ"]}
    assert [m["id"] for m in policy_service.resolve_csf_mappings(entry)] == ["GV.OC"]
    assert "ZZ.ZZ" in caplog.text


# -- Citations come only from selected drivers ---------------------------------


def test_no_drivers_means_no_citations() -> None:
    key = "breach_notification_policy"
    assert policy_catalog.citations_for(key, []) == []
    assert policy_catalog.citations_for(key, ["NIST CSF", "Internal audit"]) == []


def test_citations_follow_selected_driver_order_and_spelling() -> None:
    cites = policy_catalog.citations_for("access_control_policy", ["pci-dss", "SOC 2", "PCI DSS"])
    assert cites[0].startswith("PCI DSS v4.0.1 Requirement 7")
    assert cites[-1].startswith("TSC CC6.1")
    assert len(cites) == len(set(cites)) == 3


def test_unknown_key_has_no_citations() -> None:
    assert policy_catalog.citations_for("nope", ["GDPR"]) == []


# -- Generation -----------------------------------------------------------------


def test_generate_calls_architect_model_with_profile_prompt() -> None:
    llm = RecordingLLM()
    seen: list[str] = []
    result = policy_service.generate_policy(
        "information_security_policy", _profile(), llm=llm, settings=SETTINGS, on_text=seen.append
    )
    call = llm.calls[0]
    assert call["model"] == SETTINGS.architect_model
    assert call["max_tokens"] == 8192
    assert call["system"] == policy_service.SYSTEM_PROMPT
    user = call["user"]
    assert "Write a formal Information Security Policy for Northwind Outfitters Inc." in user
    assert "(doing business as Northwind)" in user
    assert "CEO: Dana Cruz; CISO: Sam Patel" in user
    assert "Name the Sam Patel (CISO) as policy owner" in user
    assert "Dana Cruz (CEO)" in user
    assert "Compliance drivers: PCI DSS, SOC 2." in user
    assert "Regulatory context: Sells online in the US and the EU." in user
    assert "240-person Retail and e-commerce organization" in user
    assert "PCI DSS v4.0.1 Requirement 12.1" in user
    assert seen == [llm.answer]
    assert result.pop("safeguards")["status"] in {"on", "unavailable"}
    assert result == {
        "title": "Information Security Policy",
        "body_markdown": "## Purpose\n\nText.",
        "csf_mappings": policy_service.resolve_csf_mappings(
            policy_catalog.get_entry("information_security_policy")
        ),
        "regulatory_citations": [
            "PCI DSS v4.0.1 Requirement 12.1 Information security policy",
            "TSC CC1.1-CC1.5 Control environment",
            "TSC CC5.3 Policies and procedures",
        ],
    }


def test_generate_defaults_for_a_sparse_profile() -> None:
    llm = RecordingLLM()
    result = policy_service.generate_policy(
        "access_control_policy", {"legal_name": "Acme"}, llm=llm, settings=SETTINGS
    )
    user = llm.calls[0]["user"]
    assert "Industry: technology. Leadership: Leadership team." in user
    assert "Compliance drivers: general best practices." in user
    assert "the designated executive owns" in user
    assert "Regulatory context" not in user
    assert "Cite these" not in user
    assert result["regulatory_citations"] == []


def test_generate_accepts_an_org_profile_object() -> None:
    llm = RecordingLLM()
    profile = OrgProfile.from_dict(_profile(compliance_drivers=["GDPR"]))
    result = policy_service.generate_policy(
        "breach_notification_policy", profile, llm=llm, settings=SETTINGS
    )
    assert result["regulatory_citations"][0].startswith("GDPR Art. 33")


def test_selected_framework_is_named_only_when_chosen() -> None:
    llm = RecordingLLM()
    policy_service.generate_policy(
        "sensitive_data_handling_policy", _profile(), llm=llm, settings=SETTINGS
    )
    assert "HIPAA" not in llm.calls[0]["user"]
    policy_service.generate_policy(
        "sensitive_data_handling_policy",
        _profile(compliance_drivers=["HIPAA"]),
        llm=llm,
        settings=SETTINGS,
    )
    assert "45 CFR 164.502(b) Minimum necessary" in llm.calls[1]["user"]


def test_visitor_braces_are_not_template_fields() -> None:
    llm = RecordingLLM()
    policy_service.generate_policy(
        "risk_management_policy",
        _profile(legal_name="Acme {legal_name} {0}"),
        llm=llm,
        settings=SETTINGS,
    )
    assert "Acme {legal_name} {0}" in llm.calls[0]["user"]


def test_body_is_sanitized_and_capped() -> None:
    llm = RecordingLLM("ok\x00\u202e text " + "word " * 60_000)
    result = policy_service.generate_policy(
        "access_control_policy", _profile(), llm=llm, settings=SETTINGS
    )
    body = result["body_markdown"]
    assert body.startswith("ok text ")
    assert len(body) <= policy_service.MAX_BODY_CHARS
    assert body.endswith("...")


def test_unknown_policy_key() -> None:
    with pytest.raises(ValidationError, match="not in the catalog"):
        policy_service.generate_policy("nope", _profile(), llm=RecordingLLM(), settings=SETTINGS)


def test_missing_profile() -> None:
    with pytest.raises(ValidationError, match="Save an organization profile"):
        policy_service.generate_policy(
            "access_control_policy", None, llm=RecordingLLM(), settings=SETTINGS
        )


def test_invalid_profile() -> None:
    with pytest.raises(ValidationError, match="Legal name is required"):
        policy_service.generate_policy(
            "access_control_policy", {"industry": "x"}, llm=RecordingLLM(), settings=SETTINGS
        )


def test_llm_error_propagates() -> None:
    with pytest.raises(LLMError):
        policy_service.generate_policy(
            "access_control_policy", _profile(), llm=FailingLLM(), settings=SETTINGS
        )


# Every policy generates offline with the mock model and renders.
@pytest.mark.parametrize("key", _GENERIC_KEYS + _NEW_KEYS)
def test_mock_generate_every_policy_and_render(key: str) -> None:
    streamed: list[str] = []
    result = policy_service.generate_policy(
        key, _profile(), llm=MockLLM(), settings=SETTINGS, on_text=streamed.append
    )
    entry = policy_catalog.get_entry(key)
    assert result["title"] == entry["title"]
    assert result["body_markdown"] == MOCK_POLICY.strip()
    assert "".join(streamed) == MOCK_POLICY
    assert len(result["csf_mappings"]) == len(entry["csf_baseline"])
    pdf = policy_service.render_policy_pdf({**result, "version": 1})
    assert pdf[:4] == b"%PDF"


# -- PDF -----------------------------------------------------------------------


def test_html_escapes_every_value() -> None:
    page = policy_service.build_policy_html(
        {
            "title": "<script>alert(1)</script>",
            "version": '1"><b>',
            "body_markdown": "Hello <iframe src=x></iframe> **bold**",
            "csf_mappings": [{"id": "<i>", "function_name": "F&F", "name": '"q"'}, "junk"],
            "regulatory_citations": ["<b>GDPR</b>"],
        }
    )
    assert "<script>" not in page and "&lt;script&gt;" in page
    assert "<iframe" not in page and "&lt;iframe" in page
    assert "<strong>bold</strong>" in page
    assert "&lt;i&gt; - F&amp;F: &quot;q&quot;" in page
    assert "&lt;b&gt;GDPR&lt;/b&gt;" in page
    assert 'Version 1&quot;&gt;&lt;b&gt;' in page
    assert "Regulatory Citations" in page


def test_html_omits_empty_sections_and_uses_now() -> None:
    from datetime import UTC, datetime

    page = policy_service.build_policy_html(
        {"title": "T", "body_markdown": "x"}, now=datetime(2026, 1, 2, 3, 4, tzinfo=UTC)
    )
    assert "NIST CSF 2.0 Mappings" not in page
    assert "Regulatory Citations" not in page
    assert "Generated: 2026-01-02 03:04 UTC" in page
    assert "Version 1 |" in page


def test_markdown_images_are_removed_before_rendering() -> None:
    body = "![a](http://127.0.0.1:9/a.png)\n\n![b](file:///etc/hosts)\n\n[link](javascript:x)"
    rendered = policy_service.markdown_to_html(body)
    assert "<img" not in rendered
    assert "127.0.0.1" not in rendered and "/etc/hosts" not in rendered
    assert "javascript:" not in rendered


def test_pdf_contains_title_and_citations() -> None:
    pdf = policy_service.render_policy_pdf(
        {
            "title": "Access Control Policy",
            "body_markdown": "## Purpose\n\nKeep access tight.",
            "regulatory_citations": ["GDPR Art. 32 Security of processing"],
        }
    )
    assert pdf[:4] == b"%PDF"
    assert pdf.rstrip().endswith(b"%%EOF")


def test_pdf_without_logo(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(policy_service, "_LOGO_PATH", tmp_path / "missing.png")
    assert policy_service._logo_tag() == ""
    assert policy_service.render_policy_pdf({"title": "T", "body_markdown": "x"})[:4] == b"%PDF"


def test_pdf_error_raises(monkeypatch) -> None:
    class Bad:
        err = 1

    monkeypatch.setattr(pdf_render.pisa, "CreatePDF", lambda *a, **k: Bad())
    with pytest.raises(policy_service.PolicyRenderError, match="could not be generated"):
        policy_service.render_policy_pdf({"title": "T", "body_markdown": "x"})
