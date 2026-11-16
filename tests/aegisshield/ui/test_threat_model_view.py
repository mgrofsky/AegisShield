"""The shared results view: counts, parsing helpers, every tab with real mock
output, the agentic blocks, the EU AI Act view, hostile model text, and every
export builder."""

from __future__ import annotations

import json

import pytest
from streamlit.testing.v1 import AppTest

from aegisshield.storage import Record, Workspace
from aegisshield.ui import threat_model_view as view
from tests.aegisshield.ui.tm_records import mock_payload

HOSTILE = '<img src=x onerror="alert(1)">'


def _record(payload: dict, title: str = "Checkout") -> Record:
    return Workspace().add("threat_models", title, payload)


def _render(payload: dict, *, duration: float | None = None) -> AppTest:
    def app() -> None:
        import streamlit as st

        from aegisshield.ui import threat_model_view as v
        from aegisshield.ui import tm_style
        from aegisshield.ui.theme import apply_theme

        apply_theme()
        tm_style.apply()
        record = st.session_state["record"]
        v.render_results(record, duration=st.session_state.get("duration"), key_prefix="t")
        v.render_exports(record, key_prefix="t")

    at = AppTest.from_function(app, default_timeout=30)
    at.session_state["record"] = _record(payload)
    at.session_state["duration"] = duration
    return at.run()


def _html(at: AppTest) -> str:
    return "\n".join(str(n.value) for n in at.get("html"))


def _markdown(at: AppTest) -> str:
    return "\n".join(str(n.value) for n in at.markdown)


def test_counts_from_a_real_result() -> None:
    payload = mock_payload()
    assert view.count_techniques(payload) == len(payload["mitre_data"])
    assert view.count_tree_links(payload) == payload["attack_tree_code"].count("-->")
    assert view.count_cves({"nvd_vulnerabilities_markdown": "CVE-2024-1234 and CVE-2024-1234, CVE-2023-99999"}) == 2
    assert view.count_otx_reports({"otx_data_markdown": "one\n\ntwo\n  \nthree"}) == 3
    assert view.count_otx_reports({"otx_data_markdown": "  "}) == 0
    assert view.count_techniques({"mitre_data": ["junk", {"mitre_techniques": "x"}]}) == 0


def test_stride_counts_keep_the_stride_order_then_others() -> None:
    threats = [{"Threat Type": "Tampering"}, {"Threat Type": "Spoofing"}, {"Threat Type": "Tampering"},
               {"Threat Type": "Zeta"}, {}]
    assert view.stride_counts(threats) == [("Spoofing", 1), ("Tampering", 2), ("Other", 1), ("Zeta", 1)]


@pytest.mark.parametrize(("source", "label"), [("user", "you chose them"), ("regex", "detected from the description"),
                                                ("llm", "detected by the model"), (None, "none"), ("odd", "odd")])
def test_pattern_source_labels(source: object, label: str) -> None:
    assert view.pattern_source_label(source) == label


@pytest.mark.parametrize(("payload", "expected"), [
    ({"profile": {"app_type": "AI/ML Systems"}}, True),
    ({"profile": {"app_type": "Web application", "app_pattern": ["RAG"]}}, True),
    ({"profile": {"app_type": "Web application"}, "detected_patterns": ["GenAI"]}, True),
    ({"profile": {"compliance_requirements": ["EU AI Act"]}}, True),
    ({"profile": {"app_type": "Web application"}}, False),
    ({}, False),
])
def test_is_ai_system(payload: dict, expected: bool) -> None:
    assert view.is_ai_system(payload) is expected


def test_markdown_table() -> None:
    md = "Intro\n\n| A | B |\n|---|:-:|\n| 1 | 2 |\n| 3 |\n\nAfter\n| X |\n|---|\n| 9 |"
    assert view.markdown_table(md) == [{"A": "1", "B": "2"}, {"A": "3", "B": ""}]
    assert view.markdown_table("no table") is None
    assert view.markdown_table(None) is None


def test_gherkin_text_collects_every_block() -> None:
    md = "## One\n```gherkin\nFeature: A\n```\ntext\n```\nFeature: B\n```"
    assert view.gherkin_text(md) == "Feature: A\n\nFeature: B\n"
    assert view.gherkin_text("nothing") == ""
    assert view.gherkin_text(None) == ""


def test_bundle_markdown_has_every_section() -> None:
    text = view.bundle_markdown(_record(mock_payload(), "Checkout"))
    for heading in ("# Checkout", "## Threat model", "## Mitigations", "## DREAD assessment",
                    "## Test cases", "## Attack tree", "```mermaid"):
        assert heading in text


def test_every_tab_renders_from_a_real_result() -> None:
    at = _render(mock_payload(), duration=9.12)
    assert not at.exception
    assert [t.label for t in at.tabs] == ["Attack path", "STRIDE findings", "MITRE ATT&CK mapping", "DREAD",
                                          "Mitigations", "Test cases", "Compliance mapping", "Lookup results"]
    body = _html(at)
    assert "9.1s" in body and "STRIDE breakdown" in body
    assert body.count('class="tm-svg"') == 2
    assert 'href="https://attack.mitre.org/techniques/' in body
    assert "Top mitigation" in body and "Highest risk" in body
    assert "NIST CSF 2.0 coverage" in body
    assert "PCI DSS v4.0" in body
    assert "EU AI Act" not in body
    assert len(at.dataframe) >= 5
    assert "No NVD vulnerabilities found." in _markdown(at)


def test_tabs_without_their_data_are_hidden() -> None:
    payload = {k: v for k, v in mock_payload().items()
               if k not in ("dread_assessment_markdown", "mitigations_markdown", "test_cases_markdown")}
    at = _render(payload)
    assert [t.label for t in at.tabs] == ["Attack path", "STRIDE findings", "MITRE ATT&CK mapping",
                                          "Compliance mapping", "Lookup results"]
    assert "Duration" not in _html(at)


def test_an_empty_payload_still_renders() -> None:
    at = _render({})
    assert not at.exception
    body = _html(at)
    assert "No STRIDE findings recorded." in body and "No attack tree was generated." in body
    assert "No techniques were mapped." in body and "No threats mapped to NIST CSF." in body


def test_a_tree_that_cannot_be_drawn_shows_its_source() -> None:
    at = _render({"attack_tree_code": "graph TD\n A[alone]"})
    assert "The attack tree could not be drawn" in _html(at)
    assert at.code[0].value == "graph TD\n A[alone]"


def test_hostile_model_text_never_becomes_markup() -> None:
    payload = mock_payload()
    payload["threat_model"] = [dict(payload["threat_model"][0], Scenario=HOSTILE,
                                    **{"Potential Impact": HOSTILE, "Threat Type": HOSTILE})]
    payload["detected_patterns"] = [HOSTILE]
    payload["improvement_suggestions"] = [f"![x](https://evil.example/{HOSTILE})"]
    payload["profile"] = {**payload["profile"], "compliance_requirements": [HOSTILE]}
    at = _render(payload)
    body = _html(at)
    assert "<img src=x" not in body and "&lt;img src=x" in body
    assert "![x]" not in _markdown(at)


def test_the_agentic_extras_and_the_eu_ai_act_view() -> None:
    payload = mock_payload()
    payload["profile"] = {**payload["profile"], "app_type": "AI/ML Systems"}
    payload["lead_plan"] = {"decider": "ai", "rationale": "Every section.",
                            "sections": [{"section": "STRIDE", "focus": "Sessions", "skip": False}, "junk"]}
    payload["teammate_review"] = {"flags": [{"threat": "TC-R01", "reason": "Lower."}], "notes": "Fits."}
    payload["rebuttal_review"] = {"rebuttals": [{"threat": "TC-I01", "counterexample": "UUIDs",
                                                 "adjusted": "6", "reason": "Unlikely."}]}
    at = _render(payload)
    body = _html(at)
    assert "Lead plan" in body and "Teammate review" in body and "Rebuttal review" in body
    assert "EU AI Act" in body
    assert at.expander[0].label == "Agent team: the lead's plan and the reviews"


def test_the_eu_ai_act_view_says_when_nothing_matched(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(view.regulation_service, "match_threats_to_framework", lambda *_a, **_k: {})
    at = _render({"profile": {"app_type": "AI/ML Systems"}, "threat_model": []})
    assert "No EU AI Act obligation matched these threats." in _html(at)


def test_the_eu_ai_act_view_survives_missing_data(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*_a: object, **_k: object) -> dict:
        raise OSError("gone")

    monkeypatch.setattr(view.regulation_service, "match_threats_to_framework", broken)
    at = _render({"profile": {"app_type": "AI/ML Systems"}, "threat_model": []})
    assert "The EU AI Act data could not be read." in _html(at)


def test_every_export_builds_and_carries_no_raw_markup() -> None:
    payload = mock_payload()
    payload["threat_model"] = [dict(payload["threat_model"][0], Scenario=HOSTILE)] + payload["threat_model"][1:]

    def app() -> None:
        import streamlit as st

        from aegisshield.ui import threat_model_view as v

        record = st.session_state["record"]
        st.session_state["built"] = {e.label: (e.file_name, e.build()) for e in v.exports(record)}
        v.render_exports(record, key_prefix="x")

    at = AppTest.from_function(app, default_timeout=60)
    at.session_state["record"] = _record(payload)
    at.run()
    assert not at.exception
    built = at.session_state["built"]
    assert list(built) == ["PDF", "HTML", "JSON", "SARIF", "Markdown", "Attack tree (.mmd)",
                           "Test cases (.feature)"]
    assert built["PDF"][1][:4] == b"%PDF"
    assert "<img src=x" not in built["HTML"][1]
    assert json.loads(built["JSON"][1])["threat_model"][0]["Scenario"] == HOSTILE
    assert json.loads(built["SARIF"][1])["version"] == "2.1.0"
    assert built["Attack tree (.mmd)"][1].startswith("graph TD")
    assert "Feature:" in built["Test cases (.feature)"][1]
    assert [b.label for b in at.get("download_button")][:2] == ["PDF", "HTML"]


def test_file_downloads_are_disabled_without_their_content() -> None:
    def app() -> None:
        import streamlit as st

        from aegisshield.ui import threat_model_view as v

        v.render_exports(st.session_state["record"], key_prefix="y")

    at = AppTest.from_function(app, default_timeout=60)
    at.session_state["record"] = _record({})
    at.run()
    buttons = {b.label: b for b in at.get("download_button")}
    assert buttons["Attack tree (.mmd)"].disabled and buttons["Test cases (.feature)"].disabled
    assert not buttons["PDF"].disabled


def test_the_csf_report_is_computed_once_per_record(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    real = view.nist_csf_service.csf_report
    monkeypatch.setattr(view.nist_csf_service, "csf_report",
                        lambda *a: calls.append(1) or real(*a))
    at = _render(mock_payload())
    at.run()
    at.run()
    assert len(calls) == 1
