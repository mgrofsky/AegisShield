"""The MITRE ATLAS block on the results page, for an AI system and for an
older record that has no ATLAS mapping."""

from __future__ import annotations

import re

from streamlit.testing.v1 import AppTest

from aegisshield.pipeline.atlas_service import ATLAS_RESULT_KEY
from aegisshield.storage import RecordKind, Workspace
from tests.aegisshield.pipeline import non_ai_pin
from tests.aegisshield.services.test_atlas_exports import ai_result
from tests.aegisshield.ui.tm_records import mock_payload

TECHNIQUE_LINK = re.compile(r'href="https://atlas\.mitre\.org/techniques/AML\.T\d{4}(?:\.\d{3})?"')
MITIGATION_LINK = re.compile(r'href="https://atlas\.mitre\.org/mitigations/AML\.M\d{4}"')
STUDY_LINK = re.compile(r'href="https://atlas\.mitre\.org/studies/AML\.CS\d{4}"')


def _app() -> None:
    import streamlit as st

    from aegisshield.ui import routes
    from aegisshield.ui.pages import threat_model_detail
    from aegisshield.ui.theme import apply_theme

    apply_theme()
    st.navigation(routes.build_navigation(with_tshark=False))
    threat_model_detail.render()


def _render(payload: dict) -> AppTest:
    ws = Workspace()
    record = ws.add(RecordKind.THREAT_MODELS, "Model", payload)
    at = AppTest.from_function(_app, default_timeout=30)
    at.session_state["aegis_workspace"] = ws
    at.query_params["id"] = record.id
    return at.run()


def _html(at: AppTest) -> str:
    return "\n".join(str(node.value) for node in at.get("html"))


def test_an_ai_system_shows_the_atlas_block_with_working_links() -> None:
    result = ai_result()
    at = _render({**result, "profile": {**non_ai_pin.PROFILE, "app_pattern": ["GenAI"]},
                  "description": non_ai_pin.DESCRIPTION})
    assert not at.exception
    body = _html(at)
    tabs = [t.label for t in at.tabs]
    assert "MITRE ATT&CK and ATLAS" in tabs and "MITRE ATT&CK mapping" not in tabs
    assert 'data-testid="tm-atlas"' in body
    block = body[body.index('data-testid="tm-atlas"'):]
    rows = result[ATLAS_RESULT_KEY]["threats"]
    assert len(TECHNIQUE_LINK.findall(block)) == sum(1 for r in rows if r["technique"])
    assert MITIGATION_LINK.search(block) and STUDY_LINK.search(block)
    # The findings cards link each threat's ATLAS technique too.
    findings = body[body.index('class="tm-findings"'):body.index('data-testid="tm-atlas"')]
    assert TECHNIQUE_LINK.search(findings)
    assert "attack.mitre.org/techniques/AML" not in body
    assert f"ATLAS {result[ATLAS_RESULT_KEY]['atlas_version']} technique for each threat" in body
    assert "ATLAS techniques" in body


def test_a_record_without_the_field_renders_as_before() -> None:
    at = _render({**mock_payload(), "profile": {**non_ai_pin.PROFILE, "app_type": "AI/ML Systems"}})
    assert not at.exception
    body = _html(at)
    assert "MITRE ATT&CK mapping" in [t.label for t in at.tabs]
    assert 'data-testid="tm-atlas"' not in body and "ATLAS techniques" not in body


def test_a_failed_step_and_an_unmapped_threat_are_said_plainly() -> None:
    result = ai_result()
    mapping = result[ATLAS_RESULT_KEY]
    mapping["call"] = "failed"
    mapping["threats"][0].update(status="none_fits", technique=None)
    at = _render({**result, "profile": {**non_ai_pin.PROFILE, "app_pattern": ["GenAI"]}})
    assert not at.exception
    body = _html(at) + str([n.value for n in at.get("markdown")])
    assert "The ATLAS step did not finish, so no ATLAS technique was mapped." in body
    assert "No ATLAS technique fits this threat (the model&#x27;s answer)." in body
