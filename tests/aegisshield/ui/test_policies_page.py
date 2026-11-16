"""The policies page and the organization profile form under AppTest."""

from __future__ import annotations

import html

import pytest

from aegisshield.core.errors import LLMError
from aegisshield.services import policy_catalog, policy_service
from aegisshield.services.org_profile import OrgProfile
from aegisshield.storage import RecordKind, Workspace
from aegisshield.ui import tool_parts
from aegisshield.ui.pages import policies as page
from tests.aegisshield.ui.lookup_fakes import HOSTILE
from tests.aegisshield.ui.tool_helpers import (
    Gate,
    click_and_finish,
    fresh_runner,
    html_of,
    make_app,
    wait_for_jobs,
)

__all__ = ["fresh_runner"]

FIRST = policy_catalog.get_catalog()[0]


@pytest.fixture(autouse=True)
def fast_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_MOCK_LLM", "1")
    monkeypatch.setattr(tool_parts, "MOCK_STREAM_DELAY", 0.0)


def _profiled(**extra) -> Workspace:
    ws = Workspace()
    OrgProfile.from_dict({"legal_name": "Example Retail <Inc>", "industry": "Retail and e-commerce",
                          "compliance_drivers": ["PCI DSS"], **extra}).save_to(ws)
    return ws


def _ws(at) -> Workspace:
    return at.session_state["aegis_workspace"]


def _generate(at, runner, key: str = FIRST["key"]):
    return click_and_finish(at, f"pol_gen_{key}", runner)


def test_without_a_profile_generation_is_blocked_and_says_what_is_missing(fresh_runner) -> None:
    at = make_app(page.PAGE).run()
    assert not at.exception
    body = html_of(at)
    assert '<h1 class="ax-title">Policies</h1>' in body and "ax-area-compliance" in body
    assert "Missing: Legal name, Industry." in body
    assert body.count(html.escape(page.DRAFT_NOTE)) == 1
    assert at.button(key=f"pol_gen_{FIRST['key']}").disabled


def test_industry_is_needed_too(fresh_runner) -> None:
    ws = Workspace()
    OrgProfile.from_dict({"legal_name": "Example"}).save_to(ws)
    at = make_app(page.PAGE, aegis_workspace=ws).run()
    assert "Missing: Industry." in html_of(at)


def test_profile_form_saves_and_unlocks_generation(fresh_runner) -> None:
    at = make_app(page.PAGE).run()
    legal = next(t for t in at.text_input if t.label == "Legal name *")
    legal.input("Example Retail")
    next(s for s in at.selectbox if s.label == "Industry *").set_value("Retail and e-commerce")
    at.text_input(key="org_name_0").input("Pat Lee")
    at.selectbox(key="org_role_0").set_value("CISO")
    next(m for m in at.multiselect if m.label == "Compliance drivers").set_value(["PCI DSS", "SOC 2"])
    next(b for b in at.button if b.label == "Save profile").click().run()
    assert not at.exception
    profile = OrgProfile.load_from(_ws(at))
    assert profile.legal_name == "Example Retail"
    assert [(c.role, c.name) for c in profile.leadership] == [("CISO", "Pat Lee")]
    assert profile.compliance_drivers == ("PCI DSS", "SOC 2")
    assert "Profile saved." in html_of(at)
    assert not at.button(key=f"pol_gen_{FIRST['key']}").disabled


def test_profile_form_shows_the_services_sentence(fresh_runner) -> None:
    at = make_app(page.PAGE).run()
    next(s for s in at.selectbox if s.label == "Industry *").set_value("Technology")
    next(b for b in at.button if b.label == "Save profile").click().run()
    assert "Legal name is required." in html_of(at)
    assert _ws(at).org_profile is None


def test_generate_saves_the_whole_result_once_and_opens_the_reader(fresh_runner) -> None:
    at = make_app(page.PAGE, aegis_workspace=_profiled()).run()
    at = _generate(at, fresh_runner)
    assert not at.exception
    records = _ws(at).list(RecordKind.POLICIES)
    assert len(records) == 1
    payload = records[0].payload
    assert "run" not in at.query_params
    assert payload["policy_key"] == FIRST["key"] and payload["status"] == "ready" and payload["version"] == 1
    assert payload["title"] == FIRST["title"]
    assert payload["csf_mappings"] and payload["regulatory_citations"]
    body = html_of(at)
    assert "is ready. Review it before you adopt it." in body
    assert "PCI DSS v4.0.1" in body and "GV.OC Organizational Context" in body
    assert any("Mock text" in m.value for m in at.markdown)
    at.run()
    assert len(_ws(at).list(RecordKind.POLICIES)) == 1


def test_streaming_text_shows_while_running_and_cancel_saves_nothing(fresh_runner, monkeypatch) -> None:
    gate = Gate()

    def slow(policy_key, profile, *, llm, settings, on_text=None):
        on_text("## Purpose\n\nThe first words <script>x</script>")
        gate.wait()
        return {"title": "t", "body_markdown": "b", "csf_mappings": [], "regulatory_citations": []}

    monkeypatch.setattr(policy_service, "generate_policy", slow)
    monkeypatch.setattr(tool_parts, "_PUSH_SECONDS", 0.0)
    at = make_app(page.PAGE, aegis_workspace=_profiled()).run()
    at.button(key=f"pol_gen_{FIRST['key']}").click().run()
    assert gate.started.wait(5)
    at.run()
    body = html_of(at)
    assert f"Writing the {FIRST['title']}" in body
    assert "Generating" in body
    assert any("The first words" in m.value for m in at.markdown)
    assert all("<script>" not in m.value or not m.allow_html for m in at.markdown)
    assert at.button(key=f"pol_gen_{policy_catalog.get_catalog()[1]['key']}").disabled
    at.run()  # re-attach
    assert f"Writing the {FIRST['title']}" in html_of(at)
    at.button(key="pol_cancel_danger").click().run()
    assert "Policy generation cancelled. Nothing was saved." in html_of(at)
    gate.release.set()
    wait_for_jobs(fresh_runner)
    at.run()
    assert _ws(at).list(RecordKind.POLICIES) == []


def test_a_failed_generation_names_the_policy(fresh_runner, monkeypatch) -> None:
    def broken(*args, **kwargs):
        raise LLMError("down")

    monkeypatch.setattr(policy_service, "generate_policy", broken)
    at = make_app(page.PAGE, aegis_workspace=_profiled()).run()
    at = _generate(at, fresh_runner)
    assert f"{FIRST['title']} was not generated. The AI service did not answer." in html_of(at)
    assert _ws(at).list(RecordKind.POLICIES) == []


def test_without_a_key_outside_mock_mode_it_asks_for_one(fresh_runner, monkeypatch) -> None:
    monkeypatch.delenv("AEGIS_MOCK_LLM")
    at = make_app(page.PAGE, aegis_workspace=_profiled()).run()
    assert "Add an OpenAI API key to run this step." in html_of(at)
    assert at.button(key=f"pol_gen_{FIRST['key']}").disabled


def _saved_policy(ws: Workspace, body: str = "## Purpose\n\nKeep data safe.") -> str:
    record = ws.add(RecordKind.POLICIES, FIRST["title"], {
        "title": FIRST["title"], "body_markdown": body, "policy_key": FIRST["key"], "status": "ready",
        "version": 1, "csf_mappings": [{"id": "GV.OC", "name": "Organizational Context"}],
        "regulatory_citations": [HOSTILE],
    })
    return record.id


def test_reader_edit_saves_a_new_version_and_regenerate_replaces_it(fresh_runner) -> None:
    ws = _profiled()
    rid = _saved_policy(ws)
    at = make_app(page.PAGE, aegis_workspace=ws)
    at.query_params["id"] = rid
    at.run()
    assert not at.exception
    assert "Version 1" in html_of(at)
    assert any(c.value == page.PDF_FAILED_HINT for c in at.caption)
    at.toggle(key=f"pol_edit_on_{rid}").set_value(True).run()
    at.text_area[0].input("## Purpose\n\nEdited by the owner.")
    next(b for b in at.button if b.label == "Save as a new version").click().run()
    assert not at.exception
    (record,) = _ws(at).list(RecordKind.POLICIES)
    assert record.id != rid and record.payload["version"] == 2 and record.payload["edited"] is True
    assert "Edited by the owner." in record.payload["body_markdown"]
    assert "Version 2, edited" in html_of(at)
    at.button(key="pol_reader_regen").click().run()
    wait_for_jobs(fresh_runner)
    at.run()
    (record,) = _ws(at).list(RecordKind.POLICIES)
    assert record.payload["version"] == 3 and "edited" not in record.payload


def test_an_empty_edit_is_refused(fresh_runner) -> None:
    ws = _profiled()
    rid = _saved_policy(ws)
    at = make_app(page.PAGE, aegis_workspace=ws)
    at.query_params["id"] = rid
    at.run()
    at.toggle(key=f"pol_edit_on_{rid}").set_value(True).run()
    at.text_area[0].input("   ")
    next(b for b in at.button if b.label == "Save as a new version").click().run()
    assert "The policy text cannot be empty." in html_of(at)


def test_hostile_policy_text_and_citations_are_inert(fresh_runner) -> None:
    ws = _profiled()
    rid = _saved_policy(ws, body=HOSTILE + "\n\n![x](http://127.0.0.1:9/a.png)")
    at = make_app(page.PAGE, aegis_workspace=ws)
    at.query_params["id"] = rid
    at.run()
    body = html_of(at)
    assert "<script>" not in body and "<img" not in body
    assert "&lt;script&gt;" in body
    (md,) = [m for m in at.markdown if "onerror" in m.value]
    assert not md.allow_html and "!\\[x]" in md.value


def test_delete_through_the_dialog(fresh_runner) -> None:
    ws = _profiled()
    rid = _saved_policy(ws)
    at = make_app(page.PAGE, aegis_workspace=ws)
    at.query_params["id"] = rid
    at.run()
    at.button(key="pol_reader_del_danger").click().run()
    at.button(key="pol_del_confirm_danger").click().run()
    assert not at.exception
    assert _ws(at).list(RecordKind.POLICIES) == []
    assert "Policy deleted." in html_of(at)


def test_unknown_policy_id_and_an_invalid_stored_profile(fresh_runner) -> None:
    ws = Workspace()
    ws.set_org_profile("x", {"legal_name": 5})
    at = make_app(page.PAGE, aegis_workspace=ws)
    at.query_params["id"] = "nope"
    at.run()
    assert "That policy is not in this session" in html_of(at)
    at.query_params.clear()
    at.run()
    assert "could not be read: Legal name must be text." in html_of(at)


def test_coverage_counts_generated_policies(fresh_runner) -> None:
    ws = _profiled()
    _saved_policy(ws)
    at = make_app(page.PAGE, aegis_workspace=ws).run()
    body = html_of(at)
    total = len(policy_catalog.get_catalog())
    assert f'<div class="ax-tile-value">1 / {total}</div>' in body
    assert "Ready, v1" in body and "Not generated" in body
    assert "Govern" in body
