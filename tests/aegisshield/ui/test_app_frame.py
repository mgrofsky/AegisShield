"""The app frame under AppTest: navigation, mock banner, sidebar status, stubs."""

from __future__ import annotations

from pathlib import Path

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from aegisshield.config import DEFAULT_MODEL_NAME
from aegisshield.llm.base import ModelInfo
from aegisshield.ui import routes

ROOT = Path(__file__).resolve().parents[3]
ENTRY = str(ROOT / "main.py")


def _html(at: AppTest, where=None) -> str:
    return "\n".join(h.proto.body for h in (where or at).get("html"))


@pytest.fixture
def nav_spy(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    seen: list[dict] = []
    real = st.navigation

    def spy(pages, **kwargs):
        seen.append({k: [(p.title, p.visibility) for p in v] for k, v in pages.items()})
        return real(pages, **kwargs)

    monkeypatch.setattr(st, "navigation", spy)
    return seen


def test_default_page_navigation_and_status(nav_spy: list[dict],
                                            monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes, "tshark_available", lambda: True)
    at = AppTest.from_file(ENTRY, default_timeout=30).run()
    assert not at.exception
    assert nav_spy[-1] == {
        "": [("Dashboard", "visible")],
        "Defense": [("Threat models", "visible"), ("New threat model", "visible"),
                    ("Threat model", "hidden"), ("Vulnerability lookup", "visible"),
                    ("PCAP analysis", "visible")],
        "Compliance": [("Policies", "visible")],
        "Workspace": [("Settings", "visible")],
    }
    body = _html(at)
    assert "<style>" in body
    assert '<h1 class="ax-title">Dashboard</h1>' in body
    assert "MOCK MODE" not in body  # mock mode off
    side = _html(at, at.sidebar)
    assert "Mock mode" in side and ">Off<" in side
    assert side.count(">Not set<") == 3


def test_ai_scan_page_shown_only_when_scans_are_available(nav_spy: list[dict],
                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes, "tshark_available", lambda: True)
    monkeypatch.setattr(routes, "ai_scan_available", lambda: True)
    AppTest.from_file(ENTRY, default_timeout=30).run()
    assert ("AI workflow scan", "visible") in nav_spy[-1]["Defense"]
    monkeypatch.setattr(routes, "ai_scan_available", lambda: False)
    AppTest.from_file(ENTRY, default_timeout=30).run()
    assert "AI workflow scan" not in [t for t, _ in nav_spy[-1]["Defense"]]


def test_pcap_hidden_without_tshark(nav_spy: list[dict], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes, "tshark_available", lambda: False)
    AppTest.from_file(ENTRY, default_timeout=30).run()
    assert "PCAP analysis" not in [t for t, _ in nav_spy[-1]["Defense"]]


def test_mock_banner_and_key_words(mock_mode: None) -> None:
    at = AppTest.from_file(ENTRY, default_timeout=30)
    at.session_state["aegis_key_openai"] = "sk-secret-value"
    at.run()
    body = _html(at)
    assert "MOCK MODE" in body and "No model provider is called" in body
    side = _html(at, at.sidebar)
    assert ">On<" in side and ">Mock<" in side
    assert "sk-secret-value" not in body + side


def _page_app() -> None:
    import streamlit as st

    from aegisshield.ui.pages import (
        dashboard,
        pcap_analysis,
        policies,
        threat_model_detail,
        threat_model_new,
        threat_models,
        vulnerability_lookup,
    )

    pages = {
        "dashboard": dashboard, "threat_models": threat_models,
        "threat_model_new": threat_model_new, "threat_model_detail": threat_model_detail,
        "vulnerability_lookup": vulnerability_lookup, "pcap_analysis": pcap_analysis,
        "policies": policies,
    }
    # page_link needs a registered page, so run the stub inside navigation.
    from aegisshield.ui import routes

    target = st.session_state["stub"]
    st.navigation(routes.build_navigation(with_tshark=True))
    pages[target].render()


STUBS = {
    "dashboard": ("Dashboard", "ax-area-neutral"),
    "threat_models": ("Threat models", "ax-area-defense"),
    "threat_model_new": ("New threat model", "ax-area-defense"),
    "threat_model_detail": ("Threat model", "ax-area-defense"),
    "vulnerability_lookup": ("Vulnerability lookup", "ax-area-defense"),
    "pcap_analysis": ("PCAP analysis", "ax-area-defense"),
    "policies": ("Policies", "ax-area-compliance"),
}


@pytest.mark.parametrize("name", list(STUBS))
def test_stub_pages_render_header_and_empty_state(name: str) -> None:
    title, area = STUBS[name]
    at = AppTest.from_function(_page_app, default_timeout=30)
    at.session_state["stub"] = name
    at.run()
    assert not at.exception
    body = _html(at)
    assert f'<h1 class="ax-title">{title}</h1>' in body and area in body
    # The wizard opens on its first step, not an empty state.
    assert ("ax-empty" in body) is (name != "threat_model_new")


def test_detail_page_opens_the_record_named_in_the_url() -> None:
    from aegisshield.storage import Workspace

    ws = Workspace()
    record = ws.add("threat_models", "Checkout <service>", {})
    at = AppTest.from_function(_page_app, default_timeout=30)
    at.session_state["stub"] = "threat_model_detail"
    at.session_state["aegis_workspace"] = ws
    at.query_params["id"] = record.id
    at.run()
    body = _html(at)
    assert '<h1 class="ax-title">Checkout &lt;service&gt;</h1>' in body
    assert "ax-empty" not in body


def test_sidebar_names_the_provider_in_use() -> None:
    """The sidebar's model row says "Not set" until a model is chosen from
    the provider's list, then names the provider, never the key."""
    at = AppTest.from_file(ENTRY, default_timeout=30)
    at.session_state["aegis_key_openai"] = "sk-test-0123456789abcdef"
    at.run()
    side = _html(at, at.sidebar)
    assert ">Not set<" in side  # the dashboard does not ask for the list
    at.session_state["aegis_model_lists"] = {"openai": {
        "at": 4102444800.0, "models": (ModelInfo(DEFAULT_MODEL_NAME),), "failed": False}}
    at.run()
    side = _html(at, at.sidebar)
    assert "Model</dt><dd>" in side and ">OpenAI<" in side
    assert "sk-test-0123456789abcdef" not in side
