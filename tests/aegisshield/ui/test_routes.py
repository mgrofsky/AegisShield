"""The page table: sections, order, hidden pages, and the tshark rule."""

from __future__ import annotations

import importlib

import pytest

from aegisshield.ui import routes


def _titles(sections: dict) -> dict[str, list[str]]:
    return {name: [p.title for p in items] for name, items in sections.items()}


def test_navigation_groups_and_order_with_tshark() -> None:
    assert _titles(routes.nav_sections(with_tshark=True)) == {
        "": ["Dashboard"],
        "Defense": ["Threat models", "New threat model", "Threat model", "Vulnerability lookup",
                    "PCAP analysis"],
        "Compliance": ["Policies"],
        "Workspace": ["Settings"],
    }


def test_ai_scan_page_follows_pcap_only_when_scans_are_available() -> None:
    with_scan = _titles(routes.nav_sections(with_tshark=True, with_ai_scan=True))
    assert with_scan["Defense"][-2:] == ["PCAP analysis", "AI workflow scan"]
    assert "AI workflow scan" not in _titles(routes.nav_sections(with_tshark=True))["Defense"]
    assert routes.spec("ai_scan").url_path == "ai-workflow-scan"


def test_pcap_page_is_left_out_without_tshark() -> None:
    titles = _titles(routes.nav_sections(with_tshark=False))
    assert "PCAP analysis" not in titles["Defense"]


def test_only_the_detail_page_is_hidden() -> None:
    assert [s.name for s in routes.PAGES if not s.visible] == ["threat_model_detail"]
    assert routes.spec("threat_model_detail").url_path == "threat-model"


def test_url_paths_are_unique() -> None:
    paths = [s.url_path for s in routes.PAGES]
    assert len(paths) == len(set(paths))


def test_dashboard_is_the_default_page() -> None:
    assert [s.name for s in routes.PAGES if s.default] == ["dashboard"]


def test_every_page_module_exposes_render() -> None:
    for spec in routes.PAGES:
        module = importlib.import_module(f"aegisshield.ui.pages.{spec.name}")
        assert callable(module.render), spec.name


def test_runner_imports_and_renders(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisshield.ui.pages import dashboard

    calls: list[str] = []
    monkeypatch.setattr(dashboard, "render", lambda: calls.append("ok"))
    routes._runner("dashboard")()
    assert calls == ["ok"]


def test_tshark_available_uses_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes.shutil, "which", lambda name: None)
    assert routes.tshark_available() is False
    monkeypatch.setattr(routes.shutil, "which", lambda name: "/usr/bin/tshark")
    assert routes.tshark_available() is True


def test_spec_lookup() -> None:
    assert routes.spec("policies").area.value == "compliance"
    with pytest.raises(KeyError):
        routes.spec("scans")
