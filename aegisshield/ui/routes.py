"""The app's pages: what exists, where it is listed, and how to reach it.

Each page is a module under ``aegisshield.ui.pages`` with ``render() -> None``.
The module is imported when its page runs, so a broken page cannot stop the
frame or the other pages from loading.

The table below is static configuration, shared by every session; it holds
no visitor data.
"""

from __future__ import annotations

import importlib
import shutil
from collections.abc import Callable
from dataclasses import dataclass

import streamlit as st

from aegisshield.aiscan import scan_availability
from aegisshield.config import get_settings
from aegisshield.ui.theme import Area

__all__ = [
    "PAGES",
    "PageName",
    "PageSpec",
    "ai_scan_available",
    "build_navigation",
    "nav_sections",
    "page",
    "spec",
    "tshark_available",
]

PageName = str


@dataclass(frozen=True)
class PageSpec:
    """One page of the app."""

    name: PageName
    title: str
    icon: str
    url_path: str
    section: str
    area: Area
    visible: bool = True
    default: bool = False
    needs_tshark: bool = False
    needs_ai_scan: bool = False


# Section labels. "" puts a page at the top with no heading.
_TOP = ""
_DEFENSE = "Defense"
_COMPLIANCE = "Compliance"
_WORKSPACE = "Workspace"

PAGES: tuple[PageSpec, ...] = (
    PageSpec("dashboard", "Dashboard", ":material/space_dashboard:", "dashboard", _TOP,
             Area.NEUTRAL, default=True),
    PageSpec("threat_models", "Threat models", ":material/shield:", "threat-models", _DEFENSE,
             Area.DEFENSE),
    PageSpec("threat_model_new", "New threat model", ":material/add_moderator:", "new-threat-model",
             _DEFENSE, Area.DEFENSE),
    PageSpec("threat_model_detail", "Threat model", ":material/shield:", "threat-model", _DEFENSE,
             Area.DEFENSE, visible=False),
    PageSpec("vulnerability_lookup", "Vulnerability lookup", ":material/manage_search:",
             "vulnerability-lookup", _DEFENSE, Area.DEFENSE),
    PageSpec("pcap_analysis", "PCAP analysis", ":material/monitoring:", "pcap-analysis", _DEFENSE,
             Area.DEFENSE, needs_tshark=True),
    PageSpec("ai_scan", "AI workflow scan", ":material/bug_report:", "ai-workflow-scan", _DEFENSE,
             Area.DEFENSE, needs_ai_scan=True),
    PageSpec("policies", "Policies", ":material/assignment:", "policies", _COMPLIANCE,
             Area.COMPLIANCE),
    PageSpec("settings", "Settings", ":material/settings:", "settings", _WORKSPACE, Area.NEUTRAL),
)

_BY_NAME = {spec.name: spec for spec in PAGES}


def tshark_available() -> bool:
    """True when ``tshark`` is on the PATH; the PCAP page needs it."""
    return shutil.which("tshark") is not None


def ai_scan_available() -> bool:
    """True when the operator turned scans on and garak was found; the AI
    workflow scan page needs both."""
    return scan_availability(get_settings()).available


def _runner(name: PageName) -> Callable[[], None]:
    def run() -> None:
        module = importlib.import_module(f"aegisshield.ui.pages.{name}")
        module.render()

    run.__name__ = f"page_{name}"
    return run


def page(name: PageName) -> st.Page:
    """The ``st.Page`` for ``name``. Equal for every call, because Streamlit
    identifies a page by its URL path, so it works with ``st.switch_page``
    and ``st.page_link``."""
    spec = _BY_NAME[name]
    return st.Page(
        _runner(spec.name),
        title=spec.title,
        icon=spec.icon,
        url_path=spec.url_path,
        default=spec.default,
        visibility="visible" if spec.visible else "hidden",
    )


def nav_sections(*, with_tshark: bool, with_ai_scan: bool = False) -> dict[str, list[PageSpec]]:
    """The page specs by section, in menu order. The PCAP page is left out
    when ``tshark`` is missing, and the AI workflow scan page when scans are
    off or garak was not found."""
    sections: dict[str, list[PageSpec]] = {}
    for item in PAGES:
        if (item.needs_tshark and not with_tshark) or (item.needs_ai_scan and not with_ai_scan):
            continue
        sections.setdefault(item.section, []).append(item)
    return sections


def build_navigation(*, with_tshark: bool, with_ai_scan: bool = False) -> dict[str, list[st.Page]]:
    """The pages for ``st.navigation``, grouped by section, in menu order."""
    return {
        section: [page(item.name) for item in items]
        for section, items in nav_sections(with_tshark=with_tshark, with_ai_scan=with_ai_scan).items()
    }


def spec(name: PageName) -> PageSpec:
    """The ``PageSpec`` for ``name``; raises ``KeyError`` if there is none."""
    return _BY_NAME[name]
