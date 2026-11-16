"""Helpers shared by the threat-model page tests."""

from __future__ import annotations

import time
from typing import Any

from streamlit.testing.v1 import AppTest

from aegisshield.storage import RecordKind, Workspace

READY_DRAFT: dict[str, Any] = {
    "step": 2,
    "reached": 2,
    "description": "An online checkout service where shoppers pay by card and staff issue refunds.",
    "app_type": "Web application",
    "industry_sector": "Retail",
    "sensitive_data": "High",
    "internet_facing": "Yes",
    "num_employees": "11-100",
    "technical_ability": "Medium",
    "technologies": {},
    "addons": {"mitigations": True, "dread": True, "test_cases": True},
}


def wizard_app() -> None:
    """The wizard page with the theme and navigation, as the app runs it."""
    import streamlit as st

    from aegisshield.ui import routes
    from aegisshield.ui.pages import threat_model_new
    from aegisshield.ui.theme import apply_theme

    apply_theme()
    st.navigation(routes.build_navigation(with_tshark=False))
    threat_model_new.render()


def new_wizard(draft: dict[str, Any] | None = None, workspace: Workspace | None = None) -> AppTest:
    at = AppTest.from_function(wizard_app, default_timeout=30)
    if draft is not None:
        at.session_state["aegis_tm_draft"] = dict(draft)
    if workspace is not None:
        at.session_state["aegis_workspace"] = workspace
    return at


def html_of(at: AppTest) -> str:
    return "\n".join(str(node.value) for node in at.get("html"))


def live_views(at: AppTest) -> list[str]:
    """The live components on the page, in order (``aegis_deck``, ``aegis_office``)."""
    return [node.proto.component_name for node in at.get("bidi_component")]


def run_record(at: AppTest) -> dict[str, Any] | None:
    return at.session_state["aegis_tm_run"] if "aegis_tm_run" in at.session_state else None


def wait_settled(at: AppTest, seconds: float = 20.0) -> dict[str, Any]:
    """Rerun the page until the run has settled; return the run record."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        time.sleep(0.05)
        at.run()
        run = run_record(at)
        if run and run.get("final") is not None:
            return run
    raise AssertionError("the run did not settle")


def saved_threat_models(at: AppTest) -> list[Any]:
    if "aegis_workspace" not in at.session_state:
        return []
    return at.session_state["aegis_workspace"].list(RecordKind.THREAT_MODELS)


def switchable_app() -> None:
    """The wizard, or the dashboard when ``session_state["away"]`` is set."""
    import streamlit as st

    from aegisshield.ui import routes
    from aegisshield.ui.pages import dashboard, threat_model_new
    from aegisshield.ui.theme import apply_theme

    apply_theme()
    st.navigation(routes.build_navigation(with_tshark=False))
    (dashboard if st.session_state.get("away") else threat_model_new).render()


def png_bytes() -> bytes:
    """A real 1 by 1 PNG."""
    import struct
    import zlib

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    pixels = zlib.compress(b"\x00\xff\x00\x00")
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", pixels)
            + chunk(b"IEND", b""))
