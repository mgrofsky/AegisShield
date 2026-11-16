"""The frame every page runs in: page config, theme, navigation, sidebar,
and the mock-mode banner."""

from __future__ import annotations

import html

import streamlit as st

from aegisshield.core.logging import configure_logging
from aegisshield.llm import providers
from aegisshield.storage import warn_if_shared_workspace
from aegisshield.ui import routes, state
from aegisshield.ui.state import ApiKey
from aegisshield.ui.theme import BRAND_DIR, apply_theme

__all__ = ["run"]

# The browser tab icon: the white shield on a navy tile, which reads on light
# and dark tab bars alike (a page has one icon; it cannot follow the theme).
_FAVICON = BRAND_DIR / "favicon.png"
# The sidebar shield: white artwork, for the app's dark-only theme (both
# .streamlit/config.toml and assets/theme.css fix the page dark, whatever
# the browser prefers). icon-light.png is the navy artwork for a light page.
SIDEBAR_ICON = BRAND_DIR / "icon-dark.png"
_SIDEBAR_WIDTH = 256
# Pages that call kit.wide_canvas (the live deck). The frame asks for a
# collapsed sidebar on them too: Streamlit re-applies the frame's sidebar
# state when the URL changes mid-page (the wizard writes ?run=), and an
# expanded one there would narrow the deck while it plays.
_WIDE_PAGES = frozenset({"new-threat-model"})

_KEY_WORDS = {"session": "Set", "operator": "Operator", "none": "Not set"}
_KEY_NAMES = ((ApiKey.NVD, "NVD key"), (ApiKey.OTX, "OTX key"))


def _model_words(mock: bool) -> tuple[str, str]:
    """The sidebar's model row: the provider and model in use, in words."""
    if mock:
        return "Mock", "warn"
    choice = state.model_choice()
    if choice is None:
        return "Not set", "neutral"
    return providers.provider_label(choice.provider), "ok"


def _status_html(mock: bool) -> str:
    """The sidebar's status block: mock mode, the model provider in use, and
    which keys are set, in words."""
    rows = [("Mock mode", "On" if mock else "Off", "warn" if mock else "neutral"),
            ("Model", *_model_words(mock))]
    for service, name in _KEY_NAMES:
        source = state.key_source(service)
        rows.append((name, _KEY_WORDS[source], "ok" if source != "none" else "neutral"))
    cells = "".join(
        f'<dt>{html.escape(label)}</dt><dd><span class="ax-badge ax-tone-{tone}">'
        f"{html.escape(word)}</span></dd>"
        for label, word, tone in rows
    )
    return f'<div class="ax-status"><div class="ax-status-title">Session</div><dl>{cells}</dl></div>'


def _mock_banner() -> None:
    st.html(
        '<div class="ax-mock" role="status"><strong>MOCK MODE</strong>'
        "<span>Model answers are canned examples for an online retail checkout service. "
        "No model provider is called.</span></div>"
    )


def run() -> None:
    """Build the frame and run the selected page."""
    configure_logging()
    st.set_page_config(
        page_title="AegisShield",
        page_icon=str(_FAVICON),
        layout="wide",
    )
    apply_theme()
    st.logo(str(SIDEBAR_ICON), size="medium")

    settings = state.get_settings()
    warn_if_shared_workspace(settings)
    current = st.navigation(routes.build_navigation(with_tshark=routes.tshark_available(),
                                                    with_ai_scan=routes.ai_scan_available()))
    st.set_page_config(
        initial_sidebar_state="collapsed" if current.url_path in _WIDE_PAGES else _SIDEBAR_WIDTH
    )

    with st.sidebar:
        status = st.empty()
    status.html(_status_html(settings.mock_llm))

    if settings.mock_llm:
        _mock_banner()
    current.run()
    # Drawn again once the page has run: Settings may have just fetched a
    # model list or taken a credential, which changes the model row.
    status.html(_status_html(settings.mock_llm))
