"""
Sidebar Component

Renders the application sidebar with API key inputs, model selection,
and step progress tracker.

NIST SP 800-53 Rev. 5 Control Mappings:
- IA-5: Authenticator Management - API key management
- AC-3: Access Enforcement - API key validation
"""

import streamlit as st

from config import APP_CONFIG, MODEL_CONFIG


def load_api_keys() -> None:
    """Load API keys from Streamlit secrets if available."""
    try:
        if "nvd_api_key" in st.secrets:
            st.session_state["nvd_api_key"] = st.secrets["nvd_api_key"]
        if "alienvault_api_key" in st.secrets:
            st.session_state["alienvault_api_key"] = st.secrets["alienvault_api_key"]
    except Exception:
        pass  # Secrets not available


def render_sidebar() -> None:
    """Render the complete sidebar with branding, API keys, and progress."""
    with st.sidebar:
        st.markdown(
            "Welcome to AegisShield Threat Modeler, an AI-powered tool designed "
            "to enhance and streamline cyber threat modeling."
        )
        st.markdown("---")
        st.image(APP_CONFIG.logo_path)
        st.header("How to use AegisShield")

        # Model selection
        st.markdown("### :gear: Model Settings")
        st.selectbox(
            "Select OpenAI model:",
            MODEL_CONFIG.available_models,
            key="selected_model",
            help="Select the OpenAI model for threat modeling.",
        )

        # API key inputs
        st.markdown("### :key: API Keys")
        st.markdown(
            "Enter your [OpenAI API key](https://platform.openai.com/account/api-keys). "
            "The key is only stored in your browser session."
        )

        # NIST IA-5(1): Masked input for sensitive authenticator data
        openai_key = st.text_input(
            "OpenAI API Key:",
            value=st.session_state.get("openai_api_key", ""),
            type="password",
            placeholder="sk-...",
        )
        if openai_key:
            st.session_state["openai_api_key"] = openai_key
        elif not st.session_state.get("openai_api_key"):
            st.error("OpenAI API key is required to proceed")

        # NVD API key (only if not loaded from secrets)
        if not st.session_state.get("nvd_api_key"):
            nvd_key = st.text_input(
                "NVD API Key:",
                type="password",
                help="[Get an NVD API key](https://nvd.nist.gov/developers/request-an-api-key)",
            )
            if nvd_key:
                st.session_state["nvd_api_key"] = nvd_key

        # AlienVault API key (only if not loaded from secrets)
        if not st.session_state.get("alienvault_api_key"):
            av_key = st.text_input(
                "AlienVault OTX API Key:",
                type="password",
                help="[Get an AlienVault key](https://otx.alienvault.com/api)",
            )
            if av_key:
                st.session_state["alienvault_api_key"] = av_key

        st.markdown("---")

        # Step progress tracker
        st.markdown("### :clipboard: Progress")
        steps = [
            "Description", "Technology", "Threat Model",
            "Mitigations", "DREAD Assessment", "Test Cases",
        ]
        for i, name in enumerate(steps, 1):
            completed = st.session_state.get(f"step{i}_completed", False)
            icon = ":white_check_mark:" if completed else ":black_medium_square:"
            st.markdown(f"{icon} Step {i}: {name}")
