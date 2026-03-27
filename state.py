"""
AegisShield Session State Management

Provides centralized session state initialization, validation, and typed accessors.
Ensures consistent state management across all pages.
"""

import streamlit as st

# All session state keys with their default values
_STATE_DEFAULTS: dict = {
    # Step completion flags
    "step1_completed": False,
    "step2_completed": False,
    "step3_completed": False,
    "step4_completed": False,
    "step5_completed": False,
    "step6_completed": False,
    # API keys
    "openai_api_key": "",
    "nvd_api_key": "",
    "alienvault_api_key": "",
    # Model settings
    "model_provider": "OpenAI API",
    "selected_model": "",
    # App description
    "app_input": "",
    "app_desc": "",
    "image_analysis_content": "",
    "last_analyzed_file": "",
    # Technology details
    "app_details": {},
    "selected_technologies": {},
    "selected_versions": {},
    # Threat model outputs
    "threat_model": [],
    "improvement_suggestions": [],
    "session_threat_model_json": [],
    "improvement_suggestions_json": [],
    "threat_model_markdown": "",
    "improvement_suggestions_markdown": "",
    # MITRE ATT&CK
    "mitre_data": [],
    "mitre_attack_markdown": "",
    # NVD
    "nvd_vulnerabilities_markdown": "",
    # Attack tree
    "attack_tree_code": "",
    # Mitigations
    "session_mitigations_markdown": "",
    # DREAD
    "dread_assessment": [],
    "session_dread_assessment_markdown": "",
    # Test cases
    "session_test_cases_markdown": "",
}


def initialize_session_state() -> None:
    """Initialize all session state keys with defaults if not already set."""
    for key, default in _STATE_DEFAULTS.items():
        if key not in st.session_state:
            st.session_state[key] = default


def get_step_completed(step: int) -> bool:
    """Check if a specific step is completed."""
    return bool(st.session_state.get(f"step{step}_completed", False))


def set_step_completed(step: int) -> None:
    """Mark a specific step as completed."""
    st.session_state[f"step{step}_completed"] = True


def clear_downstream_state(from_step: int) -> None:
    """Clear all state from a given step onwards (for regeneration)."""
    step_keys = {
        3: [
            "threat_model", "improvement_suggestions", "session_threat_model_json",
            "improvement_suggestions_json", "threat_model_markdown",
            "improvement_suggestions_markdown", "mitre_data", "mitre_attack_markdown",
            "nvd_vulnerabilities_markdown", "attack_tree_code",
        ],
        4: ["session_mitigations_markdown"],
        5: ["dread_assessment", "session_dread_assessment_markdown"],
        6: ["session_test_cases_markdown"],
    }
    for step in range(from_step, 7):
        st.session_state[f"step{step}_completed"] = False
        for key in step_keys.get(step, []):
            if key in _STATE_DEFAULTS:
                st.session_state[key] = _STATE_DEFAULTS[key]


def validate_session_keys(required_keys: list[str]) -> tuple[bool, str]:
    """
    Validate that required session state keys are present and non-empty.

    Returns:
        Tuple of (is_valid, error_message).
    """
    missing = [k for k in required_keys if not st.session_state.get(k)]
    if missing:
        return False, f"Missing required data: {', '.join(missing)}. Please complete previous steps first."
    return True, ""
