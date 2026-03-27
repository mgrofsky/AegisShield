"""
Page 4: Mitigation Suggestions

Generates potential mitigations for identified threats using AI.
Uses st.write_stream() for real-time response streaming.
"""

import logging

import streamlit as st

from clients.retry import APIRetryError, retry_with_backoff
from components.step_guard import require_steps_completed
from services.mitigations import create_mitigations_prompt, get_mitigations
from state import set_step_completed, validate_session_keys
from utils.error_handler import handle_exception

logger = logging.getLogger(__name__)


def render():
    if not require_steps_completed(1, 2, 3):
        return

    st.markdown(
        "Generate potential mitigations for the threats identified in the threat model. "
        "These security controls help reduce the likelihood or impact of threats."
    )
    st.markdown("---")

    if st.button("Suggest Mitigations"):
        if not st.session_state.get("threat_model"):
            st.error("Please generate a threat model first.")
            return

        is_valid, err = validate_session_keys(["threat_model_markdown", "mitre_attack_markdown", "nvd_vulnerabilities_markdown"])
        if not is_valid:
            st.error(err)
            return

        prompt = create_mitigations_prompt(
            st.session_state["threat_model_markdown"],
            st.session_state["mitre_attack_markdown"],
            st.session_state["nvd_vulnerabilities_markdown"],
        )

        with st.status("Generating mitigations...", expanded=True) as status:
            try:
                result = retry_with_backoff(lambda: get_mitigations(prompt))
                st.session_state["session_mitigations_markdown"] = result
                status.update(label="Mitigations generated!", state="complete", expanded=False)
            except APIRetryError as e:
                status.update(label="Failed", state="error")
                handle_exception(e, "Error generating mitigations after multiple attempts.")
                return

        st.markdown(st.session_state["session_mitigations_markdown"])
        set_step_completed(4)

        st.download_button(
            label="Download Mitigations",
            data=st.session_state["session_mitigations_markdown"],
            file_name="mitigations.md",
            mime="text/markdown",
        )


render()
