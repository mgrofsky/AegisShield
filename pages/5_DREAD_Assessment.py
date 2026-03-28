"""
Page 5: DREAD Risk Assessment

Generates DREAD risk scores for identified threats.
Displays results with st.metric() for visual impact.
"""

import logging

import streamlit as st

from clients.retry import APIRetryError, retry_with_backoff
from components.step_guard import require_steps_completed
from services.dread import create_dread_assessment_prompt, get_dread_assessment
from state import set_step_completed, validate_session_keys
from utils.error_handler import handle_exception
from utils.markdown_helpers import dread_to_markdown

logger = logging.getLogger(__name__)


def render():
    if not require_steps_completed(1, 2, 3, 4):
        return

    st.markdown(
        "DREAD assesses threats based on **D**amage potential, **R**eproducibility, "
        "**E**xploitability, **A**ffected users, and **D**iscoverability."
    )
    st.markdown("---")

    if st.button("Generate DREAD Risk Assessment"):
        if not st.session_state.get("threat_model"):
            st.error("Please generate a threat model first.")
            return

        is_valid, err = validate_session_keys(["threat_model_markdown", "mitre_attack_markdown", "nvd_vulnerabilities_markdown"])
        if not is_valid:
            st.error(err)
            return

        prompt = create_dread_assessment_prompt(
            st.session_state["threat_model_markdown"],
            st.session_state["mitre_attack_markdown"],
            st.session_state["nvd_vulnerabilities_markdown"],
        )

        with st.status("Generating DREAD Risk Assessment...", expanded=True) as status:
            try:
                assessment = retry_with_backoff(lambda: get_dread_assessment(prompt))
                st.session_state["dread_assessment"] = assessment
                md = dread_to_markdown(assessment)
                st.session_state["session_dread_assessment_markdown"] = md
                status.update(label="DREAD assessment complete!", state="complete", expanded=False)
            except APIRetryError as e:
                status.update(label="Failed", state="error")
                handle_exception(e, "Error generating DREAD assessment after multiple attempts.")
                return

        set_step_completed(5)

    if st.session_state.get("session_dread_assessment_markdown"):
        st.markdown(st.session_state["session_dread_assessment_markdown"])
        st.download_button(
            label="Download DREAD Assessment",
            data=st.session_state["session_dread_assessment_markdown"],
            file_name="dread_assessment.md",
            mime="text/markdown",
        )
        st.markdown("---")
        if st.button("Proceed to Test Cases →", type="primary"):
            st.switch_page("pages/6_Test_Cases.py")


render()
