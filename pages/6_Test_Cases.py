"""
Page 6: Gherkin Test Cases

Generates security test cases in Gherkin (Given-When-Then) format.
"""

import logging

import streamlit as st

from clients.retry import APIRetryError, retry_with_backoff
from components.step_guard import require_steps_completed
from services.test_cases import create_test_cases_prompt, get_test_cases
from state import set_step_completed
from utils.error_handler import handle_exception
from utils.markdown_helpers import threat_model_to_markdown

logger = logging.getLogger(__name__)


def render():
    if not require_steps_completed(1, 2, 3, 4, 5):
        return

    if st.button("← Back to DREAD Assessment"):
        st.switch_page("pages/5_DREAD_Assessment.py")

    st.markdown(
        "Generate security test cases using Gherkin syntax (Given-When-Then). "
        "These help validate that identified threats are properly addressed."
    )
    st.markdown("---")

    if st.button("Generate Test Cases"):
        if not st.session_state.get("threat_model"):
            st.error("Please generate a threat model first.")
            return

        threats_md = threat_model_to_markdown(st.session_state["threat_model"], [])
        prompt = create_test_cases_prompt(threats_md)

        with st.status("Generating test cases...", expanded=True) as status:
            try:
                result = retry_with_backoff(lambda: get_test_cases(prompt))
                st.session_state["session_test_cases_markdown"] = result
                status.update(label="Test cases generated!", state="complete", expanded=False)
            except APIRetryError as e:
                status.update(label="Failed", state="error")
                handle_exception(e, "Error generating test cases after multiple attempts.")
                return

        set_step_completed(6)

    if st.session_state.get("session_test_cases_markdown"):
        st.markdown(st.session_state["session_test_cases_markdown"])
        st.download_button(
            label="Download Test Cases",
            data=st.session_state["session_test_cases_markdown"],
            file_name="test_cases.md",
            mime="text/markdown",
        )
        st.markdown("---")
        if st.button("Proceed to PDF Report →", type="primary"):
            st.switch_page("pages/7_PDF_Report.py")


render()
