"""
Page 7: PDF Report Generation

Compiles all generated data into a comprehensive, downloadable PDF report.
"""

import logging
from datetime import datetime

import streamlit as st

from components.step_guard import require_steps_completed
from services.pdf_report.generator import generate_pdf_report
from utils.error_handler import handle_exception

logger = logging.getLogger(__name__)


def render():
    if st.button("← Back to Test Cases"):
        st.switch_page("pages/6_Test_Cases.py")

    if not require_steps_completed(1, 2, 3, 4, 5, 6):
        return

    st.markdown(
        "Generate a comprehensive PDF report compiling all threat modeling results: "
        "description, threats, MITRE ATT&CK, mitigations, DREAD, and test cases."
    )
    st.markdown("---")

    if st.button("Generate PDF Report"):
        # Verify all required data exists
        required = [
            "session_test_cases_markdown", "session_dread_assessment_markdown",
            "session_mitigations_markdown", "session_threat_model_json",
            "mitre_attack_markdown", "attack_tree_code", "app_details", "app_input",
        ]
        missing = [k for k in required if not st.session_state.get(k)]
        if missing:
            st.error("Please complete all previous steps before generating a PDF report.")
            return

        with st.status("Generating PDF Report...", expanded=True) as status:
            try:
                pdf_bytes = generate_pdf_report()
                if pdf_bytes:
                    status.update(label="PDF report generated!", state="complete", expanded=False)
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    st.download_button(
                        label="Download PDF Report",
                        data=pdf_bytes,
                        file_name=f"threat_model_report_{timestamp}.pdf",
                        mime="application/pdf",
                    )
                else:
                    status.update(label="PDF generation failed", state="error")
                    st.error("Error generating PDF. Please check the logs.")
            except Exception as e:
                status.update(label="Error", state="error")
                handle_exception(e, "Error generating PDF Document.")


render()
