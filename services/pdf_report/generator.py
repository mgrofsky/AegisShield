"""
PDF Report Generator

Orchestrates the PDF generation process by reading session state,
converting data to HTML, and producing the final PDF document.
"""

import base64
import io
import logging
from datetime import datetime

import streamlit as st
from xhtml2pdf import pisa

from config import APP_CONFIG
from services.pdf_report.converters import (
    convert_dread_to_html_table,
    convert_json_to_html,
    convert_markdown_to_html_desc,
    convert_mitigations_to_html_table,
    convert_mitre_attack_to_html,
    convert_stride_to_html_table,
    format_gherkin_tests,
)
from services.pdf_report.templates import build_pdf_html

logger = logging.getLogger(__name__)


def generate_pdf_report() -> bytes | None:
    """
    Generate a PDF report from session state data.

    Returns:
        PDF bytes if successful, None on error.
    """
    try:
        # Convert data to HTML
        stride_table_html = convert_stride_to_html_table(
            st.session_state["session_threat_model_json"]
        )
        mitigations_html = convert_mitigations_to_html_table(
            st.session_state["session_mitigations_markdown"]
        )
        dread_table_html = convert_dread_to_html_table(
            st.session_state["session_dread_assessment_markdown"]
        )
        gherkin_tests_html = format_gherkin_tests(
            st.session_state["session_test_cases_markdown"]
        )
        mitre_attack_html = convert_mitre_attack_to_html(
            st.session_state["mitre_attack_markdown"]
        )

        # Load logo
        with open(APP_CONFIG.logo_bw_path, "rb") as image_file:
            encoded_logo = base64.b64encode(image_file.read()).decode("utf-8")

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html_description = convert_markdown_to_html_desc(st.session_state["app_input"])

        # Extract app details
        details = st.session_state.get("app_details", {})
        techs = details.get("selected_technologies", {})
        versions = details.get("selected_versions", {})

        html_content = build_pdf_html(
            encoded_logo=encoded_logo,
            timestamp=timestamp,
            app_type=details.get("app_type", ""),
            industry_sector=details.get("industry_sector", ""),
            sensitive_data=details.get("sensitive_data", ""),
            internet_facing=details.get("internet_facing", ""),
            num_employees=details.get("num_employees", ""),
            compliance_requirements=str(details.get("compliance_requirements", "")),
            technical_ability=details.get("technical_ability", ""),
            authentication=str(details.get("authentication", "")),
            selected_technologies=", ".join(techs) if techs else "",
            selected_versions=", ".join(f"{k}: {v}" for k, v in versions.items()) if versions else "",
            html_description=html_description,
            improvement_suggestions_html=convert_json_to_html(
                st.session_state.get("improvement_suggestions_json", [])
            ),
            stride_table_html=stride_table_html,
            mitre_attack_html=mitre_attack_html,
            mitigations_html=mitigations_html,
            dread_table_html=dread_table_html,
            attack_tree_code=st.session_state.get("attack_tree_code", ""),
            gherkin_tests_html=gherkin_tests_html,
        )

        # Generate PDF
        pdf_file = io.BytesIO()
        pisa.CreatePDF(html_content, dest=pdf_file)
        pdf_file.seek(0)
        return pdf_file.read()

    except Exception as e:
        logger.error("Error generating PDF: %s", e)
        return None
