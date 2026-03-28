"""
Page 2: Technology Stack Selection

Users select their application's technology details including type,
industry, authentication methods, and specific technologies with versions.
"""

import logging

import streamlit as st

from components.step_guard import require_steps_completed
from data.technology_types import (
    APP_TYPE_OPTIONS,
    AUTHENTICATION_OPTIONS,
    COMPLIANCE_REQUIREMENTS_OPTIONS,
    DATA_SENSITIVITY_OPTIONS,
    INDUSTRY_SECTOR_OPTIONS,
    INTERNET_FACING_OPTIONS,
    NUM_EMPLOYEES_OPTIONS,
    TECHNOLOGY_TYPES,
)
from state import set_step_completed
from utils.validators import validate_version_format

logger = logging.getLogger(__name__)


def render():
    if st.button("← Back to Description"):
        st.switch_page("pages/1_Description.py")

    if not require_steps_completed(1):
        return

    st.markdown("Select the technology details of your application for accurate threat modeling.")
    st.markdown("---")

    col1, col2 = st.columns([1.5, 1.5])

    with col2:
        st.markdown("#### Why Collecting Technology Details is Important")
        st.markdown(
            "Detailed technology information enhances threat model accuracy by identifying "
            "relevant threats, offering tailored mitigation strategies, and addressing specific vulnerabilities."
        )
        st.markdown("#### Technology Versioning")
        st.markdown(
            "Specify exact versions (e.g., :green[4.0.0]) for accurate vulnerability matching. "
            "Wildcards like :green[4.0.*] are supported but may reduce accuracy."
        )

    with col1:
        col1a, col1b = st.columns(2)

        with col1a:
            app_type = st.selectbox("Application type :red[(Required)]", APP_TYPE_OPTIONS, key="app_type")
            industry_sector = st.selectbox("Industry sector :red[(Required)]", INDUSTRY_SECTOR_OPTIONS, key="industry_sector")
            sensitive_data = st.selectbox("Data sensitivity :red[(Required)]", DATA_SENSITIVITY_OPTIONS, key="sensitive_data")
            internet_facing = st.selectbox("Internet-facing? :red[(Required)]", INTERNET_FACING_OPTIONS, key="internet_facing")

        with col1b:
            num_employees = st.selectbox("Number of employees :red[(Required)]", NUM_EMPLOYEES_OPTIONS, key="num_employees")
            compliance_requirements = st.multiselect("Compliance requirements :orange[(Optional)]", COMPLIANCE_REQUIREMENTS_OPTIONS, key="compliance_requirements")
            authentication = st.multiselect("Authentication methods :orange[(Optional)]", AUTHENTICATION_OPTIONS, key="authentication")
            technical_ability = st.selectbox("Technical knowledge :orange[(Static)]", ["Medium"], key="technical_ability")

        # Technology stack selection
        st.subheader("Technology Stack")

        # Initialize tracking dicts
        if "selected_technologies" not in st.session_state:
            st.session_state["selected_technologies"] = {}
        if "selected_versions" not in st.session_state:
            st.session_state["selected_versions"] = {}

        for category, options in TECHNOLOGY_TYPES.items():
            with st.expander(f":package: {category}", expanded=True):
                selected = st.multiselect(
                    f"Select {category} :orange[(Optional)]",
                    list(options.keys()),
                    key=f"{category}_tech",
                )

                previous = set(st.session_state.get(f"{category}_selected_techs", []))
                current = set(selected)

                for tech in selected:
                    version = st.text_input(f"Version for {tech}", key=f"{tech}_version")
                    is_valid, msg = validate_version_format(version)
                    if not is_valid:
                        st.warning(msg)
                    st.session_state["selected_versions"][tech] = version
                    st.session_state["selected_technologies"][tech] = options[tech]

                st.session_state[f"{category}_selected_techs"] = selected

                for tech in previous - current:
                    st.session_state["selected_versions"].pop(tech, None)
                    st.session_state["selected_technologies"].pop(tech, None)

        st.markdown("---")

        if st.session_state["selected_technologies"]:
            st.subheader(":clipboard: Selected Technologies Summary")
            for tech, cpe in st.session_state["selected_technologies"].items():
                version = st.session_state["selected_versions"].get(tech, "Not specified")
                st.markdown(f"- **{tech}**: {version}")

        if st.button("Next"):
            if not industry_sector:
                st.error("Please select an industry sector.")
            else:
                st.session_state["app_details"] = {
                    "app_type": app_type,
                    "industry_sector": industry_sector,
                    "sensitive_data": sensitive_data,
                    "internet_facing": internet_facing,
                    "num_employees": num_employees,
                    "compliance_requirements": compliance_requirements,
                    "technical_ability": technical_ability,
                    "authentication": authentication,
                    "selected_technologies": st.session_state["selected_technologies"],
                    "selected_versions": st.session_state["selected_versions"],
                    "app_input": st.session_state["app_input"],
                }
                set_step_completed(2)
                st.switch_page("pages/3_Threat_Model.py")


render()
