"""
Step 2: Technology Tab Module

This module handles the second step of the threat modeling process, where users provide
details about the technologies used in their application. It collects information about:
- Application type and industry sector
- Data sensitivity and internet exposure
- Organization size and compliance requirements
- Authentication methods
- Technology stack details (databases, OS, languages, frameworks)

The module uses CPE (Common Platform Enumeration) identifiers to track technology versions
and ensure accurate vulnerability assessment.
"""

import streamlit as st
from typing import Dict, List, Optional, Set, Tuple
from error_handler import handle_exception  # Import the error handler
import logging

# Configure logging
logger = logging.getLogger(__name__)

# UI text constants
UI_TEXT = {
    'title': "Select the technology details of your application. This information helps in generating a more accurate threat model.",
    'step_warning': "Please complete Step 1 first.",
    'importance_title': "#### Why Collecting Technology Details is Important",
    'importance_text': """
    Providing detailed technology information enhances the accuracy and relevance of the threat model. Knowing the specific technologies and configurations used in your application helps in identifying potential vulnerabilities and threat vectors.

    - **Identify relevant threats** specific to your technologies.
    - **Offer tailored mitigation strategies** for your setup.
    - **Enhance security posture** by addressing specific vulnerabilities.

    This ensures a comprehensive and contextually relevant threat modeling process.
    """,
    'versioning_title': "#### Technology Versioning",
    'versioning_text': """
    Various technologies have different versioning schemes, which can impact security vulnerabilities. Providing :green[(specific version information)] helps in identifying vulnerabilities and potential threats associated with the technology stack.

    When selecting a technology, please specify the exact version used in your application. As an example, for :green[(MySQL)] version :green[(4.0.0)], you would type :green[(4.0.0)] into the version prompt. This application accepts wildcard version as well (Example :green[(4.0.*)], but this may pull older or newer versions of the technology and could reduce accuracy in the findings.

    A wildcard search will generally pull the latest version associated with the first portions of the version number.
    """
}

# Application type options
APP_TYPE_OPTIONS = [
    "5G/Wireless System",
    "AI/ML Systems",
    "Blockchain and Cryptocurrency Systems",
    "Cloud application",
    "Cyber-Physical System (CPS)",
    "Desktop application",
    "Drone as a Service (DaaS) Application",
    "Embedded systems",
    "Fog Computing",
    "HPC System",
    "ICS or SCADA System",
    "Industrial Internet of Things (IIoT)",
    "IoT application",
    "Mobile application",
    "Messaging application",
    "Network application",
    "SaaS application",
    "Smart Grid Systems",
    "Vehicular Fog Computing (VFC)",
    "Wearable Devices",
    "Web application"
]

# Industry sector options
INDUSTRY_SECTOR_OPTIONS = [
    "Agriculture", "Aerospace", "Automotive", "Biotechnology", "Chemical",
    "Commercial", "Communications", "Construction", "Dams", "Defense",
    "Education", "Emergency", "Energy", "Entertainment", "Financial",
    "Food and Beverage", "Government", "Healthcare", "Hospitality",
    "Information Technology", "Logistics", "Manufacturing", "Marine",
    "Miscellaneous", "Nuclear", "Pharmaceuticals", "Retail",
    "Telecommunications", "Transportation", "Utilities", "Water"
]

# Data sensitivity options
DATA_SENSITIVITY_OPTIONS = ["High", "Medium", "Low", "None"]

# Internet facing options
INTERNET_FACING_OPTIONS = ["Yes", "No"]

# Number of employees options
NUM_EMPLOYEES_OPTIONS = [
    "Unknown",
    "0-10",
    "11-100",
    "101-1000",
    "Over 1000"
]

# Compliance requirements options
COMPLIANCE_REQUIREMENTS_OPTIONS = [
    "3GPP TS 33.501", "HIPAA", "PCI DSS", "COPPA", "CCPA", "GDPR",
    "FAA Regulations", "FISMA", "SOX", "IEC 62443", "ISO 27001",
    "ISO/IEC 30141", "ISO/SAE 21434", "SOC 2", "FedRAMP", "GLBA",
    "FERPA", "FDA", "ISO 13485", "ITAR"
]

# Authentication methods options
AUTHENTICATION_OPTIONS = [
    "Active Directory (AD)", "API Key", "Basic", "Biometrics",
    "Firebase Authentication", "Hardware Tokens", "MFA",
    "Mutual TLS (mTLS)", "None", "OAUTH2", "Passwords", "Pins",
    "Public/Private Key Pairs", "SSO", "Smart Cards"
]

# Technology types with their CPE identifiers
TECHNOLOGY_TYPES: Dict[str, Dict[str, str]] = {
    "Databases": {
        "Google Firestore": "cpe:2.3:a:google:cloud_firestore:",
        "MySQL": "cpe:2.3:a:mysql:mysql:",
        "MS SQL Server": "cpe:2.3:a:microsoft:sql_server:",
        "Oracle Database": "cpe:2.3:a:oracle:database:",
        "PostgreSQL": "cpe:2.3:a:postgresql:postgresql:",
        "Scylla": "cpe:2.3:a:scylladb:scylla:",
        "Snowflake": "cpe:2.3:a:snowflake:snowflake:",
        "Redis": "cpe:2.3:a:redislabs:redis:",
    },
    "Operating Systems": {
        "Windows": "cpe:2.3:o:microsoft:windows:",
        "macOS": "cpe:2.3:o:apple:macos:",
        "CentOS": "cpe:2.3:o:centos:centos:",
        "Ubuntu": "cpe:2.3:o:canonical:ubuntu_linux:",
        "Debian": "cpe:2.3:o:debian:debian_linux:",
        "Fedora": "cpe:2.3:o:fedora:fedora:",
        "RHEL": "cpe:2.3:o:redhat:enterprise_linux:",
        "SUSE": "cpe:2.3:o:suse:suse_linux:",
        "Android": "cpe:2.3:o:google:android:",
        "iOS": "cpe:2.3:o:apple:iphone_os:",
        "iPadOS": "cpe:2.3:o:apple:ipados:",
        "tvOS": "cpe:2.3:o:apple:tvos:",
        "Linux Kernel": "cpe:2.3:o:linux:linux_kernel:",
        "Raspbian": "cpe:2.3:o:raspberrypi:raspbian:",
    },
    "Programming Languages": {
        "Python": "cpe:2.3:a:python:python:",
        "JavaScript": "cpe:2.3:a:ecmascript:ecmascript:",
        "Java": "cpe:2.3:a:oracle:jdk:",
        "C#": "cpe:2.3:a:microsoft:.net_framework:",
        "Go": "cpe:2.3:a:golang:go:",
        "Ruby": "cpe:2.3:a:ruby-lang:ruby:",
        "PHP": "cpe:2.3:a:php:php:",
        "Swift": "cpe:2.3:a:swift:swift:",
        "Kotlin": "cpe:2.3:a:jetbrains:kotlin:",
        "Dart": "cpe:2.3:a:dartlang:dart:",
        "Flutter": "cpe:2.3:a:google:flutter:",
    },
    "Web Frameworks": {
        "Django": "cpe:2.3:a:django:django:",
        "Flask": "cpe:2.3:a:palletsprojects:flask:",
        "React": "cpe:2.3:a:facebook:react:",
        "Angular": "cpe:2.3:a:google:angular:",
        "Vue.js": "cpe:2.3:a:vue:vue.js:",
        "Spring": "cpe:2.3:a:pivotal:spring_framework:",
        "Express": "cpe:2.3:a:expressjs:express:",
        "Laravel": "cpe:2.3:a:laravel:laravel:",
        "Ruby on Rails": "cpe:2.3:a:rubyonrails:ruby_on_rails:",
    },
}

def validate_required_fields(app_type: str, industry_sector: str, sensitive_data: str, 
                           internet_facing: str, num_employees: str) -> List[str]:
    """Validate that all required fields have been filled out.
    
    Args:
        app_type: Selected application type
        industry_sector: Selected industry sector
        sensitive_data: Selected data sensitivity level
        internet_facing: Selected internet facing status
        num_employees: Selected number of employees
        
    Returns:
        List of error messages for any missing required fields
    """
    errors: List[str] = []
    
    if not app_type:
        errors.append("Please select an application type.")
    if not industry_sector:
        errors.append("Please select an industry sector.")
    if not sensitive_data:
        errors.append("Please select a data sensitivity level.")
    if not internet_facing:
        errors.append("Please indicate if the application is internet-facing.")
    if not num_employees:
        errors.append("Please select the number of employees.")
        
    return errors

def validate_version_format(version: str) -> Tuple[bool, str]:
    """Validate the format of a technology version string.
    
    Args:
        version: The version string to validate
        
    Returns:
        Tuple of (is_valid, message) where:
        - is_valid: True if version format is valid, False otherwise
        - message: Description of the validation result
    """
    if not version:
        return True, ""  # Empty version is allowed
        
    # Version format: numbers or wildcards separated by dots
    import re
    pattern = r'^(\d+|\*)(\.(\d+|\*))*$'
    
    if not re.match(pattern, version):
        return False, "Version should be in format: numbers or wildcards separated by dots (e.g., '1.2.3', '1.2.*', '1.*', or '*')"
        
    # Check for reasonable number of segments (e.g., not too many dots)
    if len(version.split('.')) > 4:
        return False, "Version should not have more than 4 segments (e.g., '1.2.3.4')"
        
    return True, ""

def render() -> None:
    """Render the technology selection tab of the threat modeling application.
    
    This function creates the interface for Step 2 of the threat modeling process,
    allowing users to specify their application's technology stack and related details.
    
    The function:
    1. Checks if Step 1 is completed
    2. Displays technology selection interface
    3. Collects application details
    4. Manages technology version tracking
    5. Handles session state for selected technologies
    
    Note:
        This function manages session state for:
        - selected_technologies: Dictionary of selected technologies and their CPE identifiers
        - selected_versions: Dictionary of selected technologies and their versions
        - Various category-specific selected technologies
    """
    logger.info("Rendering technologies tab")
    if not st.session_state['step1_completed']:
        st.warning(UI_TEXT['step_warning'])
        return
    try:
        # Initialize session state for selected technologies and versions if not exists
        if 'selected_technologies' not in st.session_state:
            st.session_state['selected_technologies'] = {}
        if 'selected_versions' not in st.session_state:
            st.session_state['selected_versions'] = {}

        st.markdown(UI_TEXT['title'])
        st.markdown("""---""")

        col1, col2 = st.columns([1.5, 1.5])  # Adjust the column widths as needed

        with col2:
            st.write(UI_TEXT['importance_title'])
            st.write(UI_TEXT['importance_text'])

            st.markdown(UI_TEXT['versioning_title'])
            st.markdown(UI_TEXT['versioning_text'])

        with col1:
            col1a, col1b = st.columns([1, 1])

            with col1a:
                app_type: str = st.selectbox(
                    label="Application type :red[(Required)]",
                    options=APP_TYPE_OPTIONS,
                    key="app_type",
                )

                industry_sector: str = st.selectbox(
                    label="Industry sector :red[(Required)]",
                    options=INDUSTRY_SECTOR_OPTIONS,
                    key="industry_sector",
                )

                sensitive_data: str = st.selectbox(
                    label="Data sensitivity :red[(Required)]",
                    options=DATA_SENSITIVITY_OPTIONS,
                    key="sensitive_data",
                )

                internet_facing: str = st.selectbox(
                    label="Internet-facing? :red[(Required)]",
                    options=INTERNET_FACING_OPTIONS,
                    key="internet_facing",
                )

            with col1b:
                num_employees: str = st.selectbox(
                    label="Number of employees :red[(Required)]",
                    options=NUM_EMPLOYEES_OPTIONS,
                    key="num_employees",
                )

                compliance_requirements: List[str] = st.multiselect(
                    label="Compliance requirements :orange[(Optional)]",
                    options=COMPLIANCE_REQUIREMENTS_OPTIONS,
                    key="compliance_requirements",
                )

                authentication: List[str] = st.multiselect(
                    "Authentication methods :orange[(Optional)]",
                    AUTHENTICATION_OPTIONS,
                    key="authentication",
                )

                technical_ability: str = st.selectbox(
                    "Your technical knowledge: :orange[(Static)]",
                    ["Medium"],
                    index=0,
                    key="technical_ability",
                )

            # Technology selection with expanders
            st.subheader("Technology Stack")
            for category, options in TECHNOLOGY_TYPES.items():
                with st.expander(f"📦 {category}", expanded=True):
                    selected_technologies: List[str] = st.multiselect(
                        f"Select {category} :orange[(Optional)]", 
                        list(options.keys()), 
                        key=f"{category}_tech"
                    )

                    # Track current selected technologies
                    current_selected_techs: Set[str] = set(selected_technologies)

                    # Get previously selected technologies for this category from session state
                    previous_selected_techs: Set[str] = set(st.session_state.get(f"{category}_selected_techs", []))

                    for tech in selected_technologies:
                        version = st.text_input(f"Specify version for {tech}", key=f"{tech}_version")
                        is_valid, message = validate_version_format(version)
                        
                        if not is_valid:
                            st.warning(message)
                        
                        st.session_state['selected_versions'][tech] = version
                        st.session_state['selected_technologies'][tech] = options[tech]

                    # Update session state for this category
                    st.session_state[f"{category}_selected_techs"] = selected_technologies

                    # Remove unselected technologies from session state
                    for tech in previous_selected_techs - current_selected_techs:
                        st.session_state['selected_versions'].pop(tech, None)
                        st.session_state['selected_technologies'].pop(tech, None)

            # Add visual separation
            st.markdown("""---""")
            
            # Show summary of selected technologies
            if st.session_state['selected_technologies']:
                st.subheader("📋 Selected Technologies Summary")
                for tech, cpe in st.session_state['selected_technologies'].items():
                    version = st.session_state['selected_versions'].get(tech, "No version specified")
                    st.markdown(f"- **{tech}**: {version}")

            submitted = st.button("Next")

            if submitted:
                if industry_sector == "":
                    st.error("Please select an industry sector.")
                else:
                    st.session_state['app_details'] = {
                        'app_type': app_type,
                        'industry_sector': industry_sector,
                        'sensitive_data': sensitive_data,
                        'internet_facing': internet_facing,
                        'num_employees': num_employees,
                        'compliance_requirements': compliance_requirements,
                        'technical_ability': technical_ability,
                        'authentication': authentication,
                        'selected_technologies': st.session_state['selected_technologies'],
                        'selected_versions': st.session_state['selected_versions'],
                        'app_input': st.session_state['app_input']
                    }
                    st.session_state['step2_completed'] = True
                    st.success("Technology details saved. Move to the next step.")

    except Exception as e:
        handle_exception(e, "Error in Step 2: Technology tab")
