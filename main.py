"""
AegisShield Threat Modeler - Main Application Entry Point

Multi-page Streamlit application for comprehensive STRIDE threat modeling.
Uses st.navigation() for efficient page routing - only the active page renders.
"""

import streamlit as st

from components.sidebar import load_api_keys, render_sidebar
from config import APP_CONFIG
from state import initialize_session_state

# --- Page Configuration (must be first Streamlit call) ---
st.set_page_config(
    page_title=APP_CONFIG.page_title,
    page_icon=APP_CONFIG.page_icon,
    layout=APP_CONFIG.layout,
    initial_sidebar_state=APP_CONFIG.initial_sidebar_state,
)

# --- Initialize State & API Keys ---
initialize_session_state()
load_api_keys()

# --- Define Pages ---
pages = [
    st.Page("pages/1_Description.py", title="Description", icon=":material/description:", default=True),
    st.Page("pages/2_Technology.py", title="Technology", icon=":material/memory:"),
    st.Page("pages/3_Threat_Model.py", title="Threat Model", icon=":material/security:"),
    st.Page("pages/4_Mitigations.py", title="Mitigations", icon=":material/shield:"),
    st.Page("pages/5_DREAD_Assessment.py", title="DREAD Assessment", icon=":material/assessment:"),
    st.Page("pages/6_Test_Cases.py", title="Test Cases", icon=":material/checklist:"),
    st.Page("pages/7_PDF_Report.py", title="PDF Report", icon=":material/picture_as_pdf:"),
]

# --- Navigation & Sidebar ---
pg = st.navigation(pages, position="sidebar")
render_sidebar()

# --- Run Active Page ---
pg.run()
