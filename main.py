"""
AegisShield Threat Modeler - Main Application Module

This module serves as the main entry point for the AegisShield Threat Modeler application,
a Streamlit-based tool for generating comprehensive threat models. The application guides
users through a seven-step process to create detailed threat models for their systems
or applications.

The module handles:
- Application configuration and setup
- UI layout and navigation
- Session state management
- Error handling
- Integration with various AI models for threat analysis


Modify the import for api_key_handler to api_key_handler_local for local testing and create a local_config.py file with the necessary API keys

default_nvd_api_key'key'
default_openai_api_key='key'
default_alienvault_api_key='key'
"""

import streamlit as st

from api_key_handler import load_api_keys, render_api_key_inputs
from error_handler import handle_exception
from tabs import (
    step1_description,
    step2_technology,
    step3_threat_model,
    step4_mitigations,
    step5_dread_assessment,
    step6_test_cases,
    step7_generate_pdf,
)

for step in range(1, 8):
    key = f"step{step}_completed"
    if key not in st.session_state:
        st.session_state[key] = False

# Error message constants for different components of the application
ERROR_MESSAGES = {
    'step1': "Error in Step 1: Description tab",
    'step2': "Error in Step 2: Technology tab",
    'step3': "Error in Step 3: Threat Model tab",
    'step4': "Error in Step 4: Mitigations tab",
    'step5': "Error in Step 5: DREAD Assessment tab",
    'step6': "Error in Step 6: Test Cases tab",
    'step7': "Error in Step 7: Generate PDF Report tab",
    'critical': "A critical error occurred in the application."
}

# Default values for model parameters used throughout the application
DEFAULT_MODEL_PROVIDER = ''  # Default AI model provider
DEFAULT_SELECTED_MODEL = ''  # Default selected AI model
DEFAULT_OPENAI_API_KEY = ''  # Default OpenAI API key
DEFAULT_APP_DESCRIPTION = ''  # Default application description

# Page configuration settings for the Streamlit application
PAGE_CONFIG = {
    'page_title': "AegisShield Threat Modeler",
    'page_icon': ":shield:",
    'layout': "wide",
    'initial_sidebar_state': "expanded"
}

def render_sidebar():
    """Render the application sidebar with welcome message, logo, and API key inputs.
    
    This function creates the sidebar interface containing:
    - Welcome message explaining the application's purpose
    - AegisShield logo
    - Application usage instructions
    - API key input fields for AI model integration
    """
    with st.sidebar:
        st.markdown(
            """
            Welcome to AegisShield Threat Modeler, an AI-powered tool designed to enhance and streamline cyber threat modeling. Leveraging Generative AI, AegisShield provides detailed threat models tailored to specific organizational contexts.
            """
        )
        st.markdown("""---""")
        st.sidebar.image("aegisshield.png")

        # Add instructions on how to use the app to the sidebar
        st.sidebar.header("How to use AegisShield")
        # Add model selection input field to the sidebar
        render_api_key_inputs()

def render_tab(tab, render_func, error_key, **kwargs):
    """Helper function to render a tab with error handling.
    
    This function provides a consistent way to render tabs while handling any errors
    that might occur during rendering. It wraps the tab rendering in a try-except
    block and uses the error handling system to display appropriate error messages.
    
    Args:
        tab: The Streamlit tab object to render in
        render_func: The function to call for rendering the tab's content
        error_key: The key for the error message in ERROR_MESSAGES dictionary
        **kwargs: Additional arguments to pass to render_func
    """
    try:
        with tab:
            render_func(**kwargs)
    except Exception as e:
        handle_exception(e, ERROR_MESSAGES[error_key])

def main():
    """Main entry point for the AegisShield Threat Modeler application."""
    try:
        load_api_keys()

        # ------------------ Streamlit UI Configuration ------------------ #
        st.set_page_config(**PAGE_CONFIG)

        # ------------------ Sidebar ------------------ #
        render_sidebar()

        # ------------------ Main App UI ------------------ #
        tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
            "Step 1: Description",
            "Step 2: Technology",
            "Step 3: Threat Model",
            "Step 4: Mitigations",
            "Step 5: DREAD Risk Assessment",
            "Step 6: Test Cases",
            "Step 7: Generate PDF Report"
            ])

        # Define model parameters once for reuse across all tabs
        model_params = {
            'model_provider': st.session_state.get('model_provider', DEFAULT_MODEL_PROVIDER),
            'selected_model': st.session_state.get('selected_model', DEFAULT_SELECTED_MODEL),
            'openai_api_key': st.session_state.get('openai_api_key', DEFAULT_OPENAI_API_KEY)
        }

        # Render each tab using the helper function
        render_tab(tab1, step1_description.render, 'step1', 
                  **model_params, default_app_description=st.session_state.get('app_input', DEFAULT_APP_DESCRIPTION))
        render_tab(tab2, step2_technology.render, 'step2')
        render_tab(tab3, step3_threat_model.render, 'step3', **model_params)
        render_tab(tab4, step4_mitigations.render, 'step4', **model_params)
        render_tab(tab5, step5_dread_assessment.render, 'step5', **model_params)
        render_tab(tab6, step6_test_cases.render, 'step6', **model_params)
        render_tab(tab7, step7_generate_pdf.render, 'step7')

    except Exception as e:
        handle_exception(e, ERROR_MESSAGES['critical'])

if __name__ == '__main__':
    main()

# Initialize session state for each step completion status
for step in range(1, 7):
    if f'step{step}_completed' not in st.session_state:
        st.session_state[f'step{step}_completed'] = False