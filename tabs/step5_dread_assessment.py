import logging
from typing import Any

import streamlit as st

from dread import create_dread_assessment_prompt, dread_json_to_markdown, get_dread_assessment
from error_handler import handle_exception  # Import the error handler

# from threat_model import json_to_markdown

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration constants
MAX_RETRIES = 3
DOWNLOAD_FILENAME = "dread_assessment.md"
DOWNLOAD_MIME_TYPE = "text/markdown"

# Required session state variables
REQUIRED_SESSION_VARS = [
    'threat_model_markdown',
    'mitre_attack_markdown',
    'nvd_vulnerabilities_markdown'
]

def validate_session_state() -> tuple[bool, str]:
    """
    Validate that all required session state variables are present and valid.
    
    Returns:
        tuple[bool, str]: (is_valid, error_message)
    """
    missing_vars = []
    for var in REQUIRED_SESSION_VARS:
        if var not in st.session_state or not st.session_state[var]:
            missing_vars.append(var)
    
    if missing_vars:
        error_msg = f"Missing required data: {', '.join(missing_vars)}. Please complete previous steps first."
        logger.error(error_msg)
        return False, error_msg
    
    return True, ""

def render_header() -> None:
    """Render the header section of the DREAD assessment tab."""
    st.markdown("""
DREAD is a method for evaluating and prioritising risks associated with security threats. It assesses threats based on **D**amage potential, 
**R**eproducibility, **E**xploitability, **A**ffected users, and **D**iscoverability. This helps in determining the overall risk level and 
focusing on the most critical threats first. Use this tab to perform a DREAD risk assessment for your application / system.
""")
    st.markdown("""---""")

def generate_dread_assessment(model_provider: str, selected_model: str, openai_api_key: str) -> list[dict[str, Any]]:
    """
    Generate DREAD assessment using the specified model provider.
    
    Args:
        model_provider (str): The AI model provider (e.g., "OpenAI API")
        selected_model (str): The selected AI model to use
        openai_api_key (str): The API key for OpenAI services
        
    Returns:
        List[Dict[str, Any]]: The generated DREAD assessment
    """
    # Initialize empty assessment
    dread_assessment = []
    
    # Validate required session state variables
    is_valid, error_msg = validate_session_state()
    if not is_valid:
        st.error(error_msg)
        return dread_assessment

    # Generate the prompt using the create_dread_assessment_prompt function
    dread_assessment_prompt = create_dread_assessment_prompt(
        st.session_state['threat_model_markdown'],
        st.session_state['mitre_attack_markdown'],
        st.session_state['nvd_vulnerabilities_markdown']
    )

    # Show a spinner while generating DREAD Risk Assessment
    with st.spinner("Generating DREAD Risk Assessment..."):
        retry_count = 0
        while retry_count < MAX_RETRIES:
            try:
                # Call the relevant get_dread_assessment function with the generated prompt
                if model_provider == "OpenAI API":
                    logger.info(f"Generating DREAD assessment using OpenAI model: {selected_model}")
                    dread_assessment = get_dread_assessment(openai_api_key, selected_model, dread_assessment_prompt)

                # Save the DREAD assessment to the session state for later use in test cases
                st.session_state['dread_assessment'] = dread_assessment
                logger.info("Successfully generated DREAD assessment")
                break  # Exit the loop if successful
            except Exception as e:
                retry_count += 1
                if retry_count == MAX_RETRIES:
                    handle_exception(e, f"Error generating DREAD risk assessment after {MAX_RETRIES} attempts.")
                    dread_assessment = []
                else:
                    st.warning(f"Error generating DREAD risk assessment. Retrying attempt {retry_count + 1}/{MAX_RETRIES}...")

    return dread_assessment

def render_download_button(dread_assessment_markdown: str) -> None:
    """
    Render the download button for DREAD assessment.
    
    Args:
        dread_assessment_markdown (str): The DREAD assessment content in markdown format
    """
    st.download_button(
        label="Download DREAD Risk Assessment",
        data=dread_assessment_markdown,
        file_name=DOWNLOAD_FILENAME,
        mime=DOWNLOAD_MIME_TYPE,
    )
    logger.info("Added download button for DREAD assessment")

def render(model_provider: str, selected_model: str, openai_api_key: str) -> None:
    """
    Render the DREAD assessment tab in the Streamlit application.
    
    Args:
        model_provider (str): The AI model provider (e.g., "OpenAI API")
        selected_model (str): The selected AI model to use
        openai_api_key (str): The API key for OpenAI services
    """
    logger.info("Rendering DREAD assessment tab")
    
    if not st.session_state['step4_completed']:
        st.warning("Please complete Steps 1 through 4 first.")
        return

    render_header()

    # Create a submit button for DREAD Risk Assessment
    dread_assessment_submit_button = st.button(label="Generate DREAD Risk Assessment")

    if dread_assessment_submit_button:
        logger.info("DREAD assessment submit button clicked")
        # Check if threat_model data exists
        if 'threat_model' in st.session_state and st.session_state['threat_model']:
            # Convert the threat_model data into a Markdown list
            # threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
            
            # Generate DREAD assessment
            dread_assessment = generate_dread_assessment(model_provider, selected_model, openai_api_key)
            
            # Convert the DREAD assessment JSON to Markdown
            dread_assessment_markdown = dread_json_to_markdown(dread_assessment)
            st.session_state['session_dread_assessment_markdown'] = dread_assessment_markdown

            # Display the DREAD assessment in Markdown
            st.markdown(dread_assessment_markdown)
            st.session_state['step5_completed'] = True
            
            # Add download button
            render_download_button(dread_assessment_markdown)
        else:
            logger.error("User attempted to generate DREAD assessment without a threat model")
            st.error("Please generate a threat model first before requesting a DREAD risk assessment.")
