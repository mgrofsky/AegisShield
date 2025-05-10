import logging

import streamlit as st

from error_handler import handle_exception  # Import the error handler
from mitigations import create_mitigations_prompt, get_mitigations

#from threat_model import (
#    json_to_markdown,
#)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration constants
MAX_RETRIES = 3
DOWNLOAD_FILENAME = "mitigations.md"
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
    """Render the header section of the mitigations tab."""
    st.markdown("""
Use this tab to generate potential mitigations for the threats identified in the threat model. Mitigations are security controls or
countermeasures that can help reduce the likelihood or impact of a security threat. The generated mitigations can be used to enhance
the security posture of the application and protect against potential attacks.
""")
    st.markdown("""---""")

def generate_mitigations(model_provider: str, selected_model: str, openai_api_key: str) -> str:
    """
    Generate mitigations using the specified model provider.
    
    Args:
        model_provider (str): The AI model provider (e.g., "OpenAI API")
        selected_model (str): The selected AI model to use
        openai_api_key (str): The API key for OpenAI services
        
    Returns:
        str: The generated mitigations in markdown format
    """
    mitigations_markdown = ""
    
    # Validate required session state variables
    is_valid, error_msg = validate_session_state()
    if not is_valid:
        st.error(error_msg)
        return mitigations_markdown
    
    # Generate the prompt using the create_mitigations_prompt function
    mitigations_prompt = create_mitigations_prompt(
        st.session_state['threat_model_markdown'],
        st.session_state['mitre_attack_markdown'],
        st.session_state['nvd_vulnerabilities_markdown']
    )

    # Show a spinner while suggesting mitigations
    with st.spinner("Suggesting mitigations..."):
        retry_count = 0
        while retry_count < MAX_RETRIES:
            try:
                # Call the relevant get_mitigations function with the generated prompt
                if model_provider == "OpenAI API":
                    logger.info(f"Generating mitigations using OpenAI model: {selected_model}")
                    mitigations_markdown = get_mitigations(openai_api_key, selected_model, mitigations_prompt)

                logger.info("Successfully generated mitigations")
                break  # Exit the loop if successful
            except Exception as e:
                retry_count += 1
                if retry_count == MAX_RETRIES:
                    handle_exception(e, f"Error suggesting mitigations after {MAX_RETRIES} attempts.")
                    mitigations_markdown = ""
                else:
                    st.warning(f"Error suggesting mitigations. Retrying attempt {retry_count + 1}/{MAX_RETRIES}...")

    return mitigations_markdown

def render_download_button(mitigations_markdown: str) -> None:
    """
    Render the download button for mitigations.
    
    Args:
        mitigations_markdown (str): The mitigations content in markdown format
    """
    st.download_button(
        label="Download Mitigations",
        data=mitigations_markdown,
        file_name=DOWNLOAD_FILENAME,
        mime=DOWNLOAD_MIME_TYPE,
    )
    logger.info("Added download button for mitigations")

def render(model_provider: str, selected_model: str, openai_api_key: str) -> None:
    """
    Render the mitigations tab in the Streamlit application.
    
    Args:
        model_provider (str): The AI model provider (e.g., "OpenAI API")
        selected_model (str): The selected AI model to use
        openai_api_key (str): The API key for OpenAI services
    """
    logger.info("Rendering mitigations tab")
    
    if not st.session_state['step3_completed']:
        st.warning("Please complete Steps 1 through 3 first.")
        return

    render_header()

    # Create a submit button for Mitigations
    mitigations_submit_button = st.button(label="Suggest Mitigations")

    if mitigations_submit_button:
        logger.info("Mitigations submit button clicked")
        # Check if threat_model data exists
        if 'threat_model' in st.session_state and st.session_state['threat_model']:
            # Convert the threat_model data into a Markdown list - commented out for now
            # threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
            
            # Generate mitigations
            mitigations_markdown = generate_mitigations(model_provider, selected_model, openai_api_key)
            
            # Display the suggested mitigations in Markdown
            st.session_state['session_mitigations_markdown'] = mitigations_markdown
            st.markdown(mitigations_markdown)
            
            st.markdown("")
            st.session_state['step4_completed'] = True
            
            # Add download button
            render_download_button(mitigations_markdown)
        else:
            logger.error("User attempted to generate mitigations without a threat model")
            st.error("Please generate a threat model first before suggesting mitigations.")
