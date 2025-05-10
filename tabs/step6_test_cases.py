import logging

import streamlit as st

from error_handler import handle_exception  # Import the error handler
from test_cases import create_test_cases_prompt, get_test_cases
from threat_model import json_to_markdown

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration constants
MAX_RETRIES = 3
DOWNLOAD_FILENAME = "test_cases.md"
DOWNLOAD_MIME_TYPE = "text/markdown"

# Required session state variables
REQUIRED_SESSION_VARS = [
    'threat_model'
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
    """Render the header section of the test cases tab."""
    st.markdown("""
Test cases are used to validate the security of an application and ensure that potential vulnerabilities are identified and 
addressed. This tab allows you to generate test cases using Gherkin syntax. Gherkin provides a structured way to describe application 
behaviours in plain text, using a simple syntax of Given-When-Then statements. This helps in creating clear and executable test 
scenarios.
""")
    st.markdown("""---""")

def generate_test_cases(model_provider: str, selected_model: str, openai_api_key: str, threats_markdown: str) -> str:
    """
    Generate test cases using the specified model provider.
    
    Args:
        model_provider (str): The AI model provider (e.g., "OpenAI API")
        selected_model (str): The selected AI model to use
        openai_api_key (str): The API key for OpenAI services
        threats_markdown (str): The threats in markdown format
        
    Returns:
        str: The generated test cases in markdown format
    """
    # Initialize empty test cases
    test_cases_markdown = ""
    
    # Generate the prompt using the create_test_cases_prompt function
    test_cases_prompt = create_test_cases_prompt(threats_markdown)

    # Show a spinner while generating test cases
    with st.spinner("Generating test cases..."):
        retry_count = 0
        while retry_count < MAX_RETRIES:
            try:
                # Call to the relevant get_test_cases function with the generated prompt
                if model_provider == "OpenAI API":
                    logger.info(f"Generating test cases using OpenAI model: {selected_model}")
                    test_cases_markdown = get_test_cases(openai_api_key, selected_model, test_cases_prompt)

                logger.info("Successfully generated test cases")
                break  # Exit the loop if successful
            except Exception as e:
                retry_count += 1
                if retry_count == MAX_RETRIES:
                    handle_exception(e, f"Error generating test cases after {MAX_RETRIES} attempts.")
                    test_cases_markdown = ""
                else:
                    st.warning(f"Error generating test cases. Retrying attempt {retry_count+1}/{MAX_RETRIES}...")

    return test_cases_markdown

def render_download_button(test_cases_markdown: str) -> None:
    """
    Render the download button for test cases.
    
    Args:
        test_cases_markdown (str): The test cases content in markdown format
    """
    st.download_button(
        label="Download Test Cases",
        data=test_cases_markdown,
        file_name=DOWNLOAD_FILENAME,
        mime=DOWNLOAD_MIME_TYPE,
    )
    logger.info("Added download button for test cases")

def render(model_provider: str, selected_model: str, openai_api_key: str) -> None:
    """
    Render the test cases tab in the Streamlit application.
    
    Args:
        model_provider (str): The AI model provider (e.g., "OpenAI API")
        selected_model (str): The selected AI model to use
        openai_api_key (str): The API key for OpenAI services
    """
    logger.info("Rendering test cases tab")
    
    if not st.session_state['step5_completed']:
        st.warning("Please complete Steps 1 through 5 first.")
        return

    render_header()

    # Create a submit button for Test Cases
    test_cases_submit_button = st.button(label="Generate Test Cases")

    # If the Generate Test Cases button is clicked and the user has identified threats
    if test_cases_submit_button:
        logger.info("Test cases submit button clicked")
        # Check if threat_model data exists
        if 'threat_model' in st.session_state and st.session_state['threat_model']:
            # Convert the threat_model data into a Markdown list
            threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
            
            # Generate test cases
            test_cases_markdown = generate_test_cases(model_provider, selected_model, openai_api_key, threats_markdown)
            
            # Display the test cases in Markdown
            st.session_state['session_test_cases_markdown'] = test_cases_markdown
            st.markdown(test_cases_markdown)
            
            st.markdown("")
            st.session_state['step6_completed'] = True
            
            # Add download button
            render_download_button(test_cases_markdown)
        else:
            logger.error("User attempted to generate test cases without a threat model")
            st.error("Please generate a threat model first before requesting test cases.")
