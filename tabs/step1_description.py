"""
Step 1: Description Tab Module

This module handles the first step of the threat modeling process, where users provide
a description of their application. It supports both manual text input and AI-powered
image analysis of architecture diagrams.

The module provides the following key features:
- Manual text input for application description
- AI-powered analysis of architecture diagrams
- Input validation for both text and images
- Character count tracking
- Example description with best practices
- Comprehensive error handling

Dependencies:
    - streamlit: For the web interface
    - base64: For image encoding
    - threat_model: For AI-powered image analysis
    - error_handler: For consistent error handling

Session State Variables:
    - app_input: The current application description
    - step1_completed: Boolean indicating if step 1 is complete
    - uploaded_file: The currently uploaded image file
    - image_analysis_content: The AI analysis of the uploaded image
    - last_analyzed_file: Name of the last analyzed image file
"""

import base64
import logging
from typing import Any

import streamlit as st

from error_handler import handle_exception
from threat_model import create_image_analysis_prompt, get_image_analysis

# Configure logging
logger = logging.getLogger(__name__)

# Constants for UI text and messages
# These constants centralize all user-facing text for easier maintenance and localization
UI_TEXT = {
    'title': "Step 1: Application Description",
    'subtitle': "Provide a detailed description of your application",
    'description': "Start by describing your application. This information will be used to generate an accurate threat model.",
    'image_upload': "Upload an image of your application (optional)",
    'image_analysis': "Analyzing image...",
    'image_error': "Error analyzing image. Please try again.",
    'description_label': "Application Description",
    'description_placeholder': "Enter a detailed description of your application...",
    'description_help': "Include information about the application's purpose, features, and any specific security concerns.",
    'next_button': "Next",
    'success_message': "Application description saved successfully!",
    'error_message': "Please provide an application description.",
    'example_title': "Example Description",
    'example_subtitle': "Here's a detailed example of a well-structured application description:",
    'example_tooltip': "This example shows the recommended level of detail for your application description.",
    'char_count': "Characters: {}/1000"
}

def validate_image(uploaded_file: Any) -> tuple[bool, str | None]:
    """Validate the uploaded image file.
    
    This function performs validation checks on the uploaded image file:
    - Checks if the file size is within the 10MB limit
    - Verifies that the file type is one of: PNG, JPEG, or JPG
    
    Args:
        uploaded_file: The uploaded file object from Streamlit
        
    Returns:
        Tuple[bool, Optional[str]]: A tuple containing:
            - bool: True if the image is valid, False otherwise
            - Optional[str]: Error message if validation fails, None if successful
    """
    if uploaded_file.size > 10 * 1024 * 1024:  # 10MB limit
        return False, UI_TEXT['image_size_error']
    
    if uploaded_file.type not in ["image/png", "image/jpeg", "image/jpg"]:
        return False, UI_TEXT['image_type_error']
    
    return True, None

def analyze_image(uploaded_file: Any, openai_api_key: str, selected_model: str) -> str | None:
    """Analyze an uploaded image using OpenAI's vision model.
    
    This function processes an uploaded image by:
    1. Validating the image file
    2. Converting the image to base64 format
    3. Creating an analysis prompt
    4. Sending the image to OpenAI's vision model for analysis
    
    Args:
        uploaded_file: The uploaded file object from Streamlit
        openai_api_key: The OpenAI API key for authentication
        selected_model: The selected AI model name (e.g., "gpt-4o")
        
    Returns:
        Optional[str]: The AI-generated analysis of the image if successful, None otherwise
        
    Raises:
        Exception: If there's an error during image processing or API call
    """
    try:
        # Validate image before processing
        is_valid, error_message = validate_image(uploaded_file)
        if not is_valid:
            st.error(error_message)
            return None
            
        # Convert image to base64 for API transmission
        base64_image = base64.b64encode(uploaded_file.read()).decode('utf-8')
        image_analysis_prompt = create_image_analysis_prompt()
        
        # Show loading indicator during API call
        with st.spinner(UI_TEXT['image_analysis_spinner']):
            image_analysis_output = get_image_analysis(openai_api_key, selected_model, image_analysis_prompt, base64_image)
        
        # Extract and return the analysis content
        if image_analysis_output and 'choices' in image_analysis_output:
            return image_analysis_output['choices'][0]['message']['content']
        return None
    except Exception as e:
        handle_exception(e, "An error occurred while analyzing the image.")
        return None

def validate_description(description: str) -> tuple[bool, str | None]:
    """Validate the application description.
    
    This function ensures that the provided description meets the minimum requirements:
    - Must not be empty
    - Must contain at least 50 characters (excluding whitespace)
    
    Args:
        description: The text description of the application to validate
        
    Returns:
        Tuple[bool, Optional[str]]: A tuple containing:
            - bool: True if the description is valid, False otherwise
            - Optional[str]: Error message if validation fails, None if successful
    """
    if not description or len(description.strip()) < 50:
        return False, UI_TEXT['text_area_error']
    return True, None

def render(model_provider: str, selected_model: str, openai_api_key: str, default_app_description: str) -> None:
    """Render the description tab of the threat modeling application.
    
    This function creates the main interface for Step 1 of the threat modeling process.
    It includes:
    - Application description input (manual or AI-generated)
    - Image upload and analysis capabilities
    - Input validation and error handling
    - Example description and best practices
    - Progress tracking
    
    Args:
        model_provider: The selected AI model provider (e.g., "OpenAI API")
        selected_model: The selected AI model name (e.g., "gpt-4o")
        openai_api_key: The OpenAI API key for authentication
        default_app_description: The default application description to display
        
    Note:
        This function manages session state for:
        - app_input: The current application description
        - step1_completed: Whether step 1 is complete
        - uploaded_file: The current image file
        - image_analysis_content: The AI analysis result
        - last_analyzed_file: The name of the last analyzed image
    """
    logger.info("Rendering description tab")
    try:
        # Display title and description
        st.title(UI_TEXT['title'])
        st.markdown(UI_TEXT['subtitle'])
        st.markdown(UI_TEXT['description'])
        st.markdown("""---""")

        # Create two-column layout
        col1, col2 = st.columns([1.5, 1.5])

        with col1:
            # Handle image upload and analysis if OpenAI API is selected
            if model_provider == "OpenAI API" and selected_model in ["gpt-4o"]:
                uploaded_file = st.file_uploader(UI_TEXT['image_upload'], type=["jpg", "jpeg", "png"])

                if uploaded_file is not None:
                    # Check if this is a new file or if we've already analyzed it
                    current_file_name = uploaded_file.name
                    if 'last_analyzed_file' not in st.session_state or st.session_state.last_analyzed_file != current_file_name:
                        if not openai_api_key:
                            st.error(UI_TEXT['image_upload_error'])
                        else:
                            st.session_state.uploaded_file = uploaded_file
                            image_analysis_content = analyze_image(uploaded_file, openai_api_key, selected_model)
                            if image_analysis_content:
                                st.session_state.image_analysis_content = image_analysis_content
                                st.session_state['app_input'] = image_analysis_content
                                st.session_state.last_analyzed_file = current_file_name
                            else:
                                st.error(UI_TEXT['image_analysis_error'])

            # Create the application description form
            with st.form(key='app_description_form'):
                # Text area for application description
                app_input = st.text_area(
                    label=UI_TEXT['description_label'],
                    value=st.session_state.get('app_input', ""),
                    placeholder=UI_TEXT['description_placeholder'],
                    height=200,
                    key="app_desc",
                    help=UI_TEXT['description_help'],
                )
                
                # Display character count
                char_count = len(app_input)
                st.caption(UI_TEXT['char_count'].format(char_count))

                # Handle form submission
                submitted = st.form_submit_button(UI_TEXT['next_button'])

                if submitted:
                    # Validate and save the description
                    is_valid, error_message = validate_description(app_input)
                    if is_valid:
                        st.session_state['app_input'] = app_input
                        st.session_state['step1_completed'] = True
                        st.success("Application description saved. Move to the next step.")
                    else:
                        st.error(error_message)

                # Display example description in an expander
                with st.expander(UI_TEXT['example_title']):
                    st.markdown(UI_TEXT['example_subtitle'])
                    st.info(UI_TEXT['example_tooltip'])
                    st.markdown("""
                    <p style="font-size: 14px; font-style: italic;">
                    A small business management application designed for local retail stores to streamline their operations. The application features an Angular frontend and a Flask backend with a MySQL database. Store managers can sign up for an account, log in using email and password authentication, and manage their inventory, sales, and employee schedules. The application supports real-time updates and notifications, ensuring managers are always aware of low stock levels and sales trends. Data is encrypted both in transit and at rest, and the system includes role-based access control to restrict sensitive information to authorized personnel. Additionally, the application integrates with popular payment gateways like Stripe and PayPal to process transactions securely.</p>""", unsafe_allow_html=True)

        with col2:
            # Display information about data sources and threat modeling
            st.write("""AegisShield searches and pulls information from the :green[National Vulnerability Database (NVD)] and :green[AlienVault OTX] to provide a comprehensive threat model for the application. It then maps the STRIDE threat to the :green[MITRE ATT&CK framework] to identify tactics, techniques and procedures.""")

            # Display importance of application description
            st.write("""
            #### Why Providing an Application Description is Important

            Providing a detailed description of the application is crucial for effective threat modeling. This information helps in:

            - Identifying the specific context and scope of the application, which is essential for understanding its unique threat landscape.
            - Tailoring the threat model to address the particular functionalities and features of the application.
            - Ensuring that all relevant threats are considered, including those specific to the application's intended use and environment.

            The more detailed and accurate your description, the more precise and comprehensive the threat model will be. This helps in proactively identifying and mitigating potential security risks.
            """)
    except Exception as e:
        handle_exception(e, "An error occurred while rendering the description tab.")
