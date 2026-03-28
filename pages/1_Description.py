"""
Page 1: Application Description

Users provide a text description of their application or upload an
architecture diagram for AI-powered analysis.
"""

import base64
import logging

import streamlit as st

from clients.openai_client import chat_completion_with_image
from config import MODEL_CONFIG
from services.threat_model import create_image_analysis_prompt
from state import set_step_completed
from utils.error_handler import handle_exception
from utils.validators import validate_description, validate_image

logger = logging.getLogger(__name__)


def render():
    st.title("Step 1: Application Description")
    st.markdown("Provide a detailed description of your application for threat modeling.")
    st.markdown("---")

    col1, col2 = st.columns([1.5, 1.5])

    with col1:
        # Image upload for architecture diagrams
        model = st.session_state.get("selected_model", MODEL_CONFIG.default_model)
        if model in MODEL_CONFIG.vision_capable_models:
            uploaded_file = st.file_uploader(
                "Upload an architecture diagram (optional)", type=["jpg", "jpeg", "png"]
            )

            if uploaded_file is not None:
                current_name = uploaded_file.name
                if st.session_state.get("last_analyzed_file") != current_name:
                    api_key = st.session_state.get("openai_api_key", "")
                    if not api_key:
                        st.error("Please enter your OpenAI API key first.")
                    else:
                        is_valid, err = validate_image(uploaded_file)
                        if not is_valid:
                            st.error(err)
                        else:
                            with st.status("Analyzing architecture diagram...", expanded=True) as status:
                                try:
                                    b64 = base64.b64encode(uploaded_file.read()).decode("utf-8")
                                    prompt = create_image_analysis_prompt()
                                    result = chat_completion_with_image(prompt, b64)
                                    if result:
                                        st.session_state["image_analysis_content"] = result
                                        st.session_state["app_input"] = result
                                        st.session_state["last_analyzed_file"] = current_name
                                        status.update(label="Analysis complete!", state="complete")
                                    else:
                                        status.update(label="Analysis failed", state="error")
                                        st.error("Could not analyze the image. Please try again.")
                                except Exception as e:
                                    status.update(label="Error", state="error")
                                    handle_exception(e, "Error analyzing the image.")

        # Application description form
        _advance = False
        with st.form(key="app_description_form"):
            app_input = st.text_area(
                label="Application Description",
                value=st.session_state.get("app_input", ""),
                placeholder="Enter a detailed description of your application...",
                height=200,
                key="app_desc",
                help="Include the application's purpose, features, and security concerns.",
            )
            st.caption(f"Characters: {len(app_input)}/1000")

            if st.form_submit_button("Next"):
                is_valid, err = validate_description(app_input)
                if is_valid:
                    st.session_state["app_input"] = app_input
                    set_step_completed(1)
                    _advance = True
                else:
                    st.error(err)

            with st.expander("Example Description"):
                st.info("This example shows the recommended level of detail:")
                st.markdown(
                    "*A small business management application designed for local retail stores. "
                    "Features an Angular frontend and Flask backend with MySQL. Store managers "
                    "can manage inventory, sales, and schedules with role-based access control. "
                    "Integrates with Stripe and PayPal for secure payment processing.*"
                )

    with col2:
        st.write(
            "AegisShield searches the :green[National Vulnerability Database (NVD)] "
            "and :green[AlienVault OTX], then maps STRIDE threats to the "
            ":green[MITRE ATT&CK framework]."
        )
        st.markdown("""
        #### Why Providing an Application Description is Important

        A detailed description helps in:
        - Identifying the specific context and threat landscape
        - Tailoring the threat model to your application's features
        - Ensuring all relevant threats are considered

        The more detailed your description, the more comprehensive the threat model.
        """)

    # Navigate after form closes so session state changes are committed first
    if _advance:
        st.switch_page("pages/2_Technology.py")


render()
