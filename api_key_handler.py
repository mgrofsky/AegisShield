import streamlit as st

# NIST SP 800-53 Rev. 5 Control Mappings:
# - IA-5 (Authenticator Management): API key management and secure storage
# - SC-12 (Cryptographic Key Establishment and Management): Key lifecycle management
# - AC-3 (Access Enforcement): Access control through API key validation
# - IA-2 (Identification and Authentication): Authentication to external services

def load_api_keys():
    """
    Load NVD and AlienVault API keys from Streamlit secrets, and OpenAI from user input.
    If keys are not available in secrets, prompt user to input them.
    
    NIST SP 800-53 Rev. 5 Controls Implemented:
    - IA-5(1): Authenticator Management | Password-Based Authentication
    - SC-12(2): Cryptographic Key Establishment | Symmetric Keys
    - AC-3: Access Enforcement
    """
    try:
        # NIST IA-5(1): Secure storage and retrieval of authenticators
        # Check if Streamlit secrets are available and set the keys if they exist
        if 'nvd_api_key' in st.secrets:
            st.session_state['nvd_api_key'] = st.secrets['nvd_api_key']
        else:
            st.session_state['nvd_api_key'] = ""

        if 'alienvault_api_key' in st.secrets:
            st.session_state['alienvault_api_key'] = st.secrets['alienvault_api_key']
        else:
            st.session_state['alienvault_api_key'] = ""

    except KeyError:
        # In case secrets don't exist, fall back to empty string or manual input
        st.session_state['nvd_api_key'] = ""
        st.session_state['alienvault_api_key'] = ""

def render_api_key_inputs():
    """
    Render API key input fields in the sidebar if they don't exist in Streamlit secrets or session_state.
    """
    if 'model_provider' not in st.session_state:
        st.session_state['model_provider'] = "OpenAI API"  # Default value

    if 'selected_model' not in st.session_state or not st.session_state['selected_model']:
        st.session_state['selected_model'] = "gpt-5.4"  # Default value

    #model_provider = st.selectbox(
       # "Select your preferred model provider:",
        #["OpenAI API"],
        #key="model_provider",
        #help="Select the model provider you would like to use. This will determine the models available for selection.",
    #)

    if st.session_state['model_provider'] == "OpenAI API":
        st.markdown(
            """
            ### 🔑 Required: OpenAI API Key
            1. Enter your [OpenAI API key](https://platform.openai.com/account/api-keys) in the field below.
            2. Select your preferred OpenAI model below.
            3. The key is only stored in your browser session and is not saved or shared.
            """
        )

        # Add model selection input field to the sidebar
        selected_model = st.selectbox(
            "Select the model you would like to use:",
            ["gpt-4o", "gpt-5"],
            key="selected_model",
            help="Both models work well with gpt-5 being a bit more verbose.",
        )

        # NIST IA-5(1): Masked input for sensitive authenticator data
        # NIST AC-3: Access enforcement through credential validation
        # OpenAI API key input field
        openai_api_key = st.text_input(
            "🔑 OpenAI API Key:",
            value=st.session_state.get('openai_api_key', ''),
            type="password",  # NIST IA-5(1): Obscure display of authenticators
            help="You can find your OpenAI API key on the [OpenAI dashboard](https://platform.openai.com/account/api-keys).",
            placeholder="Enter your OpenAI API key here...",
        )
        # NIST AC-3: Enforce access control through authenticator validation
        if not openai_api_key:
            st.error("⚠️ OpenAI API key is required to proceed")
        st.markdown(
            """
            4. Begin on Step 1 and move through the steps to generate a threat model.
            """
        )
        if openai_api_key:
            st.session_state['openai_api_key'] = openai_api_key

    # NVD API key input field only shown if not loaded from secrets
    if not st.session_state.get('nvd_api_key'):
        nvd_api_key = st.text_input(
            "Enter your National Vulnerability Database (NVD) API key:",
            value="",
            type="password",
            help="You can find your NVD API key on the [NVD website](https://nvd.nist.gov/developers/request-an-api-key).",
        )
        if nvd_api_key:
            st.session_state['nvd_api_key'] = nvd_api_key

    # AlienVault API key input field only shown if not loaded from secrets
    if not st.session_state.get('alienvault_api_key'):
        alienvault_api_key = st.text_input(
            "Enter your AlienVault CTI API key:",
            value="",
            type="password",
            help="You can generate an AlienVault CTI API key in the [AlienVault console](https://otx.alienvault.com/api).",
        )
        if alienvault_api_key:
            st.session_state['alienvault_api_key'] = alienvault_api_key