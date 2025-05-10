# Use this file if you want to utilize the local_config.py file to store your API keys and run it on your local machine.
import streamlit as st


def load_api_keys():
    """
    Load API keys from local_config or set default values.
    """
    try:
        import local_config as conf
        st.session_state['nvd_api_key'] = conf.default_nvd_api_key
        st.session_state['openai_api_key'] = conf.default_openai_api_key
        st.session_state['alienvault_api_key'] = conf.default_alienvault_api_key
    except ImportError:
        st.session_state['nvd_api_key'] = ""
        st.session_state['openai_api_key'] = ""
        st.session_state['alienvault_api_key'] = ""

def render_api_key_inputs():
    """
    Render API key input fields in the sidebar.
    """
    model_provider = st.selectbox(
        "Select your preferred model provider:",
        ["OpenAI API"],  #, "Azure OpenAI Service", "Google AI API", "Anthropic API"
        key="model_provider",
        help="Select the model provider you would like to use. This will determine the models available for selection.",
    )

    # Configuration for OpenAI API
    if model_provider == "OpenAI API":
        st.markdown(
            """
            ### 🔑 Required: OpenAI API Key
            1. Enter your [OpenAI API key](https://platform.openai.com/account/api-keys) and chosen model below.
            2. Provide details of the application that you would like to threat model.
            3. Generate a threat list, attack tree and/or mitigating controls for your application.
            """
        )

        # Add model selection input field to the sidebar
        selected_model = st.selectbox(
            "Select the model you would like to use:",
            ["gpt-4o"],
            key="selected_model",
            help="OpenAI have moved to continuous model upgrades so `gpt-3.5-turbo`, `gpt-4`, and `gpt-4-turbo` point to the latest available version of each model.",
        )
    # Add OpenAI API key input field
    openai_api_key = st.text_input(
        "🔑 OpenAI API Key:",
        value=st.session_state.get('openai_api_key', ''),
        type="password",
        help="You can find your OpenAI API key on the [OpenAI dashboard](https://platform.openai.com/account/api-keys).",
        placeholder="Enter your OpenAI API key here...",
    )
    if not openai_api_key:
        st.error("⚠️ OpenAI API key is required to proceed")
    if openai_api_key:
        st.session_state['openai_api_key'] = openai_api_key

    # Add NVD API key input field
    nvd_api_key = st.text_input(
        "Enter your National Vulnerability Database (NVD) API key:",
        value=st.session_state.get('nvd_api_key', ''),
        type="password",
        help="You can find your NVD API key on the [NVD website](https://nvd.nist.gov/developers/request-an-api-key).",
    )
    if nvd_api_key:
        st.session_state['nvd_api_key'] = nvd_api_key


    # Add AlienVault CTI API key input field
    alienvault_api_key = st.text_input(
        "Enter your AlienVault CTI API key:",
        value=st.session_state.get('alienvault_api_key', ''),
        type="password",
        help="You can generate an AlienVault CTI API key in the [AlienVault console](https://otx.alienvault.com/api).",
    )
    if alienvault_api_key:
        st.session_state['alienvault_api_key'] = alienvault_api_key