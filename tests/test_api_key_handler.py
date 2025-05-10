"""Tests for the API key handler module."""
from unittest.mock import patch

import streamlit as st

from api_key_handler import load_api_keys, render_api_key_inputs


def test_load_api_keys_from_secrets():
    """Test loading API keys from Streamlit secrets."""
    with patch.object(st, 'secrets', {'nvd_api_key': 'test_nvd', 'alienvault_api_key': 'test_alien'}):
        load_api_keys()
        assert st.session_state['nvd_api_key'] == 'test_nvd'
        assert st.session_state['alienvault_api_key'] == 'test_alien'

def test_load_api_keys_no_secrets():
    """Test loading API keys when secrets are not available."""
    with patch.object(st, 'secrets', {}):
        load_api_keys()
        assert st.session_state['nvd_api_key'] == ''
        assert st.session_state['alienvault_api_key'] == ''

def test_load_api_keys_partial_secrets():
    """Test loading API keys when only some secrets are available."""
    with patch.object(st, 'secrets', {'nvd_api_key': 'test_nvd'}):
        load_api_keys()
        assert st.session_state['nvd_api_key'] == 'test_nvd'
        assert st.session_state['alienvault_api_key'] == ''

@patch('streamlit.text_input')
@patch('streamlit.markdown')
def test_render_api_key_inputs_default_state(mock_markdown, mock_text_input):
    """Test rendering API key inputs with default state."""
    # Setup mock returns
    mock_text_input.return_value = 'test_key'
    
    # Clear session state
    for key in ['model_provider', 'selected_model', 'openai_api_key', 'nvd_api_key', 'alienvault_api_key']:
        if key in st.session_state:
            del st.session_state[key]
    
    render_api_key_inputs()
    
    # Check default values are set
    assert st.session_state['model_provider'] == 'OpenAI API'
    assert st.session_state['selected_model'] == 'gpt-4o'
    
    # Verify OpenAI key input was rendered
    mock_text_input.assert_called()
    mock_markdown.assert_called()

@patch('streamlit.text_input')
def test_render_api_key_inputs_existing_keys(mock_text_input):
    """Test rendering API key inputs when keys already exist."""
    # Setup session state with existing keys
    st.session_state['nvd_api_key'] = 'existing_nvd'
    st.session_state['alienvault_api_key'] = 'existing_alien'
    
    render_api_key_inputs()
    
    # Should only call text_input once for OpenAI (not for NVD or AlienVault)
    assert mock_text_input.call_count == 1
    assert 'OpenAI API Key' in str(mock_text_input.call_args)

@patch('streamlit.text_input')
@patch('streamlit.error')
def test_render_api_key_inputs_empty_openai(mock_error, mock_text_input):
    """Test error message when OpenAI key is empty."""
    mock_text_input.return_value = ''
    
    render_api_key_inputs()
    
    mock_error.assert_called_once_with("⚠️ OpenAI API key is required to proceed") 