"""Tests for the Streamlit app functionality in step3_threat_model.py."""

from unittest.mock import MagicMock, patch

import pytest

from tabs.step3_threat_model import render

# Mock data
MOCK_APP_DETAILS = {
    'app_type': 'web',
    'authentication': 'basic',
    'internet_facing': True,
    'industry_sector': 'finance',
    'sensitive_data': ['PII'],
    'technical_ability': 'advanced'
}

MOCK_APP_INPUT = "A web application for online banking"

@pytest.fixture
def mock_streamlit():
    """Create a mock Streamlit environment."""
    with patch('streamlit.markdown') as mock_markdown, \
         patch('streamlit.button') as mock_button, \
         patch('streamlit.spinner') as mock_spinner, \
         patch('streamlit.error') as mock_error, \
         patch('streamlit.warning') as mock_warning:
        mock_button.return_value = True
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=None)
        yield {
            'markdown': mock_markdown,
            'button': mock_button,
            'spinner': mock_spinner,
            'error': mock_error,
            'warning': mock_warning
        }

@pytest.fixture
def mock_session_state():
    """Create a mock session state."""
    return {
        'app_details': MOCK_APP_DETAILS,
        'app_input': MOCK_APP_INPUT,
        'step2_completed': True,
        'openai_api_key': 'test-key',
        'nvd_api_key': 'test-nvd-key',
        'alienvault_api_key': 'test-otx-key',
        'industry_sector': 'finance',
        'selected_technologies': {'Python': 'cpe:/a:python:python:3.9'},
        'selected_versions': {'Python': '3.9'}
    }

def test_render_complete(mock_session_state, mock_streamlit):
    """Test rendering with complete session state."""
    with patch('tabs.step3_threat_model.st.session_state', mock_session_state), \
         patch('tabs.step3_threat_model.search_nvd') as mock_nvd, \
         patch('tabs.step3_threat_model.fetch_otx_data') as mock_otx, \
         patch('tabs.step3_threat_model.create_threat_model_prompt') as mock_prompt, \
         patch('tabs.step3_threat_model.get_threat_model') as mock_get_model:
        
        mock_nvd.return_value = {'vulnerabilities': []}
        mock_otx.return_value = "OTX data"
        mock_prompt.return_value = "Test prompt"
        mock_get_model.return_value = {'threat_model': [], 'improvement_suggestions': []}
        
        render("OpenAI API", "gpt-4", "test-key")
        
        mock_nvd.assert_called_once()
        mock_otx.assert_called_once()
        mock_prompt.assert_called_once()
        mock_get_model.assert_called_once()

def test_render_incomplete_step2(mock_session_state, mock_streamlit):
    """Test rendering when step 2 is not completed."""
    mock_session_state['step2_completed'] = False
    
    with patch('tabs.step3_threat_model.st.session_state', mock_session_state):
        render("OpenAI API", "gpt-4", "test-key")
        
        mock_streamlit['warning'].assert_called_once_with("Please complete Steps 1 and 2 first.")

def test_render_missing_app_input(mock_session_state, mock_streamlit):
    """Test rendering when app input is missing."""
    del mock_session_state['app_input']
    
    with patch('tabs.step3_threat_model.st.session_state', mock_session_state):
        render("OpenAI API", "gpt-4", "test-key")
        
        mock_streamlit['error'].assert_called_once_with("Please complete Step 1: Description first.")

def test_render_missing_app_details(mock_session_state, mock_streamlit):
    """Test rendering when app details are missing."""
    del mock_session_state['app_details']
    
    with patch('tabs.step3_threat_model.st.session_state', mock_session_state):
        render("OpenAI API", "gpt-4", "test-key")
        
        mock_streamlit['error'].assert_called_once_with("Please complete Step 2: Technology first.")

def test_render_missing_api_keys(mock_session_state, mock_streamlit):
    """Test rendering when API keys are missing."""
    del mock_session_state['nvd_api_key']
    del mock_session_state['alienvault_api_key']
    
    with patch('tabs.step3_threat_model.st.session_state', mock_session_state), \
         patch('tabs.step3_threat_model.search_nvd') as mock_nvd, \
         patch('tabs.step3_threat_model.fetch_otx_data') as mock_otx:
        
        mock_nvd.return_value = {'vulnerabilities': []}
        mock_otx.return_value = "OTX data"
        
        render("OpenAI API", "gpt-4", "test-key")
        
        error_calls = [call[0][0] for call in mock_streamlit['error'].call_args_list]
        assert "NVD API key is missing or no technologies selected" in error_calls
        assert "AlienVault API key is missing" in error_calls 