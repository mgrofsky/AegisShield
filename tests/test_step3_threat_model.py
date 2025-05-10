from unittest.mock import MagicMock, call, patch

import pytest
import streamlit as st

from mitre_attack import process_mitre_attack_data
from tabs.step3_threat_model import handle_mitre_data, render

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

MOCK_THREAT_MODEL = [
    {
        'Threat Type': 'SQL Injection',
        'Scenario': 'Attackers can inject malicious SQL queries',
        'Potential Impact': 'High',
        'Assumptions': [
            {
                'Assumption': 'Database is accessible',
                'Role': 'Attacker',
                'Condition': 'Network access'
            }
        ],
        'MITRE ATT&CK Keywords': ['T1190', 'T1505']
    }
]

MOCK_MITRE_DATA = {
    'techniques': [
        {
            'id': 'T1190',
            'name': 'Exploit Public-Facing Application',
            'description': 'Attackers exploit vulnerabilities in public-facing applications'
        }
    ]
}

@pytest.fixture(autouse=True)
def mock_session_state():
    """Mock the Streamlit session state with auto-use enabled."""
    with patch.dict(st.session_state, {
        'step2_completed': True,
        'app_input': 'A web application for online banking',
        'app_details': {
            'app_type': 'web',
            'authentication': 'basic',
            'industry_sector': 'finance',
            'internet_facing': True,
            'sensitive_data': ['PII', 'Financial'],
            'technical_ability': 'intermediate'
        },
        'selected_technologies': {
            'python': 'cpe:/a:python:python',
            'django': 'cpe:/a:djangoproject:django'
        },
        'selected_versions': {
            'python': '3.9',
            'django': '4.2'
        },
        'industry_sector': 'finance',
        'nvd_api_key': 'test-nvd-key',
        'alienvault_api_key': 'test-alienvault-key',
        'openai_api_key': 'test-openai-key',
        'mitre_attack_markdown': '',
        'session_threat_model_json': [],
        'improvement_suggestions_json': [],
        'threat_model': [],
        'mitre_data': None,
        'attack_tree_code': None,
        'nvd_vulnerabilities': None
    }, clear=True):
        yield st.session_state

@pytest.fixture
def mock_streamlit():
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

def test_handle_mitre_data_success():
    """Test successful handling of MITRE ATT&CK data."""
    with patch('tabs.step3_threat_model.fetch_mitre_attack_data') as mock_fetch, \
         patch('tabs.step3_threat_model.process_mitre_attack_data') as mock_process:
        mock_fetch.return_value = {'test': 'data'}
        mock_process.return_value = MOCK_MITRE_DATA
        
        result = handle_mitre_data()
        
        assert result == MOCK_MITRE_DATA
        mock_fetch.assert_called_once_with('web')
        mock_process.assert_called_once()

def test_handle_mitre_data_error():
    """Test error handling in MITRE ATT&CK data processing."""
    with patch('tabs.step3_threat_model.fetch_mitre_attack_data') as mock_fetch, \
         patch('tabs.step3_threat_model.handle_exception') as mock_handle:
        mock_fetch.side_effect = Exception("Test error")
        
        result = handle_mitre_data()
        
        assert result is None
        mock_handle.assert_called_once()

def test_render_complete(mock_streamlit):
    """Test complete render flow with all required data."""
    with patch('tabs.step3_threat_model.search_nvd') as mock_nvd, \
         patch('tabs.step3_threat_model.fetch_otx_data') as mock_otx, \
         patch('tabs.step3_threat_model.create_threat_model_prompt') as mock_prompt, \
         patch('tabs.step3_threat_model.get_threat_model') as mock_get_model, \
         patch('tabs.step3_threat_model.handle_exception') as mock_handle:

        # Set up mock returns
        mock_nvd.return_value = {'vulnerabilities': []}
        mock_otx.return_value = "OTX data"
        mock_prompt.return_value = "Test prompt"
        mock_get_model.return_value = {'threat_model': MOCK_THREAT_MODEL, 'improvement_suggestions': []}

        # Simulate button click
        mock_streamlit['button'].return_value = True

        render("OpenAI API", "gpt-4", "test-key")

        # Verify all expected calls were made
        assert mock_nvd.call_count == 2  # Called once for Python and once for Django
        mock_nvd.assert_has_calls([
            call('test-nvd-key', 'cpe:/a:python:python', '3.9', 'python'),
            call('test-nvd-key', 'cpe:/a:djangoproject:django', '4.2', 'django')
        ], any_order=True)
        mock_otx.assert_called_once()
        mock_prompt.assert_called_once()
        mock_get_model.assert_called_once()
        mock_handle.assert_not_called()  # No errors should be handled in successful case

def test_render_incomplete_step2(mock_streamlit):
    """Test rendering when step 2 is not completed."""
    st.session_state['step2_completed'] = False
    
    render("OpenAI API", "gpt-4", "test-key")
    
    mock_streamlit['warning'].assert_called_once_with("Please complete Steps 1 and 2 first.")

def test_render_missing_app_input(mock_streamlit):
    """Test rendering when app input is missing."""
    del st.session_state['app_input']
    
    render("OpenAI API", "gpt-4", "test-key")
    
    mock_streamlit['error'].assert_called_once_with("Please complete Step 1: Description first.")

def test_render_missing_app_details(mock_streamlit):
    """Test rendering when app details are missing."""
    del st.session_state['app_details']
    
    render("OpenAI API", "gpt-4", "test-key")
    
    mock_streamlit['error'].assert_called_once_with("Please complete Step 2: Technology first.")

def test_render_missing_api_keys(mock_streamlit):
    """Test rendering when API keys are missing."""
    with patch('tabs.step3_threat_model.search_nvd') as mock_nvd, \
         patch('tabs.step3_threat_model.fetch_otx_data') as mock_otx, \
         patch('tabs.step3_threat_model.create_threat_model_prompt') as mock_prompt, \
         patch('tabs.step3_threat_model.get_threat_model') as mock_get_model:

        # Mock the API calls to prevent actual network requests
        mock_nvd.return_value = {'vulnerabilities': []}
        mock_otx.return_value = "OTX data"
        mock_prompt.return_value = "Test prompt"
        mock_get_model.return_value = {'threat_model': MOCK_THREAT_MODEL, 'improvement_suggestions': []}

        del st.session_state['nvd_api_key']
        del st.session_state['alienvault_api_key']
        mock_streamlit['button'].return_value = True

        render("OpenAI API", "gpt-4", "test-key")

        # Verify that error messages were shown for missing API keys
        error_calls = [call[0][0] for call in mock_streamlit['error'].call_args_list]
        assert "NVD API key is missing or no technologies selected" in error_calls
        assert "AlienVault API key is missing" in error_calls

def test_render_otx_error(mock_streamlit):
    """Test handling of OTX data fetching errors."""
    mock_streamlit['button'].return_value = True

    with patch('tabs.step3_threat_model.search_nvd') as mock_nvd, \
         patch('tabs.step3_threat_model.fetch_otx_data') as mock_otx, \
         patch('tabs.step3_threat_model.create_threat_model_prompt') as mock_prompt, \
         patch('tabs.step3_threat_model.get_threat_model') as mock_get_model:

        mock_nvd.return_value = {'vulnerabilities': []}
        mock_otx.side_effect = Exception("OTX API Error")
        mock_prompt.return_value = "test prompt"
        mock_get_model.return_value = {"threat_model": MOCK_THREAT_MODEL, "improvement_suggestions": []}

        render("OpenAI API", "gpt-4", "test-key")

        # Check that the error was displayed
        mock_streamlit['error'].assert_any_call("Error fetching OTX data.")

def test_render_otx_missing_api_key(mock_streamlit):
    """Test handling of missing OTX API key."""
    del st.session_state['alienvault_api_key']
    mock_streamlit['button'].return_value = True

    with patch('tabs.step3_threat_model.search_nvd') as mock_nvd:
        mock_nvd.return_value = {'vulnerabilities': []}
        render("OpenAI API", "gpt-4", "test-key")

        # Check that the error message was displayed
        mock_streamlit['error'].assert_any_call("AlienVault API key is missing")

def test_render_otx_missing_industry(mock_streamlit):
    """Test rendering when industry sector is missing."""
    mock_streamlit['button'].return_value = True

    with patch('tabs.step3_threat_model.search_nvd') as mock_nvd, \
         patch('tabs.step3_threat_model.fetch_otx_data') as mock_otx, \
         patch('tabs.step3_threat_model.create_threat_model_prompt') as mock_prompt, \
         patch('tabs.step3_threat_model.get_threat_model') as mock_get_model:

        # Mock the API calls to prevent actual network requests
        mock_nvd.return_value = {'vulnerabilities': []}
        mock_otx.return_value = "OTX data"
        mock_prompt.return_value = "Test prompt"
        mock_get_model.return_value = {'threat_model': MOCK_THREAT_MODEL, 'improvement_suggestions': []}

        # Remove industry sector from session state
        del st.session_state['industry_sector']

        render("OpenAI API", "gpt-4", "test-key")

        # Verify that OTX data was not fetched since industry sector is missing
        mock_otx.assert_not_called()

def test_process_mitre_attack_data_no_app_details():
    """Test that process_mitre_attack_data handles missing app details correctly."""
    with patch('tabs.step3_threat_model.handle_exception') as mock_handle:
        # Ensure app_details is not in session state
        st.session_state['app_details'] = None

        # Create mock STIX data
        mock_stix = {"objects": []}
        mock_threat_model = []

        result = process_mitre_attack_data(mock_stix, mock_threat_model, None, "test-key")

        # The code will return an empty list when no threats are provided
        assert result == []
        # The code will log a warning but not call handle_exception
        mock_handle.assert_not_called() 