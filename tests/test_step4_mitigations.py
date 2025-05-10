from unittest.mock import MagicMock, patch

import pytest

from tabs.step4_mitigations import (
    generate_mitigations,
    validate_session_state,
)

# Mock data
MOCK_THREAT_MODEL_MARKDOWN = """
### Threat 1
- Type: SQL Injection
- Impact: Data breach
"""

MOCK_MITRE_ATTACK_MARKDOWN = """
### MITRE ATT&CK
- Technique: T1234
- Name: Test Attack
"""

MOCK_NVD_VULNERABILITIES_MARKDOWN = """
### Vulnerabilities
- CVE-2023-1234: SQL Injection vulnerability
"""

MOCK_MITIGATIONS_MARKDOWN = """
### Mitigations
1. Input validation
2. Prepared statements
3. WAF implementation
"""

@pytest.fixture
def mock_session_state():
    """Mock Streamlit session state with required variables."""
    with patch("streamlit.session_state", new_callable=dict) as mock_state:
        mock_state['threat_model_markdown'] = MOCK_THREAT_MODEL_MARKDOWN
        mock_state['mitre_attack_markdown'] = MOCK_MITRE_ATTACK_MARKDOWN
        mock_state['nvd_vulnerabilities_markdown'] = MOCK_NVD_VULNERABILITIES_MARKDOWN
        yield mock_state

def test_validate_session_state_success(mock_session_state):
    """Test successful validation of session state."""
    is_valid, error_msg = validate_session_state()
    assert is_valid
    assert error_msg == ""

def test_validate_session_state_missing_vars(mock_session_state):
    """Test validation when session variables are missing."""
    # Remove a required variable
    mock_session_state.pop('threat_model_markdown')
    
    is_valid, error_msg = validate_session_state()
    assert not is_valid
    assert "Missing required data" in error_msg
    assert "threat_model_markdown" in error_msg

def test_validate_session_state_empty_vars(mock_session_state):
    """Test validation when session variables are empty."""
    # Set a required variable to empty
    mock_session_state['mitre_attack_markdown'] = ""
    
    is_valid, error_msg = validate_session_state()
    assert not is_valid
    assert "Missing required data" in error_msg
    assert "mitre_attack_markdown" in error_msg

def test_generate_mitigations_success(mock_session_state):
    """Test successful generation of mitigations."""
    with patch('tabs.step4_mitigations.create_mitigations_prompt') as mock_create_prompt, \
         patch('tabs.step4_mitigations.get_mitigations') as mock_get_mitigations, \
         patch('streamlit.spinner') as mock_spinner, \
         patch('streamlit.error') as mock_error:
        
        mock_create_prompt.return_value = "test prompt"
        mock_get_mitigations.return_value = MOCK_MITIGATIONS_MARKDOWN
        mock_spinner.return_value.__enter__ = MagicMock()
        mock_spinner.return_value.__exit__ = MagicMock()

        result = generate_mitigations("OpenAI API", "gpt-4", "test_api_key")

        mock_create_prompt.assert_called_once_with(
            MOCK_THREAT_MODEL_MARKDOWN,
            MOCK_MITRE_ATTACK_MARKDOWN,
            MOCK_NVD_VULNERABILITIES_MARKDOWN
        )
        mock_get_mitigations.assert_called_once_with(
            "test_api_key",
            "gpt-4",
            "test prompt"
        )
        mock_error.assert_not_called()
        assert result == MOCK_MITIGATIONS_MARKDOWN

def test_generate_mitigations_invalid_state(mock_session_state):
    """Test mitigation generation with invalid session state."""
    # Remove a required variable
    mock_session_state.pop('threat_model_markdown')
    
    with patch('streamlit.error') as mock_error:
        result = generate_mitigations("OpenAI API", "gpt-4", "test_api_key")
        
        mock_error.assert_called_once()
        assert result == ""

def test_generate_mitigations_api_error(mock_session_state):
    """Test error handling during mitigation generation."""
    with patch('tabs.step4_mitigations.create_mitigations_prompt') as mock_create_prompt, \
         patch('tabs.step4_mitigations.get_mitigations') as mock_get_mitigations, \
         patch('tabs.step4_mitigations.handle_exception') as mock_handle_error, \
         patch('streamlit.spinner') as mock_spinner, \
         patch('streamlit.warning') as mock_warning:
        
        mock_create_prompt.return_value = "test prompt"
        mock_get_mitigations.side_effect = Exception("API Error")
        mock_spinner.return_value.__enter__ = MagicMock()
        mock_spinner.return_value.__exit__ = MagicMock()

        result = generate_mitigations("OpenAI API", "gpt-4", "test_api_key")

        assert mock_get_mitigations.call_count == 3  # MAX_RETRIES
        assert mock_warning.call_count == 2  # MAX_RETRIES - 1
        mock_handle_error.assert_called_once()
        assert result == "" 