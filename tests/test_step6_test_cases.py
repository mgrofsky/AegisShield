from unittest.mock import MagicMock, patch

import pytest

from tabs.step6_test_cases import generate_test_cases, validate_session_state

# Mock data
MOCK_THREAT_MODEL = [
    {
        "Threat Type": "SQL Injection",
        "Scenario": "An attacker exploits weak input validation",
        "Potential Impact": "Data breach and unauthorized access"
    }
]

MOCK_THREATS_MARKDOWN = """
### Threat 1
- Type: SQL Injection
- Scenario: An attacker exploits weak input validation
- Impact: Data breach and unauthorized access
"""

MOCK_TEST_CASES_MARKDOWN = """
Feature: SQL Injection Prevention

Scenario: Validate Input Against SQL Injection
  Given a web form with user input fields
  When malicious SQL code is entered
  Then the input should be sanitized
  And the query should be parameterized
  And the application should log the attempt

Scenario: Handle SQL Injection Attempt
  Given an authenticated user session
  When SQL injection is attempted
  Then the request should be blocked
  And an alert should be generated
  And the session should be terminated
"""

@pytest.fixture
def mock_session_state():
    """Mock Streamlit session state with required variables."""
    with patch("streamlit.session_state", new_callable=dict) as mock_state:
        mock_state['threat_model'] = MOCK_THREAT_MODEL
        yield mock_state

def test_validate_session_state_success(mock_session_state):
    """Test successful validation of session state."""
    is_valid, error_msg = validate_session_state()
    assert is_valid
    assert error_msg == ""

def test_validate_session_state_missing_vars(mock_session_state):
    """Test validation when session variables are missing."""
    # Remove the required variable
    mock_session_state.pop('threat_model')
    
    is_valid, error_msg = validate_session_state()
    assert not is_valid
    assert "Missing required data" in error_msg
    assert "threat_model" in error_msg

def test_validate_session_state_empty_vars(mock_session_state):
    """Test validation when session variables are empty."""
    # Set the required variable to empty
    mock_session_state['threat_model'] = []
    
    is_valid, error_msg = validate_session_state()
    assert not is_valid
    assert "Missing required data" in error_msg
    assert "threat_model" in error_msg

def test_generate_test_cases_success():
    """Test successful generation of test cases."""
    with patch('tabs.step6_test_cases.create_test_cases_prompt') as mock_create_prompt, \
         patch('tabs.step6_test_cases.get_test_cases') as mock_get_test_cases, \
         patch('streamlit.spinner') as mock_spinner, \
         patch('streamlit.error') as mock_error:
        
        mock_create_prompt.return_value = "test prompt"
        mock_get_test_cases.return_value = MOCK_TEST_CASES_MARKDOWN
        mock_spinner.return_value.__enter__ = MagicMock()
        mock_spinner.return_value.__exit__ = MagicMock()

        result = generate_test_cases("OpenAI API", "gpt-4", "test_api_key", MOCK_THREATS_MARKDOWN)

        mock_create_prompt.assert_called_once_with(MOCK_THREATS_MARKDOWN)
        mock_get_test_cases.assert_called_once_with(
            "test_api_key",
            "gpt-4",
            "test prompt"
        )
        mock_error.assert_not_called()
        assert result == MOCK_TEST_CASES_MARKDOWN

def test_generate_test_cases_api_error():
    """Test error handling during test cases generation."""
    with patch('tabs.step6_test_cases.create_test_cases_prompt') as mock_create_prompt, \
         patch('tabs.step6_test_cases.get_test_cases') as mock_get_test_cases, \
         patch('tabs.step6_test_cases.handle_exception') as mock_handle_error, \
         patch('streamlit.spinner') as mock_spinner, \
         patch('streamlit.warning') as mock_warning:
        
        mock_create_prompt.return_value = "test prompt"
        mock_get_test_cases.side_effect = Exception("API Error")
        mock_spinner.return_value.__enter__ = MagicMock()
        mock_spinner.return_value.__exit__ = MagicMock()

        result = generate_test_cases("OpenAI API", "gpt-4", "test_api_key", MOCK_THREATS_MARKDOWN)

        assert mock_get_test_cases.call_count == 3  # MAX_RETRIES
        assert mock_warning.call_count == 2  # MAX_RETRIES - 1
        mock_handle_error.assert_called_once()
        assert result == "" 