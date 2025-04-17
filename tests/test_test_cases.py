import pytest
from unittest.mock import patch, MagicMock
from test_cases import create_test_cases_prompt, get_test_cases

def test_create_test_cases_prompt():
    """Test that create_test_cases_prompt generates the expected prompt format."""
    threats = "Test threat"
    
    result = create_test_cases_prompt(threats)
    
    # Verify the prompt contains all required components
    assert threats in result
    assert "cyber security expert" in result
    assert "STRIDE threat modelling" in result
    assert "Gherkin test cases" in result
    assert "Given" in result
    assert "When" in result
    assert "Then" in result
    assert "triple backticks" in result

@patch('test_cases.handle_exception')
def test_get_test_cases_missing_api_key(mock_handle_exception):
    """Test that error is handled when API key is missing."""
    get_test_cases("", prompt="test prompt")
    assert mock_handle_exception.call_count == 2

@patch('test_cases.handle_exception')
def test_get_test_cases_missing_prompt(mock_handle_exception):
    """Test that error is handled when prompt is missing."""
    get_test_cases("test_key", prompt=None)
    assert mock_handle_exception.call_count == 2

@patch('test_cases.OpenAI')
def test_get_test_cases(mock_openai):
    """Test get_test_cases with mocked OpenAI client."""
    # Setup mock response
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "Test test case response"
    mock_openai.return_value.chat.completions.create.return_value = mock_response

    result = get_test_cases("test_api_key", prompt="test prompt")
    assert result == "Test test case response"

@patch('test_cases.handle_exception')
@patch('test_cases.OpenAI')
def test_get_test_cases_api_error(mock_openai, mock_handle_exception):
    """Test that API errors are handled by error_handler."""
    mock_openai.return_value.chat.completions.create.side_effect = Exception("API Error")
    get_test_cases("test_api_key", prompt="test prompt")
    mock_handle_exception.assert_called_once() 