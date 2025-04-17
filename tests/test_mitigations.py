import pytest
from unittest.mock import patch, MagicMock
from mitigations import create_mitigations_prompt, get_mitigations

def test_create_mitigations_prompt():
    """Test that create_mitigations_prompt generates the expected prompt format."""
    threats = "Test threat"
    mitre_mapping = "Test MITRE mapping"
    nvd_vulnerabilities = "Test NVD vulnerabilities"
    
    result = create_mitigations_prompt(threats, mitre_mapping, nvd_vulnerabilities)
    
    # Verify the prompt contains all required components
    assert threats in result
    assert mitre_mapping in result
    assert nvd_vulnerabilities in result
    assert "markdown table format" in result
    assert "Column A: Threat Type" in result
    assert "Column B: Scenario" in result
    assert "Column C: Suggested Mitigation(s)" in result

@patch('mitigations.handle_exception')
def test_get_mitigations_missing_api_key(mock_handle_exception):
    """Test that error is handled when API key is missing."""
    get_mitigations("", prompt="test")
    assert mock_handle_exception.call_count == 2

@patch('mitigations.handle_exception')
def test_get_mitigations_missing_prompt(mock_handle_exception):
    """Test that error is handled when prompt is missing."""
    get_mitigations("fake_key", prompt=None)
    assert mock_handle_exception.call_count == 2

@patch('mitigations.OpenAI')
def test_get_mitigations_success(mock_openai):
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value.choices = [
        MagicMock(message=MagicMock(content="```json\n{}\n```"))
    ]
    mock_openai.return_value = mock_client

    result = get_mitigations("fake_key", prompt="test")
    assert isinstance(result, str)
    assert "```json" in result
    assert "{}" in result

@patch('mitigations.handle_exception')
@patch('mitigations.OpenAI')
def test_get_mitigations_api_error(mock_openai, mock_handle_exception):
    """Test that API errors are handled by error_handler."""
    mock_openai.return_value.chat.completions.create.side_effect = Exception("API Error")
    get_mitigations("test_api_key", prompt="test prompt")
    mock_handle_exception.assert_called_once() 