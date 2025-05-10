"""Tests for the DREAD assessment module."""

import json
from unittest.mock import MagicMock, patch

import pytest

from dread import create_dread_assessment_prompt, dread_json_to_markdown, get_dread_assessment


def test_dread_json_to_markdown():
    """Test conversion of DREAD assessment JSON to markdown."""
    dread_assessment = {
        "Risk Assessment": [
            {
                "Threat Type": "Spoofing",
                "Scenario": "Test scenario",
                "Damage Potential": 8,
                "Reproducibility": 6,
                "Exploitability": 5,
                "Affected Users": 9,
                "Discoverability": 7
            }
        ]
    }
    markdown = dread_json_to_markdown(dread_assessment)
    assert "| Spoofing | Test scenario | 8 | 6 | 5 | 9 | 7 | 7.00 |" in markdown

def test_dread_json_to_markdown_invalid_threat():
    """Test handling of invalid threat type."""
    dread_assessment = {
        "Risk Assessment": ["invalid"]
    }
    with pytest.raises(TypeError):
        dread_json_to_markdown(dread_assessment)

def test_dread_json_to_markdown_missing_values():
    """Test handling of missing values in threat assessment."""
    dread_assessment = {
        "Risk Assessment": [
            {
                "Threat Type": "Spoofing",
                "Scenario": "Test scenario"
            }
        ]
    }
    markdown = dread_json_to_markdown(dread_assessment)
    assert "| Spoofing | Test scenario | 0 | 0 | 0 | 0 | 0 | 0.00 |" in markdown

def test_dread_json_to_markdown_multiple_threats():
    """Test conversion of multiple threats to markdown."""
    dread_assessment = {
        "Risk Assessment": [
            {
                "Threat Type": "Spoofing",
                "Scenario": "Test scenario 1",
                "Damage Potential": 8,
                "Reproducibility": 6,
                "Exploitability": 5,
                "Affected Users": 9,
                "Discoverability": 7
            },
            {
                "Threat Type": "Tampering",
                "Scenario": "Test scenario 2",
                "Damage Potential": 7,
                "Reproducibility": 5,
                "Exploitability": 6,
                "Affected Users": 8,
                "Discoverability": 6
            }
        ]
    }
    markdown = dread_json_to_markdown(dread_assessment)
    assert "| Spoofing | Test scenario 1 | 8 | 6 | 5 | 9 | 7 | 7.00 |" in markdown
    assert "| Tampering | Test scenario 2 | 7 | 5 | 6 | 8 | 6 | 6.40 |" in markdown

def test_dread_json_to_markdown_empty_threats():
    """Test handling of empty threat list."""
    dread_assessment = {
        "Risk Assessment": []
    }
    markdown = dread_json_to_markdown(dread_assessment)
    assert "| Threat Type | Scenario | Damage Potential |" in markdown
    assert "|-------------|----------|------------------|" in markdown

def test_dread_json_to_markdown_missing_risk_assessment():
    """Test handling of missing Risk Assessment key."""
    dread_assessment = {}
    markdown = dread_json_to_markdown(dread_assessment)
    # Should handle missing key gracefully by using get() with default empty list
    assert "| Threat Type | Scenario | Damage Potential |" in markdown
    assert "|-------------|----------|------------------|" in markdown

def test_dread_json_to_markdown_edge_cases():
    """Test edge cases for risk score calculation."""
    dread_assessment = {
        "Risk Assessment": [
            {
                "Threat Type": "Spoofing",
                "Scenario": "All zeros",
                "Damage Potential": 0,
                "Reproducibility": 0,
                "Exploitability": 0,
                "Affected Users": 0,
                "Discoverability": 0
            },
            {
                "Threat Type": "Tampering",
                "Scenario": "All tens",
                "Damage Potential": 10,
                "Reproducibility": 10,
                "Exploitability": 10,
                "Affected Users": 10,
                "Discoverability": 10
            }
        ]
    }
    markdown = dread_json_to_markdown(dread_assessment)
    assert "| Spoofing | All zeros | 0 | 0 | 0 | 0 | 0 | 0.00 |" in markdown
    assert "| Tampering | All tens | 10 | 10 | 10 | 10 | 10 | 10.00 |" in markdown

def test_create_dread_assessment_prompt():
    """Test creation of DREAD assessment prompt."""
    threats = "Test threats"
    mitre_mapping = "Test MITRE mapping"
    nvd_vulnerabilities = "Test NVD vulnerabilities"
    prompt = create_dread_assessment_prompt(threats, mitre_mapping, nvd_vulnerabilities)
    assert "Test threats" in prompt
    assert "Test MITRE mapping" in prompt
    assert "Test NVD vulnerabilities" in prompt
    assert "Risk Assessment" in prompt

def test_create_dread_assessment_prompt_empty_inputs():
    """Test handling of empty inputs."""
    prompt = create_dread_assessment_prompt("", "", "")
    assert "Below is the list of identified threats" in prompt
    assert "Below is how they map to the MITRE ATT&CK framework" in prompt
    assert "Below are potential vulnerabilities" in prompt

def test_create_dread_assessment_prompt_special_characters():
    """Test handling of special characters in inputs."""
    threats = "Test & < > ' \" threats"
    mitre_mapping = "Test & < > ' \" MITRE mapping"
    nvd_vulnerabilities = "Test & < > ' \" NVD vulnerabilities"
    prompt = create_dread_assessment_prompt(threats, mitre_mapping, nvd_vulnerabilities)
    assert threats in prompt
    assert mitre_mapping in prompt
    assert nvd_vulnerabilities in prompt

@patch('dread.OpenAI')
@patch('dread.handle_exception')
def test_get_dread_assessment_missing_api_key(mock_handle_exception, mock_openai):
    """Test handling of missing API key."""
    mock_openai.side_effect = Exception("Should not create client")
    
    result = get_dread_assessment("", "test-model", "test-prompt")
    assert mock_handle_exception.call_count == 2
    
    # First call should be for missing API key
    first_call = mock_handle_exception.call_args_list[0]
    assert isinstance(first_call[0][0], ValueError)
    assert str(first_call[0][0]) == "OpenAI API key is required"
    assert first_call[0][1] == "OpenAI API key is required"
    
    # Second call should be for OpenAI client error
    second_call = mock_handle_exception.call_args_list[1]
    assert isinstance(second_call[0][0], Exception)
    assert str(second_call[0][0]) == "Should not create client"
    assert second_call[0][1] == "Failed to generate DREAD assessment"
    
    assert result is None

@patch('dread.OpenAI')
@patch('dread.handle_exception')
def test_get_dread_assessment_missing_prompt(mock_handle_exception, mock_openai):
    """Test handling of missing prompt."""
    mock_openai.side_effect = Exception("Should not create client")
    
    result = get_dread_assessment("test-api-key", "test-model", "")
    assert mock_handle_exception.call_count == 2
    
    # First call should be for missing prompt
    first_call = mock_handle_exception.call_args_list[0]
    assert isinstance(first_call[0][0], ValueError)
    assert str(first_call[0][0]) == "Prompt is required for DREAD assessment generation"
    assert first_call[0][1] == "Prompt is required for DREAD assessment generation"
    
    # Second call should be for OpenAI client error
    second_call = mock_handle_exception.call_args_list[1]
    assert isinstance(second_call[0][0], Exception)
    assert str(second_call[0][0]) == "Should not create client"
    assert second_call[0][1] == "Failed to generate DREAD assessment"
    
    assert result is None

@patch('dread.OpenAI')
@patch('dread.handle_exception')
def test_get_dread_assessment_json_error(mock_handle_exception, mock_openai):
    """Test handling of JSON parsing error."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "invalid json"
    mock_openai.return_value.chat.completions.create.return_value = mock_response
    
    result = get_dread_assessment("test-api-key", "test-model", "test-prompt")
    assert mock_handle_exception.call_count == 1
    assert isinstance(mock_handle_exception.call_args[0][0], json.JSONDecodeError)
    assert result is None

@patch('dread.OpenAI')
@patch('dread.handle_exception')
def test_get_dread_assessment_api_error(mock_handle_exception, mock_openai):
    """Test handling of API error."""
    mock_openai.return_value.chat.completions.create.side_effect = Exception("API Error")
    
    result = get_dread_assessment("test-api-key", "test-model", "test-prompt")
    assert mock_handle_exception.call_count == 1
    mock_handle_exception.assert_called_with(
        mock_openai.return_value.chat.completions.create.side_effect,
        "Failed to generate DREAD assessment"
    )
    assert result is None

@patch('dread.OpenAI')
def test_get_dread_assessment_success(mock_openai):
    """Test successful API call with valid response."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = json.dumps({
        "Risk Assessment": [{
            "Threat Type": "Spoofing",
            "Scenario": "Test scenario",
            "Damage Potential": 8,
            "Reproducibility": 6,
            "Exploitability": 5,
            "Affected Users": 9,
            "Discoverability": 7
        }]
    })
    mock_openai.return_value.chat.completions.create.return_value = mock_response
    
    result = get_dread_assessment("test-api-key", "test-model", "test-prompt")
    assert result is not None
    assert "Risk Assessment" in result
    assert len(result["Risk Assessment"]) == 1

@patch('dread.OpenAI')
def test_get_dread_assessment_default_model(mock_openai):
    """Test using default model name."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = json.dumps({"Risk Assessment": []})
    mock_openai.return_value.chat.completions.create.return_value = mock_response
    
    result = get_dread_assessment("test-api-key", None, "test-prompt")
    assert result is not None
    mock_openai.return_value.chat.completions.create.assert_called_once()

@patch('dread.OpenAI')
@patch('dread.handle_exception')
def test_get_dread_assessment_empty_response(mock_handle_exception, mock_openai):
    """Test handling of empty response from API."""
    mock_response = MagicMock()
    mock_response.choices = []
    mock_openai.return_value.chat.completions.create.return_value = mock_response
    
    result = get_dread_assessment("test-api-key", "test-model", "test-prompt")
    assert mock_handle_exception.call_count == 1
    assert result is None

@patch('dread.OpenAI')
@patch('dread.handle_exception')
def test_get_dread_assessment_malformed_json(mock_handle_exception, mock_openai):
    """Test handling of malformed JSON response."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "not a json"
    mock_openai.return_value.chat.completions.create.return_value = mock_response
    
    result = get_dread_assessment("test-api-key", "test-model", "test-prompt")
    assert mock_handle_exception.call_count == 1
    assert isinstance(mock_handle_exception.call_args[0][0], json.JSONDecodeError)
    assert result is None 