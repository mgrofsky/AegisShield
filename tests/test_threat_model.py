import pytest
from unittest.mock import patch, MagicMock, call
import json
from requests.exceptions import RequestException, HTTPError
from openai import AuthenticationError, APIError
from threat_model import (
    retry_with_backoff,
    json_to_markdown,
    get_image_analysis,
    get_threat_model,
    create_threat_model_prompt,
    create_image_analysis_prompt,
    ThreatModelAPIError
)

# Mock data for tests
SYSTEM_MESSAGE = "You are a cybersecurity expert specializing in threat modeling using the STRIDE methodology."

MOCK_THREAT_MODEL = [{
    "Scenario": "Test Scenario 1",
    "MITRE ATT&CK Keywords": ["spoof", "credentials"],
    "Potential Impact": "High impact on system",
    "Assumptions": [
        {"Role": "User", "Condition": "Logged In", "Assumption": "Test Assumption 1"},
        {"Role": "Admin", "Condition": "Has Privileges", "Assumption": "Test Assumption 2"}
    ]
}]

MOCK_IMPROVEMENTS = [
    "Add more details about authentication",
    "Specify data storage methods"
]

def test_threat_model_api_error():
    """Test ThreatModelAPIError creation"""
    error = ThreatModelAPIError("Test error")
    assert str(error) == "Test error"

def test_json_to_markdown():
    """Test JSON to markdown conversion"""
    result = json_to_markdown(MOCK_THREAT_MODEL, MOCK_IMPROVEMENTS)
    assert "Test Scenario 1" in result
    assert "Test Assumption 1" in result
    assert "Add more details about authentication" in result

def test_json_to_markdown_empty():
    """Test JSON to markdown with empty data"""
    result = json_to_markdown([], [])
    assert result != ""

def test_json_to_markdown_missing_fields():
    """Test JSON to markdown with missing fields"""
    result = json_to_markdown([{}], [])
    assert result != ""

def test_create_threat_model_prompt():
    """Test threat model prompt creation"""
    result = create_threat_model_prompt(
        "Test app",
        "OAuth2",
        "Yes",
        "Technology",
        "PII",
        "Test description",
        "CVE-2021-1234",
        "OTX data",
        "High"
    )
    assert "Test app" in result
    assert "OAuth2" in result

def test_create_image_analysis_prompt():
    """Test image analysis prompt creation"""
    result = create_image_analysis_prompt()
    assert "Senior Solution Architect" in result
    assert "Security Architect" in result

@patch('requests.post')
def test_get_image_analysis_success(mock_post):
    """Test successful image analysis"""
    # Mock response object
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "choices": [{"message": {"content": "Test analysis"}}]
    }
    mock_response.raise_for_status = MagicMock()
    mock_post.return_value = mock_response

    result = get_image_analysis(
        api_key="test-key",
        model_name="gpt-4",
        prompt="Test prompt",
        base64_image="test_image_data"
    )

    assert result == mock_response.json.return_value
    mock_post.assert_called_once()

@patch('requests.post')
def test_get_image_analysis_failure(mock_post):
    """Test failed image analysis"""
    # Create mock response and error
    mock_response = MagicMock()
    mock_response.raise_for_status.side_effect = HTTPError("401 Client Error: Unauthorized")
    mock_post.return_value = mock_response

    result = get_image_analysis(
        api_key="test-key",
        model_name="gpt-4",
        prompt="Test prompt",
        base64_image="test_image_data"
    )

    assert result is None
    mock_post.assert_called_once() 