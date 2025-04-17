"""Tests for the MITRE ATT&CK module."""

import pytest
from unittest.mock import patch, mock_open, MagicMock
from openai import AuthenticationError
from mitre_attack import (
    fetch_mitre_attack_data,
    map_attack_pattern_to_technique,
    process_mitre_attack_data,
    create_mitre_prompt,
    get_relevant_techniques,
    MOBILE_APP_TYPES,
    ENTERPRISE_APP_TYPES,
    ICS_APP_TYPES
)

def test_fetch_enterprise_data():
    """Test fetching enterprise attack data."""
    mock_data = '{"objects": [{"type": "attack-pattern"}]}'
    
    with patch('builtins.open', mock_open(read_data=mock_data)):
        result = fetch_mitre_attack_data("Web application")
        assert result is not None
        assert "objects" in result
        assert len(result["objects"]) == 1

def test_fetch_mobile_data():
    """Test fetching mobile attack data."""
    mock_enterprise = '{"objects": [{"id": "enterprise"}]}'
    mock_mobile = '{"objects": [{"id": "mobile"}]}'
    
    mock_files = {
        "./MITRE_ATTACK_DATA/enterprise-attack.json": mock_enterprise,
        "./MITRE_ATTACK_DATA/mobile-attack.json": mock_mobile
    }
    
    def mock_open_files(filename, *args, **kwargs):
        return mock_open(read_data=mock_files[filename])()
    
    with patch('builtins.open', side_effect=mock_open_files):
        result = fetch_mitre_attack_data("Mobile application")
        assert result is not None
        assert "objects" in result
        assert len(result["objects"]) == 2  # Combined data

def test_fetch_ics_data():
    """Test fetching ICS attack data."""
    mock_enterprise = '{"objects": [{"id": "enterprise"}]}'
    mock_ics = '{"objects": [{"id": "ics"}]}'
    
    mock_files = {
        "./MITRE_ATTACK_DATA/enterprise-attack.json": mock_enterprise,
        "./MITRE_ATTACK_DATA/ics-attack.json": mock_ics
    }
    
    def mock_open_files(filename, *args, **kwargs):
        return mock_open(read_data=mock_files[filename])()
    
    with patch('builtins.open', side_effect=mock_open_files):
        result = fetch_mitre_attack_data("ICS or SCADA System")
        assert result is not None
        assert "objects" in result
        assert len(result["objects"]) == 2  # Combined data

def test_fetch_data_file_not_found():
    """Test handling of missing data file."""
    with patch('builtins.open', side_effect=FileNotFoundError), \
         patch('mitre_attack.handle_exception') as mock_handle:
        result = fetch_mitre_attack_data("Web application")
        assert result is None
        mock_handle.assert_called_once()

def test_fetch_data_json_error():
    """Test handling of invalid JSON data."""
    with patch('builtins.open', mock_open(read_data='invalid json')), \
         patch('mitre_attack.handle_exception') as mock_handle:
        result = fetch_mitre_attack_data("Web application")
        assert result is None
        mock_handle.assert_called_once()

def test_map_attack_pattern_to_technique():
    """Test mapping attack patterns to MITRE techniques."""
    stix_data = {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1234"
                    }
                ]
            }
        ]
    }
    
    result = map_attack_pattern_to_technique(stix_data)
    assert result == {"attack-pattern--1": "T1234"}

def test_map_attack_pattern_to_technique_no_references():
    """Test mapping attack patterns with no external references."""
    stix_data = {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "external_references": []
            }
        ]
    }
    
    result = map_attack_pattern_to_technique(stix_data)
    assert result == {}

def test_map_attack_pattern_to_technique_invalid_data():
    """Test mapping attack patterns with invalid data structure."""
    stix_data = {}
    result = map_attack_pattern_to_technique(stix_data)
    assert result == {}

def test_process_mitre_attack_data():
    """Test processing MITRE ATT&CK data with a threat model."""
    stix_data = {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Test Attack",
                "description": "test attack description",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1234"
                    }
                ]
            }
        ]
    }
    
    threat_model = [
        {
            "MITRE ATT&CK Keywords": ["test attack"],
            "Threat": "Test Threat"
        }
    ]
    
    app_details = {"name": "Test App", "industry_sector": "Test Sector", "app_type": "Web application", "authentication": "None", "internet_facing": "Yes", "sensitive_data": "No", "app_input": "Test app description"}
    
    with patch('mitre_attack.get_relevant_techniques') as mock_get:
        mock_get.return_value = ["attack-pattern--1"]
        result = process_mitre_attack_data(stix_data, threat_model, app_details, "fake_key")
        
        assert len(result) == 1
        assert result[0]["threat"] == threat_model[0]
        assert "mitre_techniques" in result[0]
        assert result[0]["mitre_techniques"][0]["technique_id"] == "T1234"

def test_process_mitre_attack_data_rate_limiting():
    """Test that process_mitre_attack_data respects rate limiting."""
    stix_data = {"objects": []}
    threat_model = [{"MITRE ATT&CK Keywords": ["test"]}]
    app_details = {"name": "Test App", "industry_sector": "Test Sector", "app_type": "Web application", "authentication": "None", "internet_facing": "Yes", "sensitive_data": "No", "app_input": "Test app description"}
    
    with patch('mitre_attack.get_relevant_techniques') as mock_get, \
         patch('time.sleep') as mock_sleep:
        mock_get.return_value = ["attack-pattern--00000000-0000-0000-0000-000000000000"]
        result = process_mitre_attack_data(stix_data, threat_model, app_details, "test_key")
        assert mock_sleep.call_count == 1  # Should sleep between requests

def test_process_mitre_attack_data_keyword_matching():
    """Test that process_mitre_attack_data correctly matches keywords to techniques."""
    stix_data = {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Test Attack",
                "description": "test attack description",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1234"
                    }
                ]
            }
        ]
    }
    
    threat_model = [
        {
            "MITRE ATT&CK Keywords": ["test attack"],
            "Threat": "Test Threat"
        }
    ]
    
    app_details = {"name": "Test App", "industry_sector": "Test Sector", "app_type": "Web application", "authentication": "None", "internet_facing": "Yes", "sensitive_data": "No", "app_input": "Test app description"}
    
    with patch('mitre_attack.get_relevant_techniques') as mock_get, \
         patch('time.sleep'):
        mock_get.return_value = ["attack-pattern--1"]
        result = process_mitre_attack_data(stix_data, threat_model, app_details, "test_key")
        assert len(result) == 1
        assert result[0]["threat"] == threat_model[0]
        assert len(result[0]["mitre_techniques"]) == 1
        assert result[0]["mitre_techniques"][0]["id"] == "attack-pattern--1"
        assert result[0]["mitre_techniques"][0]["technique_id"] == "T1234"

def test_create_mitre_prompt():
    """Test creation of MITRE ATT&CK prompt."""
    app_details = {
        "app_type": "Web application",
        "industry_sector": "Financial",
        "sensitive_data": "High",
        "internet_facing": "Yes",
        "authentication": "OAUTH2",
        "app_input": "This is a financial web application that handles sensitive user data and transactions."
    }
    
    threat = {
        "Scenario": "SQL Injection Attack",
        "MITRE ATT&CK Keywords": ["injection", "database"],
        "Potential Impact": "Data breach"
    }
    
    techniques = [
        {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program..."
        }
    ]
    
    prompt = create_mitre_prompt(app_details, threat, techniques)
    
    # Verify the prompt contains key information
    assert "Web application" in prompt
    assert "Financial" in prompt
    assert "SQL Injection Attack" in prompt
    assert "T1190" in prompt
    assert "Exploit Public-Facing Application" in prompt
    assert "injection" in prompt
    assert "database" in prompt

def test_create_mitre_prompt_missing_fields():
    """Test MITRE ATT&CK prompt creation with missing fields."""
    app_details = {
        "app_type": "Web application",
        "industry_sector": "Financial",
        "authentication": "None",
        "internet_facing": "Yes",
        "sensitive_data": "No",
        "app_input": "Test app description"
    }

    threat = {
        "Scenario": "SQL Injection Attack"
    }

    techniques = [
        {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "description": "Test description"
        }
    ]

    prompt = create_mitre_prompt(app_details, threat, techniques)
    assert "Financial" in prompt
    assert "Web application" in prompt
    assert "SQL Injection Attack" in prompt
    assert "T1190" in prompt

def test_process_mitre_attack_data_invalid_stix():
    """Test processing MITRE ATT&CK data with invalid STIX data."""
    with patch('mitre_attack.handle_exception') as mock_handle:
        result = process_mitre_attack_data({}, [], {}, "fake_key")
        assert result == []
        mock_handle.assert_called_once()

def test_process_mitre_attack_data_no_app_details():
    """Test processing MITRE ATT&CK data without app details."""
    stix_data = {"objects": []}
    threat_model = [{"MITRE ATT&CK Keywords": ["test"]}]
    
    with patch('mitre_attack.handle_exception') as mock_handle:
        result = process_mitre_attack_data(stix_data, threat_model, None, "fake_key")
        assert result == []
        mock_handle.assert_called_once()

def test_process_mitre_attack_data_openai_error():
    """Test processing MITRE ATT&CK data when OpenAI API fails."""
    stix_data = {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Test Attack",
                "description": "test attack description",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1234"
                    }
                ]
            }
        ]
    }
    
    threat_model = [
        {
            "MITRE ATT&CK Keywords": ["test attack"],
            "Threat": "Test Threat"
        }
    ]
    
    app_details = {"name": "Test App"}
    
    with patch('mitre_attack.get_relevant_techniques', side_effect=Exception("OpenAI API Error")), \
         patch('mitre_attack.handle_exception') as mock_handle:
        result = process_mitre_attack_data(stix_data, threat_model, app_details, "fake_key")
        assert len(result) == 1
        assert result[0]["threat"] == threat_model[0]
        assert result[0]["mitre_techniques"] == []
        mock_handle.assert_called_once()

def test_get_relevant_techniques_success():
    """Test successful technique selection using OpenAI."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(content='["attack-pattern--1"]'))]
    
    with patch('openai.OpenAI') as mock_openai:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client
        
        # Mock the actual API call to avoid authentication errors
        with patch('mitre_attack.OpenAI') as mock_openai_class:
            mock_openai_class.return_value = mock_client
            result = get_relevant_techniques("test prompt", "fake_key")
            assert result == ["attack-pattern--1"]
            mock_client.chat.completions.create.assert_called_once()

def test_get_relevant_techniques_invalid_response():
    """Test handling of invalid OpenAI response."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(content='{"invalid": "json"}'))]
    
    with patch('mitre_attack.OpenAI') as mock_openai:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client
        
        result = get_relevant_techniques("test prompt", "fake_key")
        assert result == []

def test_get_relevant_techniques_api_error():
    """Test handling of OpenAI API errors."""
    with patch('mitre_attack.OpenAI') as mock_openai, \
         patch('mitre_attack.handle_exception') as mock_handle:
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("API Error")
        mock_openai.return_value = mock_client
        
        with pytest.raises(Exception, match="API Error"):
            get_relevant_techniques("test prompt", "fake_key")

def test_process_mitre_attack_data_no_keywords():
    """Test processing MITRE ATT&CK data with a threat that has no keywords."""
    stix_data = {"objects": []}
    threat_model = [{"Threat": "Test Threat"}]  # No MITRE ATT&CK Keywords
    app_details = {"name": "Test App", "industry_sector": "Test Sector", "app_type": "Web application", "authentication": "None", "internet_facing": "Yes", "sensitive_data": "No", "app_input": "Test app description"}
    
    result = process_mitre_attack_data(stix_data, threat_model, app_details, "fake_key")
    assert len(result) == 1
    assert result[0]["threat"] == threat_model[0]
    assert result[0]["mitre_techniques"] == []

def test_get_relevant_techniques_empty_list():
    """Test handling of empty list response from OpenAI."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(content='[]'))]
    
    with patch('mitre_attack.OpenAI') as mock_openai:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client
        
        result = get_relevant_techniques("test prompt", "fake_key")
        assert result == ["attack-pattern--00000000-0000-0000-0000-000000000000"]

def test_get_relevant_techniques_multiple_ids():
    """Test handling of multiple IDs in OpenAI response."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(content='["id1", "id2"]'))]
    
    with patch('mitre_attack.OpenAI') as mock_openai:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client
        
        result = get_relevant_techniques("test prompt", "fake_key")
        assert result == []

def test_get_relevant_techniques_non_list():
    """Test handling of non-list response from OpenAI."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(content='"single_id"'))]
    
    with patch('mitre_attack.OpenAI') as mock_openai:
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client
        
        result = get_relevant_techniques("test prompt", "fake_key")
        assert result == []

def test_fetch_unknown_app_type():
    """Test fetching data for unknown app type."""
    mock_data = '{"objects": [{"type": "attack-pattern"}]}'
    
    with patch('builtins.open', mock_open(read_data=mock_data)):
        result = fetch_mitre_attack_data("Unknown Type")
        assert result is not None
        assert "objects" in result
        assert len(result["objects"]) == 1

def test_process_mitre_attack_data_exception():
    """Test handling of general exception in process_mitre_attack_data."""
    stix_data = {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Test Attack",
                "description": "test attack description"
            }
        ]
    }
    threat_model = [{"MITRE ATT&CK Keywords": ["test"]}]
    app_details = {"name": "Test App", "industry_sector": "Test Sector", "app_type": "Web application", "authentication": "None", "internet_facing": "Yes", "sensitive_data": "No", "app_input": "Test app description"}
    
    with patch('mitre_attack.map_attack_pattern_to_technique', side_effect=Exception("Test error")), \
         patch('mitre_attack.handle_exception') as mock_handle:
        result = process_mitre_attack_data(stix_data, threat_model, app_details, "fake_key")
        assert result == []
        mock_handle.assert_called_once()

def test_map_attack_pattern_missing_id():
    """Test mapping attack pattern with missing ID."""
    stix_data = {
        "objects": [
            {
                "type": "attack-pattern",
                # Missing ID
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1234"
                    }
                ]
            }
        ]
    }
    result = map_attack_pattern_to_technique(stix_data)
    assert result == {}

def test_map_attack_pattern_missing_external_refs():
    """Test mapping attack pattern with missing external references."""
    stix_data = {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1"
                # Missing external_references
            }
        ]
    }
    result = map_attack_pattern_to_technique(stix_data)
    assert result == {}

def test_map_attack_pattern_wrong_source():
    """Test mapping attack pattern with wrong source name."""
    stix_data = {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "external_references": [
                    {
                        "source_name": "not-mitre",
                        "external_id": "T1234"
                    }
                ]
            }
        ]
    }
    result = map_attack_pattern_to_technique(stix_data)
    assert result == {}

def test_fetch_mitre_attack_data_mobile():
    """Test fetching MITRE ATT&CK data for mobile app type."""
    mock_enterprise = '{"objects": [{"id": "enterprise"}]}'
    mock_mobile = '{"objects": [{"id": "mobile"}]}'
    
    mock_files = {
        "./MITRE_ATTACK_DATA/enterprise-attack.json": mock_enterprise,
        "./MITRE_ATTACK_DATA/mobile-attack.json": mock_mobile
    }
    
    def mock_open_files(filename, *args, **kwargs):
        return mock_open(read_data=mock_files[filename])()
    
    with patch('builtins.open', side_effect=mock_open_files):
        for app_type in MOBILE_APP_TYPES:
            result = fetch_mitre_attack_data(app_type)
            assert result is not None
            assert "objects" in result
            assert len(result["objects"]) == 2  # Combined data

def test_fetch_mitre_attack_data_enterprise():
    """Test fetching MITRE ATT&CK data for enterprise app types."""
    mock_data = '{"objects": [{"type": "attack-pattern"}]}'
    
    with patch('builtins.open', mock_open(read_data=mock_data)):
        for app_type in ENTERPRISE_APP_TYPES:
            result = fetch_mitre_attack_data(app_type)
            assert result is not None
            assert "objects" in result
            assert len(result["objects"]) == 1

def test_fetch_mitre_attack_data_ics():
    """Test fetching MITRE ATT&CK data for ICS app types."""
    mock_enterprise = '{"objects": [{"id": "enterprise"}]}'
    mock_ics = '{"objects": [{"id": "ics"}]}'
    
    mock_files = {
        "./MITRE_ATTACK_DATA/enterprise-attack.json": mock_enterprise,
        "./MITRE_ATTACK_DATA/ics-attack.json": mock_ics
    }
    
    def mock_open_files(filename, *args, **kwargs):
        return mock_open(read_data=mock_files[filename])()
    
    with patch('builtins.open', side_effect=mock_open_files):
        for app_type in ICS_APP_TYPES:
            result = fetch_mitre_attack_data(app_type)
            assert result is not None
            assert "objects" in result
            assert len(result["objects"]) == 2  # Combined data 