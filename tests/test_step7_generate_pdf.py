from unittest.mock import mock_open, patch

import pytest

from tabs.step7_generate_pdf import render

# Mock data for session state
MOCK_DATA = {
    'markdown': """
    # Test Header
    This is a test paragraph with **bold** and *italic* text.
    """,
    'app_details': {
        'app_type': 'Web Application',
        'industry_sector': 'Technology',
        'sensitive_data': 'Yes',
        'internet_facing': 'Yes',
        'num_employees': '100-500',
        'compliance_requirements': 'GDPR',
        'technical_ability': 'Advanced',
        'authentication': 'OAuth2',
        'selected_technologies': ['Python', 'Streamlit'],
        'selected_versions': ['3.9', '1.0']
    },
    'threat_model': [
        {
            "Threat Type": "SQL Injection",
            "Scenario": "An attacker exploits weak input validation",
            "Assumptions": [
                {
                    "Assumption": "No input validation",
                    "Role": "Developer",
                    "Condition": "Missing"
                }
            ],
            "Potential Impact": "Data breach"
        }
    ]
}

@pytest.fixture
def mock_session_state():
    """Mock session state with all required data"""
    with patch("streamlit.session_state", new_callable=dict) as mock_state:
        mock_state.update({
            'step6_completed': True,
            'session_test_cases_markdown': MOCK_DATA['markdown'],
            'session_dread_assessment_markdown': MOCK_DATA['markdown'],
            'session_mitigations_markdown': MOCK_DATA['markdown'],
            'session_threat_model_json': MOCK_DATA['threat_model'],
            'mitre_attack_markdown': MOCK_DATA['markdown'],
            'attack_tree_code': "digraph G { A -> B }",
            'app_details': MOCK_DATA['app_details'],
            'app_input': MOCK_DATA['markdown'],
            'improvement_suggestions_json': ["Suggestion 1", "Suggestion 2"]
        })
        yield mock_state

@patch('streamlit.warning')
@patch('streamlit.markdown')
@patch('streamlit.button')
@patch('streamlit.download_button')
@patch('builtins.open', new_callable=mock_open, read_data=b'fake_image_data')
@patch('streamlit.spinner')
def test_render_complete(mock_spinner, mock_file, mock_download, mock_button, mock_markdown, mock_warning, mock_session_state):
    """Test render function when all steps are complete"""
    # Setup
    mock_button.return_value = True
    mock_download.return_value = True
    mock_spinner.return_value.__enter__.return_value = None
    mock_spinner.return_value.__exit__.return_value = None
    
    # Execute
    render()
    
    # Verify
    mock_warning.assert_not_called()
    mock_markdown.assert_called()
    mock_button.assert_called()
    mock_download.assert_called()
    mock_file.assert_called_with("aegisshield-bw.png", "rb")

@patch('streamlit.warning')
@patch('streamlit.markdown')
@patch('streamlit.button')
@patch('streamlit.download_button')
def test_render_incomplete(mock_download, mock_button, mock_markdown, mock_warning):
    """Test render function when steps are incomplete"""
    # Setup
    with patch("streamlit.session_state", new_callable=dict) as mock_state:
        mock_state['step6_completed'] = False
        
        # Execute
        render()
        
        # Verify
        mock_warning.assert_called_once()
        mock_markdown.assert_not_called()
        mock_button.assert_not_called()
        mock_download.assert_not_called() 