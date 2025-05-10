"""Tests for step2_technology.py"""

from unittest.mock import patch

from tabs.step2_technology import render, validate_required_fields, validate_version_format


def test_validate_required_fields_all_empty():
    """Test when all fields are empty"""
    errors = validate_required_fields("", "", "", "", "")
    assert len(errors) == 5
    assert "Please select an application type." in errors
    assert "Please select an industry sector." in errors
    assert "Please select a data sensitivity level." in errors
    assert "Please indicate if the application is internet-facing." in errors
    assert "Please select the number of employees." in errors

def test_validate_required_fields_all_filled():
    """Test when all fields are filled"""
    errors = validate_required_fields(
        "Web application",
        "Financial",
        "High",
        "Yes",
        "0-10"
    )
    assert len(errors) == 0

def test_validate_required_fields_partial():
    """Test when some fields are filled and others are empty"""
    errors = validate_required_fields(
        "Web application",
        "Financial",
        "",
        "",
        "0-10"
    )
    assert len(errors) == 2
    assert "Please select a data sensitivity level." in errors
    assert "Please indicate if the application is internet-facing." in errors

def test_validate_version_format_valid():
    """Test valid version formats"""
    # Test standard version format
    is_valid, message = validate_version_format("1.2.3")
    assert is_valid is True
    assert message == ""

    # Test version with wildcard
    is_valid, message = validate_version_format("1.2.*")
    assert is_valid is True
    assert message == ""

    # Test empty version (which is allowed)
    is_valid, message = validate_version_format("")
    assert is_valid is True
    assert message == ""

def test_validate_version_format_invalid():
    """Test invalid version formats"""
    # Test invalid characters
    is_valid, message = validate_version_format("1.2.abc")
    assert is_valid is False
    assert "Version should be in format" in message

    # Test too many segments
    is_valid, message = validate_version_format("1.2.3.4.5")
    assert is_valid is False
    assert "Version should not have more than 4 segments" in message

def test_validate_version_format_special():
    """Test special version formats"""
    # Test version with multiple wildcards
    is_valid, message = validate_version_format("1.*.*")
    assert is_valid is True
    assert message == ""

    # Test version with maximum allowed segments
    is_valid, message = validate_version_format("1.2.3.4")
    assert is_valid is True
    assert message == ""

@patch('streamlit.warning')
@patch('streamlit.session_state', {'step1_completed': False})
def test_render_step1_not_completed(mock_warning):
    """Test render function when step 1 is not completed"""
    render()
    mock_warning.assert_called_once()

@patch('streamlit.session_state', {
    'step1_completed': True,
    'selected_technologies': {},
    'selected_versions': {},
    'app_input': 'test input'
})
@patch('streamlit.selectbox')
@patch('streamlit.multiselect')
@patch('streamlit.button')
def test_render_basic_functionality(mock_button, mock_multiselect, mock_selectbox):
    """Test basic render functionality with mocked Streamlit components"""
    # Mock the selectbox returns
    mock_selectbox.side_effect = [
        "Web application",  # app_type
        "Financial",        # industry_sector
        "High",            # sensitive_data
        "Yes",             # internet_facing
        "0-10",           # num_employees
        "Medium"          # technical_ability
    ]
    
    # Mock the multiselect returns
    mock_multiselect.return_value = []
    
    # Mock the button click
    mock_button.return_value = True
    
    render() 