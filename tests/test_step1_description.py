import base64
from unittest.mock import MagicMock, patch

import pytest

from tabs.step1_description import analyze_image, render, validate_description, validate_image

# Mock data
MOCK_IMAGE_CONTENT = b"test image content"
MOCK_IMAGE_BASE64 = base64.b64encode(MOCK_IMAGE_CONTENT).decode('utf-8')

MOCK_IMAGE_ANALYSIS_OUTPUT = {
    'choices': [
        {
            'message': {
                'content': 'This is a test analysis of the architecture diagram.'
            }
        }
    ]
}

# Mock UI_TEXT dictionary
MOCK_UI_TEXT = {
    'title': "Step 1: Application Description",
    'subtitle': "Provide a detailed description of your application",
    'description': "Start by describing your application.",
    'image_upload': "Upload an image of your application (optional)",
    'image_analysis': "Analyzing image...",
    'image_error': "Error analyzing image. Please try again.",
    'image_size_error': "Image must be less than 10MB",
    'image_type_error': "Image must be PNG, JPEG, or JPG",
    'image_upload_error': "OpenAI API key is required for image analysis",
    'image_analysis_spinner': "Analyzing image...",
    'image_analysis_error': "Error analyzing image. Please try again.",
    'text_area_error': "Description must be at least 50 characters",
    'description_label': "Application Description",
    'description_placeholder': "Enter a detailed description...",
    'description_help': "Include information about the application.",
    'next_button': "Next",
    'success_message': "Description saved successfully!",
    'error_message': "Please provide a description.",
    'char_count': "Characters: {}/1000",
    'example_title': "Example Description",
    'example_subtitle': "Here's an example:",
    'example_tooltip': "Example tooltip"
}

@pytest.fixture
def mock_uploaded_file():
    file = MagicMock()
    file.size = 1024 * 1024  # 1MB
    file.type = "image/png"
    file.name = "test.png"
    file.read.return_value = MOCK_IMAGE_CONTENT
    return file

@pytest.fixture
def mock_session_state():
    class SessionState(dict):
        def __getattr__(self, key):
            return self.get(key)
        
        def __setattr__(self, key, value):
            self[key] = value
    
    session_state = SessionState({
        'app_input': "",
        'step1_completed': False,
        'uploaded_file': None,
        'image_analysis_content': None,
        'last_analyzed_file': None
    })
    
    with patch('streamlit.session_state', session_state):
        yield session_state

@pytest.fixture
def mock_streamlit():
    return {
        'button': MagicMock(),
        'caption': MagicMock(),
        'col1': MagicMock(),
        'col2': MagicMock(),
        'columns': MagicMock(return_value=(MagicMock(), MagicMock())),
        'container': MagicMock(),
        'error': MagicMock(),
        'file_uploader': MagicMock(),
        'form': MagicMock(),
        'form_submit_button': MagicMock(),
        'image': MagicMock(),
        'info': MagicMock(),
        'markdown': MagicMock(),
        'spinner': MagicMock(),
        'success': MagicMock(),
        'text_area': MagicMock(),
        'warning': MagicMock()
    }

@patch('tabs.step1_description.UI_TEXT', MOCK_UI_TEXT)
def test_validate_image_success(mock_uploaded_file):
    is_valid, error = validate_image(mock_uploaded_file)
    assert is_valid is True
    assert error is None

@patch('tabs.step1_description.UI_TEXT', MOCK_UI_TEXT)
def test_validate_image_size_error():
    file = MagicMock()
    file.size = 11 * 1024 * 1024  # 11MB
    file.type = "image/png"
    
    is_valid, error = validate_image(file)
    assert is_valid is False
    assert error == MOCK_UI_TEXT['image_size_error']

@patch('tabs.step1_description.UI_TEXT', MOCK_UI_TEXT)
def test_validate_image_type_error():
    file = MagicMock()
    file.size = 1024 * 1024  # 1MB
    file.type = "image/gif"
    
    is_valid, error = validate_image(file)
    assert is_valid is False
    assert error == MOCK_UI_TEXT['image_type_error']

@patch('tabs.step1_description.UI_TEXT', MOCK_UI_TEXT)
def test_analyze_image_success(mock_uploaded_file):
    with patch('tabs.step1_description.get_image_analysis') as mock_get_analysis:
        mock_get_analysis.return_value = MOCK_IMAGE_ANALYSIS_OUTPUT
        
        result = analyze_image(mock_uploaded_file, "test-key", "gpt-4o")
        
        assert result == MOCK_IMAGE_ANALYSIS_OUTPUT['choices'][0]['message']['content']
        mock_get_analysis.assert_called_once()

@patch('tabs.step1_description.UI_TEXT', MOCK_UI_TEXT)
def test_analyze_image_invalid_file():
    file = MagicMock()
    file.size = 11 * 1024 * 1024  # 11MB
    file.type = "image/png"
    
    result = analyze_image(file, "test-key", "gpt-4o")
    assert result is None

@patch('tabs.step1_description.UI_TEXT', MOCK_UI_TEXT)
def test_analyze_image_api_error(mock_uploaded_file):
    with patch('tabs.step1_description.get_image_analysis') as mock_get_analysis, \
         patch('tabs.step1_description.handle_exception') as mock_handle_error:
        mock_get_analysis.side_effect = Exception("API Error")
        
        result = analyze_image(mock_uploaded_file, "test-key", "gpt-4o")
        
        assert result is None
        mock_handle_error.assert_called_once()

@patch('tabs.step1_description.UI_TEXT', MOCK_UI_TEXT)
def test_validate_description_success():
    description = "This is a valid description that is longer than fifty characters to meet the minimum requirement."
    is_valid, error = validate_description(description)
    assert is_valid is True
    assert error is None

@patch('tabs.step1_description.UI_TEXT', MOCK_UI_TEXT)
def test_validate_description_empty():
    description = ""
    is_valid, error = validate_description(description)
    assert is_valid is False
    assert error == MOCK_UI_TEXT['text_area_error']

@patch('tabs.step1_description.UI_TEXT', MOCK_UI_TEXT)
def test_validate_description_too_short():
    description = "Too short"
    is_valid, error = validate_description(description)
    assert is_valid is False
    assert error == MOCK_UI_TEXT['text_area_error']

@patch('tabs.step1_description.UI_TEXT', MOCK_UI_TEXT)
def test_render_complete(mock_session_state, mock_streamlit):
    with patch('tabs.step1_description.analyze_image') as mock_analyze, \
         patch('tabs.step1_description.validate_description') as mock_validate, \
         patch('streamlit.form') as mock_form, \
         patch('streamlit.form_submit_button') as mock_submit:
        mock_analyze.return_value = "Test analysis"
        mock_validate.return_value = (True, None)
        mock_streamlit['file_uploader'].return_value = None  # No file uploaded
        mock_streamlit['text_area'].return_value = "Valid description text that meets the minimum length requirement"

        # Mock form and form submit button
        mock_form_instance = MagicMock()
        mock_form_instance.__enter__ = MagicMock(return_value=mock_form_instance)
        mock_form_instance.__exit__ = MagicMock()
        mock_form.return_value = mock_form_instance
        mock_submit.return_value = True  # Form is submitted

        render("OpenAI API", "gpt-4o", "test-key", "default description")

        # Verify form was used
        mock_form.assert_called_once()
        mock_submit.assert_called_once()
        assert mock_session_state['step1_completed'] is True 