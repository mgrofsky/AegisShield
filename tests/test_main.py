"""Tests for the main application module."""

import pytest
from unittest.mock import patch, MagicMock
import streamlit as st
from main import (
    render_sidebar,
    render_tab,
    ERROR_MESSAGES,
    DEFAULT_MODEL_PROVIDER,
    DEFAULT_SELECTED_MODEL,
    DEFAULT_OPENAI_API_KEY
)

@pytest.fixture
def mock_streamlit():
    """Mock Streamlit components."""
    with patch('streamlit.sidebar') as mock_sidebar, \
         patch('streamlit.tabs') as mock_tabs, \
         patch('streamlit.error') as mock_error, \
         patch('streamlit.secrets') as mock_secrets:
        
        # Mock session state
        st.session_state = {
            'model_provider': DEFAULT_MODEL_PROVIDER,
            'selected_model': DEFAULT_SELECTED_MODEL,
            'openai_api_key': DEFAULT_OPENAI_API_KEY
        }
        
        # Mock secrets
        mock_secrets.__contains__.return_value = True
        mock_secrets.get.return_value = 'test_key'
        
        # Mock tabs to return a list of mock tabs
        mock_tab_list = [MagicMock() for _ in range(7)]
        mock_tabs.return_value = mock_tab_list
        
        # Mock render functions for each step
        mock_render_funcs = {
            'step1_render': MagicMock(),
            'step2_render': MagicMock(),
            'step3_render': MagicMock(),
            'step4_render': MagicMock(),
            'step5_render': MagicMock(),
            'step6_render': MagicMock(),
            'step7_render': MagicMock()
        }
        
        yield {
            'sidebar': mock_sidebar,
            'tabs': mock_tabs,
            'error': mock_error,
            'secrets': mock_secrets,
            'state': st.session_state,
            **mock_render_funcs
        }

def test_render_sidebar(mock_streamlit):
    """Test the sidebar rendering."""
    with patch('main.render_api_key_inputs') as mock_render_keys:
        render_sidebar()
        
        # Verify API key inputs were rendered
        mock_render_keys.assert_called_once()

def test_render_tab_success(mock_streamlit):
    """Test successful tab rendering."""
    mock_tab = MagicMock()
    mock_render_func = MagicMock()
    
    # Set up session state
    st.session_state.update({
        'model_provider': DEFAULT_MODEL_PROVIDER,
        'selected_model': DEFAULT_SELECTED_MODEL,
        'openai_api_key': DEFAULT_OPENAI_API_KEY
    })
    
    render_tab(mock_tab, mock_render_func, 'step1', 
              model_provider=DEFAULT_MODEL_PROVIDER,
              selected_model=DEFAULT_SELECTED_MODEL,
              openai_api_key=DEFAULT_OPENAI_API_KEY)
    
    # Verify render function was called with correct arguments
    mock_render_func.assert_called_once_with(
        model_provider=DEFAULT_MODEL_PROVIDER,
        selected_model=DEFAULT_SELECTED_MODEL,
        openai_api_key=DEFAULT_OPENAI_API_KEY
    )

def test_render_tab_error(mock_streamlit):
    """Test error handling during tab rendering."""
    mock_tab = MagicMock()
    mock_render_func = MagicMock(side_effect=Exception("Test error"))
    
    render_tab(mock_tab, mock_render_func, 'step1')
    
    # Verify error was displayed
    mock_streamlit['error'].assert_any_call(ERROR_MESSAGES['step1'])

def test_main_flow(mock_streamlit):
    """Test the main application flow."""
    with patch('main.render_sidebar') as mock_render_sidebar, \
         patch('main.render_tab') as mock_render_tab, \
         patch('api_key_handler.load_api_keys') as mock_load_keys, \
         patch('api_key_handler_local.load_api_keys') as mock_load_keys_local, \
         patch('streamlit.set_page_config') as mock_set_config:
        
        # Import and run main
        import main
        main.main()
        
        # Verify sidebar and tabs were rendered
        mock_render_sidebar.assert_called_once()
        assert mock_render_tab.call_count == 7  # One for each step 