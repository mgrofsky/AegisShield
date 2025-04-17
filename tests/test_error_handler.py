"""Tests for the error handling module."""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from error_handler import setup_logging, log_error, display_error_to_user, handle_exception

def test_setup_logging_creates_directory():
    """Test that setup_logging creates the log directory if it doesn't exist."""
    with patch('pathlib.Path.mkdir') as mock_mkdir:
        setup_logging()
        mock_mkdir.assert_called_once_with(exist_ok=True)

def test_log_error_writes_to_console():
    """Test that log_error writes to console."""
    with patch('os.write') as mock_write:
        log_error("Test error")
        assert mock_write.call_count == 2  # Expecting two writes
        # First write should contain the error message
        assert b"ERROR: Test error" in mock_write.call_args_list[0][0][1]

def test_log_error_with_additional_info():
    """Test that log_error includes additional info when provided."""
    with patch('os.write') as mock_write:
        log_error("Test error", "Additional context")
        assert mock_write.call_count == 2  # Expecting two writes
        # First write should contain both error and additional info
        assert b"Additional context" in mock_write.call_args_list[0][0][1]

def test_display_error_to_user():
    """Test that display_error_to_user shows error to user."""
    with patch('streamlit.error') as mock_error:
        display_error_to_user("User error message")
        mock_error.assert_called_once_with("User error message")

def test_handle_exception():
    """Test that handle_exception properly handles exceptions."""
    with patch('error_handler.log_error') as mock_log, \
         patch('error_handler.display_error_to_user') as mock_display:
        test_exception = Exception("Test exception")
        handle_exception(test_exception, "User message")
        
        mock_log.assert_called_once()
        mock_display.assert_called_once_with("User message") 