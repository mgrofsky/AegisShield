"""Tests for the AlienVault search module."""

import pytest
from unittest.mock import patch, MagicMock
from requests.exceptions import Timeout, HTTPError
from alientvault_search import retry_with_backoff, fetch_otx_data, AlienVaultAPIError
from unittest.mock import call
from unittest.mock import Mock
from requests.exceptions import RequestException

def test_retry_success():
    """Test that retry succeeds and returns the result."""
    mock_func = MagicMock(return_value="success")
    result = retry_with_backoff(lambda: mock_func())
    assert result == "success"

def test_retry_fails():
    """Test that retry fails after max retries."""
    mock_func = MagicMock(side_effect=Timeout("Connection timeout"))
    with patch('alientvault_search.handle_exception') as mock_handle:
        retry_with_backoff(lambda: mock_func())
        assert mock_handle.call_count == 1

def test_retry_custom_params():
    """Test retry with custom max_retries and initial_delay."""
    mock_func = MagicMock(side_effect=Timeout("Connection timeout"))
    with patch('alientvault_search.handle_exception') as mock_handle:
        retry_with_backoff(lambda: mock_func(), max_retries=2, initial_delay=0.1)
        assert mock_handle.call_count == 1

def test_alienvault_api_error():
    """Test AlienVaultAPIError creation."""
    error = AlienVaultAPIError("Test error")
    assert str(error) == "Test error"

def test_fetch_otx_data():
    """Test OTX data fetching."""
    mock_pulse = {
        "name": "Test Pulse",
        "description": "Test Description",
        "created": "2024-01-01",
        "modified": "2024-01-01",
        "adversary": "Test Adversary",
        "malware_families": ["Test Malware"],
        "TLP": "white"
    }
    mock_otx = MagicMock()
    mock_otx.search_pulses.return_value = {"results": [mock_pulse], "count": 1}
    with patch('alientvault_search.OTXv2', return_value=mock_otx):
        result = fetch_otx_data("api_key", technology="test_tech")
        assert "Test Pulse" in result
        assert "Test Description" in result
        assert "Test Adversary" in result
        assert "Test Malware" in result

def test_fetch_otx_data_empty_api_key():
    """Test OTX data fetching with empty API key."""
    mock_otx = MagicMock()
    mock_otx.search_pulses.return_value = None  # Simulate empty response
    with patch('alientvault_search.OTXv2', return_value=mock_otx), \
         patch('alientvault_search.handle_exception') as mock_handle, \
         patch('alientvault_search.retry_with_backoff', side_effect=lambda x: x()):
        result = fetch_otx_data("", technology="test_tech")
        assert result is None
        # Check that handle_exception was called with the correct error
        assert mock_handle.call_count == 1
        actual_call = str(mock_handle.call_args)
        expected_call = str(call(AlienVaultAPIError("No response from OTX API"), "No response from OTX API"))
        assert actual_call == expected_call

def test_fetch_otx_data_rate_limit():
    """Test handling of rate limit exceeded."""
    mock_otx = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 429
    mock_otx.search_pulses.side_effect = HTTPError(response=mock_response)
    with patch('alientvault_search.OTXv2', return_value=mock_otx), \
         patch('alientvault_search.handle_exception') as mock_handle, \
         patch('alientvault_search.retry_with_backoff', side_effect=lambda x: x()):
        result = fetch_otx_data("api_key", technology="test_tech")
        assert result is None
        # Check that handle_exception was called with the correct error
        assert mock_handle.call_count == 1
        actual_call = str(mock_handle.call_args)
        expected_call = str(call(AlienVaultAPIError("Rate limit exceeded. Please wait before making more requests."), "Rate limit exceeded"))
        assert actual_call == expected_call

def test_fetch_otx_data_http_error():
    """Test handling of HTTP errors."""
    mock_otx = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_otx.search_pulses.side_effect = HTTPError(response=mock_response)
    with patch('alientvault_search.OTXv2', return_value=mock_otx), \
         patch('alientvault_search.handle_exception') as mock_handle, \
         patch('alientvault_search.retry_with_backoff', side_effect=lambda x: x()):
        result = fetch_otx_data("api_key", technology="test_tech")
        assert result is None
        # Check that handle_exception was called with the correct error
        assert mock_handle.call_count == 1
        actual_call = str(mock_handle.call_args)
        expected_call = str(call(AlienVaultAPIError("HTTP error while searching pulses: "), "HTTP error while searching pulses"))
        assert actual_call == expected_call

def test_fetch_otx_data_no_pulses():
    """Test handling of no pulses found."""
    mock_otx = MagicMock()
    mock_otx.search_pulses.return_value = {"results": []}
    with patch('alientvault_search.OTXv2', return_value=mock_otx), \
         patch('alientvault_search.handle_exception') as mock_handle, \
         patch('alientvault_search.retry_with_backoff', side_effect=lambda x: x()):
        result = fetch_otx_data("api_key", technology="test_tech")
        assert result == "No threat intelligence data found"
        assert mock_handle.call_count == 0

def test_fetch_otx_data_filter_adversary():
    """Test filtering by adversary."""
    mock_pulse = {
        "name": "Test Pulse",
        "description": "Test Description",
        "modified": "2024-01-01",
        "adversary": "Test Adversary",
        "malware_families": [],
        "TLP": "white"
    }
    mock_otx = MagicMock()
    mock_otx.search_pulses.return_value = {"results": [mock_pulse], "count": 1}
    with patch('alientvault_search.OTXv2', return_value=mock_otx):
        result = fetch_otx_data("api_key", adversary="Test Adversary")
        assert "Test Adversary" in result

def test_fetch_otx_data_filter_malware():
    """Test filtering by malware family."""
    mock_pulse = {
        "name": "Test Pulse",
        "description": "Test Description",
        "modified": "2024-01-01",
        "adversary": "Test Adversary",
        "malware_families": ["Test Malware"],
        "TLP": "white"
    }
    mock_otx = MagicMock()
    mock_otx.search_pulses.return_value = {"results": [mock_pulse], "count": 1}
    with patch('alientvault_search.OTXv2', return_value=mock_otx):
        result = fetch_otx_data("api_key", malware_family="Test Malware")
        assert "Test Malware" in result

def test_fetch_otx_data_filter_tlp():
    """Test filtering by TLP."""
    mock_pulse = {
        "name": "Test Pulse",
        "description": "Test Description",
        "modified": "2024-01-01",
        "adversary": "Test Adversary",
        "malware_families": [],
        "TLP": "white"
    }
    mock_otx = MagicMock()
    mock_otx.search_pulses.return_value = {"results": [mock_pulse], "count": 1}
    with patch('alientvault_search.OTXv2', return_value=mock_otx):
        result = fetch_otx_data("api_key", tlp="white")
        assert "TLP: white" in result

def test_fetch_otx_data_tlp_filter():
    """Test filtering of pulses based on TLP."""
    mock_otx = MagicMock()
    mock_otx.search_pulses.return_value = {
        "results": [
            {
                "name": "Test Pulse",
                "description": "Test Description",
                "TLP": "white",
                "created": "2023-01-01T00:00:00",
                "modified": "2023-01-01T00:00:00",
                "adversary": "Test Adversary",
                "malware_families": ["Test Malware"],
                "industries": ["Test Industry"],
                "tags": ["Test Tag"]
            }
        ]
    }
    with patch('alientvault_search.OTXv2', return_value=mock_otx), \
         patch('alientvault_search.handle_exception') as mock_handle, \
         patch('alientvault_search.retry_with_backoff', side_effect=lambda x: x()):
        result = fetch_otx_data("api_key", technology="test_tech", tlp="white")
        assert "TLP: white" in result
        assert mock_handle.call_count == 0

def test_fetch_otx_data_pulse_error():
    """Test handling of pulse formatting error."""
    mock_otx = MagicMock()
    mock_otx.search_pulses.return_value = {"results": [{"invalid": "data"}]}
    with patch('alientvault_search.OTXv2', return_value=mock_otx), \
         patch('alientvault_search.handle_exception') as mock_handle, \
         patch('alientvault_search.retry_with_backoff', side_effect=lambda x: x()):
        result = fetch_otx_data("api_key", technology="test_tech")
        assert result == "No threat intelligence data found"
        assert mock_handle.call_count == 0

def test_retry_with_backoff_all_fail():
    """Test retry_with_backoff when all attempts fail."""
    mock_func = Mock(side_effect=RequestException("Test error"))
    with patch('time.sleep') as mock_sleep:
        with patch('alientvault_search.handle_exception') as mock_handle:
            result = retry_with_backoff(mock_func, max_retries=2, initial_delay=0.1)
            assert result is None
            mock_handle.assert_called_once()
            error_msg = mock_handle.call_args[0][1]
            assert "Failed after 2 retry attempts" in error_msg

def test_retry_with_backoff_timeout():
    """Test retry_with_backoff with Timeout exception."""
    mock_func = Mock(side_effect=Timeout("Test timeout"))
    with patch('time.sleep') as mock_sleep:
        with patch('alientvault_search.handle_exception') as mock_handle:
            result = retry_with_backoff(mock_func, max_retries=2, initial_delay=0.1)
            assert result is None
            mock_handle.assert_called_once()
            error_msg = mock_handle.call_args[0][1]
            assert "Failed after 2 retry attempts" in error_msg

def test_fetch_otx_data_no_matching_pulses():
    """Test fetch_otx_data when pulses are found but none match filters."""
    mock_pulses = {
        "count": 2,
        "results": [
            {
                "modified": "2020-01-01T00:00:00Z",
                "public": 1,
                "adversary": "Test Adversary",
                "malware_families": ["Test Malware"],
                "TLP": "white",
                "name": "Test Pulse 1",
                "description": "Test Description 1"
            },
            {
                "modified": "2020-01-02T00:00:00Z",
                "public": 1,
                "adversary": "Different Adversary",
                "malware_families": ["Different Malware"],
                "TLP": "green",
                "name": "Test Pulse 2",
                "description": "Test Description 2"
            }
        ]
    }
    
    mock_otx = MagicMock()
    mock_otx.search_pulses.return_value = mock_pulses
    with patch('alientvault_search.OTXv2', return_value=mock_otx):
        result = fetch_otx_data(
            "test_key",
            industry="Test Industry",
            adversary="Non-Matching Adversary",
            malware_family="Non-Matching Malware",
            tlp="red"
        )
        assert result == "No threat intelligence data found"

def test_fetch_otx_data_pulse_processing_error(mocker):
    """Test error handling when processing pulses fails."""
    # Mock the OTXv2 class and its methods
    mock_otx = mocker.Mock()
    mock_otx.search_pulses.return_value = {"results": [{"modified": None}]}  # This will cause a TypeError
    mocker.patch("alientvault_search.OTXv2", return_value=mock_otx)
    
    # Mock the error handler
    mock_error_handler = mocker.patch("alientvault_search.handle_exception")
    
    # Call the function
    result = fetch_otx_data("test_key", industry="test_industry")
    
    # Verify the result is None
    assert result is None
    
    # Verify the error handler was called
    mock_error_handler.assert_called_once()

def test_fetch_otx_data_alienvault_api_error(mocker):
    """Test error handling when AlienVault API returns an error."""
    # Mock the OTXv2 class and its methods
    mock_otx = mocker.Mock()
    mock_otx.search_pulses.side_effect = Exception("API Error")
    mocker.patch("alientvault_search.OTXv2", return_value=mock_otx)
    
    # Mock the error handler
    mock_error_handler = mocker.patch("alientvault_search.handle_exception")
    
    # Call the function
    result = fetch_otx_data("test_key", industry="test_industry")
    
    # Verify the result is None
    assert result is None
    
    # Verify the error handler was called
    mock_error_handler.assert_called_once()

def test_fetch_otx_data_general_error():
    """Test fetch_otx_data when a general error occurs."""
    mock_otx = MagicMock()
    mock_otx.search_pulses.side_effect = Exception("Test error")
    with patch('alientvault_search.OTXv2', return_value=mock_otx), \
         patch('alientvault_search.handle_exception') as mock_handle:
        result = fetch_otx_data("test_key", technology="test_tech")
        assert result is None
        mock_handle.assert_called_once()
        error_msg = mock_handle.call_args[0][1]
        assert "Unexpected error while searching pulses" in error_msg 