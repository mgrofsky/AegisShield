"""Tests for the NVD search module."""

import pytest
from unittest.mock import patch, MagicMock, Mock
from requests.exceptions import Timeout, HTTPError
from nvd_search import NVDConfig, retry_with_backoff, fetch_cpe_name, NVDAPIError, search_nvd
import time

def test_retry_success():
    """Test that retry succeeds and returns the result."""
    mock_func = MagicMock(return_value="success")
    result = retry_with_backoff(lambda: mock_func())
    assert result == "success"

def test_retry_fails():
    """Test that retry handles failures properly."""
    mock_func = MagicMock(side_effect=Timeout("Connection timeout"))
    config = NVDConfig(max_retries=1)
    
    with patch('nvd_search.handle_exception') as mock_handle:
        retry_with_backoff(lambda: mock_func(), config)
        mock_handle.assert_called_once()

def test_fetch_cpe_name():
    """Test CPE name fetching."""
    mock_cpe = MagicMock(deprecated=False, cpeName="test:cpe:name")
    
    with patch('nvdlib.searchCPE', return_value=[mock_cpe]):
        result = fetch_cpe_name("api_key", "test:cpe:", "1.0")
        assert result == "test:cpe:name"

@patch('nvdlib.searchCPE')
def test_fetch_cpe_name_deprecated(mock_search_cpe):
    """Test fetching a CPE name when the result is deprecated"""
    # Create a mock CPE result that is deprecated
    mock_cpe = MagicMock()
    mock_cpe.deprecated = True
    mock_cpe.deprecatedBy = [MagicMock(cpeName="cpe:2.3:a:deprecated:test:1.0:*:*:*:*:*:*:*")]
    mock_cpe.cpeName = "cpe:2.3:a:original:test:1.0:*:*:*:*:*:*:*"
    
    # Set up the mock to return our deprecated CPE
    mock_search_cpe.return_value = [mock_cpe]
    
    # Call the function
    result = fetch_cpe_name("test-key", "cpe:2.3:a:original:test:")
    
    # Verify the result is the deprecated CPE name
    assert result == "cpe:2.3:a:deprecated:test:1.0:*:*:*:*:*:*:*"
    
    # Verify the search was called with correct parameters
    mock_search_cpe.assert_called_once_with(
        cpeMatchString="cpe:2.3:a:original:test:*:*",
        key="test-key"
    ) 

def test_nvd_config_defaults():
    """Test that NVDConfig has correct default values."""
    config = NVDConfig()
    assert config.max_retries == 3
    assert config.initial_delay == 1.0
    assert config.default_top_n == 10

def test_nvd_config_custom_values():
    """Test that NVDConfig can be initialized with custom values."""
    config = NVDConfig(max_retries=5, initial_delay=2.0, default_top_n=20)
    assert config.max_retries == 5
    assert config.initial_delay == 2.0
    assert config.default_top_n == 20

def test_nvd_api_error():
    """Test that NVDAPIError can be created with a message."""
    error = NVDAPIError("Test error message")
    assert str(error) == "Test error message"

def test_retry_with_backoff_success():
    """Test that retry_with_backoff returns the function result on success."""
    mock_func = Mock(return_value="success")
    result = retry_with_backoff(mock_func)
    assert result == "success"
    mock_func.assert_called_once()

def test_search_nvd_success():
    """Test successful NVD search with mock CVE results."""
    mock_cve = MagicMock()
    mock_cve.id = "CVE-2023-1234"
    mock_cve.descriptions = [MagicMock(value="Test description")]
    mock_cve.published = "2023-01-01T00:00:00"
    mock_cve.score = 7.5

    with patch('nvdlib.searchCVE', return_value=[mock_cve]), \
         patch('nvd_search.fetch_cpe_name', return_value="cpe:2.3:a:test:tech:1.0:*:*:*:*:*:*:*"):
        result = search_nvd("api_key", "cpe:2.3:a:test:tech:", "1.0", "Test Tech", "Test Category")
        assert "CVE-2023-1234" in result
        assert "Test description" in result
        assert "CVSS Score: 7.5" in result
        assert "Test Tech" in result
        assert "Test Category" in result

def test_search_nvd_no_results():
    """Test NVD search when no CVEs are found."""
    with patch('nvdlib.searchCVE', return_value=[]), \
         patch('nvd_search.fetch_cpe_name', return_value="cpe:2.3:a:test:tech:1.0:*:*:*:*:*:*:*"):
        result = search_nvd("api_key", "cpe:2.3:a:test:tech:", "1.0", "Test Tech", "Test Category")
        assert "No vulnerabilities found" in result

def test_search_nvd_timeout():
    """Test NVD search when API times out."""
    with patch('nvdlib.searchCVE', side_effect=Timeout()), \
         patch('nvd_search.fetch_cpe_name', return_value="cpe:2.3:a:test:tech:1.0:*:*:*:*:*:*:*"):
        result = search_nvd("api_key", "cpe:2.3:a:test:tech:", "1.0", "Test Tech", "Test Category")
        assert "Error: Timeout while searching CVEs" in result

def test_search_nvd_rate_limit():
    """Test NVD search when rate limit is exceeded."""
    mock_response = MagicMock()
    mock_response.status_code = 429
    with patch('nvdlib.searchCVE', side_effect=HTTPError(response=mock_response)), \
         patch('nvd_search.fetch_cpe_name', return_value="cpe:2.3:a:test:tech:1.0:*:*:*:*:*:*:*"):
        result = search_nvd("api_key", "cpe:2.3:a:test:tech:", "1.0", "Test Tech", "Test Category")
        assert "Error: Rate limit exceeded" in result

def test_search_nvd_cpe_error():
    """Test NVD search when CPE name fetch fails."""
    with patch('nvd_search.fetch_cpe_name', side_effect=NVDAPIError("CPE fetch failed")):
        result = search_nvd("api_key", "cpe:2.3:a:test:tech:", "1.0", "Test Tech", "Test Category")
        assert "Error: CPE fetch failed" in result

def test_search_nvd_custom_config():
    """Test NVD search with custom configuration."""
    mock_cve = MagicMock()
    mock_cve.id = "CVE-2023-1234"
    mock_cve.descriptions = [MagicMock(value="Test description")]
    mock_cve.published = "2023-01-01T00:00:00"
    mock_cve.score = 7.5

    config = NVDConfig(max_retries=2, initial_delay=0.1, default_top_n=5)
    
    with patch('nvdlib.searchCVE', return_value=[mock_cve]), \
         patch('nvd_search.fetch_cpe_name', return_value="cpe:2.3:a:test:tech:1.0:*:*:*:*:*:*:*"):
        result = search_nvd("api_key", "cpe:2.3:a:test:tech:", "1.0", "Test Tech", "Test Category", top_n=5, config=config)
        assert "CVE-2023-1234" in result 