import logging
import time
from dataclasses import dataclass

import nvdlib
from requests.exceptions import HTTPError, RequestException, Timeout

from error_handler import handle_exception

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class NVDConfig:
    """Configuration settings for NVD API operations."""
    max_retries: int = 3
    initial_delay: float = 1.0
    default_top_n: int = 10

class NVDAPIError(Exception):
    """Custom exception for NVD API related errors."""
    pass

def retry_with_backoff(func, config: NVDConfig | None = None):
    """
    Retry a function with exponential backoff.
    
    Args:
        func: The function to retry
        config: Optional configuration settings
    
    Returns:
        The result of the function call
    
    Raises:
        NVDAPIError: If all retry attempts fail
    """
    config = config or NVDConfig()
    delay = config.initial_delay
    
    for attempt in range(config.max_retries):
        try:
            return func()
        except (RequestException, Timeout) as e:
            if attempt < config.max_retries - 1:
                logger.warning(f"Attempt {attempt + 1} failed: {str(e)}. Retrying in {delay} seconds...")
                time.sleep(delay)
                delay *= 2  # Exponential backoff
            else:
                handle_exception(NVDAPIError(f"Failed after {config.max_retries} attempts. Last error: {str(e)}"), "NVD API request failed")

def fetch_cpe_name(api_key: str, cpe_prefix: str, version: str = "*") -> str:
    """
    Fetch the CPE name for a given technology and version from the NVD API using NVDLib.

    Args:
        api_key (str): The API key for accessing the NVD API.
        cpe_prefix (str): The CPE prefix for the technology.
        version (str, optional): The version of the technology. Defaults to "*".

    Returns:
        str: The CPE name.

    Raises:
        NVDAPIError: If there's an error accessing the NVD API or no CPE is found.
    """
    cpe_match_string = f"{cpe_prefix}{version}:*"
    logger.debug(f"Searching for CPE with match string: {cpe_match_string}")

    def _fetch_cpe():
        try:
            cpe_results = nvdlib.searchCPE(
                cpeMatchString=cpe_match_string,
                key=api_key
            )
            if not cpe_results:
                handle_exception(NVDAPIError(f"No CPE found for {cpe_prefix} version {version}"), "No CPE found")
            
            cpe = cpe_results[0]
            if cpe.deprecated and cpe.deprecatedBy:
                cpe_name = cpe.deprecatedBy[0].cpeName
            else:
                cpe_name = cpe.cpeName
            
            logger.debug(f"Found CPE name: {cpe_name}")
            return cpe_name
            
        except Timeout:
            handle_exception(NVDAPIError(f"Timeout while fetching CPE for {cpe_prefix}"), "NVD API timeout")
        except HTTPError as e:
            if e.response.status_code == 429:
                handle_exception(NVDAPIError("Rate limit exceeded. Please wait before making more requests."), "NVD API rate limit exceeded")
            handle_exception(NVDAPIError(f"HTTP error while fetching CPE: {str(e)}"), "NVD API HTTP error")
        except Exception as e:
            handle_exception(NVDAPIError(f"Unexpected error while fetching CPE: {str(e)}"), "Unexpected NVD API error")

    return retry_with_backoff(_fetch_cpe)

def search_nvd(
    api_key: str,
    cpe_name: str,
    version: str = "*",
    tech: str = "",
    category: str = "",
    top_n: int = 10,
    config: NVDConfig | None = None
) -> str:
    """
    Search the NVD for CVEs related to a specific technology and version using NVDLib.

    Args:
        api_key (str): The API key for accessing the NVD API.
        cpe_name (str): The CPE name for the technology.
        version (str, optional): The version of the technology. Defaults to "*".
        tech (str, optional): The technology name. Defaults to "".
        category (str, optional): The category of the technology. Defaults to "".
        top_n (int, optional): The number of top CVEs to return. Defaults to 10.
        config (NVDConfig, optional): Configuration settings. Defaults to None.

    Returns:
        str: A formatted string of CVE information.

    Raises:
        NVDAPIError: If there's an error accessing the NVD API or processing the results.
    """
    config = config or NVDConfig()
    logger.info(f"Searching NVD for: {cpe_name}{version} | Tech: {tech} | Category: {category}")

    try:
        cpe_name = fetch_cpe_name(api_key, cpe_name, version)
    except NVDAPIError as e:
        logger.error(f"Failed to fetch CPE name: {str(e)}")
        return f"Error: {str(e)}"

    def _search_cves():
        try:
            cve_results = nvdlib.searchCVE(
                cpeName=cpe_name,
                key=api_key
            )
            
            if not cve_results:
                logger.info(f"No CVEs found for {cpe_name}")
                return []
            
            logger.info(f"Found {len(cve_results)} CVEs for CPE: {cpe_name}")
                
            # Sort results by CVSS score and published date
            sorted_results = sorted(
                cve_results,
                key=lambda x: (x.score, x.published),
                reverse=True
            )
            
            return sorted_results[:top_n]
            
        except Timeout as e:
            raise NVDAPIError(f"Timeout while searching CVEs for {cpe_name}") from e

        except HTTPError as e:
            if e.response.status_code == 429:
                raise NVDAPIError("Rate limit exceeded. Please wait before making more requests.") from e
            raise NVDAPIError(f"HTTP error while searching CVEs: {str(e)}") from e

        except Exception as e:
            raise NVDAPIError(f"Unexpected error while searching CVEs: {str(e)}") from e


    try:
        top_results = retry_with_backoff(_search_cves, config)
    except NVDAPIError as e:
        logger.error(f"Failed to search CVEs: {str(e)}")
        return f"Error: {str(e)}"

    vulnerabilities = []
    for idx, item in enumerate(top_results):
        try:
            cve_id = item.id
            description = (
                item.descriptions[0].value
                if item.descriptions
                else "No description available"
            )
            published_date = (
                item.published.split("T")[0] if item.published else "Unknown date"
            )
            cvss_score = item.score if hasattr(item, 'score') else "N/A"
            cve_entry = f"""{tech} NVD {idx + 1}
CVE ID: {cve_id}
Technology: {tech}
Category: {category}
Version: {version}
CVSS Score: {cvss_score}
Published Date: {published_date}
Description: {description.replace('\\n', ' ').replace('/', '-')}|"""
            vulnerabilities.append(cve_entry)
        except Exception as e:
            logger.warning(f"Error processing CVE {idx + 1}: {str(e)}")
            continue

    result = "".join(vulnerabilities) if vulnerabilities else "No vulnerabilities found"
    if vulnerabilities:
        result += f"\n\nTotal vulnerabilities found: {len(vulnerabilities)}"
    return result
