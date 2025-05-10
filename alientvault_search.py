import logging
import time
from datetime import datetime, timedelta

from OTXv2 import OTXv2
from requests.exceptions import HTTPError, RequestException, Timeout

from error_handler import handle_exception

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AlienVaultAPIError(Exception):
    """Custom exception for AlienVault API related errors."""
    pass

def retry_with_backoff(func, max_retries: int = 3, initial_delay: float = 1.0):
    """
    Retry a function with exponential backoff.
    
    Args:
        func: The function to retry
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay between retries in seconds
    
    Returns:
        The result of the function call or None if all retries fail
    """
    delay = initial_delay
    
    for attempt in range(max_retries):
        try:
            return func()
        except (RequestException, Timeout) as e:
            if attempt < max_retries - 1:
                logger.warning(f"Attempt {attempt + 1} failed: {str(e)}. Retrying in {delay} seconds...")
                time.sleep(delay)
                delay *= 2  # Exponential backoff
            else:
                error = AlienVaultAPIError(f"Failed after {max_retries} attempts. Last error: {str(e)}")
                handle_exception(error, f"Failed after {max_retries} retry attempts")
                return None

def fetch_otx_data(
    api_key: str,
    technology: str | None = None,
    industry: str | None = None,
    days: int = 2920,
    max_results: int = 5,
    adversary: str | None = None,
    malware_family: str | None = None,
    tlp: str | None = None,
) -> str:
    """
    Fetch Threat Intelligence data from AlienVault OTX.
    
    Args:
        api_key: The API key for accessing the OTX API
        technology: The technology of interest
        industry: The industry of interest
        days: The number of days to look back from today
        max_results: The maximum number of results to return
        adversary: The adversary of interest
        malware_family: The malware family of interest
        tlp: The TLP (Traffic Light Protocol) level of interest
    
    Returns:
        A formatted string of Threat Intelligence data
    
    Raises:
        AlienVaultAPIError: If there's an error accessing the OTX API or processing the results
    """
    try:
        # Initialize OTXv2 with the provided API key
        otx = OTXv2(api_key)
        cti_data = []

        # Construct the search query based on the provided industry
        query = f"{industry if industry else ''}".strip()
        logger.debug(f"Searching OTX with query: {query}")

        # Calculate the date for filtering pulses
        modified_since = (datetime.now() - timedelta(days=days)).isoformat()
        logger.debug(f"Looking back to: {modified_since}")

        def _search_pulses():
            try:
                pulses = otx.search_pulses(query, max_results=100)
                if not pulses:
                    handle_exception(AlienVaultAPIError("No response from OTX API"), "No response from OTX API")
                    return None
                return pulses
            except Timeout:
                handle_exception(AlienVaultAPIError("Timeout while searching pulses"), "Timeout while searching pulses")
                return None
            except HTTPError as e:
                if e.response.status_code == 429:
                    handle_exception(AlienVaultAPIError("Rate limit exceeded. Please wait before making more requests."), "Rate limit exceeded")
                else:
                    handle_exception(AlienVaultAPIError(f"HTTP error while searching pulses: {str(e)}"), "HTTP error while searching pulses")
                return None
            except Exception as e:
                handle_exception(AlienVaultAPIError(f"Unexpected error while searching pulses: {str(e)}"), "Unexpected error while searching pulses")
                return None

        # Search for pulses with retry logic
        pulses = retry_with_backoff(_search_pulses)
        if pulses is None:
            return None
        logger.info(f"Found {pulses.get('count', 0)} pulses")

        # Filter and sort pulses
        filtered_pulses = [
            pulse
            for pulse in pulses.get("results", [])
            if pulse.get("modified", "") >= modified_since
            and pulse.get("public", 1) == 1  # Ensure the pulse is public
            and (
                adversary is None or adversary.lower() in pulse.get("adversary", "").lower()
            )
            and (
                malware_family is None
                or any(
                    mf.lower() == malware_family.lower()
                    for mf in pulse.get("malware_families", [])
                )
            )
            and (tlp is None or pulse.get("TLP", "").lower() == tlp.lower())
        ]

        logger.info(f"Filtered to {len(filtered_pulses)} relevant pulses")

        # Sort the filtered pulses by modified date in descending order and limit to max_results
        sorted_pulses = sorted(
            filtered_pulses, key=lambda x: x.get("modified", ""), reverse=True
        )[:max_results]

        # Format the data for each pulse
        for idx, pulse in enumerate(sorted_pulses):
            try:
                pulse_data = f"""Cyber Threat Intelligence Pulse {idx + 1}
Industry: {industry if industry else 'N/A'}
Pulse Name: {pulse.get('name', 'N/A')}
Description: {pulse.get('description', 'N/A') or 'No description available'}
Modified: {pulse.get('modified', 'N/A')}
TLP: {pulse.get('TLP', 'N/A')}
Adversary: {pulse.get('adversary', 'N/A')}
Malware Families: {', '.join(pulse.get('malware_families', []))}
|
"""
                cti_data.append(pulse_data)
            except Exception as e:
                logger.warning(f"Error processing pulse {idx + 1}: {str(e)}")
                continue

        result = "".join(cti_data) if cti_data else "No threat intelligence data found"
        if cti_data:
            result += f"\n\nTotal pulses found: {len(cti_data)}"
        return result

    except AlienVaultAPIError as e:
        handle_exception(e, "AlienVault API error")
    except Exception as e:
        handle_exception(e, "Unexpected error while fetching AlienVault data")
