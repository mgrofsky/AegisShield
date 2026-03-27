"""
AlienVault OTX Threat Intelligence Service

Fetches threat intelligence data from AlienVault OTX.

NIST SP 800-53 Rev. 5 Control Mappings:
- SI-4: Information System Monitoring
- RA-3: Risk Assessment - Threat intelligence integration
- PM-16: Threat Awareness Program
"""

import logging
from datetime import datetime, timedelta

import streamlit as st
from OTXv2 import OTXv2
from requests.exceptions import RequestException, Timeout

from clients.retry import APIRetryError, retry_with_backoff
from config import API_CONFIG
from utils.error_handler import handle_exception

logger = logging.getLogger(__name__)


class AlienVaultAPIError(Exception):
    """Custom exception for AlienVault API errors."""


@st.cache_data(ttl=1800, show_spinner=False)
def fetch_otx_data(
    api_key: str,
    technology: str | None = None,
    industry: str | None = None,
    days: int | None = None,
    max_results: int | None = None,
    adversary: str | None = None,
    malware_family: str | None = None,
    tlp: str | None = None,
) -> str | None:
    """
    Fetch threat intelligence from AlienVault OTX.
    Results are cached for 30 minutes.
    """
    days = days or API_CONFIG.otx_lookback_days
    max_results = max_results or API_CONFIG.otx_max_results

    try:
        otx = OTXv2(api_key)
        query = f"{industry if industry else ''}".strip()
        modified_since = (datetime.now() - timedelta(days=days)).isoformat()

        def _search_pulses():
            try:
                pulses = otx.search_pulses(query, max_results=100)
                if not pulses:
                    return None
                return pulses
            except (RequestException, Timeout) as e:
                raise AlienVaultAPIError(f"OTX search failed: {e}") from e

        try:
            pulses = retry_with_backoff(_search_pulses)
        except APIRetryError:
            return None

        if pulses is None:
            return None

        # Filter and sort pulses
        filtered = [
            p for p in pulses.get("results", [])
            if p.get("modified", "") >= modified_since
            and p.get("public", 1) == 1
            and (adversary is None or adversary.lower() in p.get("adversary", "").lower())
            and (malware_family is None or any(
                mf.lower() == malware_family.lower() for mf in p.get("malware_families", [])
            ))
            and (tlp is None or p.get("TLP", "").lower() == tlp.lower())
        ]

        sorted_pulses = sorted(
            filtered, key=lambda x: x.get("modified", ""), reverse=True
        )[:max_results]

        cti_data = []
        for idx, pulse in enumerate(sorted_pulses):
            try:
                entry = f"""Cyber Threat Intelligence Pulse {idx + 1}
Industry: {industry if industry else 'N/A'}
Pulse Name: {pulse.get('name', 'N/A')}
Description: {pulse.get('description', 'N/A') or 'No description available'}
Modified: {pulse.get('modified', 'N/A')}
TLP: {pulse.get('TLP', 'N/A')}
Adversary: {pulse.get('adversary', 'N/A')}
Malware Families: {', '.join(pulse.get('malware_families', []))}
|
"""
                cti_data.append(entry)
            except Exception as e:
                logger.warning("Error processing pulse %d: %s", idx + 1, e)

        if not cti_data:
            return "No threat intelligence data found"
        return "".join(cti_data) + f"\n\nTotal pulses found: {len(cti_data)}"

    except Exception as e:
        handle_exception(e, "Unexpected error while fetching AlienVault data")
        return None
