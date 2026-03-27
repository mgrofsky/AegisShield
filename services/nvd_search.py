"""
NVD Vulnerability Search Service

Searches the National Vulnerability Database for CVEs.

NIST SP 800-53 Rev. 5 Control Mappings:
- SI-7: Software Integrity - Vulnerability assessment
- RA-5: Vulnerability Scanning - Automated CVE discovery
"""

import logging

import nvdlib
import streamlit as st
from requests.exceptions import HTTPError, Timeout

from clients.retry import APIRetryError, retry_with_backoff
from config import API_CONFIG

logger = logging.getLogger(__name__)


class NVDAPIError(Exception):
    """Custom exception for NVD API errors."""


def _fetch_cpe_name(api_key: str, cpe_prefix: str, version: str = "*") -> str | None:
    """Fetch the CPE name for a given technology and version."""
    cpe_match_string = f"{cpe_prefix}{version}:*"

    def _fetch():
        cpe_results = nvdlib.searchCPE(cpeMatchString=cpe_match_string, key=api_key)
        if not cpe_results:
            return None
        cpe = cpe_results[0]
        if cpe.deprecated and cpe.deprecatedBy:
            return cpe.deprecatedBy[0].cpeName
        return cpe.cpeName

    try:
        return retry_with_backoff(_fetch)
    except APIRetryError as e:
        logger.error("Failed to fetch CPE name: %s", e)
        return None


@st.cache_data(ttl=1800, show_spinner=False)
def search_nvd(
    api_key: str,
    cpe_name: str,
    version: str = "*",
    tech: str = "",
    category: str = "",
    top_n: int | None = None,
) -> str:
    """
    Search the NVD for CVEs related to a specific technology.
    Results are cached for 30 minutes.
    """
    top_n = top_n or API_CONFIG.nvd_top_n
    logger.info("Searching NVD for CPE: %s%s | Tech: %s", cpe_name, version, tech)

    resolved_cpe = _fetch_cpe_name(api_key, cpe_name, version)
    if not resolved_cpe:
        return f"No CPE found for {tech} version {version}"

    def _search_cves():
        try:
            cve_results = nvdlib.searchCVE(cpeName=resolved_cpe, key=api_key)
            if not cve_results:
                return []
            sorted_results = sorted(
                cve_results, key=lambda x: (x.score, x.published), reverse=True
            )
            return sorted_results[:top_n]
        except Timeout as e:
            raise NVDAPIError(f"Timeout searching CVEs for {resolved_cpe}") from e
        except HTTPError as e:
            raise NVDAPIError(f"HTTP error searching CVEs: {e}") from e
        except Exception as e:
            raise NVDAPIError(f"Unexpected error searching CVEs: {e}") from e

    try:
        top_results = retry_with_backoff(_search_cves)
    except APIRetryError as e:
        logger.error("Failed to search CVEs: %s", e)
        return f"Error: {e}"

    vulnerabilities = []
    for idx, item in enumerate(top_results):
        try:
            description = item.descriptions[0].value if item.descriptions else "No description available"
            published_date = item.published.split("T")[0] if item.published else "Unknown date"
            cvss_score = item.score if hasattr(item, "score") else "N/A"
            cve_entry = f"""{tech} NVD {idx + 1}
CVE ID: {item.id}
Technology: {tech}
Category: {category}
Version: {version}
CVSS Score: {cvss_score}
Published Date: {published_date}
Description: {description.replace(chr(10), ' ').replace('/', '-')}|"""
            vulnerabilities.append(cve_entry)
        except Exception as e:
            logger.warning("Error processing CVE %d: %s", idx + 1, e)

    if not vulnerabilities:
        return "No vulnerabilities found"
    return "".join(vulnerabilities) + f"\n\nTotal vulnerabilities found: {len(vulnerabilities)}"
