"""
DREAD Risk Assessment Service

Generates DREAD risk assessments for identified threats.
"""

import logging
from typing import Any

from clients.openai_client import chat_completion

logger = logging.getLogger(__name__)


def create_dread_assessment_prompt(threats: str, mitre_mapping: str, nvd_vulnerabilities: str) -> str:
    """Create a prompt for generating a DREAD risk assessment."""
    return f"""
Act as a cyber security expert with more than 20 years of experience in threat modeling using STRIDE and DREAD methodologies.
Your task is to produce a DREAD risk assessment for the threats identified in a threat model.

Below is the list of identified threats (This should be your primary focus):
{threats}

Below is how they map to the MITRE ATT&CK framework (This is supplemental information for context):
{mitre_mapping}

Below are potential vulnerabilities found in the National Vulnerability Database (NVD) that could be exploited by attackers (This is supplemental information for context:
{nvd_vulnerabilities}

When providing the risk assessment, use a JSON formatted response with a top-level key "Risk Assessment" and a list of threats, each with the following sub-keys:
- "Threat Type": A string representing the type of threat (e.g., "Spoofing").
- "Scenario": A string describing the threat scenario.
- "Damage Potential": An integer between 1 and 10.
- "Reproducibility": An integer between 1 and 10.
- "Exploitability": An integer between 1 and 10.
- "Affected Users": An integer between 1 and 10.
- "Discoverability": An integer between 1 and 10.
Assign a value between 1 and 10 for each sub-key based on the DREAD methodology. Use the following scale:
- 1-3: Low
- 4-6: Medium
- 7-10: High
Ensure the JSON response is correctly formatted and does not contain any additional text. Here is an example of the expected JSON response format:
{{
  "Risk Assessment": [
    {{
      "Threat Type": "Spoofing",
      "Scenario": "An attacker could create a fake OAuth2 provider.",
      "Damage Potential": 8,
      "Reproducibility": 6,
      "Exploitability": 5,
      "Affected Users": 9,
      "Discoverability": 7
    }}
  ]
}}
"""


def get_dread_assessment(prompt: str) -> dict[str, Any] | None:
    """
    Generate a DREAD risk assessment using OpenAI API.

    Returns:
        Parsed JSON dict with "Risk Assessment" key, or None on error.
    """
    try:
        return chat_completion(
            prompt=prompt,
            system_prompt="You are a helpful assistant designed to output JSON.",
            json_mode=True,
        )
    except Exception as e:
        logger.error("Error generating DREAD assessment: %s", e)
        return None
