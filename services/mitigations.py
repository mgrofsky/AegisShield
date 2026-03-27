"""
Mitigation Generation Service

Generates security mitigation strategies for identified threats.
"""

import logging

from clients.openai_client import chat_completion

logger = logging.getLogger(__name__)


def create_mitigations_prompt(threats: str, mitre_mapping: str, nvd_vulnerabilities: str) -> str:
    """Create a prompt for generating mitigating controls."""
    return f"""
Act as a cybersecurity expert with more than 20 years of experience using the STRIDE threat modeling methodology. Your task is to provide potential mitigations for the threats identified in the threat model. It is crucial that your responses are tailored to reflect the details of the threats.

Please output the results in a markdown table format using the following columns:
    - Column A: Threat Type
    - Column B: Scenario
    - Column C: Suggested Mitigation(s)

Do not use '<br>' or any other HTML tags in your response as a line break and do not use bullet points in a table cell.

Below is the list of identified threats:
{threats}

Below is how they map to the MITRE ATT&CK framework:
{mitre_mapping}

Below are potential vulnerabilities found in the National Vulnerability Database (NVD) that could be exploited by attackers:
{nvd_vulnerabilities}

YOUR RESPONSE (do not wrap in a code block):
"""


def get_mitigations(prompt: str, stream: bool = False):
    """
    Generate mitigations using OpenAI API.

    Args:
        prompt: The mitigations prompt.
        stream: If True, return a streaming iterator.

    Returns:
        Mitigations markdown string, or stream iterator if stream=True.
    """
    return chat_completion(
        prompt=prompt,
        system_prompt="You are a helpful assistant that provides threat mitigation strategies in Markdown format.",
        stream=stream,
    )
