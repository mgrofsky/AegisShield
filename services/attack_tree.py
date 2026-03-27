"""
Attack Tree Generation Service

Generates Mermaid-syntax attack trees for threat visualization.
"""

import logging
import re

from clients.openai_client import chat_completion

logger = logging.getLogger(__name__)

MERMAID_CODE_BLOCK_PATTERN = r"^```mermaid\s*|\s*```$"

ATTACK_TREE_SYSTEM_PROMPT = """
Act as a cyber security expert with more than 20 years of experience using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to use the application description provided to you to produce an attack tree in Mermaid syntax.

The attack tree should reflect the potential threats for the application based on all the details given. You should create multiple levels in the tree to capture the hierarchy of threats and sub-threats, ensuring a very detailed and comprehensive representation of the attack scenarios. Use subgraphs to group related threats for better readability.

You MUST only respond with the Mermaid code block. See below for an example of the required format and syntax for your output.

Please utilize proper terminology and structure to ensure the attack tree is clear, organized, and informative. If a MITRE ATT&CK pattern is mentioned, include the relevant details in the attack tree.

```mermaid
graph LR
    A["Compromise of Application (CIA)"] --> B(Spoofing)
    A --> C(Tampering)
    A --> D(Repudiation)
    A --> E["Information Disclosure"]
    A --> F["Denial of Service (DoS)"]
    A --> G["Elevation of Privilege"]

    subgraph Spoofing Threats
        B[Sub-threat 1: Spoofing]
        B --> B1[Detailed Threat 1.1]
        B --> B2[Detailed Threat 1.2]
    end

    subgraph Tampering Threats
        C[Sub-threat 2: Tampering]
        C --> C1[Detailed Threat 2.1]
    end
```

IMPORTANT: Round brackets are special characters in Mermaid syntax. If you want to use round brackets inside a node label you MUST wrap the label in double quotes. For example, ["Example Node Label (ENL)"].

Application description: {application_description}
"""


def create_attack_tree_prompt(
    app_type: str,
    authentication: str,
    internet_facing: str,
    sensitive_data: str,
    mitre_data: str,
    nvd_vulnerabilities: str,
    otx_vulnerabilities: str,
    app_input: str,
) -> str:
    """Create a prompt for generating an attack tree."""
    return f"""
APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
APPLICATION DESCRIPTION: {app_input}

#STRIDE AND MITRE ATT&CK TTPs:
#{mitre_data}

#NVD VULNERABILITIES:
#{nvd_vulnerabilities}

#ALIENTVAULT OTX CYBER THREAT INTELLIGENCE:
#{otx_vulnerabilities}
"""


def get_attack_tree(prompt: str) -> str | None:
    """
    Generate an attack tree in Mermaid syntax using OpenAI API.

    Returns:
        Cleaned Mermaid code string, or None on error.
    """
    try:
        raw = chat_completion(
            prompt=prompt,
            system_prompt=ATTACK_TREE_SYSTEM_PROMPT,
        )
        # Remove markdown code block delimiters
        return re.sub(MERMAID_CODE_BLOCK_PATTERN, "", raw, flags=re.MULTILINE)
    except Exception as e:
        logger.error("Error generating attack tree: %s", e)
        return None
