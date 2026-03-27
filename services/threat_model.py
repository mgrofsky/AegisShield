"""
Threat Model Generation Service

Generates STRIDE-based threat models using OpenAI API.
Handles prompt creation and response parsing.
"""

import logging

from clients.openai_client import chat_completion

logger = logging.getLogger(__name__)


def create_threat_model_prompt(
    app_type: str,
    authentication: str,
    internet_facing: str,
    industry_sector: str,
    sensitive_data: str,
    app_input: str,
    nvd_vulnerabilities: str,
    otx_data: str,
    technical_ability: str,
) -> str:
    """Create a prompt for generating a STRIDE threat model."""
    prompt = f"""
Act as a cybersecurity expert in the {industry_sector} sector with more than 20 years of experience using the STRIDE threat modeling methodology to produce comprehensive threat models for a wide range of applications. Your task is to use the application description and additional provided data to produce a list of specific threats for the application.

1. On a scale of Low, Medium, or High, the user's technical ability is: {technical_ability}. Simplify explanations for lower abilities without omitting details. For higher abilities, include all technical aspects; for lower abilities, provide clear, more readable explanations despite their lack of technical experience.

2. For each of the STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege), list a mandatory multiple (3) credible threats per category. Each threat scenario should provide a credible scenario in which the threat could occur in the context of the application. It is very important that your responses are tailored to reflect the details you are given.

3. For each threat scenario, assess the potential impact on data confidentiality, integrity, and availability. Describe how the threat could lead to unauthorized disclosure of sensitive information, corruption or tampering of data, and disruption to system or data access. Not every threat scenario will impact all three aspects, but you should consider each in your analysis.

4. Threat models always have assumptions. For each threat scenario, provide a list of assumptions that must be true for the threat to be realized. Each assumption should include a description of the assumption, the role of the actor making the assumption, and the condition under which the assumption is valid.

5. When providing the threat model, use a JSON-formatted response with the keys "threat_model" and "improvement_suggestions". Under "threat_model", include an array of objects with the keys "Threat Type", "Scenario", "Potential Impact", and "MITRE ATT&CK Keywords".

6. Under "MITRE ATT&CK Keywords", include an array of relevant keywords that accurately represent the threat scenario. These should be a mix of specific and broad terms that capture relevant MITRE ATT&CK techniques. Avoid overly narrow terms and consider including related actions (e.g., "injection," "spoofing") and targets (e.g., "network," "device"). Do NOT include STIX IDs, ATT&CK Reference IDs, or Technique IDs.

7. Ensure that the "Potential Impact" is a concise summary string, not a nested object.

8. Under "improvement_suggestions", include an array of strings with suggestions on how the threat modeler can improve their application description to allow the tool to produce a more comprehensive threat model.

APPLICATION TYPE: {app_type}
INDUSTRY SECTOR: {industry_sector}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
APPLICATION DESCRIPTION: {app_input}

HIGH RISK NVD CVE VULNERABILITIES BELOW BASED ON TECHNOLOGIES USED IN THE APPLICATION:
{nvd_vulnerabilities}

ALIENVAULT OTX PULSE DATA FOR THE INDUSTRY SECTOR:
{otx_data}

Example of expected JSON response format:

{{
  "threat_model": [
    {{
      "Threat Type": "Spoofing",
      "Scenario": "Example Scenario 1",
      "Assumptions": [
        {{"Assumption": "Example Assumption 1", "Role": "Example Role 1", "Condition": "Example Condition 1"}},
        {{"Assumption": "Example Assumption 2", "Role": "Example Role 2", "Condition": "Example Condition 2"}}
      ],
      "Potential Impact": "Example Potential Impact 1",
      "MITRE ATT&CK Keywords": ["Example Keyword 1", "Example Keyword 2", "Example Keyword 3"]
    }}
  ],
  "improvement_suggestions": [
    "Example improvement suggestion 1.",
    "Example improvement suggestion 2."
  ]
}}
"""
    return prompt


def create_image_analysis_prompt() -> str:
    """Create a prompt for analyzing architecture diagrams."""
    return """
    You are a Senior Solution Architect tasked with explaining the following architecture diagram to
    a Security Architect to support the threat modelling of the system.

    In order to complete this task you must:

      1. Analyse the diagram
      2. Explain the system architecture to the Security Architect. Your explanation should cover the key
         components, their interactions, and any technologies used.

    Provide a direct explanation of the diagram in a clear, structured format, suitable for a professional
    discussion.

    IMPORTANT INSTRUCTIONS:
     - Do not include any words before or after the explanation itself. For example, do not start your
    explanation with "The image shows..." or "The diagram shows..." just start explaining the key components
    and other relevant details.
     - Do not infer or speculate about information that is not visible in the diagram. Only provide information that can be
    directly determined from the diagram itself.
    """


def get_threat_model(prompt: str) -> dict | None:
    """
    Generate a threat model using the OpenAI API.

    Args:
        prompt: The threat model generation prompt.

    Returns:
        Parsed JSON response dict, or None on error.
    """
    try:
        return chat_completion(
            prompt=prompt,
            system_prompt="You are a helpful assistant designed to output JSON.",
            json_mode=True,
        )
    except Exception as e:
        logger.error("Error generating threat model: %s", e)
        return None
