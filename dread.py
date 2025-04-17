import re
import json
from openai import OpenAI
import streamlit as st
import logging
from typing import Dict, Any, List, Optional
from error_handler import handle_exception

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration constants
DEFAULT_MODEL_NAME = "gpt-4o"

def dread_json_to_markdown(dread_assessment: Dict[str, Any]) -> str:
    """
    Convert DREAD assessment JSON to a Markdown table.

    Args:
        dread_assessment (Dict[str, Any]): The DREAD assessment in JSON format.

    Returns:
        str: Markdown formatted table of the DREAD assessment.

    Raises:
        TypeError: If a threat is not a dictionary
        Exception: For any other errors during conversion
    """
    logger.debug("Converting DREAD assessment to markdown")
    markdown_output = "| Threat Type | Scenario | Damage Potential | Reproducibility | Exploitability | Affected Users | Discoverability | Risk Score |\n"
    markdown_output += "|-------------|----------|------------------|-----------------|----------------|----------------|-----------------|-------------|\n"
    
    try:
        threats = dread_assessment.get("Risk Assessment", [])
        for threat in threats:
            if isinstance(threat, dict):
                damage_potential = threat.get("Damage Potential", 0)
                reproducibility = threat.get("Reproducibility", 0)
                exploitability = threat.get("Exploitability", 0)
                affected_users = threat.get("Affected Users", 0)
                discoverability = threat.get("Discoverability", 0)

                risk_score = (
                    damage_potential
                    + reproducibility
                    + exploitability
                    + affected_users
                    + discoverability
                ) / 5

                markdown_output += f"| {threat.get('Threat Type', 'N/A')} | {threat.get('Scenario', 'N/A')} | {damage_potential} | {reproducibility} | {exploitability} | {affected_users} | {discoverability} | {risk_score:.2f} |\n"
            else:
                logger.error(f"Invalid threat type: {type(threat)}")
                raise TypeError(f"Expected a dictionary, got {type(threat)}: {threat}")
        logger.debug("Successfully converted DREAD assessment to markdown")
        return markdown_output
    except Exception as e:
        logger.error(f"Error converting DREAD assessment to markdown: {str(e)}")
        st.error(f"Error: {str(e)}")
        raise

def create_dread_assessment_prompt(threats: str, mitre_mapping: str, nvd_vulnerabilities: str) -> str:
    """
    Create a prompt for generating a DREAD risk assessment.
    
    Args:
        threats (str): A string containing the list of identified threats.
        mitre_mapping (str): A string containing the mapping of threats to MITRE ATT&CK framework.
        nvd_vulnerabilities (str): A string containing potential vulnerabilities from the National Vulnerability Database.
        
    Returns:
        str: A formatted prompt for generating a DREAD risk assessment.
    """
    logger.debug("Creating DREAD assessment prompt")
    prompt = f"""
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
      "Scenario": "An attacker could create a fake OAuth2 provider and trick users into logging in through it.",
      "Damage Potential": 8,
      "Reproducibility": 6,
      "Exploitability": 5,
      "Affected Users": 9,
      "Discoverability": 7
    }},
    {{
      "Threat Type": "Spoofing",
      "Scenario": "An attacker could intercept the OAuth2 token exchange process through a Man-in-the-Middle (MitM) attack.",
      "Damage Potential": 8,
      "Reproducibility": 7,
      "Exploitability": 6,
      "Affected Users": 8,
      "Discoverability": 6
    }}
  ]
}}
"""
    return prompt

def get_dread_assessment(api_key: str, model_name: Optional[str] = None, prompt: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate a DREAD risk assessment using OpenAI's API.
    
    Args:
        api_key (str): OpenAI API key.
        model_name (Optional[str]): Name of the OpenAI model to use. Defaults to DEFAULT_MODEL_NAME.
        prompt (Optional[str]): Prompt for generating the DREAD assessment.
        
    Returns:
        Dict[str, Any]: The DREAD assessment in JSON format.
        
    Raises:
        ValueError: If API key is empty or prompt is empty
        Exception: If there's an error during API call or response processing
    """
    if not api_key:
        handle_exception(ValueError("OpenAI API key is required"), "OpenAI API key is required")
        
    if not prompt:
        handle_exception(ValueError("Prompt is required for DREAD assessment generation"), "Prompt is required for DREAD assessment generation")
        
    model_name = model_name or DEFAULT_MODEL_NAME
    logger.info(f"Generating DREAD assessment using model: {model_name}")
    
    try:
        client = OpenAI(api_key=api_key)
        logger.debug("Created OpenAI client")

        response = client.chat.completions.create(
            model=model_name,
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful assistant designed to output JSON."
                },
                {"role": "user", "content": prompt},
            ],
        )
        logger.debug("Received response from OpenAI API")

        try:
            dread_assessment = json.loads(response.choices[0].message.content)
            logger.debug("Successfully parsed DREAD assessment JSON")
            return dread_assessment
        except json.JSONDecodeError as e:
            handle_exception(e, "Failed to parse DREAD assessment JSON")

    except Exception as e:
        handle_exception(e, "Failed to generate DREAD assessment")

