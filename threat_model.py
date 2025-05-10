# threat_model.py

import json
import logging
import time
from typing import Any

import requests
import streamlit as st
from openai import OpenAI
from requests.exceptions import RequestException, Timeout

from error_handler import handle_exception

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatModelAPIError(Exception):
    """Custom exception for Threat Model API related errors."""
    pass

def retry_with_backoff(func, max_retries: int = 3, initial_delay: float = 1.0):
    """
    Retry a function with exponential backoff.
    
    Args:
        func: The function to retry
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay between retries in seconds
    
    Returns:
        The result of the function call
    
    Raises:
        ThreatModelAPIError: If all retry attempts fail
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
                handle_exception(ThreatModelAPIError(f"Failed after {max_retries} attempts. Last error: {str(e)}"), "Threat Model API request failed")

def json_to_markdown(threat_model: list[dict[str, Any]], improvement_suggestions: list[str]) -> str:
    """
    Convert threat model JSON to Markdown format for display.
    
    Args:
        threat_model: List of threat model entries
        improvement_suggestions: List of improvement suggestions
    
    Returns:
        Formatted markdown string
    """
    try:
        markdown_output = ""

        # Start the markdown table with headers
        markdown_output += "| Threat Type | Scenario | Potential Impact | Assumptions |\n"
        markdown_output += "|-------------|----------|------------------|-------------|\n"

        # Fill the table rows with the threat model data
        for threat in threat_model:
            assumptions = ""
            try:
                # Handle case where Assumptions might be missing
                assumptions_list = threat.get("Assumptions", [])
                if assumptions_list:
                    for assumption in assumptions_list:
                        try:
                            assumptions += f"- **{assumption.get('Assumption', 'No assumption provided')}** (Role: {assumption.get('Role', 'N/A')}, Condition: {assumption.get('Condition', 'N/A')})<br>"
                        except Exception as e:
                            logger.warning(f"Error processing assumption: {str(e)}")
                            assumptions += "- **Error processing assumption**<br>"
                else:
                    assumptions = "No assumptions provided"
            except Exception as e:
                logger.warning(f"Error processing assumptions for threat: {str(e)}")
                assumptions = "Error processing assumptions"

            markdown_output += f"| {threat.get('Threat Type', 'N/A')} | {threat.get('Scenario', 'N/A')} | {threat.get('Potential Impact', 'N/A')} | {assumptions} |\n"

        markdown_output += "\n# Improvement Suggestions\n\n"
        for suggestion in improvement_suggestions:
            markdown_output += f"- {suggestion}\n"

        return markdown_output
    except Exception as e:
        logger.error(f"Error converting JSON to markdown: {str(e)}")
        return "Error: Unable to format threat model data"


if "threat_model" in st.session_state:
    st.session_state["threat_model_markdown"] = json_to_markdown(
        st.session_state["threat_model"], st.session_state["improvement_suggestions"]
    )


# Example usage:
if "threat_model" in st.session_state:
    st.session_state["threat_model_markdown"] = json_to_markdown(
        st.session_state["threat_model"], st.session_state["improvement_suggestions"]
    )


# Function to create a prompt for generating a threat model


def create_threat_model_prompt(
    app_type,
    authentication,
    internet_facing,
    industry_sector,
    sensitive_data,
    app_input,
    nvd_vulnerabilities,
    otx_data,
    technical_ability,
):
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
    }},
    {{
      "Threat Type": "Spoofing",
      "Scenario": "Example Scenario 2",
      "Assumptions": [
        {{"Assumption": "Example Assumption 3", "Role": "Example Role 3", "Condition": "Example Condition 3"}},
        {{"Assumption": "Example Assumption 4", "Role": "Example Role 4", "Condition": "Example Condition 4"}}
      ],
      "Potential Impact": "Example Potential Impact 2",
      "MITRE ATT&CK Keywords": ["Example Keyword 1", "Example Keyword 2", "Example Keyword 3", "Example Keyword 4"]
    }}
    // ... more threats
  ],
  "improvement_suggestions": [
    "Example improvement suggestion 1.",
    "Example improvement suggestion 2."
    // ... more suggestions
  ]
}}
"""

    # print(prompt)
    # Specify the file name
    #file_name = "output.txt"

    # Open the file in write mode and save the string
   # with open(file_name, "w") as file:
        #file.write(prompt)

    #print(f"String saved to {file_name}")
    return prompt


def create_image_analysis_prompt():
    prompt = """
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
    return prompt


# Function to get analyse uploaded architecture diagrams.
def get_image_analysis(api_key: str, model_name: str, prompt: str, base64_image: str) -> dict[str, Any] | None:
    """
    Analyze an uploaded architecture diagram using the OpenAI API.
    
    Args:
        api_key: OpenAI API key
        model_name: Name of the model to use
        prompt: The prompt for the analysis
        base64_image: Base64 encoded image data
    
    Returns:
        API response content or None if there's an error
    
    Raises:
        ThreatModelAPIError: If there's an error with the API call
    """
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}

    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": prompt},
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"},
                },
            ],
        }
    ]

    payload = {"model": model_name, "messages": messages, "max_tokens": 4000}

    try:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions", headers=headers, json=payload
        )
        response.raise_for_status()  # Raise an HTTPError for bad responses
        response_content = response.json()
        logger.info("Successfully analyzed image")
        return response_content
    except requests.exceptions.HTTPError as http_err:
        handle_exception(http_err, "HTTP error occurred while analyzing image")
        return None
    except Exception as err:
        handle_exception(err, "Error analyzing image")
        return None


# Function to get threat model from the GPT response.
def get_threat_model(api_key: str, model_name: str, prompt: str) -> dict[str, Any]:
    """
    Get threat model from the GPT response.
    
    Args:
        api_key: OpenAI API key
        model_name: Name of the model to use
        prompt: The prompt for generating the threat model
    
    Returns:
        Parsed threat model response
    
    Raises:
        ThreatModelAPIError: If there's an error with the API call or response parsing
    """
    try:
        client = OpenAI(api_key=api_key)

        response = client.chat.completions.create(
            model=model_name,
            response_format={"type": "json_object"},
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful assistant designed to output JSON.",
                },
                {"role": "user", "content": prompt},
            ],
        )

        # Convert the JSON string in the 'content' field to a Python dictionary
        response_content = json.loads(response.choices[0].message.content)
        logger.info("Successfully generated threat model")
        return response_content
    except Exception as e:
        handle_exception(e, "Error generating threat model")
        return None


