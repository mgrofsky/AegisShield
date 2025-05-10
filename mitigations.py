import logging

from openai import OpenAI

from error_handler import handle_exception

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration constants
DEFAULT_MODEL_NAME = "gpt-4o"

def create_mitigations_prompt(threats: str, mitre_mapping: str, nvd_vulnerabilities: str) -> str:
    """
    Create a prompt for generating mitigating controls based on identified threats, MITRE ATT&CK mapping, and NVD vulnerabilities.
    
    Args:
        threats (str): A string containing the list of identified threats.
        mitre_mapping (str): A string containing the mapping of threats to MITRE ATT&CK framework.
        nvd_vulnerabilities (str): A string containing potential vulnerabilities from the National Vulnerability Database.
        
    Returns:
        str: A formatted prompt for generating mitigating controls.
    """
    logger.debug("Creating mitigations prompt")
    prompt = f"""
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
    return prompt

def get_mitigations(api_key: str, model_name: str | None = None, prompt: str | None = None) -> str:
    """
    Generate mitigations using OpenAI's API.
    
    Args:
        api_key (str): OpenAI API key.
        model_name (Optional[str]): Name of the OpenAI model to use. Defaults to DEFAULT_MODEL_NAME.
        prompt (Optional[str]): Prompt for generating mitigations.
        
    Returns:
        str: Generated mitigations in Markdown format.
        
    Raises:
        ValueError: If API key is empty or prompt is empty
        Exception: If there's an error during API call or response processing
    """
    if not api_key:
        handle_exception(ValueError("OpenAI API key is required"), "OpenAI API key is required")
        
    if not prompt:
        handle_exception(ValueError("Prompt is required for mitigations generation"), "Prompt is required for mitigations generation")
        
    model_name = model_name or DEFAULT_MODEL_NAME
    logger.info(f"Generating mitigations using model: {model_name}")
    
    try:
        client = OpenAI(api_key=api_key)
        logger.debug("Created OpenAI client")

        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful assistant that provides threat mitigation strategies in Markdown format."
                },
                {"role": "user", "content": prompt},
            ],
        )
        logger.debug("Received response from OpenAI API")

        mitigations = response.choices[0].message.content
        logger.debug("Successfully extracted mitigations from response")
        return mitigations

    except Exception as e:
        handle_exception(e, "Failed to generate mitigations")


