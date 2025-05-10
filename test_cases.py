import logging

from openai import OpenAI

from error_handler import handle_exception

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration constants
DEFAULT_MODEL_NAME = "gpt-4o"

def create_test_cases_prompt(threats: str) -> str:
    """
    Create a prompt for generating Gherkin test cases based on identified threats.
    
    Args:
        threats (str): A string containing the list of identified threats.
        
    Returns:
        str: A formatted prompt for generating Gherkin test cases.
    """
    logger.debug("Creating test cases prompt")
    prompt = f"""
Act as a cyber security expert with more than 20 years experience of using the STRIDE threat modelling methodology.
Your task is to provide Gherkin test cases for the threats identified in a threat model. It is very important that
your responses are tailored to reflect the details of the threats.

Below is the list of identified threats:
{threats}

Use the threat descriptions in the 'Given' steps so that the test cases are specific to the threats identified.
Put the Gherkin syntax inside triple backticks (```) to format the test cases in Markdown. Add a title for each test case.
For example:

    ```gherkin
    Given a user with a valid account
    When the user logs in
    Then the user should be able to access the system
    ```

YOUR RESPONSE (do not add introductory text, just provide the Gherkin test cases):
"""
    return prompt

def get_test_cases(api_key: str, model_name: str | None = None, prompt: str | None = None) -> str:
    """
    Generate test cases using OpenAI's API.
    
    Args:
        api_key (str): OpenAI API key.
        model_name (Optional[str]): Name of the OpenAI model to use. Defaults to DEFAULT_MODEL_NAME.
        prompt (Optional[str]): Prompt for generating test cases.
        
    Returns:
        str: Generated Gherkin test cases in Markdown format.
        
    Raises:
        ValueError: If API key is empty or prompt is empty
        Exception: If there's an error during API call or response processing
    """
    if not api_key:
        handle_exception(ValueError("OpenAI API key is required"), "OpenAI API key is required")
        
    if not prompt:
        handle_exception(ValueError("Prompt is required for test cases generation"), "Prompt is required for test cases generation")
        
    model_name = model_name or DEFAULT_MODEL_NAME
    logger.info(f"Generating test cases using model: {model_name}")
    
    try:
        client = OpenAI(api_key=api_key)
        logger.debug("Created OpenAI client")

        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful assistant that provides Gherkin test cases in Markdown format."
                },
                {"role": "user", "content": prompt},
            ],
        )
        logger.debug("Received response from OpenAI API")

        test_cases = response.choices[0].message.content
        logger.debug("Successfully extracted test cases from response")
        return test_cases

    except Exception as e:
        handle_exception(e, "Failed to generate test cases")