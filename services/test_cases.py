"""
Test Case Generation Service

Generates Gherkin-format test cases for identified threats.
"""

import logging

from clients.openai_client import chat_completion

logger = logging.getLogger(__name__)


def create_test_cases_prompt(threats: str) -> str:
    """Create a prompt for generating Gherkin test cases."""
    return f"""
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


def get_test_cases(prompt: str, stream: bool = False):
    """
    Generate Gherkin test cases using OpenAI API.

    Args:
        prompt: The test cases prompt.
        stream: If True, return a streaming iterator.

    Returns:
        Test cases markdown string, or stream iterator if stream=True.
    """
    return chat_completion(
        prompt=prompt,
        system_prompt="You are a helpful assistant that provides Gherkin test cases in Markdown format.",
        stream=stream,
    )
