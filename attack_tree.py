import logging
import re

from openai import OpenAI

from error_handler import handle_exception

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration constants
DEFAULT_MODEL_NAME = "gpt-4o"
MERMAID_CODE_BLOCK_PATTERN = r"^```mermaid\s*|\s*```$"


# Function to create a prompt to generate an attack tree
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
    """
    Create a prompt for generating an attack tree based on application details.
    
    Args:
        app_type (str): Type of application
        authentication (str): Authentication methods used
        internet_facing (str): Whether the application is internet-facing
        sensitive_data (str): Types of sensitive data handled
        mitre_data (str): MITRE ATT&CK data
        nvd_vulnerabilities (str): NVD vulnerability data
        otx_vulnerabilities (str): AlienVault OTX threat intelligence data
        app_input (str): Application description
        
    Returns:
        str: Formatted prompt for attack tree generation
    """
    logger.debug("Creating attack tree prompt")
    prompt = f"""
APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
APPLICATION DESCRIPTION: {app_input}

#STRIDE AND MITRE ATT&CK TTPs:
#{mitre_data}

#VD VULNERABILITIES:
#{nvd_vulnerabilities}

#ALIENTVAULT OTX CYBER THREAT INTELLIGENCE:
#{otx_vulnerabilities}
"""
    return prompt


# Function to get attack tree from the GPT response.
def get_attack_tree(api_key: str, model_name: str | None = None, prompt: str | None = None) -> str:
    """
    Generate an attack tree using OpenAI's API.
    
    Args:
        api_key (str): OpenAI API key
        model_name (Optional[str]): Name of the OpenAI model to use. Defaults to DEFAULT_MODEL_NAME
        prompt (Optional[str]): Prompt for generating the attack tree. If None, uses default prompt
        
    Returns:
        str: Generated attack tree in Mermaid syntax
        
    Raises:
        ValueError: If API key is empty or prompt is empty
        Exception: If there's an error during API call or response processing
    """
    if not api_key:
        handle_exception(ValueError("OpenAI API key is required"), "OpenAI API key is required")
        
    if not prompt:
        handle_exception(ValueError("Prompt is required for attack tree generation"), "Prompt is required for attack tree generation")
        
    model_name = model_name or DEFAULT_MODEL_NAME
    logger.info(f"Generating attack tree using model: {model_name}")
    
    try:
        client = OpenAI(api_key=api_key)
        logger.debug("Created OpenAI client")

        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {
                    "role": "system",
                    "content": """
                    Act as a cyber security expert with more than 20 years of experience using the STRIDE threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to use the application description provided to you to produce an attack tree in Mermaid syntax.

                    The attack tree should reflect the potential threats for the application based on all the details given. You should create multiple levels in the tree to capture the hierarchy of threats and sub-threats, ensuring a very detailed and comprehensive representation of the attack scenarios. Use subgraphs to group related threats for better readability.

                    You MUST only respond with the Mermaid code block. See below for an example of the required format and syntax for your output.

                    Please utilize proper terminology and structure to ensure the attack tree is clear, organized, and informative.  If a MITRE ATT&CK pattern is mentioned, include the relevant details in the attack tree.

                    ```mermaid
                    graph LR
                        A["Compromise of Application (CIA)"] --> B(Spoofing)
                        A --> C(Tampering)
                        A --> D(Repudiation)
                        A --> E["Information Disclosure"]
                        A --> F["Denial of Service (DoS)"]
                        A --> G["Elevation of Privilege"]

                        %% Subgraph for Spoofing Threats
                        subgraph Spoofing Threats
                            B[Sub-threat 1: Spoofing]
                            B --> B1[Detailed Threat 1.1]
                            B --> B2[Detailed Threat 1.2]
                            B1 --> B1a[Specific Attack Vector 1.1]
                            B2 --> B2a[Specific Attack Vector 1.2]
                            ...
                            ...
                        end

                        %% Subgraph for Tampering Threats
                        subgraph Tampering Threats
                            C[Sub-threat 2: Tampering]
                            C --> C1[Detailed Threat 2.1]
                            C --> C2[Detailed Threat 2.2]
                            ...
                            ...
                            C1 --> C1a[Specific Attack Vector 2.1]
                            C2 --> C2a[Specific Attack Vector 2.2]
                            ...
                            ...
                        end

                        %% Subgraph for Repudiation Threats
                        subgraph Repudiation Threats
                            D[Sub-threat 3: Repudiation]
                            D --> D1[Detailed Threat 3.1]
                            D --> D2[Detailed Threat 3.2]
                            ...
                            ...
                            D1 --> D1a[Specific Attack Vector 3.1]
                            D2 --> D2a[Specific Attack Vector 3.2]
                            ...
                            ...
                        end

                        %% Subgraph for Information Disclosure Threats
                        subgraph Information Disclosure Threats
                            E[Sub-threat 4: Information Disclosure]
                            E --> E1[Detailed Threat 4.1]
                            E --> E2[Detailed Threat 4.2]
                            ...
                            ...
                            E1 --> E1a[Specific Attack Vector 4.1]
                            E2 --> E2a[Specific Attack Vector 4.2]
                            ...
                            ...
                        end

                        %% Subgraph for Denial of Service Threats
                        subgraph Denial of Service Threats
                            F[Sub-threat 5: Denial of Service]
                            F --> F1[Detailed Threat 5.1]
                            F --> F2[Detailed Threat 5.2]
                            F1 --> F1a[Specific Attack Vector 5.1]
                            F2 --> F2a[Specific Attack Vector 5.2]
                        end

                        %% Subgraph for Elevation of Privilege Threats
                        subgraph Elevation of Privilege Threats
                            G[Sub-threat 6: Elevation of Privilege]
                            G --> G1[Detailed Threat 6.1]
                            G --> G2[Detailed Threat 6.2]
                            ...
                            ...
                            G1 --> G1a[Specific Attack Vector 6.1]
                            G2 --> G2a[Specific Attack Vector 6.2]
                            ...
                            ...
                        end
                    ```

                    IMPORTANT: Round brackets are special characters in Mermaid syntax. If you want to use round brackets inside a node label you MUST wrap the label in double quotes. For example, ["Example Node Label (ENL)"].

                    Application description: {application_description}
                    """
                },
                {"role": "user", "content": prompt},
            ],
        )
        logger.debug("Received response from OpenAI API")

        # Access the 'content' attribute of the 'message' object directly
        attack_tree_code = response.choices[0].message.content
        logger.debug("Extracted attack tree code from response")

        # Remove Markdown code block delimiters using regular expression
        attack_tree_code = re.sub(
            MERMAID_CODE_BLOCK_PATTERN, "", attack_tree_code, flags=re.MULTILINE
        )
        logger.debug("Cleaned attack tree code")

        return attack_tree_code

    except Exception as e:
        handle_exception(e, "Failed to generate attack tree")