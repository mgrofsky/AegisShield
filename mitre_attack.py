from openai import OpenAI
import json
import streamlit as st
import time
import random
import os
import logging
from error_handler import handle_exception

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration constants

# Special case that requires both mobile and enterprise data
MOBILE_APP_TYPES = [
    "Mobile application",
    "5G/Wireless System",
]

ENTERPRISE_APP_TYPES = [
    "Desktop application",
    "Web application",
    "SaaS application",
    "Cloud application",
    "Network application",
    "AI/ML Systems",
    "Blockchain and Cryptocurrency Systems",
    "Messaging application",
    "HPC System",
    "Drone as a Service (DaaS) Application",
]

ICS_APP_TYPES = [
    "ICS or SCADA System",
    "Smart Grid Systems",
    "Industrial Internet of Things (IIoT)",
    "Cyber-Physical System (CPS)",
    "Vehicular Fog Computing (VFC)",
    "Embedded systems",
    "IoT application",
    "Fog Computing",
    "Wearable Devices",
]

# MITRE ATT&CK processing configuration
MAX_TECHNIQUES = 25  # Maximum number of techniques to consider per threat
RATE_LIMIT_SLEEP_MIN = 0  # Minimum seconds to sleep between API calls
RATE_LIMIT_SLEEP_MAX = 5  # Maximum seconds to sleep between API calls

def fetch_mitre_attack_data(app_type):
    """
    Fetches MITRE ATT&CK data based on the application type.

    Args:
    app_type (str): The type of application for which to fetch MITRE ATT&CK data.

    Returns:
    dict: The loaded STIX data or None if there was an error.
    """
    logger.info(f"Fetching MITRE ATT&CK data for app_type: {app_type}")

    try:
        if app_type in MOBILE_APP_TYPES:
            with open("./MITRE_ATTACK_DATA/mobile-attack.json", "r") as mobile_file, open(
                "./MITRE_ATTACK_DATA/enterprise-attack.json", "r"
            ) as enterprise_file:
                mobile_data = json.load(mobile_file)
                enterprise_data = json.load(enterprise_file)
                stix_data = enterprise_data
                stix_data["objects"].extend(mobile_data["objects"])
                logger.info("Successfully loaded mobile and enterprise attack data")

        elif app_type in ENTERPRISE_APP_TYPES:
            with open("./MITRE_ATTACK_DATA/enterprise-attack.json", "r") as file:
                stix_data = json.load(file)
                logger.info("Successfully loaded enterprise attack data")

        elif app_type in ICS_APP_TYPES:
            with open("./MITRE_ATTACK_DATA/ics-attack.json", "r") as ics_file, open(
                "./MITRE_ATTACK_DATA/enterprise-attack.json", "r"
            ) as enterprise_file:
                ics_data = json.load(ics_file)
                enterprise_data = json.load(enterprise_file)
                stix_data = enterprise_data
                stix_data["objects"].extend(ics_data["objects"])
                logger.info("Successfully loaded ICS and enterprise attack data")

        else:
            with open("./MITRE_ATTACK_DATA/enterprise-attack.json", "r") as file:
                stix_data = json.load(file)
                logger.info("Successfully loaded enterprise attack data")

        return stix_data

    except FileNotFoundError as e:
        handle_exception(e, "Required MITRE ATT&CK data file not found")
    except json.JSONDecodeError as e:
        handle_exception(e, "Invalid JSON format in MITRE ATT&CK data file")
    except Exception as e:
        handle_exception(e, "Unexpected error while loading MITRE ATT&CK data")

def map_attack_pattern_to_technique(stix_data):
    """
    Map attack pattern IDs to MITRE ATT&CK technique IDs (T####).
    
    Args:
        stix_data (dict): The STIX data containing attack patterns and their references.
    
    Returns:
        dict: A mapping of attack pattern IDs to MITRE ATT&CK technique IDs.
    """
    logger.info("Starting attack pattern to technique mapping")
    attack_pattern_to_technique = {}
    
    try:
        if not stix_data or 'objects' not in stix_data:
            logger.warning("No objects found in STIX data")
            return attack_pattern_to_technique

        # Iterate through each object in the STIX data
        for obj in stix_data.get('objects', []):
            if obj.get('type') == 'attack-pattern':  # Look for attack-pattern objects
                attack_pattern_id = obj.get('id')
                if not attack_pattern_id:
                    logger.warning("Found attack pattern object without ID")
                    continue
                    
                external_refs = obj.get('external_references', [])

                # Loop through external references to find the MITRE ATT&CK technique ID
                for ref in external_refs:
                    if ref.get('source_name') == 'mitre-attack' and 'external_id' in ref:
                        technique_id = ref['external_id']  # Technique ID (T####)
                        attack_pattern_to_technique[attack_pattern_id] = technique_id
                        break  # Stop after finding the technique ID

        logger.info(f"Successfully mapped {len(attack_pattern_to_technique)} attack patterns to techniques")
        return attack_pattern_to_technique

    except Exception as e:
        handle_exception(e, "Error mapping attack patterns to techniques")

def process_mitre_attack_data(stix_data, threat_model, app_details, openai_api_key):
    """
    Process MITRE ATT&CK data to map threats to relevant techniques.
    
    Args:
        stix_data (dict): The STIX data containing attack patterns
        threat_model (list): List of threats from the threat model
        app_details (dict): Application details for context
        openai_api_key (str): OpenAI API key for technique selection
    
    Returns:
        list: Processed data with threats mapped to relevant MITRE ATT&CK techniques
    """
    logger.info("Starting MITRE ATT&CK data processing")
    processed_data = []

    try:
        # Validate inputs
        if not stix_data or 'objects' not in stix_data:
            handle_exception(ValueError("Invalid STIX data structure"), "Invalid STIX data structure")
            return processed_data

        if not threat_model:
            logger.warning("No threats provided in threat model")
            return processed_data

        if not app_details:
            handle_exception(ValueError("No application details provided"), "No application details provided")
            return processed_data

        # Map from attack pattern ID to MITRE ATT&CK Technique ID (T####)
        logger.info("Mapping attack patterns to techniques")
        attack_pattern_to_technique = map_attack_pattern_to_technique(stix_data)

        for threat in threat_model:
            try:
                relevant_techniques = []
                keywords = threat.get("MITRE ATT&CK Keywords", [])
                logger.debug(f"Processing threat with keywords: {keywords}")

                if not keywords:
                    logger.debug("No keywords found for threat, skipping")
                    processed_data.append(
                        {
                            "threat": threat,
                            "mitre_techniques": [],
                        }
                    )
                    continue

                # Match relevant attack patterns based on keywords
                for obj in stix_data["objects"]:
                    if obj["type"] == "attack-pattern":
                        name = obj.get("name", "").lower()
                        description = obj.get("description", "").lower()

                        # Check if any keyword matches the attack pattern name or description
                        for keyword in keywords:
                            if keyword.lower() in name or keyword.lower() in description:
                                relevant_techniques.append(
                                    {
                                        "name": obj["name"],
                                        "description": obj.get("description", "No description available"),
                                        "id": obj["id"],  # STIX Attack Pattern ID
                                    }
                                )
                                break  # Stop after the first match

                # Keep the top N relevant techniques
                relevant_techniques = relevant_techniques[:MAX_TECHNIQUES]
                logger.debug(f"Found {len(relevant_techniques)} relevant techniques for threat")

                # Create prompt and get the top technique using OpenAI
                prompt = create_mitre_prompt(app_details, threat, relevant_techniques)
                random_integer = random.randint(RATE_LIMIT_SLEEP_MIN, RATE_LIMIT_SLEEP_MAX)
                logger.debug(f"Sleeping for {random_integer} seconds to avoid rate limiting")
                time.sleep(random_integer)  # This and the above line are added to alleviate OpenAI API exceptions

                try:
                    top_1_id = get_relevant_techniques(prompt, openai_api_key)
                    logger.debug(f"Selected top technique ID: {top_1_id}")

                    # Retrieve the corresponding MITRE ATT&CK Technique ID for the Top 1 attack pattern ID
                    technique_id = attack_pattern_to_technique.get(top_1_id[0], "N/A")  # Get Technique ID

                    # Add the Top 1 technique and the corresponding MITRE ATT&CK Technique ID
                    top_1_technique = [
                        {
                            "name": next((tech['name'] for tech in relevant_techniques if tech["id"] == top_1_id[0]), "Unknown"),
                            "description": next((tech['description'] for tech in relevant_techniques if tech["id"] == top_1_id[0]), "No description available"),
                            "id": top_1_id[0],  # Keep the original STIX Attack Pattern ID
                            "technique_id": technique_id  # Add MITRE ATT&CK Technique ID
                        }
                    ]

                    processed_data.append(
                        {
                            "threat": threat,
                            "mitre_techniques": top_1_technique,  # Return the selected technique with its details
                        }
                    )

                except Exception as e:
                    handle_exception(e, "Error processing threat technique selection")
                    processed_data.append(
                        {
                            "threat": threat,
                            "mitre_techniques": [],
                        }
                    )

            except Exception as e:
                handle_exception(e, "Error processing threat")
                processed_data.append(
                    {
                        "threat": threat,
                        "mitre_techniques": [],
                    }
                )

        return processed_data

    except Exception as e:
        handle_exception(e, "Error processing MITRE ATT&CK data")
        return processed_data

def create_mitre_prompt(app_details, threat, techniques):
    #print("create_mitre_prompt called")
    """
    Create a prompt for ChatGPT to determine which technique is most relevant.

    Args:
    app_details (dict): The application details from Streamlit session state.
    threat (dict): The threat dictionary from the threat model.
    techniques (list): The top 25 techniques as determined by the keyword match.

    Returns:
    str: The prompt to send to ChatGPT.
    """
    technique_descriptions = [{"id": tech["id"], "name": tech["name"], "description": tech["description"]} for tech in techniques]

    prompt = f"""
You are to respond in a very specific format. Do not include any additional text, explanations, or context. Only output the JSON array as specified below.

Act as a cybersecurity expert in the {app_details['industry_sector']} sector with more than 20 years of experience using the STRIDE threat modeling methodology.
Your task is to analyze the following threat scenario and select the single most relevant MITRE ATT&CK attack pattern from the provided list of 25.

APPLICATION TYPE: {app_details['app_type']}
INDUSTRY SECTOR: {app_details['industry_sector']}
AUTHENTICATION METHODS: {app_details['authentication']}
INTERNET FACING: {app_details['internet_facing']}
SENSITIVE DATA: {app_details['sensitive_data']}
APPLICATION DESCRIPTION: {app_details['app_input']}

Threat Scenario:
{json.dumps(threat, indent=2)}

MITRE ATT&CK Techniques:
{json.dumps(technique_descriptions, indent=2)}

Your response should **ONLY** include the single most relevant MITRE ATT&CK Attack Pattern ID from the above MITRE ATT&CK Techniques, in a JSON array format like this:

["attack-pattern--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"]

If none of the provided techniques are a perfect match, select the closest one. If there truly is no relevant match, respond with ["attack-pattern--00000000-0000-0000-0000-000000000000"].
"""
    return prompt

def get_relevant_techniques(prompt,openai_api_key):
    #print("OPENAI: get_relevant_techniques called")
    """
    Generate relevant MITRE ATT&CK techniques using OpenAI's API.

    Args:
    prompt (str): Prompt for generating relevant attack patterns.

    Returns:
    list: The ID of the most relevant attack patterns as determined by ChatGPT.
    """
    client = OpenAI(api_key=openai_api_key)

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": "You are a cybersecurity expert helping to identify the most relevant MITRE ATT&CK attack patterns.",
            },
            {"role": "user", "content": prompt},
        ],

    )

    response_content = response.choices[0].message.content.strip()

    # Clean the response to remove any markdown formatting or code block identifiers
    if response_content.startswith("```json"):
        response_content = response_content[7:]  # Remove the starting ```json
    if response_content.endswith("```"):
        response_content = response_content[:-3]  # Remove the ending ````

    try:
        top_1_id = json.loads(response_content)
    except json.JSONDecodeError:
        print(f"Error parsing JSON from response: {response_content}")
        top_1_id = []

    # Ensure the result is a list with exactly 1 ID
    if isinstance(top_1_id, list):
        if len(top_1_id) == 1:
            return top_1_id
        elif len(top_1_id) == 0:
            print("Warning: The response returned an empty list.")
            return ["attack-pattern--00000000-0000-0000-0000-000000000000"]  # Handle empty case
        else:
            print(f"Unexpected length of list in response: {len(top_1_id)}")
            return []  # Handle unexpected length
    else:
        print(f"Unexpected format in response: {response_content}")
        print(f"top_1_id: {top_1_id}, Type: {type(top_1_id)}")  # Print the top_1_id and its type for debugging
        return []  # Return an empty list or handle as needed
