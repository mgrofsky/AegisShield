"""
MITRE ATT&CK Integration Service

Fetches and processes MITRE ATT&CK data, mapping threats to relevant techniques.
Uses caching for the large STIX JSON files.

NIST SP 800-53 Rev. 5 Control Mappings:
- RA-3: Risk Assessment - Threat intelligence integration
"""

import json
import logging
import random
import time
from pathlib import Path

import streamlit as st

from clients.openai_client import chat_completion
from config import API_CONFIG
from data.technology_types import ICS_APP_TYPES, MOBILE_APP_TYPES
from utils.error_handler import handle_exception

logger = logging.getLogger(__name__)

MITRE_DATA_DIR = Path("./MITRE_ATTACK_DATA")


@st.cache_data(ttl=3600, show_spinner="Loading MITRE ATT&CK data...")
def fetch_mitre_attack_data(app_type: str) -> dict | None:
    """
    Fetch MITRE ATT&CK STIX data based on the application type.
    Results are cached for 1 hour.
    """
    logger.info("Fetching MITRE ATT&CK data for app_type: %s", app_type)
    try:
        enterprise_path = MITRE_DATA_DIR / "enterprise-attack.json"

        if app_type in MOBILE_APP_TYPES:
            mobile_path = MITRE_DATA_DIR / "mobile-attack.json"
            with open(enterprise_path) as ef, open(mobile_path) as mf:
                enterprise_data = json.load(ef)
                mobile_data = json.load(mf)
                enterprise_data["objects"].extend(mobile_data["objects"])
                return enterprise_data

        elif app_type in ICS_APP_TYPES:
            ics_path = MITRE_DATA_DIR / "ics-attack.json"
            with open(enterprise_path) as ef, open(ics_path) as icf:
                enterprise_data = json.load(ef)
                ics_data = json.load(icf)
                enterprise_data["objects"].extend(ics_data["objects"])
                return enterprise_data

        else:
            with open(enterprise_path) as ef:
                return json.load(ef)

    except FileNotFoundError as e:
        handle_exception(e, "Required MITRE ATT&CK data file not found")
    except json.JSONDecodeError as e:
        handle_exception(e, "Invalid JSON format in MITRE ATT&CK data file")
    except Exception as e:
        handle_exception(e, "Unexpected error while loading MITRE ATT&CK data")
    return None


def map_attack_pattern_to_technique(stix_data: dict) -> dict[str, str]:
    """Map attack pattern IDs to MITRE ATT&CK technique IDs (T####)."""
    mapping = {}
    if not stix_data or "objects" not in stix_data:
        return mapping

    for obj in stix_data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            attack_id = obj.get("id")
            if not attack_id:
                continue
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and "external_id" in ref:
                    mapping[attack_id] = ref["external_id"]
                    break

    logger.info("Mapped %d attack patterns to techniques", len(mapping))
    return mapping


def _create_mitre_prompt(app_details: dict, threat: dict, techniques: list[dict]) -> str:
    """Create prompt for selecting the most relevant MITRE technique."""
    technique_descriptions = [
        {"id": t["id"], "name": t["name"], "description": t["description"]}
        for t in techniques
    ]
    return f"""
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


def _get_relevant_technique(prompt: str) -> list[str]:
    """Get the most relevant technique ID from OpenAI."""
    raw = chat_completion(
        prompt=prompt,
        system_prompt="You are a cybersecurity expert helping to identify the most relevant MITRE ATT&CK attack patterns.",
    )
    content = raw.strip()
    # Clean markdown formatting
    if content.startswith("```json"):
        content = content[7:]
    if content.endswith("```"):
        content = content[:-3]

    try:
        result = json.loads(content)
    except json.JSONDecodeError:
        logger.warning("Error parsing technique selection JSON: %s", content)
        return ["attack-pattern--00000000-0000-0000-0000-000000000000"]

    if isinstance(result, list) and len(result) == 1:
        return result
    if isinstance(result, list) and len(result) == 0:
        return ["attack-pattern--00000000-0000-0000-0000-000000000000"]
    return []


def process_mitre_attack_data(
    stix_data: dict, threat_model: list, app_details: dict
) -> list[dict]:
    """
    Process MITRE ATT&CK data to map threats to relevant techniques.

    Args:
        stix_data: STIX data containing attack patterns.
        threat_model: List of threats from the threat model.
        app_details: Application details for context.

    Returns:
        List of dicts with 'threat' and 'mitre_techniques' keys.
    """
    logger.info("Starting MITRE ATT&CK data processing")
    processed_data = []

    if not stix_data or "objects" not in stix_data or not threat_model or not app_details:
        return processed_data

    attack_pattern_to_technique = map_attack_pattern_to_technique(stix_data)

    for threat in threat_model:
        try:
            keywords = threat.get("MITRE ATT&CK Keywords", [])
            if not keywords:
                processed_data.append({"threat": threat, "mitre_techniques": []})
                continue

            # Match relevant attack patterns based on keywords
            relevant_techniques = []
            for obj in stix_data["objects"]:
                if obj["type"] == "attack-pattern":
                    name = obj.get("name", "").lower()
                    description = obj.get("description", "").lower()
                    for keyword in keywords:
                        if keyword.lower() in name or keyword.lower() in description:
                            relevant_techniques.append({
                                "name": obj["name"],
                                "description": obj.get("description", "No description available"),
                                "id": obj["id"],
                            })
                            break

            relevant_techniques = relevant_techniques[:API_CONFIG.mitre_max_techniques]

            # Rate limit mitigation
            sleep_time = random.randint(API_CONFIG.mitre_rate_limit_min, API_CONFIG.mitre_rate_limit_max)
            if sleep_time > 0:
                time.sleep(sleep_time)

            prompt = _create_mitre_prompt(app_details, threat, relevant_techniques)
            top_1_id = _get_relevant_technique(prompt)

            if top_1_id:
                technique_id = attack_pattern_to_technique.get(top_1_id[0], "N/A")
                top_technique = [{
                    "name": next((t["name"] for t in relevant_techniques if t["id"] == top_1_id[0]), "Unknown"),
                    "description": next((t["description"] for t in relevant_techniques if t["id"] == top_1_id[0]), "No description available"),
                    "id": top_1_id[0],
                    "technique_id": technique_id,
                }]
                processed_data.append({"threat": threat, "mitre_techniques": top_technique})
            else:
                processed_data.append({"threat": threat, "mitre_techniques": []})

        except Exception as e:
            handle_exception(e, "Error processing threat")
            processed_data.append({"threat": threat, "mitre_techniques": []})

    return processed_data
