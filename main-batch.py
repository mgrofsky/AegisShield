import os
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threat_model import (
    create_threat_model_prompt,
    get_threat_model,
)
from mitre_attack import (
    fetch_mitre_attack_data,
    process_mitre_attack_data,
)
from nvd_search import search_nvd
from alientvault_search import fetch_otx_data
from error_handler import handle_exception

# Attempting to import sensitive configuration keys from 'local_config.py'.
try:
    import local_config as conf
    default_nvd_api_key = conf.default_nvd_api_key
    default_openai_api_key = conf.default_openai_api_key
    default_alienvault_api_key = conf.default_alienvault_api_key
    selected_model = "gpt-4o"  # The OpenAI model selected for threat modeling
except ImportError as e:
    handle_exception(e, "local_config.py not found or missing keys")
    exit(1)

# Global variables defining the number of batches to process and the number of parallel threads to use.
batches = 30
workers = 3
retries = 6

# Global variable to control which case study to run
# Set this to a specific number, like 1, to run a single case study, or set to None to run all case studies
SPECIFIC_CASE_STUDY = None # Change to None if you want to run all case studies

# Batch processing loop
if SPECIFIC_CASE_STUDY:
    case_studies = [SPECIFIC_CASE_STUDY]  # Run only the specified case study
else:
    case_studies = range(1, 16)  # Loop over all case studies if SPECIFIC_CASE_STUDY is None



# Error logging function
def log_error(case_study, batch_number, error_message):
    """
    Logs an error message related to a specific case study and batch.

    Args:
        case_study (int): The case study number.
        batch_number (int/str): The batch number or "N/A" if not applicable.
        error_message (str): The error message to log.

    Writes:
        Appends the error message to 'error_log.txt'.
    """
    log_file = "error_log.txt"
    with open(log_file, "a") as log:
        log.write(f"Error in Case Study {case_study}, Batch {batch_number}: {error_message}\n")

# Validation function to ensure the threat model has 18 threats, 3 from each STRIDE category
def validate_threat_model(threat_model):
    """
    Validates that the threat model contains exactly 18 threats, with 3 from each STRIDE category.

    Args:
        threat_model (list): List of threat objects generated from the threat model.

    Returns:
        bool: True if the threat model is valid (3 threats per STRIDE category), False otherwise.
    """
    stride_categories = {"Spoofing": 0, "Tampering": 0, "Repudiation": 0, "Information Disclosure": 0, "Denial of Service": 0, "Elevation of Privilege": 0}
    for threat in threat_model:
        threat_type = threat.get("Threat Type", "").strip()
        if threat_type in stride_categories:
            stride_categories[threat_type] += 1
        else:
            print(f"Unexpected threat type found: {threat_type}")
    valid = all(count == 3 for count in stride_categories.values())
    print(f"Validation result: {valid}")
    print(f"Threats by category: {stride_categories}")
    return valid

# Function to load application details from JSON file
def load_app_details_from_file(file_path):
    """
    Loads application details from a specified JSON file.

    Args:
        file_path (str): The path to the JSON file containing application details.

    Returns:
        dict: A dictionary containing the application's details.
    """
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return {
            'app_input': data.get('app_input', ""),
            'app_type': data.get('app_type', "Unknown"),
            'industry_sector': data.get('industry_sector', "Unknown"),
            'sensitive_data': data.get('sensitive_data', "Unknown"),
            'internet_facing': data.get('internet_facing', "Unknown"),
            'num_employees': data.get('num_employees', "Unknown"),
            'compliance_requirements': data.get('compliance_requirements', []),
            'technical_ability': data.get('technical_ability', "Medium"),
            'authentication': data.get('authentication', []),
            'selected_technologies': data.get('selected_technologies', {}),
            'selected_versions': data.get('selected_versions', {})
        }
    except Exception as e:
        handle_exception(e, f"Error loading application details from {file_path}")

def fetch_and_process_mitre_data(app_details, threat_model, openai_api_key):
    """
    Fetches and processes MITRE ATT&CK data, with retries on failure.

    Args:
        app_details (dict): Details about the application being threat modeled.
        threat_model (list): List of threats in the threat model.
        openai_api_key (str): API key for OpenAI's GPT model.

    Returns:
        dict or None: Processed MITRE ATT&CK data if successful, otherwise None after retry attempts.
    """
    for attempt in range(retries):
        print(f"Step 5 (Attempt {attempt + 1}/{retries}): Fetching MITRE ATT&CK data...")
        try:
            stix_data = fetch_mitre_attack_data(app_details['app_type'])
            if stix_data:
                print("STIX data fetched, processing MITRE ATT&CK data...")
                mitre_data = process_mitre_attack_data(stix_data, threat_model, app_details, openai_api_key)
                print("MITRE ATT&CK data processed successfully.")
                return mitre_data
            else:
                handle_exception(ValueError("STIX data is None"), "Failed to fetch MITRE ATT&CK data")
                if attempt < retries - 1:
                    print(f"Retrying MITRE ATT&CK data fetch... (Attempt {attempt + 1}/{retries})")
                    time.sleep(2 ** attempt)  # Sleep before retrying
                else:
                    print("Max retries reached. MITRE ATT&CK data fetch failed.")
                    return None
        except Exception as e:
            handle_exception(e, "Error fetching or processing MITRE ATT&CK data")
            if attempt < retries - 1:
                print(f"Retrying MITRE ATT&CK data fetch... (Attempt {attempt + 1}/{retries})")
                time.sleep(2 ** attempt)
            else:
                print("Max retries reached. MITRE ATT&CK data fetch failed.")
                return None


# Core function to process a batch, generate a threat model, and handle retries
def process_batch(case_number, batch_iteration, app_details, nvd_vulnerabilities, otx_vulnerabilities):
    """
    Processes a single batch for a specific case study, generating a threat model and fetching MITRE ATT&CK data.

    Args:
        case_number (int): The case study number being processed.
        batch_iteration (int): The iteration number for the current batch.
        app_details (dict): Details of the application being modeled.
        nvd_vulnerabilities (dict): NVD vulnerabilities fetched for the application.
        otx_vulnerabilities (str): OTX vulnerabilities fetched for the application.

    Returns:
        dict or None: A dictionary with batch results if successful, None if failed after retries.
    """
    for attempt in range(retries):
        try:
            print(f"Step 3 (Batch {batch_iteration}): Generating threat model prompt for Case Study {case_number}...")
            threat_model_prompt = create_threat_model_prompt(
                app_details['app_type'],
                app_details['authentication'],
                app_details['internet_facing'],
                app_details['industry_sector'],
                app_details['sensitive_data'],
                app_details['app_input'],
                nvd_vulnerabilities,
                otx_vulnerabilities,
                app_details['technical_ability']
            )
            print("Threat model prompt generated.")

            # Generate and validate the threat model
            threat_model = []
            for attempt in range(retries):
                print("Step 4: Generating threat model...")
                model_output = get_threat_model(default_openai_api_key, selected_model, threat_model_prompt)
                threat_model = model_output.get("threat_model", [])
                if validate_threat_model(threat_model):
                    print("Valid threat model with 18 threats (3 from each STRIDE category).")
                    break
                else:
                    print("Invalid threat model. Regenerating...")
                    time.sleep(2)
            else:
                handle_exception(ValueError("Failed to generate valid threat model"), f"Failed to generate valid threat model for Case Study {case_number} after {retries} attempts")
                return None

            # Fetch and process MITRE ATT&CK data
            mitre_data = fetch_and_process_mitre_data(app_details, threat_model, default_openai_api_key)

            # Dynamically build the batch output based on generated threats
            batch_output = {
                "case_number": str(case_number),
                "batch_number": f"{batch_iteration}",
                "threats": []
            }

            # Loop over the threat model to generate the required output structure
            for i, threat in enumerate(threat_model):
                mitre_technique = {"name": "Unknown", "description": "Unknown", "id": "", "technique_id": ""}

                # Ensure there is relevant MITRE data for this threat
                if mitre_data and len(mitre_data) > i:
                    relevant_mitre = mitre_data[i].get('mitre_techniques', [])
                    if relevant_mitre:
                        mitre_technique = relevant_mitre[0]  # Take the first relevant technique

                threat_output = {
                    "Threat Type": threat.get("Threat Type", "Unknown"),  # Dynamic threat type
                    "Scenario": threat.get("Scenario", "Unknown"),  # Dynamic scenario
                    "Assumptions": [
                        {
                            "Assumption": assumption.get("Assumption", "Unknown"),
                            "Role": assumption.get("Role", "Unknown"),
                            "Condition": assumption.get("Condition", "Unknown")
                        }
                        for assumption in threat.get("Assumptions", [])
                    ],
                    "Potential Impact": threat.get("Potential Impact", "Unknown"),  # Dynamic potential impact
                    "MITRE ATT&CK Keywords": threat.get("MITRE ATT&CK Keywords", []),  # Dynamic MITRE ATT&CK keywords
                    "mitre_technique": mitre_technique  # Populated dynamically from MITRE ATT&CK data
                }

                # Append each threat to the list of threats in the batch output
                batch_output["threats"].append(threat_output)

            print(f"Batch {batch_iteration} completed successfully.\n")
            return batch_output

        except Exception as e:
            error_message = f"Attempt {attempt+1}: Error generating threat model for file Case-Study-{case_number}, batch {batch_iteration}: {e}"
            print(error_message)
            if attempt < retries - 1:
                print(f"Retrying... ({attempt+1}/{retries})")
                time.sleep(2 ** attempt)
            else:
                handle_exception(e, error_message)
                print(f"Max retries reached for file Case-Study-{case_number}, batch {batch_iteration}. Moving on.")
                return None


# Batch processing loop
for i in case_studies:
    json_file = f"Case-Study-{i}-schema.json"
    output_file = f"Case-Study-{i}-results.json"
    file_path_input = os.path.join("batch_inputs", json_file)
    output_filepath = os.path.join("batch_outputs", output_file)

    print(f"\n=== Processing file: {json_file} ===")

    try:
        app_details = load_app_details_from_file(file_path_input)
    except FileNotFoundError:
        print(f"File {json_file} not found, skipping...")
        log_error(i, "N/A", f"File {json_file} not found.")
        continue
    except Exception as e:
        print(f"Error loading app details from {json_file}: {e}")
        log_error(i, "N/A", f"Error loading app details: {e}")
        continue

    print("Fetching AlienVault OTX data...")
    otx_vulnerabilities = ""
    if default_alienvault_api_key:
        try:
            otx_vulnerabilities_raw = fetch_otx_data(default_alienvault_api_key, industry=app_details['industry_sector'], max_results=10)
            otx_vulnerabilities = otx_vulnerabilities_raw.replace('|', '\n\n')
            print("AlienVault OTX data fetched successfully.")
        except Exception as e:
            print(f"Error fetching OTX data: {e}")
            log_error(i, "N/A", f"Error fetching OTX data: {e}")
    else:
        print("AlienVault API key missing. Skipping OTX search.")

    print("Fetching NVD vulnerabilities...")
    nvd_vulnerabilities = {}
    if default_nvd_api_key and app_details['selected_technologies']:
        try:
            for tech, cpe_name in app_details['selected_technologies'].items():
                version = app_details['selected_versions'].get(tech, "*")
                vulnerabilities = search_nvd(default_nvd_api_key, cpe_name, version, tech, app_details['app_type'])
                if vulnerabilities:
                    nvd_vulnerabilities[f"{tech} {version}"] = vulnerabilities
            print("NVD vulnerabilities fetched successfully.")
        except Exception as e:
            print(f"Error fetching NVD data: {e}")
            log_error(i, "N/A", f"Error fetching NVD data: {e}")
    else:
        print("No technologies selected or NVD API key missing. Skipping NVD search.")

    results = []

    with open(output_filepath, "w") as outfile:
        outfile.write("[\n")

    first_batch = True
    from concurrent.futures import TimeoutError

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(process_batch, i, batch_iteration, app_details, nvd_vulnerabilities, otx_vulnerabilities)
            for batch_iteration in range(1, batches + 1)
        ]

        try:
            for future in as_completed(futures, timeout=3600):
                try:
                    result = future.result()
                    if result:
                        batch_number = result['batch_number']
                        with open(output_filepath, "a") as outfile:
                            if not first_batch:
                                outfile.write(",\n")
                            json.dump(result, outfile, indent=4)
                            outfile.flush()
                            print(f"Batch {batch_number} written to {output_filepath}")
                            first_batch = False
                        results.append(result)  # Save for later validation
                except Exception as e:
                    print(f"Error processing batch: {e}")
        except TimeoutError as e:
            print(f"Timeout: {e} - Some batches did not complete within the timeout limit.")
            for future in futures:
                if not future.done():
                    print("Unfinished future:", future)

    # Ensure the final closing of the JSON array
    with open(output_filepath, "a") as outfile:
        outfile.write("\n]")

    print(f"Case Study {i} processing completed. Results written to {output_file}.")