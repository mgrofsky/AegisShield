"""
Step 3: Threat Model Tab Module

This module handles the third step of the threat modeling process, where users generate
a comprehensive threat model for their application. It includes threat model generation,
MITRE ATT&CK mapping, and attack tree visualization.

The module provides the following key features:
- Threat model generation based on application description and technology details
- MITRE ATT&CK mapping for identified threats
- Attack tree visualization
- NVD vulnerability integration
- AlienVault OTX threat intelligence integration
- Comprehensive error handling and retry mechanisms

Dependencies:
    - streamlit: For the web interface
    - mitre_attack: For MITRE ATT&CK data processing
    - nvd_search: For vulnerability database integration
    - alientvault_search: For threat intelligence
    - threat_model: For threat model generation
    - attack_tree: For attack tree visualization
    - error_handler: For consistent error handling

Session State Variables:
    - threat_model: The generated threat model
    - mitre_data: Processed MITRE ATT&CK data
    - attack_tree_code: Generated attack tree visualization
    - improvement_suggestions: Suggestions for improving the threat model
    - nvd_vulnerabilities: NVD vulnerability data
    - mitre_attack_markdown: Formatted MITRE ATT&CK data
"""

import logging

import streamlit as st

from alientvault_search import fetch_otx_data
from attack_tree import (
    create_attack_tree_prompt,
    get_attack_tree,
)
from error_handler import handle_exception
from mitre_attack import fetch_mitre_attack_data, process_mitre_attack_data
from nvd_search import search_nvd
from threat_model import (
    create_threat_model_prompt,
    get_threat_model,
    json_to_markdown,
)

# Configure logging
logger = logging.getLogger(__name__)

def handle_mitre_data() -> dict:
    """Handle MITRE ATT&CK data fetching and processing.
    
    This function manages the retrieval and processing of MITRE ATT&CK data:
    1. Fetches STIX data for the application type
    2. Processes the data to map threats to MITRE techniques
    3. Stores the results in session state
    
    Returns:
        dict: Processed MITRE ATT&CK data if successful, None otherwise
        
    Raises:
        Exception: If there's an error during data fetching or processing
    """
    logger.info("Fetching MITRE ATT&CK data")
    try:
        stix_data = fetch_mitre_attack_data(st.session_state['app_details']['app_type'])
        logger.info("Processing MITRE ATT&CK data")

        threat_model = st.session_state.get('threat_model', [])
        mitre_data = process_mitre_attack_data(stix_data, threat_model, st.session_state['app_details'], st.session_state['openai_api_key'])
        st.session_state['mitre_data'] = mitre_data
        return mitre_data
    except Exception as e:
        handle_exception(e, "Error fetching MITRE ATT&CK data.")
        return None

def render(model_provider: str, selected_model: str, openai_api_key: str) -> None:
    """Render the threat model tab of the threat modeling application.
    
    This function creates the main interface for Step 3 of the threat modeling process.
    It includes:
    - Threat model generation
    - MITRE ATT&CK mapping
    - Attack tree visualization
    - NVD vulnerability integration
    - AlienVault OTX threat intelligence
    
    Args:
        model_provider: The selected AI model provider (e.g., "OpenAI API")
        selected_model: The selected AI model name (e.g., "gpt-4o")
        openai_api_key: The OpenAI API key for authentication
        
    Note:
        This function manages session state for:
        - threat_model: The generated threat model
        - mitre_data: Processed MITRE ATT&CK data
        - attack_tree_code: Generated attack tree visualization
        - improvement_suggestions: Suggestions for improving the threat model
        - nvd_vulnerabilities: NVD vulnerability data
        - mitre_attack_markdown: Formatted MITRE ATT&CK data
    """
    logger.info("Rendering threat model tab")
    try:
        if not st.session_state['step2_completed']:
            st.warning("Please complete Steps 1 and 2 first.")
            return
        st.markdown("""
        Generate the threat model based on the application description and technology details provided, including an Attack Tree, and automatic MITRE ATT&CK mapping.
        """)
        st.markdown("""---""")

        if 'app_input' not in st.session_state:
            st.error("Please complete Step 1: Description first.")
        elif 'app_details' not in st.session_state:
            st.error("Please complete Step 2: Technology first.")
        else:
            app_input = st.session_state['app_input']
            app_details = st.session_state['app_details']
            selected_technologies = st.session_state.get('selected_technologies', {})
            selected_versions = st.session_state.get('selected_versions', {})

            threat_model_submit_button = st.button(label="Generate Threat Model")

            if threat_model_submit_button:
                logger.info("Generate Threat Model button clicked")
                nvd_vulnerabilities = {}
                nvd_api_key = st.session_state.get('nvd_api_key')

                if nvd_api_key and selected_technologies:
                    with st.spinner("Searching the National Vulnerability Database..."):
                        for tech, cpe_name in selected_technologies.items():
                            version = selected_versions.get(tech, "*")
                            try:
                                vulnerabilities = search_nvd(nvd_api_key, cpe_name, version, tech)
                                if vulnerabilities:
                                    nvd_vulnerabilities[f"{tech} {version}"] = vulnerabilities
                            except Exception as e:
                                handle_exception(e, f"Error fetching NVD data for {tech} {version}.")
                else:
                    st.error("NVD API key is missing or no technologies selected")

                alienvault_api_key = st.session_state.get('alienvault_api_key')
                otx_vulnerabilities = ""

                if alienvault_api_key:
                    with st.spinner(f"Searching AlienVault OTX for {st.session_state['industry_sector']} sector threat intelligence..."):
                        try:
                            otx_vulnerabilities_raw = fetch_otx_data(alienvault_api_key, industry=st.session_state['industry_sector'], max_results=10)
                            otx_vulnerabilities = otx_vulnerabilities_raw.replace('|', '\n\n')
                        except Exception as e:
                            handle_exception(e, "Error fetching OTX data.")
                else:
                    st.error("AlienVault API key is missing")

                threat_model_prompt = create_threat_model_prompt(
                    app_details['app_type'],
                    app_details['authentication'],
                    app_details['internet_facing'],
                    app_details['industry_sector'],
                    app_details['sensitive_data'],
                    app_input,
                    nvd_vulnerabilities,
                    otx_vulnerabilities,
                    app_details['technical_ability']
                )

                # Initialize variables
                threat_model = []
                improvement_suggestions = []
                model_output = None

                with st.spinner("Analyzing application and creating potential threats..."):
                    max_retries = 3
                    retry_count = 0
                    while retry_count < max_retries:
                        try:
                            if model_provider == "OpenAI API":
                                model_output = get_threat_model(openai_api_key, selected_model, threat_model_prompt)
                                if not model_output:
                                    raise ValueError("No threat model output received")
                            
                            if model_output and isinstance(model_output, dict):
                                threat_model = model_output.get("threat_model", [])
                                improvement_suggestions = model_output.get("improvement_suggestions", [])
                                
                                if not isinstance(threat_model, list) or not isinstance(improvement_suggestions, list):
                                    raise ValueError("Invalid model output format: threat_model and improvement_suggestions must be lists")
                                
                                st.session_state['session_threat_model_json'] = threat_model
                                st.session_state['improvement_suggestions_json'] = improvement_suggestions

                                for threat in threat_model:
                                    if not isinstance(threat, dict):
                                        raise ValueError("Each threat must be a dictionary")
                                    if 'MITRE ATT&CK Keywords' not in threat or not threat['MITRE ATT&CK Keywords']:
                                        threat['MITRE ATT&CK Keywords'] = f"{threat.get('Scenario', '')} Potential impact: {threat.get('Potential Impact', '')}"

                                st.session_state['threat_model'] = threat_model
                                st.session_state['improvement_suggestions'] = improvement_suggestions
                                break
                            else:
                                raise ValueError("Invalid model output format: expected a dictionary with threat_model and improvement_suggestions keys")
                        except Exception as e:
                            retry_count += 1
                            if retry_count == max_retries:
                                handle_exception(e, f"Error generating threat model after {max_retries} attempts.")
                            else:
                                st.warning(f"Error generating threat model. Retrying attempt {retry_count + 1}/{max_retries}...")

                # Initialize markdown strings
                st.session_state['improvement_suggestions_markdown'] = ""
                st.session_state['threat_model_markdown'] = ""
                st.session_state['mitre_attack_markdown'] = ""
                st.session_state['nvd_vulnerabilities_markdown'] = ""

                # Process improvement suggestions
                if improvement_suggestions:
                    for suggestion in improvement_suggestions:
                        st.session_state['improvement_suggestions_markdown'] += f"- {suggestion.strip()}\n"
                else:
                    st.session_state['improvement_suggestions_markdown'] = "No improvement suggestions provided.\n"

                # Process threat model
                if threat_model:
                    st.session_state['threat_model_markdown'] = json_to_markdown(threat_model, [])
                else:
                    st.session_state['threat_model_markdown'] = "No threat model generated.\n"

                # Process MITRE ATT&CK data
                with st.spinner("Matching generated threats with MITRE ATT&CK tactics, techniques, and procedures..."):
                    mitre_data = handle_mitre_data()
                    st.session_state['mitre_data'] = mitre_data

                    if st.session_state.get('mitre_data'):
                        mitre_data = st.session_state['mitre_data']
                        for entry in mitre_data:
                            st.session_state['mitre_attack_markdown'] += f"### Threat: {entry['threat']['Threat Type']}\n"
                            st.session_state['mitre_attack_markdown'] += f"**Scenario**: {entry['threat']['Scenario']}\n"
                            st.session_state['mitre_attack_markdown'] += f"**Potential Impact**: {entry['threat']['Potential Impact']}\n"
                            if entry['mitre_techniques']:
                                st.session_state['mitre_attack_markdown'] += "#### MITRE ATT&CK Techniques\n"
                                for item in entry['mitre_techniques']:
                                    st.session_state['mitre_attack_markdown'] += f"**Name**: {item['name']}\n"
                                    st.session_state['mitre_attack_markdown'] += f"- **URL**: [https://attack.mitre.org/techniques/{item['technique_id'].replace('.','/')}/](https://attack.mitre.org/techniques/{item['technique_id'].replace('.','/')}/)\n"
                                    st.session_state['mitre_attack_markdown'] += f"- **Technique ID**: {item['technique_id']}\n"
                                    st.session_state['mitre_attack_markdown'] += f"- **Attack Pattern ID**: {item['id']}\n"
                                    st.session_state['mitre_attack_markdown'] += "\n\n"
                            else:
                                st.session_state['mitre_attack_markdown'] += "- No relevant MITRE ATT&CK techniques found.\n"
                            st.session_state['mitre_attack_markdown'] += "---\n"
                    else:
                        st.session_state['mitre_attack_markdown'] = "No MITRE ATT&CK data found.\n"

                with st.spinner("Generating Attack Tree..."):
                    max_retries = 3
                    retry_count = 0
                    while retry_count < max_retries:
                        try:
                            logger.info("Generating Attack Tree...")
                            attack_tree_prompt = create_attack_tree_prompt(
                                app_details['app_type'],
                                app_details['authentication'],
                                app_details['internet_facing'],
                                app_details['sensitive_data'],
                                st.session_state['mitre_data'],
                                nvd_vulnerabilities,
                                otx_vulnerabilities,
                                app_input
                            )

                            if model_provider == "OpenAI API":
                                logger.info("Calling get_attack_tree")
                                attack_tree_code = get_attack_tree(openai_api_key, selected_model, attack_tree_prompt)

                            st.session_state['attack_tree_code'] = attack_tree_code

                            if st.session_state.get('attack_tree_code'):
                                attack_tree_markdown = st.session_state['attack_tree_code']
                            else:
                                attack_tree_markdown = "No attack tree generated.\n"

                            break
                        except Exception as e:
                            retry_count += 1
                            if retry_count == max_retries:
                                handle_exception(e, f"Error generating attack tree after {max_retries} attempts.")
                            else:
                                st.warning(f"Error generating attack tree. Retrying attempt {retry_count + 1}/{max_retries}...")

                if nvd_vulnerabilities:
                    for tech_version, vulnerabilities in nvd_vulnerabilities.items():
                        st.session_state['nvd_vulnerabilities_markdown'] += f"#### {tech_version}\n\n"
                        if isinstance(vulnerabilities, str):
                            vulnerabilities_list = vulnerabilities.split('|')
                            for vuln in vulnerabilities_list:
                                st.session_state['nvd_vulnerabilities_markdown'] += f"{vuln}\n\n---\n\n"
                        else:
                            st.session_state['nvd_vulnerabilities_markdown'] += f"Unexpected data type for {tech_version}: {type(vulnerabilities)}\n\n"
                else:
                    st.session_state['nvd_vulnerabilities_markdown'] = "No NVD vulnerabilities found.\n\n"

                st.markdown(f"""### Improvement Suggestions

{st.session_state['improvement_suggestions_markdown']}

### Threat Model

{st.session_state['threat_model_markdown']}
""", unsafe_allow_html=True)

                st.markdown("### Attack Tree")
                attack_tree_code = st.session_state['attack_tree_code']
                mermaid_html = f"""
<div class="mermaid">
{attack_tree_code}
</div>
"""
                st.markdown(mermaid_html, unsafe_allow_html=True)

                st.markdown(f"""### MITRE ATT&CK

{st.session_state['mitre_attack_markdown']}

### National Vulnerability Database CVEs

{st.session_state['nvd_vulnerabilities_markdown']}

### AlienVault OTX Data

{otx_vulnerabilities}
""", unsafe_allow_html=True)
                st.session_state['step3_completed'] = True
                st.balloons()

                combined_markdown = f"""### Improvement Suggestions

{st.session_state['improvement_suggestions_markdown']}

### Threat Model

{st.session_state['threat_model_markdown']}

### Attack Tree

{attack_tree_markdown}

### MITRE ATT&CK

{st.session_state['mitre_attack_markdown']}

### National Vulnerability Database CVEs

{st.session_state['nvd_vulnerabilities_markdown']}

### AlienVault OTX Data

{otx_vulnerabilities}"""

                combined_markdown = combined_markdown.strip()

                st.download_button(
                    label="Download All Results",
                    data=combined_markdown,
                    file_name="threat_gpt_results.md",
                    mime="text/markdown",
                )
    except Exception as e:
        handle_exception(e, "An unexpected error occurred while rendering the threat model tab.")
