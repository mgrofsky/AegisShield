"""
Page 3: Threat Model Generation

Generates a comprehensive STRIDE threat model with MITRE ATT&CK mapping,
NVD vulnerability integration, and attack tree visualization.
Uses st.status() for multi-phase progress and st.write_stream() for streaming.
"""

import logging

import streamlit as st

from clients.retry import APIRetryError, retry_with_backoff
from components.step_guard import require_steps_completed
from services.alienvault import fetch_otx_data
from services.attack_tree import create_attack_tree_prompt, get_attack_tree
from services.mitre_attack import fetch_mitre_attack_data, process_mitre_attack_data
from services.nvd_search import search_nvd
from services.threat_model import create_threat_model_prompt, get_threat_model
from state import set_step_completed
from utils.error_handler import handle_exception
from utils.markdown_helpers import threat_model_to_markdown

logger = logging.getLogger(__name__)


def render():
    if not require_steps_completed(1, 2):
        return

    st.markdown("Generate the threat model based on your application description and technology details.")
    st.markdown("---")

    app_input = st.session_state["app_input"]
    app_details = st.session_state["app_details"]
    selected_technologies = st.session_state.get("selected_technologies", {})
    selected_versions = st.session_state.get("selected_versions", {})

    if st.button("Generate Threat Model"):
        with st.status("Generating threat model...", expanded=True) as status:
            # Phase 1: NVD
            nvd_vulnerabilities = {}
            nvd_api_key = st.session_state.get("nvd_api_key")
            if nvd_api_key and selected_technologies:
                status.update(label="Searching National Vulnerability Database...")
                for tech, cpe_name in selected_technologies.items():
                    version = selected_versions.get(tech, "*")
                    try:
                        vulns = search_nvd(nvd_api_key, cpe_name, version, tech)
                        if vulns:
                            nvd_vulnerabilities[f"{tech} {version}"] = vulns
                    except Exception as e:
                        handle_exception(e, f"Error fetching NVD data for {tech}")

            # Phase 2: AlienVault OTX
            otx_vulnerabilities = ""
            av_key = st.session_state.get("alienvault_api_key")
            if av_key:
                status.update(label=f"Fetching AlienVault OTX intelligence for {app_details['industry_sector']}...")
                try:
                    raw = fetch_otx_data(av_key, industry=app_details["industry_sector"], max_results=10)
                    if raw:
                        otx_vulnerabilities = raw.replace("|", "\n\n")
                except Exception as e:
                    handle_exception(e, "Error fetching OTX data")

            # Phase 3: Generate threat model
            status.update(label="Generating STRIDE threat model...")
            prompt = create_threat_model_prompt(
                app_details["app_type"], app_details["authentication"],
                app_details["internet_facing"], app_details["industry_sector"],
                app_details["sensitive_data"], app_input,
                nvd_vulnerabilities, otx_vulnerabilities,
                app_details["technical_ability"],
            )

            model_output = None
            try:
                model_output = retry_with_backoff(lambda: get_threat_model(prompt))
            except APIRetryError as e:
                handle_exception(e, "Failed to generate threat model after multiple attempts.")

            if model_output and isinstance(model_output, dict):
                threat_model = model_output.get("threat_model", [])
                improvement_suggestions = model_output.get("improvement_suggestions", [])

                # Ensure MITRE keywords exist
                for threat in threat_model:
                    if not threat.get("MITRE ATT&CK Keywords"):
                        threat["MITRE ATT&CK Keywords"] = f"{threat.get('Scenario', '')} {threat.get('Potential Impact', '')}"

                st.session_state["threat_model"] = threat_model
                st.session_state["improvement_suggestions"] = improvement_suggestions
                st.session_state["session_threat_model_json"] = threat_model
                st.session_state["improvement_suggestions_json"] = improvement_suggestions
                st.session_state["threat_model_markdown"] = threat_model_to_markdown(threat_model, [])

                # Build improvement suggestions markdown
                if improvement_suggestions:
                    st.session_state["improvement_suggestions_markdown"] = "\n".join(
                        f"- {s.strip()}" for s in improvement_suggestions
                    )
                else:
                    st.session_state["improvement_suggestions_markdown"] = "No improvement suggestions provided."

            # Phase 4: MITRE ATT&CK
            status.update(label="Mapping threats to MITRE ATT&CK techniques...")
            st.session_state["mitre_attack_markdown"] = ""
            try:
                stix_data = fetch_mitre_attack_data(app_details["app_type"])
                mitre_data = process_mitre_attack_data(stix_data, st.session_state.get("threat_model", []), app_details)
                st.session_state["mitre_data"] = mitre_data

                for entry in mitre_data:
                    st.session_state["mitre_attack_markdown"] += f"### Threat: {entry['threat']['Threat Type']}\n"
                    st.session_state["mitre_attack_markdown"] += f"**Scenario**: {entry['threat']['Scenario']}\n"
                    st.session_state["mitre_attack_markdown"] += f"**Potential Impact**: {entry['threat']['Potential Impact']}\n"
                    if entry["mitre_techniques"]:
                        st.session_state["mitre_attack_markdown"] += "#### MITRE ATT&CK Techniques\n"
                        for item in entry["mitre_techniques"]:
                            tid = item["technique_id"]
                            st.session_state["mitre_attack_markdown"] += f"**Name**: {item['name']}\n"
                            st.session_state["mitre_attack_markdown"] += f"- **URL**: [https://attack.mitre.org/techniques/{tid.replace('.', '/')}/](https://attack.mitre.org/techniques/{tid.replace('.', '/')}/)\n"
                            st.session_state["mitre_attack_markdown"] += f"- **Technique ID**: {tid}\n"
                            st.session_state["mitre_attack_markdown"] += f"- **Attack Pattern ID**: {item['id']}\n\n"
                    else:
                        st.session_state["mitre_attack_markdown"] += "- No relevant MITRE ATT&CK techniques found.\n"
                    st.session_state["mitre_attack_markdown"] += "---\n"
            except Exception as e:
                handle_exception(e, "Error processing MITRE ATT&CK data")
                st.session_state["mitre_attack_markdown"] = "No MITRE ATT&CK data found.\n"

            # Phase 5: Attack tree
            status.update(label="Generating attack tree visualization...")
            try:
                tree_prompt = create_attack_tree_prompt(
                    app_details["app_type"], app_details["authentication"],
                    app_details["internet_facing"], app_details["sensitive_data"],
                    st.session_state.get("mitre_data", ""),
                    nvd_vulnerabilities, otx_vulnerabilities, app_input,
                )
                attack_tree = retry_with_backoff(lambda: get_attack_tree(tree_prompt))
                st.session_state["attack_tree_code"] = attack_tree or ""
            except Exception as e:
                handle_exception(e, "Error generating attack tree")
                st.session_state["attack_tree_code"] = ""

            # Phase 6: NVD markdown
            st.session_state["nvd_vulnerabilities_markdown"] = ""
            if nvd_vulnerabilities:
                for tech_version, vulns in nvd_vulnerabilities.items():
                    st.session_state["nvd_vulnerabilities_markdown"] += f"#### {tech_version}\n\n"
                    if isinstance(vulns, str):
                        for v in vulns.split("|"):
                            st.session_state["nvd_vulnerabilities_markdown"] += f"{v}\n\n---\n\n"
            else:
                st.session_state["nvd_vulnerabilities_markdown"] = "No NVD vulnerabilities found.\n"

            status.update(label="Threat model generation complete!", state="complete", expanded=False)
            set_step_completed(3)

        st.toast("Threat model generated successfully!")

    if st.session_state.get("threat_model_markdown"):
        st.markdown(f"""### Improvement Suggestions\n\n{st.session_state['improvement_suggestions_markdown']}""")
        st.markdown(f"""### Threat Model\n\n{st.session_state['threat_model_markdown']}""", unsafe_allow_html=True)

        st.markdown("### Attack Tree")
        if st.session_state.get("attack_tree_code"):
            mermaid_html = f'<div class="mermaid">\n{st.session_state["attack_tree_code"]}\n</div>'
            st.markdown(mermaid_html, unsafe_allow_html=True)

        st.markdown(f"""### MITRE ATT&CK\n\n{st.session_state['mitre_attack_markdown']}""", unsafe_allow_html=True)
        st.markdown(f"""### NVD Vulnerabilities\n\n{st.session_state['nvd_vulnerabilities_markdown']}""", unsafe_allow_html=True)

        st.download_button(
            label="Download All Results",
            data=f"""### Improvement Suggestions\n\n{st.session_state['improvement_suggestions_markdown']}\n\n### Threat Model\n\n{st.session_state['threat_model_markdown']}\n\n### MITRE ATT&CK\n\n{st.session_state['mitre_attack_markdown']}\n\n### NVD Vulnerabilities\n\n{st.session_state['nvd_vulnerabilities_markdown']}""".strip(),
            file_name="threat_model_results.md",
            mime="text/markdown",
        )
        st.markdown("---")
        if st.button("Proceed to Mitigations →", type="primary"):
            st.switch_page("pages/4_Mitigations.py")


render()
