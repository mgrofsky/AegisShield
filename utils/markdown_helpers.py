"""
Markdown Conversion Utilities

Provides functions for converting JSON data structures to markdown format.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


def threat_model_to_markdown(
    threat_model: list[dict[str, Any]], improvement_suggestions: list[str] | None = None
) -> str:
    """
    Convert threat model JSON to a Markdown table.

    Args:
        threat_model: List of threat entries with Threat Type, Scenario, etc.
        improvement_suggestions: Optional list of improvement suggestions.

    Returns:
        Formatted markdown string.
    """
    try:
        md = "| Threat Type | Scenario | Potential Impact | Assumptions |\n"
        md += "|-------------|----------|------------------|-------------|\n"

        for threat in threat_model:
            assumptions = ""
            assumptions_list = threat.get("Assumptions", [])
            if assumptions_list:
                for a in assumptions_list:
                    assumption_text = a.get("Assumption", "No assumption provided")
                    role = a.get("Role", "N/A")
                    condition = a.get("Condition", "N/A")
                    # Escape pipe characters in cell content
                    assumption_text = assumption_text.replace("|", "\\|")
                    assumptions += f"- **{assumption_text}** (Role: {role}, Condition: {condition})<br>"
            else:
                assumptions = "No assumptions provided"

            threat_type = threat.get("Threat Type", "N/A").replace("|", "\\|")
            scenario = threat.get("Scenario", "N/A").replace("|", "\\|")
            impact = threat.get("Potential Impact", "N/A").replace("|", "\\|")
            md += f"| {threat_type} | {scenario} | {impact} | {assumptions} |\n"

        if improvement_suggestions:
            md += "\n# Improvement Suggestions\n\n"
            for suggestion in improvement_suggestions:
                md += f"- {suggestion}\n"

        return md
    except Exception as e:
        logger.error("Error converting threat model to markdown: %s", e)
        return "Error: Unable to format threat model data"


def dread_to_markdown(dread_assessment: dict[str, Any]) -> str:
    """
    Convert DREAD assessment JSON to a Markdown table.

    Args:
        dread_assessment: Dict with "Risk Assessment" key containing threat list.

    Returns:
        Formatted markdown table string.
    """
    md = "| Threat Type | Scenario | Damage Potential | Reproducibility | Exploitability | Affected Users | Discoverability | Risk Score |\n"
    md += "|-------------|----------|------------------|-----------------|----------------|----------------|-----------------|-------------|\n"

    try:
        threats = dread_assessment.get("Risk Assessment", [])
        for threat in threats:
            if not isinstance(threat, dict):
                raise TypeError(f"Expected a dictionary, got {type(threat)}")

            d = threat.get("Damage Potential", 0)
            r = threat.get("Reproducibility", 0)
            e = threat.get("Exploitability", 0)
            a = threat.get("Affected Users", 0)
            disc = threat.get("Discoverability", 0)
            risk_score = (d + r + e + a + disc) / 5

            md += (
                f"| {threat.get('Threat Type', 'N/A')} "
                f"| {threat.get('Scenario', 'N/A')} "
                f"| {d} | {r} | {e} | {a} | {disc} | {risk_score:.2f} |\n"
            )
        return md
    except Exception as ex:
        logger.error("Error converting DREAD assessment to markdown: %s", ex)
        raise
