"""DREAD risk scoring for the threats of a threat model."""

from __future__ import annotations

import json
import re
from typing import Any

from aegisshield.core.errors import LLMResponseError
from aegisshield.llm.base import LLMClient, OnText
from aegisshield.pipeline.sector_context import focus_block

_TC_ID_RE = re.compile(r"TC-[A-Z]\d{2,}")


def _extract_id(item: dict[str, Any]) -> str:
    """Pull a TC-X## id from the ID field, or from any text field if the model embedded it."""
    direct = str(item.get("ID") or "").strip()
    if direct and _TC_ID_RE.match(direct):
        return direct
    for key in ("Threat ID", "id", "ID", "Scenario", "Threat Type"):
        value = item.get(key)
        if not isinstance(value, str):
            continue
        match = _TC_ID_RE.search(value)
        if match:
            return match.group(0)
    return direct or "-"


def dread_json_to_markdown(dread_assessment: dict[str, Any]) -> str:
    """The DREAD table, with the risk score as the mean of the five axes.

    Raises ``LLMResponseError`` when the answer does not have the expected shape.
    """
    markdown_output = "| ID | Damage Potential | Reproducibility | Exploitability | Affected Users | Discoverability | Risk Score |\n"
    markdown_output += "|----|------------------|-----------------|----------------|----------------|-----------------|-------------|\n"

    threats = dread_assessment.get("Risk Assessment", [])
    if not isinstance(threats, list):
        raise LLMResponseError("DREAD response is invalid: 'Risk Assessment' must be a list")

    for threat in threats:
        if not isinstance(threat, dict):
            raise LLMResponseError("DREAD response is invalid: each threat must be an object")

        damage_potential = int(threat.get("Damage Potential", 0))
        reproducibility = int(threat.get("Reproducibility", 0))
        exploitability = int(threat.get("Exploitability", 0))
        affected_users = int(threat.get("Affected Users", 0))
        discoverability = int(threat.get("Discoverability", 0))
        risk_score = (damage_potential + reproducibility + exploitability + affected_users + discoverability) / 5

        markdown_output += (
            f"| {_extract_id(threat)} | "
            f"{damage_potential} | {reproducibility} | {exploitability} | {affected_users} | "
            f"{discoverability} | {risk_score:.2f} |\n"
        )

    return markdown_output


def create_dread_assessment_prompt(
    threats: str, mitre_mapping: str, nvd_vulnerabilities: str, focus: str | None = None
) -> str:
    """The DREAD prompt; ``focus`` is the agentic Lead's note for this section."""
    return f"""
Act as a cyber security expert with more than 20 years of experience in STRIDE and DREAD.
Produce a DREAD risk assessment for the threats.

The threats table below has an ID column (values like TC-S01, TC-T01, TC-I03).
You MUST output one JSON entry per row, keyed by that exact ID. Do not omit the ID field.
Do not include "Threat Type" or "Scenario" fields in your output; the ID is the only identifier.

Threats (for context; DO NOT repeat the Scenario or Threat Type text in your output):
{threats}

MITRE mapping (supplemental):
{mitre_mapping}

NVD vulnerabilities (supplemental):
{nvd_vulnerabilities}

Return JSON with this exact structure and no other fields:
{{
  "Risk Assessment": [
    {{
      "ID": "TC-S01",
      "Damage Potential": 7,
      "Reproducibility": 6,
      "Exploitability": 5,
      "Affected Users": 8,
      "Discoverability": 4
    }},
    ...
  ]
}}

All scores are integers 1-10. Include exactly one entry per threat ID from the table above.
{focus_block(focus)}""".strip()


def generate_dread_assessment(
    llm: LLMClient,
    model: str,
    threats_markdown: str,
    mitre_markdown: str,
    nvd_markdown: str,
    on_text: OnText | None = None,
    focus: str | None = None,
) -> dict[str, Any]:
    """Ask the model for a DREAD score per threat id and return the parsed JSON."""
    prompt = create_dread_assessment_prompt(threats_markdown, mitre_markdown, nvd_markdown, focus)
    response = llm.chat_json(
        system="You are a helpful assistant designed to output JSON.",
        user=prompt,
        model=model,
        on_text=on_text,
    )

    # Ensure JSON serializable and normalized.
    json.dumps(response)
    return response
