"""Mitigation recommendations for the threats of a threat model."""

from __future__ import annotations

from aegisshield.llm.base import LLMClient, OnText
from aegisshield.pipeline.sector_context import focus_block


def create_mitigations_prompt(
    threats: str,
    mitre_mapping: str,
    nvd_vulnerabilities: str,
    focus: str | None = None,
    atlas_reference: str | None = None,
) -> str:
    """The mitigations prompt; ``focus`` is the agentic Lead's note for this section.

    ``atlas_reference`` (an AI system only) lists each threat's mapped ATLAS
    technique and the names of the ATLAS mitigations the catalog links to it,
    so the advice can line up with them. Without it the prompt is unchanged.
    """
    atlas = (
        f"\nMITRE ATLAS mapping (reference data from the bundled catalog):\n{atlas_reference}\n"
        if atlas_reference else ""
    )
    return f"""
Act as a cybersecurity expert with more than 20 years of experience using STRIDE.
Provide mitigations for the identified threats.

Each threat has an ID (TC-S01, TC-T01, etc.). Reference threats by their ID only; do not rewrite
the scenario text.

Output a markdown table with exactly these columns (in order):
- ID
- Suggested Mitigation(s)

Include one row per threat ID. Do not use HTML tags in table cells.

Threats (for reference; do not repeat scenario text in your output):
{threats}

MITRE ATT&CK mapping:
{mitre_mapping}

NVD vulnerabilities:
{nvd_vulnerabilities}
{atlas}{focus_block(focus)}
YOUR RESPONSE (markdown table only, no code fence):
""".strip()


def generate_mitigations(
    llm: LLMClient,
    model: str,
    threats_markdown: str,
    mitre_markdown: str,
    nvd_markdown: str,
    on_text: OnText | None = None,
    focus: str | None = None,
    atlas_reference: str | None = None,
) -> str:
    """Ask the model for a markdown table of mitigations, one row per threat id."""
    prompt = create_mitigations_prompt(threats_markdown, mitre_markdown, nvd_markdown, focus,
                                       atlas_reference)
    return llm.chat_text(
        system="You provide threat mitigation strategies in Markdown format.",
        user=prompt,
        model=model,
        on_text=on_text,
    )
