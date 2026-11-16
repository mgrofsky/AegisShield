"""The Mermaid attack tree built from the mapped threat model."""

from __future__ import annotations

from aegisshield.core.errors import ValidationError
from aegisshield.llm.base import LLMClient, OnText

_MERMAID_FENCE = "```mermaid"
_FENCE = "```"


def strip_code_fences(raw: str) -> str:
    """Mermaid text without its code fences: a ```` ```mermaid ```` opening at
    the start of a line and any ```` ``` ```` that ends a line are removed.

    String methods line by line, so a long run of whitespace costs time in
    step with its length (the pattern this replaces cost its square).
    """
    lines = []
    for line in raw.split("\n"):
        if line.startswith(_MERMAID_FENCE):
            line = line[len(_MERMAID_FENCE) :].lstrip()
        if line.endswith(_FENCE):
            line = line[: -len(_FENCE)].rstrip()
        lines.append(line)
    return "\n".join(lines).strip()


def create_attack_tree_prompt(
    app_type: str,
    authentication: list[str],
    internet_facing: str,
    sensitive_data: str,
    mitre_data: list[dict],
    nvd_vulnerabilities: dict[str, str],
    otx_vulnerabilities: str,
    app_input: str,
) -> str:
    """The attack tree prompt: the profile, mapped techniques, and lookup results."""
    return f"""
APPLICATION TYPE: {app_type}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
APPLICATION DESCRIPTION: {app_input}

# STRIDE AND MITRE ATT&CK TTPs:
{mitre_data}

# NVD VULNERABILITIES:
{nvd_vulnerabilities}

# ALIENVAULT OTX CYBER THREAT INTELLIGENCE:
{otx_vulnerabilities}
""".strip()


def get_attack_tree(
    llm: LLMClient,
    model: str,
    prompt: str,
    on_text: OnText | None = None,
) -> str:
    """Ask the model for a Mermaid attack tree and return it without code fences."""
    if not prompt.strip():
        raise ValidationError("Prompt is required for attack tree generation")

    system_prompt = """
Act as a cyber security expert with more than 20 years of experience using STRIDE threat modeling.
Generate an attack tree in Mermaid syntax for the given application details.
Return only a Mermaid code block.
IMPORTANT: If a node label includes round brackets, wrap the label in double quotes.
""".strip()

    raw = llm.chat_text(system=system_prompt, user=prompt, model=model, on_text=on_text)
    return strip_code_fences(raw)
