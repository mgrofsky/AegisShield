"""The STRIDE threat model prompt and call, and architecture diagram analysis."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from typing import Any

from aegisshield.config import Settings, get_settings
from aegisshield.core.errors import LLMResponseError, ValidationError
from aegisshield.core.text import sanitize_user_markdown
from aegisshield.llm.base import LLMClient, OnText
from aegisshield.pipeline.sector_context import context_block
from aegisshield.safeguards import Safeguards, Source

# Largest image accepted: 10 MB.
MAX_IMAGE_BYTES = 10 * 1024 * 1024
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xff\xd8\xff"


def create_threat_model_prompt(
    app_type: str,
    authentication: list[str],
    internet_facing: str,
    industry_sector: str,
    sensitive_data: str,
    app_input: str,
    nvd_vulnerabilities: dict[str, str],
    otx_data: str,
    technical_ability: str,
    extra_cards: list[Any] | None = None,
    app_details: Mapping[str, Any] | None = None,
) -> str:
    """Build the STRIDE threat-model prompt.

    ``app_details`` is the request's profile; the organization context built
    from it (see ``sector_context``) follows the lookup data. Without it the
    context is built from the arguments given here.

    ``extra_cards`` is an optional list of ``ThreatCard`` objects (or any
    object with a ``render()`` method that returns markdown). When supplied,
    each card's text is appended after the application context so the model
    considers OWASP LLM / OWASP ASI / MITRE ATLAS in addition to STRIDE.
    """

    card_block = ""
    if extra_cards:
        rendered = "\n\n".join(card.render() for card in extra_cards)
        card_block = (
            "\n\nADDITIONAL THREAT REFERENCE CARDS (use in addition to STRIDE):\n\n"
            f"{rendered}\n"
        )

    details = app_details if app_details is not None else {
        "industry_sector": industry_sector,
        "sensitive_data": sensitive_data,
        "authentication": authentication,
        "internet_facing": internet_facing,
    }
    context = context_block(details)
    context_part = f"\n\n{context}\n" if context else ""

    return f"""
Act as a cybersecurity expert in the {industry_sector} sector with more than 20 years of experience using the STRIDE threat modeling methodology to produce comprehensive threat models for a wide range of applications. Your task is to use the application description and additional provided data to produce a list of specific threats for the application.

1. On a scale of Low, Medium, or High, the user's technical ability is: {technical_ability}. Simplify explanations for lower abilities without omitting details. For higher abilities, include all technical aspects; for lower abilities, provide clear, more readable explanations despite their lack of technical experience.

2. For each of the STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege), list a mandatory multiple (3) credible threats per category. Each threat scenario should provide a credible scenario in which the threat could occur in the context of the application.

3. For each threat scenario, assess the potential impact on data confidentiality, integrity, and availability.

4. For each threat scenario, provide assumptions with Assumption, Role, and Condition.

5. Return JSON with keys "threat_model" and "improvement_suggestions".

6. Under "threat_model", include objects with keys "Threat Type", "Scenario", "Assumptions", "Potential Impact", and "MITRE ATT&CK Keywords".

7. Under "MITRE ATT&CK Keywords", include relevant keywords only (no STIX IDs or ATT&CK technique IDs).

APPLICATION TYPE: {app_type}
INDUSTRY SECTOR: {industry_sector}
AUTHENTICATION METHODS: {authentication}
INTERNET FACING: {internet_facing}
SENSITIVE DATA: {sensitive_data}
APPLICATION DESCRIPTION: {app_input}

HIGH RISK NVD CVE VULNERABILITIES:
{nvd_vulnerabilities}

ALIENVAULT OTX PULSE DATA:
{otx_data}{context_part}{card_block}
""".strip()


def create_image_analysis_prompt() -> str:
    """The prompt that asks for a plain description of an architecture diagram."""
    return """
You are a Senior Solution Architect tasked with explaining the architecture diagram to a Security Architect for threat modeling.

Requirements:
1. Analyze the diagram.
2. Explain components, interactions, and visible technologies.
3. Do not speculate beyond what is visible.
4. Output only the explanation without prefacing text.
""".strip()


def decode_image(image_base64: str, max_bytes: int = MAX_IMAGE_BYTES) -> tuple[str, bytes]:
    """``(media type, bytes)`` for a base64 PNG or JPEG, plain or as a data URL.

    The type is read from the file's own first bytes, not from the data URL,
    so a mislabeled upload cannot pass. Raises ``ValidationError`` for
    anything that is not a PNG or JPEG of at most ``max_bytes``.
    """
    data = (image_base64 or "").strip()
    if data.startswith("data:"):
        header, sep, data = data.partition(",")
        if not sep or not header.lower().startswith(("data:image/png", "data:image/jpeg", "data:image/jpg")):
            raise ValidationError("Only PNG and JPEG images are supported.")
    # A base64 string is about 4/3 the size of its bytes; refuse a huge one
    # before decoding it.
    if len(data) > (max_bytes // 3 + 1) * 4 + 4:
        raise ValidationError("The image is too large.")
    try:
        decoded = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        raise ValidationError("The image could not be read.") from None
    if not decoded:
        raise ValidationError("The image is empty.")
    if len(decoded) > max_bytes:
        raise ValidationError("The image is too large.")
    if decoded.startswith(_PNG_MAGIC):
        return "image/png", decoded
    if decoded.startswith(_JPEG_MAGIC):
        return "image/jpeg", decoded
    raise ValidationError("Only PNG and JPEG images are supported.")


def analyze_architecture_image(
    llm: LLMClient,
    model: str,
    architecture_image_base64: str,
    max_bytes: int = MAX_IMAGE_BYTES,
    *,
    settings: Settings | None = None,
    safeguards: Safeguards | None = None,
    screen: bool = True,
) -> str:
    """Describe an architecture diagram so the description can join the prompt.

    The answer passes the output rails, and the description, which a model
    wrote from an uploaded image, is screened as ``Source.DIAGRAM`` unless
    ``screen`` is False. The wizard passes False: the visitor reviews the
    text first, and the run screens what reaches the prompt and keeps the
    record. ``safeguards`` None builds them from ``settings`` (the
    environment's settings when that is None too). May raise
    ``SafeguardsStopped``.
    """
    sg = safeguards if safeguards is not None else Safeguards.from_settings(
        settings if settings is not None else get_settings()
    )
    media_type, decoded = decode_image(architecture_image_base64, max_bytes)
    result = sg.wrap(llm).describe_image(
        image_bytes=decoded,
        media_type=media_type,
        prompt=create_image_analysis_prompt(),
        model=model,
    )
    text = sanitize_user_markdown(result)
    return sg.screen(Source.DIAGRAM, text) if screen else text


def generate_threat_model(
    llm: LLMClient,
    model: str,
    prompt: str,
    on_text: OnText | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Run the STRIDE prompt; return the threats and the improvement suggestions.

    ``on_text`` streams the answer for the live view. Raises
    ``LLMResponseError`` when the answer does not have the expected shape.
    """
    response = llm.chat_json(
        system="You are a helpful assistant designed to output JSON.",
        user=prompt,
        model=model,
        on_text=on_text,
    )

    threat_model = response.get("threat_model", [])
    raw_suggestions = response.get("improvement_suggestions", [])

    if not isinstance(threat_model, list):
        raise LLMResponseError("Threat model response is invalid: 'threat_model' must be a list")
    if not isinstance(raw_suggestions, list):
        raise LLMResponseError("Threat model response is invalid: 'improvement_suggestions' must be a list")

    for threat in threat_model:
        if not isinstance(threat, dict):
            raise LLMResponseError("Threat model response is invalid: each threat must be an object")
        keywords = threat.get("MITRE ATT&CK Keywords")
        if not isinstance(keywords, list) or not keywords:
            threat["MITRE ATT&CK Keywords"] = [
                f"{threat.get('Scenario', '')} Potential impact: {threat.get('Potential Impact', '')}".strip()
            ]

    suggestions: list[str] = []
    for item in raw_suggestions:
        if isinstance(item, str):
            normalized = item.strip()
        elif isinstance(item, dict):
            normalized = ""
            for key in (
                "suggestion",
                "text",
                "improvement",
                "recommendation",
                "message",
                "description",
                "item",
            ):
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    normalized = value.strip()
                    break
            if not normalized:
                normalized = json.dumps(item, ensure_ascii=True)
        else:
            normalized = str(item).strip()

        if normalized:
            suggestions.append(normalized)

    return threat_model, suggestions
