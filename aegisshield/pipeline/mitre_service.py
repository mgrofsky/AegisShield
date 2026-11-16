"""Map each STRIDE threat to one catalog-validated MITRE ATT&CK technique.

An AI system's threats also get an ATLAS technique, from a separate pick over
ATLAS candidates only (``atlas_service``), so ATLAS is never crowded out of
this pick's candidate cap and this pick reads ATT&CK entries only.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

from aegisshield.core.errors import ConfigurationError
from aegisshield.llm.base import LLMClient
from aegisshield.pipeline.catalog_service import (
    CatalogEntry,
    catalog_for_app_type,
    index_by_id,
    validate_id,
)
from aegisshield.pipeline.sector_context import compact_context, focus_block

logger = logging.getLogger(__name__)

MAX_TECHNIQUES = 25



def create_mitre_prompt(
    app_details: dict[str, Any],
    threat: dict[str, Any],
    candidates: list[CatalogEntry],
    focus: str | None = None,
) -> str:
    """Build a prompt that constrains the model to pick from a typed candidate list.

    Each candidate is presented with its catalog technique ID
    (e.g. ``T1059`` or ``AML.T0051``), name, and a short description so the
    model has enough context to choose. The output schema is a single JSON
    object with a ``technique_id`` field, easier to validate than a STIX ID.
    ``focus`` is the agentic Lead's note for this section.
    """

    rendered = [
        {
            "framework": entry.framework,
            "technique_id": entry.technique_id,
            "name": entry.name,
            "tactic": entry.tactic,
            "description": entry.short_description(),
        }
        for entry in candidates
    ]

    industry_sector = app_details["industry_sector"]
    context = compact_context(app_details)
    context_line = f"\n{context}\n" if context else ""
    sensitive_data = app_details["sensitive_data"]

    return f"""
You are to respond in a very specific format. Do not include additional text.

Act as a cybersecurity expert in the {industry_sector} sector with more than 20 years of experience using the STRIDE threat modeling methodology.
Choose the single most relevant attack technique from the provided list. You must select an entry that is in the list; do not invent a technique ID.
{context_line}
APPLICATION TYPE: {app_details['app_type']}
INDUSTRY SECTOR: {industry_sector}
AUTHENTICATION METHODS: {app_details['authentication']}
INTERNET FACING: {app_details['internet_facing']}
SENSITIVE DATA: {sensitive_data}
APPLICATION DESCRIPTION: {app_details['app_input']}

{focus_block(focus).lstrip()}
Threat Scenario:
{json.dumps(threat, indent=2)}

Candidate Techniques (ATT&CK + ATLAS):
{json.dumps(rendered, indent=2)}

Output only a single JSON object with one key:
{{"technique_id": "T1059"}}
If no candidate is a good fit, output:
{{"technique_id": "NONE"}}
""".strip()


def _select_best_technique_id(prompt: str, llm: LLMClient, model: str) -> str:
    """Ask the model to pick a technique_id; on an unreadable answer return ``"NONE"``.

    Catalog validation happens in the caller; this function just normalises
    the response shape.
    """

    response_text = llm.chat_text(
        system="You are a cybersecurity expert helping identify relevant attack techniques.",
        user=prompt,
        model=model,
    )

    cleaned = response_text.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    if cleaned.startswith("```"):
        cleaned = cleaned[3:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        return "NONE"

    if isinstance(parsed, dict):
        candidate = parsed.get("technique_id")
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    if isinstance(parsed, list) and parsed:
        candidate = parsed[0]
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()

    return "NONE"


def _candidates_from_keywords(
    catalog: list[CatalogEntry], keywords: list[str], max_candidates: int
) -> list[CatalogEntry]:
    """Filter the catalog by keyword overlap with technique name + description.

    This is a cheap pre-filter that bounds the candidate list passed to the
    model. Falling back to ``catalog[:max_candidates]`` would still be valid;
    we filter to keep the prompt small and topical.
    """

    if not keywords:
        return catalog[:max_candidates]
    lowered = [k.lower() for k in keywords if isinstance(k, str) and k.strip()]
    matches: list[CatalogEntry] = []
    for entry in catalog:
        haystack = f"{entry.name} {entry.description}".lower()
        if any(keyword in haystack for keyword in lowered):
            matches.append(entry)
            if len(matches) >= max_candidates:
                break
    return matches


def process_mitre_attack_data(
    threat_model: list[dict[str, Any]],
    app_details: dict[str, Any],
    llm: LLMClient,
    model: str,
    catalog: list[CatalogEntry] | None = None,
    on_mapped: Callable[[int, dict[str, Any], dict[str, Any] | None], None] | None = None,
    focus: str | None = None,
) -> list[dict[str, Any]]:
    """Map each STRIDE threat to a catalog-grounded ATT&CK technique.

    The model receives a list of typed candidate techniques (the ATT&CK
    entries that survived the keyword pre-filter) and must return a single
    ``technique_id`` from that list. We validate the response against the
    catalog index; if the model hallucinates an ID, we fall back to the
    top keyword-match candidate rather than emitting a fake ID downstream.

    The catalog is derived from ``app_details["app_type"]`` when none is
    passed; any ATLAS entries in it are left out of this pick (an AI
    system's ATLAS technique comes from ``atlas_service``). ``focus`` is the
    agentic Lead's note for this section.

    ``on_mapped(index, threat, technique)`` is called after each threat is
    mapped (``technique`` is None when it has none), for the live view. A
    failing callback is logged and never fails the mapping.
    """

    def _report(index: int, threat: dict[str, Any], technique: dict[str, Any] | None) -> None:
        if on_mapped is None:
            return
        try:
            on_mapped(index, threat, technique)
        # Display only: a failing live-view callback must never stop the mapping.
        except Exception as exc:
            logger.warning("mitre_on_mapped_failed kind=%s", type(exc).__name__)

    if catalog is None:
        catalog = catalog_for_app_type(app_details.get("app_type", ""))

    catalog = [entry for entry in catalog if entry.framework != "ATLAS"]
    if not catalog:
        # No catalog at all is a hard configuration problem, not a soft miss.
        raise ConfigurationError("The ATT&CK technique catalog is empty.")

    catalog_index = index_by_id(catalog)
    processed_data: list[dict[str, Any]] = []

    for index, threat in enumerate(threat_model):
        keywords = threat.get("MITRE ATT&CK Keywords", [])
        candidates = _candidates_from_keywords(
            catalog,
            keywords if isinstance(keywords, list) else [],
            MAX_TECHNIQUES,
        )
        if not candidates:
            processed_data.append({"threat": threat, "mitre_techniques": []})
            _report(index, threat, None)
            continue

        prompt = create_mitre_prompt(app_details, threat, candidates, focus)
        chosen_id = _select_best_technique_id(prompt, llm, model)

        selected = validate_id(catalog_index, chosen_id)
        if selected is None:
            # Hallucinated, "NONE", or an ID outside the catalog: fall back
            # to the top keyword-filter match so downstream code always has a
            # valid entry.
            logger.info("mitre_unknown_technique_id fallback=top_candidate")
            selected = candidates[0]

        processed_data.append(
            {
                "threat": threat,
                "mitre_techniques": [
                    {
                        "name": selected.name,
                        "description": selected.description or "No description available",
                        "id": selected.stix_id or selected.technique_id,
                        "technique_id": selected.technique_id,
                        "framework": selected.framework,
                        "tactic": selected.tactic,
                    }
                ],
            }
        )
        _report(index, threat, processed_data[-1]["mitre_techniques"][0])

    return processed_data
