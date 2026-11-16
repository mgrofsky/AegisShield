"""Reference cards (OWASP LLM, OWASP ASI, MITRE ATLAS) for threat-model prompts.

Cards are static markdown files packaged under
``aegisshield/data/threat_cards/`` plus a dynamic ATLAS card built from
the pinned ATLAS catalog. The selection logic is intentionally simple: a
caller passes a list of pattern tags (``"GenAI"``, ``"Agentic"``, ``"RAG"``,
``"Tool Use"``, ``"Code Execution"``) and we return the cards relevant to
those tags. Pattern detection itself lives in ``pattern_detection_service``.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from aegisshield.data import data_path
from aegisshield.pipeline.ai_system import AI_APP_TYPES, is_ai_system
from aegisshield.pipeline.catalog_service import load_atlas_entries

THREAT_CARD_DIR = "threat_cards"
ATLAS_CARD_NAME = "MITRE ATLAS Techniques"


@dataclass(frozen=True)
class ThreatCard:
    name: str
    body: str  # markdown content rendered into the prompt as-is

    def render(self) -> str:
        """The card as markdown for the prompt."""
        return f"## Threat Card: {self.name}\n\n{self.body.strip()}"


def _read_static_card(filename: str, name: str) -> ThreatCard:
    path = data_path(THREAT_CARD_DIR, filename)
    with path.open("r", encoding="utf-8") as fh:
        body = fh.read()
    return ThreatCard(name=name, body=body)


def owasp_llm_card() -> ThreatCard:
    """The OWASP Top 10 for LLM applications."""
    return _read_static_card("owasp_llm_top_10.md", "OWASP Top 10 for LLM Applications")


def owasp_agentic_card() -> ThreatCard:
    """The OWASP Agentic Security Initiative threats."""
    return _read_static_card("owasp_agentic.md", "OWASP Agentic Security Initiative")


def owasp_crosswalk_card() -> ThreatCard:
    """Cross-walk between OWASP LLM, ASI, MCP, Skills, and ML Top 10s.

    Built from the committed JSON so the model sees one row per concept
    (e.g. "prompt injection") instead of having to mentally merge five
    independent lists. Useful for AI/ML apps that touch multiple OWASP
    surface areas (LLM + MCP, agent + skill catalog, etc.).
    """

    path = data_path(THREAT_CARD_DIR, "owasp_crosswalk.json")
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    lines = [
        "Concept-level cross-walk across the OWASP AI Top 10 family",
        "(LLM applications, Agentic Security Initiative, Model Context",
        "Protocol, Skills, and ML Top 10). Each row is a single threat",
        "concept with the matching entry in each list, so threats only",
        "have to be enumerated once even when an app touches several of",
        "the surfaces.",
        "",
    ]
    for cat in data.get("categories", []):
        ids = []
        for label, key in (
            ("LLM", "owasp_llm"),
            ("ASI", "owasp_asi"),
            ("MCP", "owasp_mcp"),
            ("Skills", "owasp_skills"),
            ("ML", "owasp_ml"),
        ):
            value = cat.get(key)
            if value:
                ids.append(f"{label}: {value}")
        ids_str = " | ".join(ids) if ids else "(no direct mapping)"
        lines.append(f"- **{cat['theme']}**: {ids_str}. {cat['summary']}")
    return ThreatCard(name="OWASP AI Top-10 Cross-walk", body="\n".join(lines))


def mitre_atlas_card() -> ThreatCard:
    """Build the ATLAS card from the pinned catalog so the cards never drift
    from the IDs we'll later validate against.

    The full catalog's descriptions run to about 180,000 characters, too much
    for every prompt, so the card lists each top-level technique by id, name,
    and tactic only, and says that sub-techniques exist.
    """

    entries = [e for e in load_atlas_entries() if "." not in e.technique_id.removeprefix("AML.")]
    lines = [
        "MITRE ATLAS catalogues adversary techniques against ML/AI systems.",
        "When threats touch model training, inference, or agent capabilities,",
        "consider these techniques in addition to MITRE ATT&CK Enterprise.",
        "Many have sub-techniques with ids such as AML.T0051.000.",
        "",
    ]
    for entry in entries:
        lines.append(f"- **{entry.technique_id} {entry.name}** ({entry.tactic})")
    return ThreatCard(name=ATLAS_CARD_NAME, body="\n".join(lines))


# Pattern to cards. Patterns can layer (an agentic RAG app gets ASI + LLM +
# ATLAS) so we use a set-based selector.

_PATTERN_TO_CARDS = {
    "GenAI": ("owasp_llm", "owasp_crosswalk"),
    "RAG": ("owasp_llm", "owasp_crosswalk"),
    "Agentic": ("owasp_llm", "owasp_agentic", "owasp_crosswalk"),
    "Tool Use": ("owasp_llm", "owasp_agentic", "owasp_crosswalk"),
    "Code Execution": ("owasp_llm", "owasp_agentic", "owasp_crosswalk"),
    "ML": ("mitre_atlas", "owasp_crosswalk"),
}

def _card_factories() -> dict[str, Callable[[], ThreatCard]]:
    return {
        "owasp_llm": owasp_llm_card,
        "owasp_agentic": owasp_agentic_card,
        "owasp_crosswalk": owasp_crosswalk_card,
        "mitre_atlas": mitre_atlas_card,
    }


def cards_for_patterns(patterns: Iterable[str]) -> list[ThreatCard]:
    """Return the deduped list of ThreatCard objects for a set of pattern tags.

    Unknown patterns are ignored. Order is stable: OWASP LLM, OWASP Agentic,
    ATLAS, so the prompt reads consistently across requests.
    """

    keys: list[str] = []
    seen: set[str] = set()
    for pattern in patterns:
        for key in _PATTERN_TO_CARDS.get(pattern, ()):
            if key not in seen:
                seen.add(key)
                keys.append(key)

    factories = _card_factories()
    canonical_order = ["owasp_llm", "owasp_agentic", "owasp_crosswalk", "mitre_atlas"]
    ordered = [key for key in canonical_order if key in seen]
    return [factories[key]() for key in ordered]


def cards_for_app(app_type: str, patterns: Iterable[str]) -> list[ThreatCard]:
    """Convenience: combine app-type implications with explicit patterns.

    Every AI system (``ai_system.is_ai_system``: an AI application type or
    any AI pattern) gets the ATLAS card. AI application types also get the
    OWASP LLM card even when no pattern was tagged.
    """

    pattern_set: set[str] = set(patterns or [])
    if app_type in AI_APP_TYPES:
        pattern_set.add("ML")
        pattern_set.add("GenAI")
    cards = cards_for_patterns(pattern_set)
    if is_ai_system(app_type, pattern_set) and not any(c.name == ATLAS_CARD_NAME for c in cards):
        cards.append(mitre_atlas_card())
    return cards
