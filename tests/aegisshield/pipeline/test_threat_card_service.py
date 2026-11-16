"""Threat cards: rendering each card and choosing cards by pattern and app type."""

from __future__ import annotations

from aegisshield.data import data_path
from aegisshield.pipeline import threat_card_service
from aegisshield.pipeline.threat_card_service import (
    ThreatCard,
    cards_for_app,
    cards_for_patterns,
    mitre_atlas_card,
    owasp_agentic_card,
    owasp_crosswalk_card,
    owasp_llm_card,
)


def test_owasp_llm_card_renders() -> None:
    card = owasp_llm_card()
    assert isinstance(card, ThreatCard)
    rendered = card.render()
    assert "OWASP Top 10 for LLM Applications" in rendered
    assert "LLM01" in rendered  # spot-check that body content shipped


def test_owasp_agentic_card_renders() -> None:
    rendered = owasp_agentic_card().render()
    assert "ASI01" in rendered
    assert "Tool Misuse" in rendered or "ASI02" in rendered


def test_mitre_atlas_card_built_from_pinned_catalog() -> None:
    card = mitre_atlas_card()
    rendered = card.render()
    # Must include the canonical LLM Prompt Injection technique from the pin.
    assert "AML.T0051" in rendered
    assert "MITRE ATLAS" in rendered
    # Top-level techniques only, without descriptions, so the card stays prompt-sized.
    assert "- **AML.T0051 LLM Prompt Injection** (Execution)" in rendered
    assert "AML.T0051.000 Direct" not in rendered
    assert len(rendered) < 12_000


def test_owasp_crosswalk_card_renders_concept_rows() -> None:
    rendered = owasp_crosswalk_card().render()
    assert "Cross-walk" in rendered
    # Spot-check a couple of canonical concept rows.
    assert "Prompt-injection" in rendered or "prompt-injection" in rendered.lower()
    assert "LLM01" in rendered
    assert "Resource exhaustion" in rendered


def test_cards_for_patterns_returns_canonical_order() -> None:
    cards = cards_for_patterns(["Tool Use", "ML"])  # arbitrary input order
    names = [c.name for c in cards]
    # Canonical order: OWASP LLM, OWASP Agentic, OWASP cross-walk, ATLAS.
    assert names.index("OWASP Top 10 for LLM Applications") < names.index(
        "OWASP Agentic Security Initiative"
    )
    assert "MITRE ATLAS Techniques" in names
    assert "OWASP AI Top-10 Cross-walk" in names


def test_cards_for_patterns_dedups() -> None:
    # "GenAI" and "RAG" both pull owasp_llm + cross-walk; only one of each.
    cards = cards_for_patterns(["GenAI", "RAG"])
    assert [c.name for c in cards] == [
        "OWASP Top 10 for LLM Applications",
        "OWASP AI Top-10 Cross-walk",
    ]


def test_cards_for_patterns_ignores_unknown_tags() -> None:
    cards = cards_for_patterns(["NotARealPattern"])
    assert cards == []


def test_cards_for_app_auto_attaches_for_ai_app_types() -> None:
    cards = cards_for_app("AI/ML Systems", patterns=[])
    names = {c.name for c in cards}
    assert "OWASP Top 10 for LLM Applications" in names
    assert "MITRE ATLAS Techniques" in names
    assert "OWASP AI Top-10 Cross-walk" in names


def test_cards_for_app_no_cards_for_plain_web_app() -> None:
    cards = cards_for_app("Web application", patterns=[])
    assert cards == []


def test_threat_card_service_uses_committed_files() -> None:
    # The cards are read from the package data directory, so the files must
    # be committed there.
    card_dir = threat_card_service.THREAT_CARD_DIR
    assert data_path(card_dir, "owasp_llm_top_10.md").is_file()
    assert data_path(card_dir, "owasp_agentic.md").is_file()
    assert data_path(card_dir, "owasp_crosswalk.json").is_file()
