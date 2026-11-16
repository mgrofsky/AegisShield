"""The one definition of an AI system, and every place that uses it agreeing."""

from __future__ import annotations

import pytest

from aegisshield.pipeline import ai_system, catalog_service, pattern_detection_service
from aegisshield.pipeline.threat_card_service import ATLAS_CARD_NAME, cards_for_app
from aegisshield.ui import options
from aegisshield.ui import threat_model_view as view

CASES = [
    ("AI/ML Systems", [], True),
    ("Machine Learning Inference Service", [], True),
    ("Federated Learning System", [], True),
    *[("Web application", [pattern], True) for pattern in sorted(ai_system.AI_PATTERNS)],
    ("Mobile application", ["Tool Use"], True),
    ("Web application", [], False),
    ("Robotic Process Automation (RPA)", [], False),
    ("ICS or SCADA System", ["Not a pattern"], False),
    ("", None, False),
]


@pytest.mark.parametrize(("app_type", "patterns", "expected"), CASES)
def test_is_ai_system_across_app_types_and_patterns(app_type: str, patterns: list[str] | None,
                                                    expected: bool) -> None:
    assert ai_system.is_ai_system(app_type, patterns) is expected


@pytest.mark.parametrize(("app_type", "patterns", "expected"), CASES)
def test_the_catalog_the_cards_and_the_results_view_agree(app_type: str, patterns: list[str] | None,
                                                          expected: bool) -> None:
    patterns = patterns or []
    assert catalog_service.domains_for_app_type(app_type, patterns)[1] is expected
    has_atlas = any(e.framework == "ATLAS" for e in catalog_service.catalog_for_app_type(app_type, patterns))
    assert has_atlas is expected
    assert any(c.name == ATLAS_CARD_NAME for c in cards_for_app(app_type, patterns)) is expected
    payload = {"profile": {"app_type": app_type, "app_pattern": patterns}}
    assert ai_system.payload_is_ai_system(payload) is expected
    assert view.is_ai_system(payload) is expected


def test_detected_patterns_count_as_much_as_chosen_ones() -> None:
    payload = {"profile": {"app_type": "Web application"}, "detected_patterns": ["RAG"]}
    assert ai_system.payload_is_ai_system(payload)
    assert not ai_system.payload_is_ai_system({"profile": "not a profile", "detected_patterns": "RAG"})


def test_every_wizard_pattern_is_an_ai_pattern_and_the_lists_are_one() -> None:
    assert ai_system.AI_PATTERNS == set(pattern_detection_service.supported_patterns())
    assert options.AI_PATTERNS is ai_system.AI_PATTERNS
    assert ai_system.AI_APP_TYPES <= set(options.APP_TYPE_OPTIONS)


def test_the_eu_ai_act_view_also_opens_for_the_framework_alone() -> None:
    payload = {"profile": {"app_type": "Web application", "compliance_requirements": ["EU AI Act"]}}
    assert view.is_ai_system(payload)
    assert not ai_system.payload_is_ai_system(payload)
