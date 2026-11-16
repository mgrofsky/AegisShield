"""The one definition of an AI system, used wherever MITRE ATLAS applies.

An application is an AI system when its application type is one of
``AI_APP_TYPES`` or when any AI pattern (``AI_PATTERNS``) was selected in the
wizard or detected from the description. An AI system gets the ATLAS
reference card in the STRIDE prompt, an ATLAS technique per threat, and the
ATLAS block in the results and exports; any other system gets none of them.
The catalog, the threat cards, the results view, and the EU AI Act view all
ask this module, so they cannot disagree.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

# Application types that are AI systems on their own, whatever the patterns.
AI_APP_TYPES: frozenset[str] = frozenset({
    "AI/ML Systems",
    "Machine Learning Inference Service",
    "Federated Learning System",
})

# Every architecture pattern the wizard offers is an AI pattern
# (``pattern_detection_service.supported_patterns()``; a test pins both).
AI_PATTERNS: frozenset[str] = frozenset({"GenAI", "RAG", "Agentic", "Tool Use", "Code Execution", "ML"})


def is_ai_system(app_type: object, patterns: Iterable[object] | None = None) -> bool:
    """True for an AI application type or any AI pattern, selected or detected."""
    if isinstance(app_type, str) and app_type in AI_APP_TYPES:
        return True
    return any(isinstance(p, str) and p in AI_PATTERNS for p in patterns or ())


def payload_is_ai_system(payload: Mapping[str, Any]) -> bool:
    """``is_ai_system`` for a stored threat model: its profile's application
    type and chosen patterns, plus the patterns the run detected."""
    profile = payload.get("profile") if isinstance(payload.get("profile"), Mapping) else {}
    chosen = profile.get("app_pattern") if isinstance(profile.get("app_pattern"), list) else []
    detected = payload.get("detected_patterns") if isinstance(payload.get("detected_patterns"), list) else []
    return is_ai_system(profile.get("app_type"), [*chosen, *detected])
