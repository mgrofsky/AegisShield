"""Match threats to regulatory obligations.

``match_threats_to_framework`` scores each threat against each obligation of
a pinned framework (today the EU AI Act) by keyword overlap and returns the
top obligations per threat. Pure data, no model calls.
"""

from __future__ import annotations

import copy
import json
import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from aegisshield.data import data_path

logger = logging.getLogger(__name__)

REGULATIONS_DIR = "regulations"

# Pinned framework registry. Adding a file here is the only step needed to
# expose another regulation through the matcher.
_PINNED_FRAMEWORKS: dict[str, str] = {
    "eu-ai-act": "eu-ai-act-2026-graph.json",
}


@dataclass(frozen=True)
class ObligationMatch:
    """One obligation that matched a threat, with its overlap score (0 to 1)."""

    obligation_id: str
    article: str
    name: str
    summary: str
    score: float


@lru_cache(maxsize=len(_PINNED_FRAMEWORKS))
def _load(filename: str) -> dict[str, Any]:
    """A pinned framework file. Public reference data, so a process cache is fine."""
    with data_path(REGULATIONS_DIR, filename).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_framework(framework_slug: str) -> dict[str, Any]:
    """A copy of the pinned framework's data. Raises ``ValueError`` for an unknown slug."""
    filename = _PINNED_FRAMEWORKS.get(framework_slug)
    if not filename:
        raise ValueError(f"Unknown regulation framework: {framework_slug}")
    # The cached dict is shared by every visitor, so callers get their own copy.
    return copy.deepcopy(_load(filename))


def _tokenise(text: str) -> set[str]:
    """Lower-case alphanumeric word tokens plus overlapping bigrams.

    Bigrams let "data poisoning" in a threat match the keyword "data
    poisoning" without matching every threat that says "data".
    """
    if not text:
        return set()
    words = [w.lower() for w in re.findall(r"[A-Za-z][A-Za-z0-9]+", text)]
    tokens: set[str] = set(words)
    for a, b in zip(words, words[1:], strict=False):
        tokens.add(f"{a} {b}")
    return tokens


def _score(threat_tokens: set[str], keyword_tokens: set[str]) -> float:
    if not keyword_tokens:
        return 0.0
    overlap = threat_tokens & keyword_tokens
    if not overlap:
        return 0.0
    # Soft denominator so a single-keyword obligation that matches still
    # comes out near the top of the list.
    return len(overlap) / max(len(keyword_tokens), 4)


def match_threats_to_obligations(
    threat_model: list[dict[str, Any]],
    framework: dict[str, Any],
    *,
    top_n: int = 3,
    min_score: float = 0.05,
) -> dict[str, list[ObligationMatch]]:
    """Top obligation matches per threat, keyed by threat ``ID`` (or ``Scenario``).

    ``framework`` is a pinned file or what ``extract_requirements_from_pdf``
    returns. Obligations without an ``id`` are skipped.
    """
    obligations: list[tuple[dict[str, Any], set[str]]] = []
    for ob in framework.get("obligations", []) or []:
        if not isinstance(ob, dict) or not ob.get("id"):
            continue
        kw_tokens: set[str] = set()
        keywords = ob.get("threat_keywords") or []
        for kw in keywords if isinstance(keywords, list) else []:
            kw_tokens.update(_tokenise(str(kw)))
        kw_tokens.update(_tokenise(str(ob.get("name", ""))))
        obligations.append((ob, kw_tokens))

    out: dict[str, list[ObligationMatch]] = {}
    for threat in threat_model:
        threat_text = " ".join(
            str(threat.get(k, "")) for k in ("Threat Type", "Scenario", "Potential Impact")
        )
        # MITRE keywords are often the most specific signal.
        kws = threat.get("MITRE ATT&CK Keywords") or []
        if isinstance(kws, list):
            threat_text += " " + " ".join(str(k) for k in kws)
        threat_tokens = _tokenise(threat_text)

        scored: list[ObligationMatch] = []
        for ob, kw_tokens in obligations:
            score = _score(threat_tokens, kw_tokens)
            if score >= min_score:
                scored.append(
                    ObligationMatch(
                        obligation_id=str(ob["id"]),
                        article=str(ob.get("article", "")),
                        name=str(ob.get("name", "")),
                        summary=str(ob.get("summary", "")),
                        score=round(score, 3),
                    )
                )
        scored.sort(key=lambda m: m.score, reverse=True)
        key = str(threat.get("ID") or threat.get("Scenario") or "")
        out[key] = scored[:top_n]
    return out


def match_threats_to_framework(
    threat_model: list[dict[str, Any]],
    framework_slug: str,
    *,
    top_n: int = 3,
    min_score: float = 0.05,
) -> dict[str, list[ObligationMatch]]:
    """Top obligation matches per threat for a pinned framework.

    Raises ``ValueError`` for an unknown slug.
    """
    return match_threats_to_obligations(
        threat_model, load_framework(framework_slug), top_n=top_n, min_score=min_score
    )
