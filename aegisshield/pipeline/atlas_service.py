"""Map each threat of an AI system to one MITRE ATLAS technique.

This runs after the ATT&CK mapping and leaves it as it is. It costs one model
call per run, whatever the number of threats:

1. Candidates (no model): for each threat, the ATLAS techniques and
   sub-techniques whose name and description share the most informative
   words with the threat's scenario, impact, and ATT&CK keywords. A word
   counts more the fewer ATLAS entries use it (inverse document frequency),
   and three times more in a name than in a description. Words for the
   application's AI patterns ("prompt", "retrieval", "agent") add a little,
   and an entry whose tactic suits the threat's STRIDE category gets a small
   bonus. The best ``MAX_CANDIDATES`` with any word in common are kept.
2. One structured request: every threat with its candidate ids, and each
   distinct candidate once (id, name, tactic, first sentence of its
   description). The model answers one technique id or ``NONE`` per threat.
3. Checking: an id counts only when it is in the ATLAS catalog and among
   that threat's candidates. ``NONE`` is stored as no technique; an id that
   fails the check is stored as no technique too, never replaced by a guess.
4. Mitigations and case studies for each mapped technique come from the
   catalog, never from the model.

Text from the catalog that reaches a prompt is bundled reference data. Only
names, tactics, and first sentences reach a prompt; case studies never do
(some quote real injection payloads). A test checks every string that can
reach a prompt against the safeguards' detectors.
"""

from __future__ import annotations

import json
import logging
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from functools import lru_cache
from typing import Any

from aegisshield.llm.base import LLMClient
from aegisshield.pipeline import catalog_service
from aegisshield.pipeline.catalog_service import CatalogEntry
from aegisshield.pipeline.sector_context import focus_block

logger = logging.getLogger(__name__)

# The result key that holds the ATLAS mapping (present only for an AI system).
ATLAS_RESULT_KEY = "atlas_mapping"

MAX_CANDIDATES = 10
DESCRIPTION_CHARS = 160
MAX_SHOWN = 5
MAX_REFERENCE_MITIGATIONS = 5

STATUS_MAPPED = "mapped"
STATUS_NONE_FITS = "none_fits"
STATUS_NO_CANDIDATES = "no_candidates"
STATUS_REJECTED = "rejected"
STATUS_NOT_ANSWERED = "not_answered"

STATUS_TEXT = {
    STATUS_MAPPED: "Mapped",
    STATUS_NONE_FITS: "No ATLAS technique fits this threat (the model's answer).",
    STATUS_NO_CANDIDATES: "No ATLAS technique shares words with this threat, so none was offered.",
    STATUS_REJECTED: "The model named an id that is not one of this threat's ATLAS candidates; it was not used.",
    STATUS_NOT_ANSWERED: "The ATLAS step gave no usable answer for this threat.",
}

ATLAS_SYSTEM = (
    "You map threats to MITRE ATLAS techniques. For each threat, choose the one candidate "
    "technique that best describes how an adversary would carry it out, or NONE when no "
    "candidate fits. Choose only from that threat's own candidates. Answer only with a JSON "
    'object of the form {"atlas": [{"threat_id": "TC-S01", "technique_id": "AML.T0051"}]}.'
)
CANDIDATES_HEADER = "ATLAS candidates per threat"

_WORD_RE = re.compile(r"[a-z0-9]+")
_NAME_WEIGHT = 3.0
_HINT_WEIGHT = 0.5
_TACTIC_BONUS = 1.0
_STOPWORDS = frozenset(
    "a an and are as at be been being by can could do does for from has have how in into is it "
    "its may might more most of on or other such than that the their them then there these they "
    "this those through to use used uses using via was were when where which while who will with "
    "within without would adversary adversaries attacker attackers threat threats".split()
)
_SUFFIXES = ("ations", "ation", "ions", "ion", "ings", "ing", "ed", "es", "s", "e")

# STRIDE letter (as in threat ids) to the ATLAS tactics that usually carry it.
_STRIDE_TACTICS: dict[str, frozenset[str]] = {
    "S": frozenset({"Initial Access", "Credential Access", "Defense Evasion", "Lateral Movement"}),
    "T": frozenset({"Persistence", "AI Attack Adaptation", "Execution", "Impact"}),
    "R": frozenset({"Defense Evasion"}),
    "I": frozenset({"Exfiltration", "Collection", "Discovery", "Credential Access"}),
    "D": frozenset({"Impact"}),
    "E": frozenset({"Privilege Escalation", "Execution", "Lateral Movement"}),
}
_PATTERN_HINTS: dict[str, str] = {
    "GenAI": "llm prompt injection jailbreak",
    "RAG": "rag retrieval poisoning",
    "Agentic": "agent",
    "Tool Use": "agent tool invocation",
    "Code Execution": "command execution sandbox escape",
    "ML": "model training data inference",
}


# ------------------------------------------------------------- candidates


def _stem(word: str) -> str:
    if word.endswith("ss"):
        return word
    for suffix in _SUFFIXES:
        if word.endswith(suffix) and len(word) - len(suffix) >= 4:
            return word[: -len(suffix)]
    return word


def words(text: str) -> set[str]:
    """The informative words of ``text``, lower case and lightly stemmed.

    One pass of a single-class pattern, so linear in the length of ``text``.
    """
    return {_stem(w) for w in _WORD_RE.findall(text.lower()) if len(w) > 2 and w not in _STOPWORDS}


@lru_cache(maxsize=1)
def _index() -> tuple[tuple[tuple[CatalogEntry, frozenset[str], frozenset[str]], ...], dict[str, float]]:
    """Each ATLAS entry with its name and description words, and each word's weight."""
    rows = []
    frequency: dict[str, int] = {}
    for entry in catalog_service.load_atlas_entries():
        name = frozenset(words(catalog_service.atlas_display_name(entry)))
        description = frozenset(words(entry.description)) - name
        rows.append((entry, name, description))
        for word in name | description:
            frequency[word] = frequency.get(word, 0) + 1
    total = len(rows)
    weights = {word: math.log((1 + total) / (1 + count)) + 1.0 for word, count in frequency.items()}
    return tuple(rows), weights


def _threat_text(threat: Mapping[str, Any]) -> str:
    keywords = threat.get("MITRE ATT&CK Keywords")
    parts = [str(threat.get("Scenario") or ""), str(threat.get("Potential Impact") or "")]
    if isinstance(keywords, list):
        parts.extend(str(k) for k in keywords if isinstance(k, str))
    return " ".join(parts)


def _stride_letter(threat: Mapping[str, Any]) -> str:
    threat_id = str(threat.get("ID") or "")
    return threat_id[3] if threat_id.startswith("TC-") and len(threat_id) > 3 else ""


def candidates(threat: Mapping[str, Any], patterns: Iterable[str] = (),
               limit: int = MAX_CANDIDATES) -> list[CatalogEntry]:
    """The ATLAS entries most likely to describe ``threat``, best first.

    Only entries that share at least one word with the threat or its
    patterns' hint words are kept; ties keep catalog order.
    """
    rows, weights = _index()
    query = words(_threat_text(threat))
    hints = set().union(*(words(_PATTERN_HINTS.get(p, "")) for p in patterns)) - query
    tactics = _STRIDE_TACTICS.get(_stride_letter(threat), frozenset())
    scored: list[tuple[float, int, CatalogEntry]] = []
    for position, (entry, name, description) in enumerate(rows):
        score = 0.0
        for word in query & name:
            score += _NAME_WEIGHT * weights[word]
        for word in query & description:
            score += weights[word]
        for word in hints & name:
            score += _HINT_WEIGHT * _NAME_WEIGHT * weights[word]
        for word in hints & description:
            score += _HINT_WEIGHT * weights[word]
        if score <= 0:
            continue
        if entry.tactic in tactics:
            score += _TACTIC_BONUS
        scored.append((-score, position, entry))
    scored.sort(key=lambda item: (item[0], item[1]))
    return [entry for _score, _position, entry in scored[:limit]]


# ----------------------------------------------------------------- prompt


def first_sentence(text: str, limit: int = DESCRIPTION_CHARS) -> str:
    """The first sentence of ``text`` on one line, cut to ``limit`` characters.

    Only this much of a description reaches a prompt: later sentences of a
    few entries quote markup or phrases a model could read as instructions.
    """
    flat = " ".join(text.split())
    end = flat.find(". ")
    sentence = flat[: end + 1] if end != -1 else flat
    return sentence if len(sentence) <= limit else sentence[: limit - 3].rstrip() + "..."


def candidate_card(entry: CatalogEntry) -> dict[str, str]:
    """What the prompt shows of one candidate."""
    return {
        "id": entry.technique_id,
        "name": catalog_service.atlas_display_name(entry),
        "tactic": entry.tactic,
        "summary": first_sentence(entry.description),
    }


def create_atlas_prompt(
    app_details: Mapping[str, Any],
    patterns: Sequence[str],
    threats: Sequence[Mapping[str, Any]],
    per_threat: Mapping[str, Sequence[CatalogEntry]],
    focus: str | None = None,
) -> str:
    """The one ATLAS request: the threats, each distinct candidate once, and each threat's candidate ids."""
    pool: dict[str, dict[str, str]] = {}
    for entries in per_threat.values():
        for entry in entries:
            pool.setdefault(entry.technique_id, candidate_card(entry))
    listed = [
        {"threat_id": str(t.get("ID") or ""), "threat_type": str(t.get("Threat Type") or ""),
         "scenario": str(t.get("Scenario") or "")}
        for t in threats if str(t.get("ID") or "") in per_threat
    ]
    ids = {tid: [e.technique_id for e in entries] for tid, entries in per_threat.items()}
    return f"""
APPLICATION TYPE: {app_details.get('app_type', '')}
AI PATTERNS: {', '.join(patterns) or 'none'}
{focus_block(focus).lstrip()}
Threats, one per line:
{chr(10).join(json.dumps(item) for item in listed)}

ATLAS techniques (reference data from the bundled MITRE ATLAS {catalog_service.atlas_version()} catalog), one per line:
{chr(10).join(json.dumps(card) for card in pool.values())}

{CANDIDATES_HEADER}:
{json.dumps(ids)}

For each threat choose one id from its own candidates, or "NONE" when none of them fits.
""".strip()


# ----------------------------------------------------------------- answer


def _picks(answer: object) -> dict[str, str]:
    """``threat_id -> technique_id`` from the model's answer; anything else is ignored."""
    rows = answer.get("atlas") if isinstance(answer, Mapping) else None
    picks: dict[str, str] = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, Mapping):
            continue
        threat_id, technique_id = row.get("threat_id"), row.get("technique_id")
        if isinstance(threat_id, str) and isinstance(technique_id, str) and threat_id.strip():
            picks.setdefault(threat_id.strip(), technique_id.strip())
    return picks


def _linked(items: Sequence[Any]) -> list[dict[str, str]]:
    return [{"id": item.id, "name": item.name} for item in items[:MAX_SHOWN]]


def technique_links(technique_id: str) -> dict[str, Any]:
    """The mitigations and case studies the catalog links to a technique.

    A sub-technique with none of its own shows its parent's, and says so
    (``mitigations_from`` and ``case_studies_from`` name the id whose links
    are shown). Lists are cut to ``MAX_SHOWN``; the totals are not.
    """
    parent = technique_id.rsplit(".", 1)[0] if technique_id.count(".") == 2 else None
    out: dict[str, Any] = {}
    for key, lookup in (("mitigations", catalog_service.atlas_mitigations_for),
                        ("case_studies", catalog_service.atlas_case_studies_for)):
        source = technique_id
        items = lookup(technique_id)
        if not items and parent:
            items, source = lookup(parent), parent
        out[key] = _linked(items)
        out[f"{key}_total"] = len(items)
        out[f"{key}_from"] = source
    return out


def _row(threat: Mapping[str, Any], status: str, entry: CatalogEntry | None) -> dict[str, Any]:
    row: dict[str, Any] = {
        "threat_id": str(threat.get("ID") or ""),
        "threat_type": str(threat.get("Threat Type") or ""),
        "status": status,
        "technique": None,
    }
    if entry is not None:
        row["technique"] = {"technique_id": entry.technique_id,
                            "name": catalog_service.atlas_display_name(entry), "tactic": entry.tactic}
        row.update(technique_links(entry.technique_id))
    return row


def map_threats_to_atlas(
    threats: Sequence[Mapping[str, Any]],
    app_details: Mapping[str, Any],
    patterns: Sequence[str],
    llm: LLMClient,
    model: str,
    focus: str | None = None,
) -> dict[str, Any]:
    """The ATLAS mapping of an AI system's threats, from one model call.

    Returns ``{"attack_version", "atlas_version", "call", "threats": [row, ...]}``
    with one row per threat in order (see ``_row``). ``call`` is "answered",
    or "none" when no threat had candidates and so no call was made. A failed
    call raises; ``atlas_step`` turns that into a stored "failed" mapping.
    """
    per_threat: dict[str, list[CatalogEntry]] = {}
    for threat in threats:
        threat_id = str(threat.get("ID") or "")
        found = candidates(threat, patterns)
        if threat_id and found:
            per_threat.setdefault(threat_id, found)
    picks: dict[str, str] = {}
    if per_threat:
        prompt = create_atlas_prompt(app_details, patterns, threats, per_threat, focus)
        picks = _picks(llm.chat_json(system=ATLAS_SYSTEM, user=prompt, model=model))
    index = catalog_service.atlas_index()
    rows = []
    for threat in threats:
        threat_id = str(threat.get("ID") or "")
        offered = per_threat.get(threat_id)
        pick = picks.get(threat_id)
        if not offered:
            rows.append(_row(threat, STATUS_NO_CANDIDATES, None))
        elif pick is None or not pick:
            rows.append(_row(threat, STATUS_NOT_ANSWERED, None))
        elif pick.upper() == "NONE":
            rows.append(_row(threat, STATUS_NONE_FITS, None))
        elif pick in index and any(e.technique_id == pick for e in offered):
            rows.append(_row(threat, STATUS_MAPPED, index[pick]))
        else:
            logger.info("atlas_pick_rejected")
            rows.append(_row(threat, STATUS_REJECTED, None))
    return _mapping("answered" if per_threat else "none", rows)


def _mapping(call: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "attack_version": catalog_service.attack_version(),
        "atlas_version": catalog_service.atlas_version(),
        "call": call,
        "threats": rows,
    }


def unanswered_mapping(threats: Sequence[Mapping[str, Any]], patterns: Sequence[str]) -> dict[str, Any]:
    """The mapping to store when the ATLAS call failed: every threat that had
    candidates reads "not answered", the rest "no candidates"."""
    rows = [_row(t, STATUS_NOT_ANSWERED if candidates(t, patterns) else STATUS_NO_CANDIDATES, None)
            for t in threats]
    return _mapping("failed", rows)


def atlas_step(
    threats: Sequence[Mapping[str, Any]],
    app_details: Mapping[str, Any],
    patterns: Sequence[str],
    llm: LLMClient,
    model: str,
    focus: str | None = None,
) -> dict[str, Any]:
    """``map_threats_to_atlas`` for a run: a failed call (the model, its
    answer, or the safeguards withholding it) is stored as a "failed"
    mapping with no techniques, and the run goes on with its ATT&CK mapping."""
    try:
        return map_threats_to_atlas(threats, app_details, patterns, llm, model, focus)
    # The ATLAS pick adds to a finished ATT&CK mapping; any failure leaves
    # that mapping as it is, and the stored "failed" mapping says so.
    except Exception as exc:
        logger.warning("atlas_mapping_failed kind=%s", type(exc).__name__)
        return unanswered_mapping(threats, patterns)


# ------------------------------------------------------------ downstream


def mapping_rows(mapping: object) -> list[dict[str, Any]]:
    """The rows of a stored mapping, or none for anything else (an older record)."""
    rows = mapping.get("threats") if isinstance(mapping, Mapping) else None
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def mitigation_reference(mapping: object) -> str:
    """A short reference for the mitigations prompt: each mapped threat's ATLAS
    technique and up to ``MAX_REFERENCE_MITIGATIONS`` mitigation names, all
    from the catalog. Empty when nothing was mapped."""
    lines = []
    for row in mapping_rows(mapping):
        technique = row.get("technique")
        if not isinstance(technique, Mapping):
            continue
        names = [str(m.get("name") or "") for m in row.get("mitigations") or [] if isinstance(m, Mapping)]
        names = [n for n in names if n][:MAX_REFERENCE_MITIGATIONS]
        line = f"- {row.get('threat_id')}: {technique.get('technique_id')} {technique.get('name')}"
        lines.append(f"{line}. ATLAS mitigations: {'; '.join(names)}" if names else line)
    return "\n".join(lines)


__all__ = [
    "ATLAS_RESULT_KEY",
    "ATLAS_SYSTEM",
    "CANDIDATES_HEADER",
    "MAX_CANDIDATES",
    "MAX_SHOWN",
    "STATUS_TEXT",
    "atlas_step",
    "candidate_card",
    "candidates",
    "create_atlas_prompt",
    "first_sentence",
    "map_threats_to_atlas",
    "mapping_rows",
    "mitigation_reference",
    "technique_links",
    "unanswered_mapping",
    "words",
]
