"""Detect architectural patterns from a free-text application description.

Patterns flagged here drive which OWASP/ATLAS reference cards (Step 2) are
appended to the threat-model prompt. The detector is deliberately
deterministic-first: a small regex/keyword sweep is cheap and predictable.
A model-based fallback is available when the regex pass returns nothing;
the caller decides whether to use it (it costs a model call).

Pattern tags returned: ``"GenAI"``, ``"RAG"``, ``"Agentic"``, ``"Tool Use"``,
``"Code Execution"``, ``"ML"``. Tags are deduplicated and sorted so the
output is stable across runs (important for snapshot-style prompts).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass

from aegisshield.core.errors import LLMError
from aegisshield.llm.base import LLMClient

logger = logging.getLogger(__name__)

# Pattern to list of regex strings. Each pattern is matched if ANY of its
# regexes hits (case-insensitive). Keep these conservative; false positives
# attach extra cards but don't change correctness, while false negatives
# miss the cards entirely. Bias toward recall.

_PATTERN_RULES: dict[str, list[str]] = {
    "GenAI": [
        r"\bllm\b",
        r"\blarge\s+language\s+model\b",
        r"\bgenerative\s+ai\b",
        r"\bgen[\s-]?ai\b",
        r"\bgpt\b",
        r"\bclaude\b",
        r"\bbedrock\b",
        r"\bopenai\b",
        r"\bchatbot\b",
        r"\bcopilot\b",
        r"\bprompt(s|ing)?\b",
        r"\bembedding(s)?\b",
    ],
    "RAG": [
        r"\brag\b",
        r"\bretrieval[\s-]?augmented\b",
        r"\bvector\s+(database|store|index|search)\b",
        r"\b(pgvector|pinecone|weaviate|chroma|qdrant|milvus|opensearch[\s-]?neural|elastic[\s-]?vector)\b",
        r"\b(faiss|hnsw)\b",
        r"\b(knowledge\s+base|document\s+chunks?)\b",
    ],
    "Agentic": [
        r"\bagent(s|ic)?\b",
        r"\bautonomous\s+agent\b",
        r"\bmulti[\s-]?agent\b",
        r"\b(crew[\s-]?ai|langgraph|autogen|metagpt|swarm)\b",
        r"\breasoning\s+loop\b",
        r"\b(plan(ning|ner)?|orchestrator)\b",
    ],
    "Tool Use": [
        r"\btool[\s-]?use\b",
        r"\btool[\s-]?call(s|ing)?\b",
        r"\bfunction[\s-]?call(s|ing)?\b",
        r"\bplugin(s)?\b",
        r"\bmcp\b",  # Model Context Protocol
        r"\bopenapi\s+spec\b",
    ],
    "Code Execution": [
        r"\bcode\s+execution\b",
        r"\bcode[\s-]?interpreter\b",
        r"\bsandbox\b",
        r"\b(eval|exec)\s*\(",
        r"\bjupyter\b",
        r"\bcontainer\s+execution\b",
        r"\bshell\s+access\b",
    ],
    "ML": [
        r"\bmachine\s+learning\b",
        r"\bneural\s+network\b",
        r"\bdeep\s+learning\b",
        r"\bmodel\s+training\b",
        r"\binference\s+endpoint\b",
        r"\bsagemaker\b",
        r"\bhugging\s*face\b",
        r"\bpytorch\b|\btensorflow\b|\bjax\b",
    ],
}

_COMPILED_RULES: dict[str, list[re.Pattern[str]]] = {
    pattern: [re.compile(rx, re.IGNORECASE) for rx in regexes]
    for pattern, regexes in _PATTERN_RULES.items()
}


@dataclass(frozen=True)
class PatternDetectionResult:
    """The detected pattern tags and how they were found."""

    patterns: list[str]
    method: str  # "regex", "llm", or "regex+llm"

    def is_empty(self) -> bool:
        """True when no pattern was detected."""
        return not self.patterns


def detect_patterns_regex(description: str) -> list[str]:
    """Apply regex rules and return the matched patterns, sorted for stability."""

    if not description:
        return []
    matched: set[str] = set()
    for pattern, regexes in _COMPILED_RULES.items():
        for rx in regexes:
            if rx.search(description):
                matched.add(pattern)
                break
    return sorted(matched)


def detect_patterns_llm(description: str, llm: LLMClient, model: str) -> list[str]:
    """Ask the model to choose pattern tags from a fixed list.

    Returned tags are validated against the known set; anything else is
    discarded. This is intended as a fallback when regex misses (e.g., a
    description that euphemises an LLM as "an AI assistant") and is gated
    by the caller; it costs a model call.
    """

    allowed = sorted(_PATTERN_RULES.keys())
    prompt = (
        "You are tagging an application description with architectural patterns.\n"
        "Return only a JSON array of tags chosen from this exact list:\n"
        f"{json.dumps(allowed)}\n\n"
        "Use only tags that clearly apply. Output an empty array if none apply.\n\n"
        "APPLICATION DESCRIPTION:\n"
        f"{description}\n"
    )
    try:
        response_text = llm.chat_text(
            system="You are a precise application classifier.",
            user=prompt,
            model=model,
        )
    except LLMError as exc:
        logger.warning("pattern_detection_llm_failed kind=%s", type(exc).__name__)
        return []

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
        return []
    if not isinstance(parsed, list):
        return []
    valid = {tag for tag in parsed if isinstance(tag, str) and tag in _PATTERN_RULES}
    return sorted(valid)


def detect_patterns(
    description: str,
    *,
    llm: LLMClient | None = None,
    model: str | None = None,
    use_llm_fallback: bool = False,
) -> PatternDetectionResult:
    """Run the deterministic pass; optionally ask an LLM if it returned nothing.

    The LLM fallback only fires when ``use_llm_fallback=True`` AND the regex
    pass found nothing AND ``llm``/``model`` are supplied. This
    keeps the default path zero-cost and side-effect-free.
    """

    regex_hits = detect_patterns_regex(description)
    if regex_hits:
        return PatternDetectionResult(patterns=regex_hits, method="regex")

    if not use_llm_fallback or llm is None or not model:
        return PatternDetectionResult(patterns=[], method="regex")

    llm_hits = detect_patterns_llm(description, llm, model)
    if llm_hits:
        return PatternDetectionResult(patterns=llm_hits, method="llm")
    return PatternDetectionResult(patterns=[], method="regex+llm")


def supported_patterns() -> list[str]:
    """Public, sorted list of pattern tags. The UI options and tests check against it."""

    return sorted(_PATTERN_RULES.keys())
