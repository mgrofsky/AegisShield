"""Pattern detection: the supported patterns and the model-based detector.

The service takes an ``llm`` object, so these tests pass a fake one.
"""

from __future__ import annotations

import json

from aegisshield.core.errors import LLMError
from aegisshield.pipeline import pattern_detection_service
from aegisshield.pipeline.pattern_detection_service import (
    detect_patterns,
    detect_patterns_llm,
    detect_patterns_regex,
    supported_patterns,
)


class _TextLLM:
    """A fake LLM whose chat_text gives a fixed answer or raises ``error``."""

    def __init__(self, answer: str = "", error: Exception | None = None):
        self.answer = answer
        self.error = error

    def chat_text(self, *, system, user, model, max_tokens=8192, on_text=None):
        if self.error is not None:
            raise self.error
        return self.answer


def test_supported_patterns_is_stable_sorted_set() -> None:
    out = supported_patterns()
    assert out == sorted(out)
    assert {"GenAI", "RAG", "Agentic", "Tool Use", "Code Execution", "ML"}.issubset(out)


def test_regex_detects_genai_via_keyword() -> None:
    text = "A chatbot UI on top of an LLM that answers customer support tickets."
    assert "GenAI" in detect_patterns_regex(text)


def test_regex_detects_rag() -> None:
    text = "We retrieve document chunks from a vector database before prompting the model."
    hits = detect_patterns_regex(text)
    assert "RAG" in hits
    # GenAI is also implied by 'prompting'; the rules are intentionally loose,
    # so assert at least RAG.
    assert hits  # non-empty


def test_regex_detects_agentic_and_tool_use() -> None:
    text = "An autonomous multi-agent system that uses tool calls via MCP."
    hits = detect_patterns_regex(text)
    assert "Agentic" in hits
    assert "Tool Use" in hits


def test_regex_detects_code_execution() -> None:
    text = "Users can run Python via a sandboxed code interpreter."
    hits = detect_patterns_regex(text)
    assert "Code Execution" in hits


def test_regex_detects_ml() -> None:
    text = "We train neural networks on PyTorch and serve them on SageMaker."
    hits = detect_patterns_regex(text)
    assert "ML" in hits


def test_regex_returns_empty_for_plain_web_app() -> None:
    text = "A traditional CRUD web application that stores customer records in PostgreSQL."
    assert detect_patterns_regex(text) == []


def test_regex_returns_empty_for_blank() -> None:
    assert detect_patterns_regex("") == []


def test_detect_patterns_short_circuits_when_regex_finds_anything(monkeypatch) -> None:
    called = {"llm": False}

    def fake_llm(*_args, **_kwargs):
        called["llm"] = True
        return ["GenAI"]

    monkeypatch.setattr(pattern_detection_service, "detect_patterns_llm", fake_llm)
    result = detect_patterns(
        "An LLM-based assistant.",
        llm=_TextLLM(),
        model="m",
        use_llm_fallback=True,
    )
    assert result.method == "regex"
    assert "GenAI" in result.patterns
    assert called["llm"] is False


def test_detect_patterns_llm_fallback_runs_when_regex_empty(monkeypatch) -> None:
    monkeypatch.setattr(
        pattern_detection_service,
        "detect_patterns_llm",
        lambda *args, **kwargs: ["Agentic"],
    )
    result = detect_patterns(
        "Some opaque description.",
        llm=_TextLLM(),
        model="m",
        use_llm_fallback=True,
    )
    assert result.method == "llm"
    assert result.patterns == ["Agentic"]


def test_detect_patterns_skips_llm_when_disabled() -> None:
    result = detect_patterns("plain crud", use_llm_fallback=False)
    assert result.method == "regex"
    assert result.patterns == []
    assert result.is_empty()


def test_detect_patterns_llm_validates_against_allow_list() -> None:
    payload = json.dumps(["GenAI", "TotallyMadeUpTag", "Agentic"])
    out = detect_patterns_llm("desc", _TextLLM(payload), "m")
    assert "TotallyMadeUpTag" not in out
    assert set(out) == {"GenAI", "Agentic"}


def test_detect_patterns_llm_handles_garbage() -> None:
    assert detect_patterns_llm("desc", _TextLLM("totally-not-json"), "m") == []


def test_detect_patterns_llm_handles_chat_text_failure() -> None:
    # The model's own error class is caught and gives no patterns; other
    # exceptions are not swallowed.
    llm = _TextLLM(error=LLMError("upstream down"))
    assert detect_patterns_llm("desc", llm, "m") == []
