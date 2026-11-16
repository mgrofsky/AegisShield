"""Every provider credential shape is removed wherever the app removes keys.

The provider registry takes keys for Claude, OpenAI, and Gemini, a Bedrock
API key in either of the two shapes AWS documents, and AWS access key IDs.
Each shape is removed from a model answer by the safeguards' output rails,
through each of the four backends, and from text by ``redact_keys`` (used
for log lines and the scan's stored workflow).
"""

from __future__ import annotations

from typing import Any

import pytest

from aegisshield.config import Settings
from aegisshield.core.text import redact_keys
from aegisshield.safeguards import Safeguards, detect
from tests.aegisshield.llm.provider_fakes import (
    ANSWERING,
    CLAUDE_KEY,
    GEMINI_KEY,
    OPENAI_KEY,
    OTHER_BEARER,
    VISITOR_BEARER,
    answering_client,
)

PROVIDERS = ("openai", "claude", "bedrock", "gemini")
SHAPES = {
    "openai": OPENAI_KEY,
    "claude": CLAUDE_KEY,
    "gemini": GEMINI_KEY,
    "bedrock-long-term": VISITOR_BEARER,
    "bedrock-short-term": OTHER_BEARER,
    # AWS's own documentation example, built at run time.
    "aws-access-key-id": "AKIA" + "IOSFODNN7EXAMPLE",
    "aws-temporary-key-id": "ASIA" + "IOSFODNN7EXAMPLE",
}
SYSTEM = "You are a careful assistant for a security team. Keep answers short and plain."


def _answer(secret: str) -> str:
    return f"Here is the configuration you asked about: {secret} and nothing else."


@pytest.mark.parametrize("shape", list(SHAPES))
@pytest.mark.parametrize("provider", PROVIDERS)
def test_each_provider_credential_shape_is_removed_from_each_backends_answer(provider: str,
                                                                             shape: str) -> None:
    secret = SHAPES[shape]
    fake = ANSWERING[provider](lambda system, user: _answer(secret), sizes=(0,))
    guards = Safeguards.from_settings(Settings())
    text = guards.wrap(answering_client(provider, fake)).chat_text(
        system=SYSTEM, user="Show the configuration.", model="test-model-id")
    assert secret not in text and detect.SECRET_MARKER in text
    # No piece of the key is left beside the marker.
    assert secret[8:24] not in text


@pytest.mark.parametrize("shape", list(SHAPES))
def test_each_provider_credential_shape_is_redacted_from_text(shape: str) -> None:
    secret = SHAPES[shape]
    text: Any = redact_keys(f"provider said: bad credential {secret} (status 403)")
    assert secret not in text and secret[8:24] not in text and "[redacted]" in text
