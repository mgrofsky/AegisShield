"""Pull a JSON object out of model text.

Models sometimes wrap JSON in a code fence or put a sentence before it; both
are handled. Text that still cannot be read, including an answer cut off
mid-object, raises ``LLMResponseError``.
"""

from __future__ import annotations

import json
from typing import Any

from aegisshield.core.errors import LLMResponseError

UNREADABLE = "The AI returned an answer that could not be read."


def _strip_fence(text: str) -> str:
    if not text.startswith("```"):
        return text
    body = text.split("\n", 1)[1] if "\n" in text else text[3:]
    body = body.rstrip()
    if body.endswith("```"):
        body = body[:-3]
    return body.strip()


def extract_json(text: str) -> dict[str, Any]:
    """Parse ``text`` as a JSON object, tolerating a fence or leading prose.

    Tries the whole (unfenced) text first, then the span from the first
    ``{`` to the last ``}``. Raises ``LLMResponseError`` if neither parses
    or the value is not an object.
    """
    stripped = _strip_fence((text or "").strip())
    if not stripped:
        raise LLMResponseError(UNREADABLE)
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start == -1 or end <= start:
            raise LLMResponseError(UNREADABLE) from None
        try:
            value = json.loads(stripped[start : end + 1])
        except json.JSONDecodeError:
            raise LLMResponseError(UNREADABLE) from None
    if not isinstance(value, dict):
        raise LLMResponseError(UNREADABLE)
    return value
