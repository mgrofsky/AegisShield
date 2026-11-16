"""OpenAI's model list, kept to the models the app can chat with.

``client.models.list()`` also returns embedding, audio, image, moderation,
and other models that the Chat Completions API does not serve. The rule
(``is_chat_model``):

1. Keep an id that starts with ``gpt-`` or ``chatgpt-``, or that is ``o``
   followed by a digit (``o1``, ``o3-mini``, ``o4-mini``).
2. Drop it when any hyphen-separated part of the id names another kind of
   model or another API: ``audio``, ``realtime``, ``transcribe``, ``tts``,
   ``image``, ``embedding``, ``moderation``, ``search``, ``instruct``,
   ``codex``, ``pro``, ``deep``, or ``research``.

Fine-tuned models (``ft:...``) are not offered. The listing says nothing
about image input, so ``vision`` is None: an image call is tried and its
failure handled.
"""

from __future__ import annotations

import itertools
import logging
import re
from typing import Any

from aegisshield.core.errors import LLMError
from aegisshield.llm.base import (
    ERROR_LIST_FAILED,
    LIST_RETRIES,
    MAX_RAW_MODELS,
    ModelInfo,
    status_of,
)

logger = logging.getLogger(__name__)

__all__ = ["is_chat_model", "list_models"]

_CHAT_PREFIX = re.compile(r"(?:gpt-|chatgpt-|o[0-9])")
_OTHER_KINDS = frozenset({
    "audio", "realtime", "transcribe", "tts", "image", "embedding", "moderation", "search",
    "instruct", "codex", "pro", "deep", "research",
})


def is_chat_model(model_id: str) -> bool:
    """True for an OpenAI model id the Chat Completions API can answer with
    text (the rule in this module's docstring)."""
    if not _CHAT_PREFIX.match(model_id):
        return False
    return not any(part in _OTHER_KINDS for part in model_id.lower().split("-"))


def list_models(credential: Any, *, timeout_seconds: float,
                sdk_client: Any | None = None) -> list[ModelInfo]:
    """OpenAI's chat models for the visitor's key."""
    import openai

    client = sdk_client or openai.OpenAI(api_key=credential.api_key, timeout=timeout_seconds,
                                         max_retries=LIST_RETRIES)
    found: list[ModelInfo] = []
    try:
        for item in itertools.islice(client.models.list(), MAX_RAW_MODELS):
            model_id = getattr(item, "id", None)
            if isinstance(model_id, str) and is_chat_model(model_id):
                found.append(ModelInfo(model_id, None))
    except openai.OpenAIError as exc:
        logger.warning("openai model list failed kind=%s status=%s", type(exc).__name__,
                       status_of(exc))
        raise LLMError(ERROR_LIST_FAILED) from None
    return found
