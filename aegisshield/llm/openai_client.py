"""``LLMClient`` backed by the OpenAI Chat Completions API.

Each visitor supplies their own key, so a client is built per visitor and
passed to the services. The key lives only inside the SDK client this object
holds: it is never logged, never put in an exception message, and never kept
in a second place. Provider errors are logged by class name and status code
only, and re-raised as ``LLMError`` with a fixed sentence and no cause chain,
because some SDK messages quote part of the key.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

import openai

from aegisshield.core.errors import LLMError, LLMResponseError
from aegisshield.llm.base import (
    DEFAULT_IMAGE_MAX_TOKENS,
    DEFAULT_JSON_MAX_TOKENS,
    DEFAULT_SDK_RETRIES,
    DEFAULT_TEXT_MAX_TOKENS,
    DEFAULT_TIMEOUT_SECONDS,
    ERROR_FILTERED,
    ERROR_NO_ANSWER,
    ERROR_STREAM_CUT,
    ERROR_TRUNCATED,
    JSON_SYSTEM_SUFFIX,
    OnText,
    SafeText,
    normalize_media_type,
)
from aegisshield.llm.json_extract import extract_json

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_SDK_RETRIES", "DEFAULT_TIMEOUT_SECONDS", "ERROR_FILTERED", "ERROR_NO_ANSWER",
    "ERROR_STREAM_CUT", "ERROR_TRUNCATED", "OpenAIClient",
]


class OpenAIClient:
    """Calls OpenAI with one visitor's key.

    ``sdk_client`` lets tests pass a fake with the same
    ``chat.completions.create`` shape; production code passes only the key.
    """

    def __init__(
        self,
        api_key: str,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_SDK_RETRIES,
        sdk_client: Any | None = None,
    ) -> None:
        if sdk_client is None:
            if not api_key:
                raise LLMError("An OpenAI API key is required.")
            sdk_client = openai.OpenAI(
                api_key=api_key, timeout=timeout_seconds, max_retries=max_retries
            )
        self._sdk = sdk_client

    def __repr__(self) -> str:
        return "OpenAIClient()"

    # The protocol ----------------------------------------------------------

    def chat_text(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int = DEFAULT_TEXT_MAX_TOKENS,
        on_text: OnText | None = None,
    ) -> str:
        """Return the model's text answer (see ``LLMClient.chat_text``)."""
        text, finish = self._complete(
            system=system,
            content=user,
            model=model,
            max_tokens=max_tokens,
            json_mode=False,
            on_text=on_text,
        )
        if finish == "length":
            logger.warning("openai text answer hit max_tokens model=%s", model)
        return text

    def chat_json(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int = DEFAULT_JSON_MAX_TOKENS,
        on_text: OnText | None = None,
    ) -> dict[str, Any]:
        """Return the answer as a JSON object (see ``LLMClient.chat_json``)."""
        text, finish = self._complete(
            system=f"{system}\n\n{JSON_SYSTEM_SUFFIX}".strip(),
            content=user,
            model=model,
            max_tokens=max_tokens,
            json_mode=True,
            on_text=on_text,
        )
        if finish == "length":
            raise LLMResponseError(ERROR_TRUNCATED)
        return extract_json(text)

    def describe_image(
        self,
        *,
        image_bytes: bytes,
        media_type: str,
        prompt: str,
        model: str,
        max_tokens: int = DEFAULT_IMAGE_MAX_TOKENS,
    ) -> str:
        """Return a description of a PNG or JPEG image (see ``LLMClient``)."""
        mime = normalize_media_type(media_type)
        encoded = base64.b64encode(image_bytes).decode("ascii")
        content = [
            {"type": "text", "text": prompt},
            {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{encoded}"}},
        ]
        text, _finish = self._complete(
            system="",
            content=content,
            model=model,
            max_tokens=max_tokens,
            json_mode=False,
            on_text=None,
        )
        return text

    # Internals -------------------------------------------------------------

    def _complete(
        self,
        *,
        system: str,
        content: str | list[dict[str, Any]],
        model: str,
        max_tokens: int,
        json_mode: bool,
        on_text: OnText | None,
    ) -> tuple[str, str | None]:
        messages: list[dict[str, Any]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": content})
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            # ``max_tokens`` is deprecated in the SDK and refused by reasoning
            # models; ``max_completion_tokens`` covers visible and reasoning tokens.
            "max_completion_tokens": max_tokens,
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        try:
            if on_text is None:
                text, finish = self._once(kwargs)
            else:
                text, finish = self._stream(kwargs, SafeText(on_text))
        except openai.OpenAIError as exc:
            logger.warning(
                "openai call failed model=%s kind=%s status=%s",
                model,
                type(exc).__name__,
                getattr(exc, "status_code", None),
            )
            # ``from None``: the SDK's message can quote part of the key.
            raise LLMError(ERROR_NO_ANSWER) from None
        if finish == "content_filter":
            raise LLMResponseError(ERROR_FILTERED)
        return text.strip(), finish

    def _once(self, kwargs: dict[str, Any]) -> tuple[str, str | None]:
        response = self._sdk.chat.completions.create(**kwargs)
        choices = getattr(response, "choices", None) or []
        if not choices:
            raise LLMResponseError(ERROR_NO_ANSWER)
        choice = choices[0]
        message = getattr(choice, "message", None)
        return (getattr(message, "content", None) or ""), choice.finish_reason

    def _stream(self, kwargs: dict[str, Any], on_text: SafeText) -> tuple[str, str | None]:
        parts: list[str] = []
        finish: str | None = None
        stream = self._sdk.chat.completions.create(**kwargs, stream=True)
        try:
            for chunk in stream:
                for choice in getattr(chunk, "choices", None) or []:
                    delta = getattr(choice, "delta", None)
                    piece = getattr(delta, "content", None) if delta is not None else None
                    if piece:
                        parts.append(piece)
                        on_text(piece)
                    if choice.finish_reason:
                        finish = choice.finish_reason
        finally:
            close = getattr(stream, "close", None)
            if callable(close):
                close()
        if finish is None:
            # A stream with no end marker may be missing part of the
            # answer, so it is never treated as complete.
            raise LLMError(ERROR_STREAM_CUT)
        return "".join(parts), finish
