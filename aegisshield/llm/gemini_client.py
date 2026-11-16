"""``LLMClient`` backed by the Gemini API through the ``google-genai`` SDK.

Each visitor supplies their own Gemini API key. The SDK client is built with
that key and ``vertexai=False``, so it never switches to Vertex AI or to the
server's Google Cloud credentials because of an environment variable. The
request sets only ``system_instruction`` and ``max_output_tokens``; thought
parts are never read as the answer. JSON answers use the app's JSON system
suffix and ``extract_json``.

Provider errors are logged by class name and status code only, and
re-raised as ``LLMError`` with a fixed sentence and no cause chain. The SDK
is imported inside this module only.
"""

from __future__ import annotations

import itertools
import logging
from typing import Any

from aegisshield.core.errors import AegisError, LLMError, LLMResponseError
from aegisshield.llm.base import (
    DEFAULT_IMAGE_MAX_TOKENS,
    DEFAULT_JSON_MAX_TOKENS,
    DEFAULT_SDK_RETRIES,
    DEFAULT_TEXT_MAX_TOKENS,
    DEFAULT_TIMEOUT_SECONDS,
    ERROR_FILTERED,
    ERROR_IMAGE_REFUSED,
    ERROR_LIST_FAILED,
    ERROR_NO_ANSWER,
    ERROR_STREAM_CUT,
    ERROR_TRUNCATED,
    JSON_SYSTEM_SUFFIX,
    LIST_RETRIES,
    MAX_RAW_MODELS,
    LLMImageError,
    ModelInfo,
    OnText,
    SafeText,
    normalize_media_type,
    status_of,
)
from aegisshield.llm.json_extract import extract_json

logger = logging.getLogger(__name__)

__all__ = ["GeminiClient", "list_models"]

# Finish reasons, from the SDK's ``FinishReason`` enum.
_COMPLETE = frozenset({"STOP"})
_TRUNCATED = frozenset({"MAX_TOKENS"})
_DECLINED = frozenset({
    "SAFETY", "RECITATION", "LANGUAGE", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII",
    "IMAGE_SAFETY", "IMAGE_PROHIBITED_CONTENT", "IMAGE_RECITATION", "MODEL_ARMOR",
})
_REQUEST_REFUSED = frozenset({400, 413, 422})
_GENERATE = "generateContent"


def _genai() -> tuple[Any, Any]:
    from google import genai
    from google.genai import types

    return genai, types


def _errors() -> tuple[type[BaseException], ...]:
    """The SDK's own errors and the transport errors it lets through."""
    import httpx
    from google.genai import errors

    found: list[type[BaseException]] = [errors.APIError, httpx.HTTPError]
    try:
        import httpx2
    except ImportError:  # pragma: no cover - the SDK works with httpx alone
        return tuple(found)
    found.append(httpx2.HTTPError)
    return tuple(found)


def _build(api_key: str, timeout_seconds: float, max_retries: int) -> Any:
    genai, types = _genai()
    options = types.HttpOptions(
        timeout=int(timeout_seconds * 1000),
        retry_options=types.HttpRetryOptions(attempts=max_retries + 1),
    )
    return genai.Client(vertexai=False, api_key=api_key, http_options=options)


def _name(value: object) -> str | None:
    """An enum's value or a plain string, else None."""
    value = getattr(value, "value", value)
    return value if isinstance(value, str) and value else None


class GeminiClient:
    """Calls Gemini with one visitor's key.

    ``sdk_client`` lets tests pass a fake with the same
    ``models.generate_content`` and ``models.generate_content_stream`` shape.
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
                raise LLMError("A Gemini API key is required.")
            sdk_client = _build(api_key, timeout_seconds, max_retries)
        self._sdk = sdk_client
        self._types = _genai()[1]
        self._error_types = _errors()

    def __repr__(self) -> str:
        return "GeminiClient()"

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
        text, finish = self._call(system=system, contents=user, model=model,
                                  max_tokens=max_tokens, on_text=on_text)
        if finish in _TRUNCATED:
            logger.warning("gemini text answer hit max_tokens model=%s", model)
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
        text, finish = self._call(system=f"{system}\n\n{JSON_SYSTEM_SUFFIX}".strip(), contents=user,
                                  model=model, max_tokens=max_tokens, on_text=on_text)
        if finish in _TRUNCATED:
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
        """Return a description of a PNG or JPEG image (see ``LLMClient``).

        Raises ``LLMImageError`` when Gemini refuses the request, for
        example because the chosen model does not take images.
        """
        mime = normalize_media_type(media_type)
        contents = [self._types.Part.from_bytes(data=image_bytes, mime_type=mime), prompt]
        text, _finish = self._call(system="", contents=contents, model=model,
                                   max_tokens=max_tokens, on_text=None, image=True)
        return text

    # Internals -------------------------------------------------------------

    def _call(self, *, system: str, contents: Any, model: str, max_tokens: int,
              on_text: OnText | None, image: bool = False) -> tuple[str, str]:
        config = self._types.GenerateContentConfig(
            max_output_tokens=max_tokens, system_instruction=system or None)
        safe = SafeText(on_text) if on_text is not None else None
        parts: list[str] = []
        finish: str | None = None
        try:
            if safe is None:
                responses: Any = [self._sdk.models.generate_content(
                    model=model, contents=contents, config=config)]
            else:
                responses = self._sdk.models.generate_content_stream(
                    model=model, contents=contents, config=config)
            for response in responses:
                blocked = _name(getattr(getattr(response, "prompt_feedback", None),
                                        "block_reason", None))
                if blocked:
                    raise LLMResponseError(ERROR_FILTERED)
                candidates = getattr(response, "candidates", None) or []
                if not candidates:
                    continue
                candidate = candidates[0]
                for part in getattr(getattr(candidate, "content", None), "parts", None) or []:
                    piece = getattr(part, "text", None)
                    if isinstance(piece, str) and piece and getattr(part, "thought", None) is not True:
                        parts.append(piece)
                        if safe is not None:
                            safe(piece)
                finish = _name(getattr(candidate, "finish_reason", None)) or finish
        except AegisError:
            raise
        except self._error_types as exc:
            status = status_of(exc)
            logger.warning("gemini call failed model=%s kind=%s status=%s",
                           model, type(exc).__name__, status)
            if image and status in _REQUEST_REFUSED:
                raise LLMImageError(ERROR_IMAGE_REFUSED) from None
            # ``from None``: the SDK's message can quote request details.
            raise LLMError(ERROR_NO_ANSWER) from None
        if finish is None:
            if safe is not None:
                # No chunk carried a finish reason: the stream was cut.
                raise LLMError(ERROR_STREAM_CUT)
            raise LLMResponseError(ERROR_NO_ANSWER)
        if finish in _DECLINED:
            raise LLMResponseError(ERROR_FILTERED)
        if finish not in _COMPLETE and finish not in _TRUNCATED:
            logger.warning("gemini answer ended unexpectedly model=%s finish=%s", model, finish)
            raise LLMResponseError(ERROR_NO_ANSWER)
        return "".join(parts).strip(), finish


def list_models(credential: Any, *, timeout_seconds: float,
                sdk_client: Any | None = None) -> list[ModelInfo]:
    """Gemini's models for the visitor's key that support content
    generation (``generateContent`` in ``supported_actions``). The listing
    says nothing about image input, so ``vision`` is None: an image call is
    tried and a refusal handled."""
    client = sdk_client or _build(credential.api_key, timeout_seconds, LIST_RETRIES)
    found: list[ModelInfo] = []
    try:
        for item in itertools.islice(client.models.list(), MAX_RAW_MODELS):
            if _GENERATE not in (getattr(item, "supported_actions", None) or []):
                continue
            name = getattr(item, "name", None)
            if isinstance(name, str):
                found.append(ModelInfo(name.removeprefix("models/"), None))
    except _errors() as exc:
        logger.warning("gemini model list failed kind=%s status=%s", type(exc).__name__,
                       status_of(exc))
        raise LLMError(ERROR_LIST_FAILED) from None
    return found
