"""``LLMClient`` backed by Anthropic's Messages API (Claude).

Each visitor supplies their own Claude API key, so a client is built per
visitor and passed to the services. The key lives only inside the SDK client
this object holds. Provider errors are logged by class name and status code
only, and re-raised as ``LLMError`` with a fixed sentence and no cause chain,
as ``OpenAIClient`` does.

Every call streams (``messages.stream`` and ``get_final_message``), so a long
answer never hits an HTTP timeout. The request sends ``system`` as its own
parameter, no assistant prefill, no ``temperature``, ``top_p``, or ``top_k``,
and no ``thinking`` setting, so the model's default applies. Only ``text``
blocks are read, and ``stop_reason`` is checked before the answer is used.
JSON answers use the app's JSON system suffix and ``extract_json``.

The SDK is imported inside this module only, so the app starts without it.
"""

from __future__ import annotations

import base64
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

__all__ = ["AnthropicClient", "list_models"]

# Stop reasons, from the SDK's ``StopReason`` type.
_COMPLETE = frozenset({"end_turn", "stop_sequence"})
_TRUNCATED = frozenset({"max_tokens", "model_context_window_exceeded"})
_DECLINED = frozenset({"refusal"})
# A status that means the request itself was refused; on an image call, the
# image is the only part a visitor chose.
_REQUEST_REFUSED = frozenset({400, 413, 422})


def _sdk() -> Any:
    import anthropic

    return anthropic


def _errors() -> tuple[type[BaseException], ...]:
    """The SDK's errors, plus the transport's for a stream cut mid-read."""
    anthropic = _sdk()
    import httpx2

    return (anthropic.AnthropicError, httpx2.HTTPError)


def _build(api_key: str, timeout_seconds: float, max_retries: int) -> Any:
    # An explicit ``api_key`` means the SDK reads no credential from the
    # environment or a profile on disk (its documented order).
    return _sdk().Anthropic(api_key=api_key, timeout=timeout_seconds, max_retries=max_retries)


class AnthropicClient:
    """Calls Claude with one visitor's key.

    ``sdk_client`` lets tests pass a fake with the same ``messages.stream``
    shape; production code passes only the key.
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
                raise LLMError("A Claude API key is required.")
            sdk_client = _build(api_key, timeout_seconds, max_retries)
        self._sdk = sdk_client
        self._error_types = _errors()

    def __repr__(self) -> str:
        return "AnthropicClient()"

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
        text, stop = self._call(system=system, content=user, model=model,
                                max_tokens=max_tokens, on_text=on_text)
        if stop in _TRUNCATED:
            logger.warning("claude text answer hit max_tokens model=%s", model)
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
        text, stop = self._call(system=f"{system}\n\n{JSON_SYSTEM_SUFFIX}".strip(), content=user,
                                model=model, max_tokens=max_tokens, on_text=on_text)
        if stop in _TRUNCATED:
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

        Raises ``LLMImageError`` when Claude refuses the request, for
        example because the chosen model does not take images.
        """
        mime = normalize_media_type(media_type)
        content = [
            {"type": "image", "source": {"type": "base64", "media_type": mime,
                                         "data": base64.standard_b64encode(image_bytes).decode("ascii")}},
            {"type": "text", "text": prompt},
        ]
        text, _stop = self._call(system="", content=content, model=model,
                                 max_tokens=max_tokens, on_text=None, image=True)
        return text

    # Internals -------------------------------------------------------------

    def _call(self, *, system: str, content: str | list[dict[str, Any]], model: str,
              max_tokens: int, on_text: OnText | None, image: bool = False) -> tuple[str, str]:
        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": content}],
        }
        if system:
            kwargs["system"] = system
        safe = SafeText(on_text) if on_text is not None else None
        try:
            started = False
            with self._sdk.messages.stream(**kwargs) as stream:
                for event in stream:
                    kind = getattr(event, "type", None)
                    started = started or kind == "message_start"
                    if safe is not None and kind == "text":
                        safe(event.text)
                # With no ``message_start`` the SDK has no message to give.
                message = stream.get_final_message() if started else None
            if message is None:
                raise LLMError(ERROR_STREAM_CUT)
        except AegisError:
            raise
        except self._error_types as exc:
            status = status_of(exc)
            logger.warning("claude call failed model=%s kind=%s status=%s",
                           model, type(exc).__name__, status)
            if image and status in _REQUEST_REFUSED:
                raise LLMImageError(ERROR_IMAGE_REFUSED) from None
            # ``from None``: the SDK's message can quote part of the key.
            raise LLMError(ERROR_NO_ANSWER) from None
        stop = getattr(message, "stop_reason", None)
        if stop is None:
            # No ``message_delta`` arrived: the stream ended mid-answer.
            raise LLMError(ERROR_STREAM_CUT)
        if stop in _DECLINED:
            raise LLMResponseError(ERROR_FILTERED)
        if stop not in _COMPLETE and stop not in _TRUNCATED:
            logger.warning("claude answer ended unexpectedly model=%s stop=%s", model, stop)
            raise LLMResponseError(ERROR_NO_ANSWER)
        text = "".join(
            block.text for block in getattr(message, "content", None) or []
            if getattr(block, "type", None) == "text" and isinstance(getattr(block, "text", None), str)
        )
        return text.strip(), stop


def _capability(item: Any) -> bool | None:
    """``capabilities.image_input.supported`` from a listed model, or None.

    The SDK types ``capabilities`` as an object; the API documents it as a
    nested mapping. Both are read.
    """
    caps = getattr(item, "capabilities", None)
    image = caps.get("image_input") if isinstance(caps, dict) else getattr(caps, "image_input", None)
    supported = image.get("supported") if isinstance(image, dict) else getattr(image, "supported", None)
    return supported if isinstance(supported, bool) else None


def list_models(credential: Any, *, timeout_seconds: float,
                sdk_client: Any | None = None) -> list[ModelInfo]:
    """Claude's models for the visitor's key (``client.models.list()``).

    Every listed model the API does not mark retired is kept; whether it
    takes images is read from its ``image_input`` capability.
    """
    client = sdk_client or _build(credential.api_key, timeout_seconds, LIST_RETRIES)
    found: list[ModelInfo] = []
    try:
        for item in itertools.islice(client.models.list(), MAX_RAW_MODELS):
            model_id = getattr(item, "id", None)
            if not isinstance(model_id, str) or getattr(item, "lifecycle", None) == "retired":
                continue
            found.append(ModelInfo(model_id, _capability(item)))
    except _errors() as exc:
        logger.warning("claude model list failed kind=%s status=%s", type(exc).__name__, status_of(exc))
        raise LLMError(ERROR_LIST_FAILED) from None
    return found
