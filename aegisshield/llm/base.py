"""The ``LLMClient`` protocol every model backend implements.

- ``llm.chat_text(system=, user=, model=, max_tokens=, on_text=)`` returns text.
- ``llm.chat_json(...)`` takes the same arguments and returns a ``dict``.
- ``llm.describe_image(prompt=, image_bytes=, media_type=, model=)`` describes
  an image.

The request timeout is set on the client's constructor. Defaults for
``max_tokens`` are 16000 for JSON, 8192 for text, and 4096 for images.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

from aegisshield.core.errors import LLMError, ValidationError

logger = logging.getLogger(__name__)

OnText = Callable[[str], None]

DEFAULT_JSON_MAX_TOKENS = 16000
DEFAULT_TEXT_MAX_TOKENS = 8192
DEFAULT_IMAGE_MAX_TOKENS = 4096

# Appended to every JSON request's system prompt. OpenAI's
# JSON mode also requires the word "JSON" to appear in the messages.
JSON_SYSTEM_SUFFIX = "Return ONLY a JSON object. No prose, no code fences."

# Every backend's request timeout and retry count (the SDK retries a rate
# limit, a timeout, and a server error this many times before giving up).
DEFAULT_TIMEOUT_SECONDS = 300.0
DEFAULT_SDK_RETRIES = 2

# The fixed sentences every backend raises. A provider's own error text never
# reaches a visitor: some SDK messages quote part of the key.
ERROR_NO_ANSWER = "The AI service did not answer. Try again in a minute."
ERROR_STREAM_CUT = "The AI service stopped before finishing its answer. Try again."
ERROR_TRUNCATED = "The AI answer was too long and was cut short. Try again."
ERROR_FILTERED = "The AI service declined to answer this request."
ERROR_IMAGE_REFUSED = "The chosen model could not read the diagram, so it was not described."


class LLMImageError(LLMError):
    """The provider refused the image in a ``describe_image`` call (for
    example, the chosen model does not take images)."""


@runtime_checkable
class LLMClient(Protocol):
    """A chat model the services can call. Every method may raise ``LLMError``."""

    def chat_text(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int = DEFAULT_TEXT_MAX_TOKENS,
        on_text: OnText | None = None,
    ) -> str:
        """Return the model's text answer, streaming deltas to ``on_text`` if given."""
        ...

    def chat_json(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int = DEFAULT_JSON_MAX_TOKENS,
        on_text: OnText | None = None,
    ) -> dict[str, Any]:
        """Return the model's answer parsed as a JSON object.

        Raises ``LLMResponseError`` when the answer is empty, cut short, or
        not a JSON object.
        """
        ...

    def describe_image(
        self,
        *,
        image_bytes: bytes,
        media_type: str,
        prompt: str,
        model: str,
        max_tokens: int = DEFAULT_IMAGE_MAX_TOKENS,
    ) -> str:
        """Return the model's description of a PNG or JPEG image."""
        ...


class SafeText:
    """Wrap an ``on_text`` callback so a failing display never fails the call.

    The first exception is logged and the callback is not called again.
    """

    def __init__(self, fn: OnText) -> None:
        self._fn = fn
        self._dead = False

    def __call__(self, text: str) -> None:
        if self._dead or not text:
            return
        try:
            self._fn(text)
        # A display callback can fail in any way; the model call must go on.
        except Exception as exc:
            self._dead = True
            logger.warning("on_text callback failed kind=%s", type(exc).__name__)


_MEDIA_TYPES = {
    "png": "image/png",
    "image/png": "image/png",
    "jpeg": "image/jpeg",
    "jpg": "image/jpeg",
    "image/jpeg": "image/jpeg",
    "image/jpg": "image/jpeg",
}


def normalize_media_type(media_type: str) -> str:
    """``image/png`` or ``image/jpeg`` for a PNG or JPEG type or extension.

    Raises ``ValidationError`` for anything else.
    """
    found = _MEDIA_TYPES.get((media_type or "").strip().lower())
    if found is None:
        raise ValidationError("Only PNG and JPEG images are supported.")
    return found


# ------------------------------------------------------------- model lists

# A listing that fails shows only this sentence, never the provider's text.
ERROR_LIST_FAILED = "The model list could not be loaded. Check the credentials and try again."
# At most this many entries are read from a provider's listing, whatever it
# returns, before any filter runs; the kept list is bounded again after.
MAX_RAW_MODELS = 2000
# A model listing is asked with a shorter timeout and one retry: the page
# waits for it.
LIST_TIMEOUT_SECONDS = 20.0
LIST_RETRIES = 1


class ModelInfo:
    """One model a provider listed: its id, and whether it takes images
    (``True`` or ``False`` when the listing says, ``None`` when it does not)."""

    __slots__ = ("id", "vision")

    def __init__(self, model_id: str, vision: bool | None = None) -> None:
        self.id = model_id
        self.vision = vision

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ModelInfo) and (self.id, self.vision) == (other.id, other.vision)

    def __hash__(self) -> int:
        return hash((self.id, self.vision))

    def __repr__(self) -> str:
        return f"ModelInfo({self.id!r}, vision={self.vision!r})"


def status_of(exc: BaseException) -> int | None:
    """The HTTP status code an SDK error carries, or None. Read from the
    attribute each SDK uses (``status_code``, ``code``, or botocore's
    ``response`` metadata); never from the error's message."""
    for name in ("status_code", "code"):
        value = getattr(exc, name, None)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        meta = response.get("ResponseMetadata")
        if isinstance(meta, dict) and isinstance(meta.get("HTTPStatusCode"), int):
            return meta["HTTPStatusCode"]
    return None
