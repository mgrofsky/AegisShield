"""``LLMClient`` backed by Amazon Bedrock's Converse API.

``converse`` and ``converse_stream`` take one request shape for every model
family on Bedrock. The request sends only ``maxTokens`` in
``inferenceConfig``.

**The visitor's AWS credential only.** The visitor gives one of two
credentials: a Bedrock API key (the bearer token AWS issues for Bedrock)
and a region, or an access key id, secret access key, optional session
token, and region. When both are held, the API key is used. The boto3
session is built from that credential and from nothing on this server: no
profile, no shared config or credentials file, no environment variable
(``AWS_PROFILE``, ``AWS_ACCESS_KEY_ID``, ``AWS_BEARER_TOKEN_BEDROCK``,
``AWS_ENDPOINT_URL``, and the rest are all ignored), no instance role, and
no default credential chain. With access keys, requests are signed with
SigV4 and no bearer token is ever loaded. With an API key, requests carry
``Authorization: Bearer <the visitor's key>``: the session's token
provider returns only that key, its credential provider returns nothing,
and the signature version is set to ``bearer`` in code.
(``visitor_session``)

Provider errors are logged by class name and status code only, and
re-raised as ``LLMError`` with a fixed sentence and no cause chain.
boto3 and botocore are imported inside this module only.
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
from aegisshield.llm.providers import bedrock_uses_api_key

logger = logging.getLogger(__name__)

__all__ = ["BedrockClient", "list_models", "visitor_session"]

# Stop reasons, from the service model's ``StopReason`` enum.
_COMPLETE = frozenset({"end_turn", "stop_sequence"})
_TRUNCATED = frozenset({"max_tokens", "model_context_window_exceeded"})
_DECLINED = frozenset({"guardrail_intervened", "content_filtered"})
_REQUEST_REFUSED = frozenset({400, 413, 422})
_CONNECT_TIMEOUT_SECONDS = 10
# The most pages of inference profiles read in one listing.
_MAX_PROFILE_PAGES = 5
_IMAGE_FORMATS = {"image/png": "png", "image/jpeg": "jpeg"}


class _NoToken:
    """A token provider that never finds a token, so a Bedrock bearer
    token in this server's environment is never loaded."""

    def load_token(self, **_kwargs: Any) -> None:
        """No token, whatever is asked."""
        return None


class _VisitorToken:
    """A token provider that returns only the visitor's Bedrock API key.

    botocore asks it twice per client (``Session.get_auth_token``, with and
    without ``signing_name="bedrock"``); both get the visitor's key, so the
    server's ``AWS_BEARER_TOKEN_BEDROCK`` provider is never reached.
    """

    def __init__(self, token: str) -> None:
        from botocore.tokens import FrozenAuthToken

        self._token = FrozenAuthToken(token)

    def __repr__(self) -> str:
        return "_VisitorToken()"

    def load_token(self, **_kwargs: Any) -> Any:
        """The visitor's key, whatever is asked."""
        return self._token


class _NoCredentials:
    """A credential provider that finds nothing, so a client that signs with
    the visitor's bearer token never loads this server's AWS keys."""

    def load_credentials(self) -> None:
        """No credentials."""
        return None


def _errors() -> tuple[type[BaseException], ...]:
    from botocore.exceptions import BotoCoreError, ClientError

    return (ClientError, BotoCoreError)


def visitor_session(credential: Any) -> Any:
    """A boto3 session that holds the visitor's credential and region and
    reads nothing from this server.

    Every botocore session variable loses its environment source and
    config-file source (keeping only botocore's default), the shared config
    and credentials files are not named, and configured endpoint URLs are
    ignored. With a Bedrock API key, the token provider returns only that
    key and the credential provider finds nothing; with access keys, the
    token provider never finds a token.
    """
    import boto3
    import botocore.session
    from botocore.configprovider import BOTOCORE_DEFAUT_SESSION_VARIABLES

    session_vars = {name: (None, None, default, convert)
                    for name, (_cfg, _env, default, convert) in BOTOCORE_DEFAUT_SESSION_VARIABLES.items()}
    session_vars["ignore_configured_endpoint_urls"] = (None, None, True, None)
    core = botocore.session.Session(session_vars=session_vars)
    region = credential.region.strip()
    if bedrock_uses_api_key(credential):
        core.register_component("token_provider", _VisitorToken(credential.api_key.strip()))
        core.register_component("credential_provider", _NoCredentials())
        return boto3.session.Session(region_name=region, botocore_session=core)
    core.register_component("token_provider", _NoToken())
    return boto3.session.Session(
        aws_access_key_id=credential.access_key_id.strip(),
        aws_secret_access_key=credential.secret_access_key.strip(),
        aws_session_token=credential.session_token.strip() or None,
        region_name=region,
        botocore_session=core,
    )


def _client(credential: Any, service: str, timeout_seconds: float, max_retries: int) -> Any:
    from botocore.config import Config

    config = Config(
        # Set in code, so botocore's own preference rules (a bearer token in
        # the environment, ``auth_scheme_preference``) never change it.
        signature_version="bearer" if bedrock_uses_api_key(credential) else "v4",
        connect_timeout=_CONNECT_TIMEOUT_SECONDS,
        read_timeout=timeout_seconds,
        retries={"total_max_attempts": max_retries + 1, "mode": "standard"},
    )
    return visitor_session(credential).client(service, config=config)


def _complete(credential: Any) -> bool:
    if not (credential and credential.region.strip()):
        return False
    return bedrock_uses_api_key(credential) or bool(credential.access_key_id.strip()
                                                    and credential.secret_access_key.strip())


class BedrockClient:
    """Calls Bedrock with one visitor's AWS credential.

    ``sdk_client`` lets tests pass a fake ``bedrock-runtime`` client with
    the same ``converse`` and ``converse_stream`` shapes.
    """

    def __init__(
        self,
        credential: Any,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_SDK_RETRIES,
        sdk_client: Any | None = None,
    ) -> None:
        if sdk_client is None:
            if not _complete(credential):
                raise LLMError("A region and either a Bedrock API key or an AWS access key ID and "
                               "secret access key are required.")
            sdk_client = _client(credential, "bedrock-runtime", timeout_seconds, max_retries)
        self._sdk = sdk_client
        self._error_types = _errors()

    def __repr__(self) -> str:
        return "BedrockClient()"

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
        text, stop = self._call(system=system, content=[{"text": user}], model=model,
                                max_tokens=max_tokens, on_text=on_text)
        if stop in _TRUNCATED:
            logger.warning("bedrock text answer hit max_tokens model=%s", model)
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
        text, stop = self._call(system=f"{system}\n\n{JSON_SYSTEM_SUFFIX}".strip(),
                                content=[{"text": user}], model=model, max_tokens=max_tokens,
                                on_text=on_text)
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

        Raises ``LLMImageError`` when Bedrock refuses the request, for
        example because the chosen model does not take images.
        """
        image_format = _IMAGE_FORMATS[normalize_media_type(media_type)]
        content = [
            {"image": {"format": image_format, "source": {"bytes": image_bytes}}},
            {"text": prompt},
        ]
        text, _stop = self._call(system="", content=content, model=model, max_tokens=max_tokens,
                                 on_text=None, image=True)
        return text

    # Internals -------------------------------------------------------------

    def _call(self, *, system: str, content: list[dict[str, Any]], model: str, max_tokens: int,
              on_text: OnText | None, image: bool = False) -> tuple[str, str]:
        kwargs: dict[str, Any] = {
            "modelId": model,
            "messages": [{"role": "user", "content": content}],
            "inferenceConfig": {"maxTokens": max_tokens},
        }
        if system:
            kwargs["system"] = [{"text": system}]
        try:
            if on_text is None:
                text, stop = self._once(kwargs)
            else:
                text, stop = self._stream(kwargs, SafeText(on_text))
        except AegisError:
            raise
        except self._error_types as exc:
            status = status_of(exc)
            logger.warning("bedrock call failed model=%s kind=%s status=%s",
                           model, type(exc).__name__, status)
            if image and status in _REQUEST_REFUSED:
                raise LLMImageError(ERROR_IMAGE_REFUSED) from None
            # ``from None``: botocore's message can quote request details.
            raise LLMError(ERROR_NO_ANSWER) from None
        if stop in _DECLINED:
            raise LLMResponseError(ERROR_FILTERED)
        if stop not in _COMPLETE and stop not in _TRUNCATED:
            logger.warning("bedrock answer ended unexpectedly model=%s stop=%s", model, stop)
            raise LLMResponseError(ERROR_NO_ANSWER)
        return text.strip(), stop

    def _once(self, kwargs: dict[str, Any]) -> tuple[str, str | None]:
        response = self._sdk.converse(**kwargs)
        message = ((response or {}).get("output") or {}).get("message") or {}
        text = "".join(block["text"] for block in message.get("content") or []
                       if isinstance(block, dict) and isinstance(block.get("text"), str))
        return text, (response or {}).get("stopReason")

    def _stream(self, kwargs: dict[str, Any], on_text: SafeText) -> tuple[str, str]:
        response = self._sdk.converse_stream(**kwargs)
        stream = (response or {}).get("stream")
        if stream is None:
            raise LLMError(ERROR_NO_ANSWER)
        parts: list[str] = []
        stop: str | None = None
        try:
            for event in stream:
                if not isinstance(event, dict):
                    continue
                if any(key.endswith("Exception") for key in event):
                    # An error event inside the stream (botocore usually
                    # raises these itself); its text is never read.
                    logger.warning("bedrock stream error event kinds=%s",
                                   sorted(k for k in event if k.endswith("Exception")))
                    raise LLMError(ERROR_NO_ANSWER)
                delta = (event.get("contentBlockDelta") or {}).get("delta") or {}
                piece = delta.get("text")
                if isinstance(piece, str) and piece:
                    parts.append(piece)
                    on_text(piece)
                if "messageStop" in event:
                    stop = (event["messageStop"] or {}).get("stopReason") or ""
        finally:
            close = getattr(stream, "close", None)
            if callable(close):
                close()
        if stop is None:
            # No ``messageStop`` event: the answer may be missing its end.
            raise LLMError(ERROR_STREAM_CUT)
        return "".join(parts), stop


# ------------------------------------------------------------- the listing


def _text_model(summary: dict[str, Any]) -> bool:
    """A foundation model that takes text, gives text (not embeddings),
    streams, and is active."""
    inputs = summary.get("inputModalities") or []
    outputs = summary.get("outputModalities") or []
    lifecycle = (summary.get("modelLifecycle") or {}).get("status")
    return ("TEXT" in inputs and "TEXT" in outputs and "EMBEDDING" not in outputs
            and summary.get("responseStreamingSupported") is True and lifecycle == "ACTIVE")


def _foundation_id(arn: object) -> str | None:
    if not isinstance(arn, str) or "foundation-model/" not in arn:
        return None
    return arn.split("foundation-model/", 1)[1] or None


def list_models(credential: Any, *, timeout_seconds: float,
                sdk_client: Any | None = None) -> list[ModelInfo]:
    """Bedrock's text models in the visitor's region.

    Bedrock's listing does not say which models the Converse API serves, so
    the rule is: a foundation model is offered when it takes text in, gives
    text out (not embeddings), supports streaming, is ``ACTIVE``, and can be
    called on demand; an active inference profile is offered when every
    model it routes to passes the same text, streaming, and lifecycle tests
    in this region's list. A model Converse does not serve fails at call
    time with the fixed sentence. A model takes images when its
    ``inputModalities`` include ``IMAGE`` (for a profile, when every model
    it routes to does).
    """
    client = sdk_client or _client(credential, "bedrock", timeout_seconds, LIST_RETRIES)
    found: list[ModelInfo] = []
    try:
        summaries = client.list_foundation_models(byOutputModality="TEXT").get("modelSummaries") or []
        text_models: dict[str, bool] = {}
        for summary in itertools.islice(summaries, MAX_RAW_MODELS):
            if not isinstance(summary, dict) or not _text_model(summary):
                continue
            model_id = summary.get("modelId")
            if not isinstance(model_id, str):
                continue
            vision = "IMAGE" in (summary.get("inputModalities") or [])
            text_models[model_id] = vision
            if "ON_DEMAND" in (summary.get("inferenceTypesSupported") or []):
                found.append(ModelInfo(model_id, vision))
        token: str | None = None
        for _page in range(_MAX_PROFILE_PAGES):
            request: dict[str, Any] = {"maxResults": 1000}
            if token:
                request["nextToken"] = token
            page = client.list_inference_profiles(**request)
            for profile in itertools.islice(page.get("inferenceProfileSummaries") or [], MAX_RAW_MODELS):
                if not isinstance(profile, dict) or profile.get("status") != "ACTIVE":
                    continue
                routed = [_foundation_id((m or {}).get("modelArn")) for m in profile.get("models") or []]
                if not routed or any(r not in text_models for r in routed):
                    continue
                profile_id = profile.get("inferenceProfileId")
                if isinstance(profile_id, str):
                    found.append(ModelInfo(profile_id, all(text_models[r] for r in routed)))
            token = page.get("nextToken")
            if not isinstance(token, str) or not token:
                break
    except _errors() as exc:
        logger.warning("bedrock model list failed kind=%s status=%s", type(exc).__name__,
                       status_of(exc))
        raise LLMError(ERROR_LIST_FAILED) from None
    return found
