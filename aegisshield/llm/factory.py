"""Choose the ``LLMClient`` for a visitor."""

from __future__ import annotations

from aegisshield.config import Settings
from aegisshield.core.errors import LLMError
from aegisshield.llm.base import LLMClient
from aegisshield.llm.mock import MockLLM
from aegisshield.llm.providers import (
    ERROR_NO_MODEL,
    ERROR_PROVIDER_OFF,
    ERROR_PROVIDER_UNAVAILABLE,
    Credential,
    Provider,
    missing_credential,
    sdk_available,
)

# The sentence for a run with no OpenAI key (kept under its old name).
ERROR_NO_KEY = "Add an OpenAI API key to run this step."


def get_llm(
    settings: Settings,
    credential: Credential | str | None,
    *,
    mock_chunk_delay_seconds: float = 0.0,
    mock_call_delay_seconds: float = 0.0,
) -> LLMClient:
    """Return ``MockLLM`` when ``settings.mock_llm`` is set, else the client
    for ``settings.provider`` built with the visitor's ``credential``.

    A plain string is an OpenAI API key (the form callers used before there
    were other providers). ``mock_chunk_delay_seconds`` slows the mock's
    streamed chunks so the page can show its live animation without a key,
    and ``mock_call_delay_seconds`` pauses each call that does not stream;
    both are ignored for real providers.

    Raises ``LLMError`` with one fixed sentence when a real client is needed
    and the provider is not offered, the credential is missing a field (the
    sentence names it), the provider's SDK is not installed, or no model is
    chosen. The credential is passed straight to the client and kept
    nowhere else.
    """
    if settings.mock_llm:
        return MockLLM(chunk_delay_seconds=mock_chunk_delay_seconds,
                       call_delay_seconds=mock_call_delay_seconds)
    try:
        provider = Provider(settings.provider)
    except ValueError:
        raise LLMError(ERROR_PROVIDER_OFF) from None
    if provider.value not in settings.providers:
        raise LLMError(ERROR_PROVIDER_OFF)
    cred = Credential(api_key=credential) if isinstance(credential, str) else (credential or Credential())
    missing = missing_credential(provider, cred)
    if missing:
        raise LLMError(missing)
    if not sdk_available(provider):
        raise LLMError(ERROR_PROVIDER_UNAVAILABLE)
    if not settings.architect_model:
        raise LLMError(ERROR_NO_MODEL)
    return _build(provider, cred)


def _build(provider: Provider, cred: Credential) -> LLMClient:
    # Each client module imports its SDK, so it is imported only when used.
    if provider is Provider.CLAUDE:
        from aegisshield.llm.anthropic_client import AnthropicClient

        return AnthropicClient(cred.api_key.strip())
    if provider is Provider.BEDROCK:
        from aegisshield.llm.bedrock_client import BedrockClient

        return BedrockClient(cred)
    if provider is Provider.GEMINI:
        from aegisshield.llm.gemini_client import GeminiClient

        return GeminiClient(cred.api_key.strip())
    from aegisshield.llm.openai_client import OpenAIClient

    return OpenAIClient(cred.api_key.strip())
