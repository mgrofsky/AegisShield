import pytest

from aegisshield.config import Settings
from aegisshield.core.errors import LLMError
from aegisshield.llm import get_llm
from aegisshield.llm.mock import MockLLM
from aegisshield.llm.openai_client import OpenAIClient


def test_mock_when_enabled_even_without_key():
    assert isinstance(get_llm(Settings(mock_llm=True), None), MockLLM)


@pytest.mark.parametrize("key", [None, "", "   "])
def test_no_key_raises_plain_error(key):
    with pytest.raises(LLMError) as info:
        get_llm(Settings(), key)
    assert type(info.value) is LLMError
    assert "key" in str(info.value)


def test_openai_with_key():
    client = get_llm(Settings(), "sk-test-abcdefgh12345678")
    assert isinstance(client, OpenAIClient)
    assert "sk-test" not in repr(client)


def test_mock_delay_passed_through():
    llm = get_llm(Settings(mock_llm=True), None, mock_chunk_delay_seconds=0.02,
                  mock_call_delay_seconds=0.5)
    assert isinstance(llm, MockLLM)
    assert llm._delay == 0.02 and llm._call_delay == 0.5


# ----------------------------------------------------------- other providers


def _choice(provider, model="some-model", **changes):
    from dataclasses import replace

    from aegisshield.config import with_model_choice

    return replace(with_model_choice(Settings(), provider=provider, model=model), **changes)


def _creds():
    from aegisshield.llm.providers import Credential

    from .provider_fakes import CLAUDE_KEY, GEMINI_KEY, OPENAI_KEY, VISITOR_KEY_ID, VISITOR_SECRET

    return {
        "claude": Credential(api_key=CLAUDE_KEY),
        "openai": Credential(api_key=OPENAI_KEY),
        "gemini": Credential(api_key=GEMINI_KEY),
        "bedrock": Credential(access_key_id=VISITOR_KEY_ID, secret_access_key=VISITOR_SECRET,
                              region="us-east-1"),
    }


@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    import os

    for name in list(os.environ):
        if name.startswith(("AWS_", "ANTHROPIC_", "GOOGLE_", "GEMINI_", "OPENAI_")):
            monkeypatch.delenv(name)
    monkeypatch.setenv("HOME", str(tmp_path))


@pytest.mark.parametrize("provider", ["claude", "bedrock", "openai", "gemini"])
def test_each_provider_builds_its_client(clean_env, provider):
    from aegisshield.llm.anthropic_client import AnthropicClient
    from aegisshield.llm.bedrock_client import BedrockClient
    from aegisshield.llm.gemini_client import GeminiClient

    from .provider_fakes import assert_not_leaked

    expected = {"claude": AnthropicClient, "bedrock": BedrockClient, "openai": OpenAIClient,
                "gemini": GeminiClient}[provider]
    cred = _creds()[provider]
    client = get_llm(_choice(provider), cred)
    assert type(client) is expected
    for value in (cred.api_key, cred.access_key_id, cred.secret_access_key):
        if value:
            assert_not_leaked(value, client=client)


def test_string_key_is_openai():
    client = get_llm(_choice("openai"), "  " + _creds()["openai"].api_key + "  ")
    assert isinstance(client, OpenAIClient)
    assert client._sdk.api_key == _creds()["openai"].api_key


@pytest.mark.parametrize("provider", ["claude", "openai", "gemini"])
def test_missing_key_names_the_field(provider):
    from aegisshield.llm.providers import Credential, missing_credential

    with pytest.raises(LLMError) as info:
        get_llm(_choice(provider), Credential())
    assert str(info.value) == missing_credential(provider, Credential())


@pytest.mark.parametrize(("field", "value", "word"), [
    ("access_key_id", "", "access key ID"),
    ("secret_access_key", " ", "secret access key"),
    ("region", "", "region"),
    ("region", "mars-north-1", "region"),
])
def test_missing_bedrock_field_names_it(field, value, word):
    from dataclasses import replace

    with pytest.raises(LLMError) as info:
        get_llm(_choice("bedrock"), replace(_creds()["bedrock"], **{field: value}))
    assert word in str(info.value)


def test_provider_not_offered():
    from aegisshield.llm.providers import ERROR_PROVIDER_OFF

    with pytest.raises(LLMError) as info:
        get_llm(_choice("claude", providers=("openai",)), _creds()["claude"])
    assert str(info.value) == ERROR_PROVIDER_OFF
    with pytest.raises(LLMError) as info:
        get_llm(_choice("acme"), _creds()["claude"])
    assert str(info.value) == ERROR_PROVIDER_OFF
    assert info.value.__cause__ is None and info.value.__suppress_context__


def test_sdk_missing(monkeypatch):
    from aegisshield.llm import factory
    from aegisshield.llm.providers import ERROR_PROVIDER_UNAVAILABLE

    monkeypatch.setattr(factory, "sdk_available", lambda _p: False)
    with pytest.raises(LLMError) as info:
        get_llm(_choice("gemini"), _creds()["gemini"])
    assert str(info.value) == ERROR_PROVIDER_UNAVAILABLE


def test_no_model_chosen():
    from aegisshield.llm.providers import ERROR_NO_MODEL

    with pytest.raises(LLMError) as info:
        get_llm(_choice("claude", model=""), _creds()["claude"])
    assert str(info.value) == ERROR_NO_MODEL


def test_mock_ignores_provider_and_credential():
    from aegisshield.llm.mock import MockLLM

    assert isinstance(get_llm(_choice("acme", model="", mock_llm=True), None), MockLLM)
