import logging

import httpx2
import openai
import pytest

from aegisshield.core.errors import LLMError
from aegisshield.llm import openai_models
from aegisshield.llm.base import ERROR_LIST_FAILED, MAX_RAW_MODELS, ModelInfo
from aegisshield.llm.openai_models import is_chat_model
from aegisshield.llm.providers import Credential

from .provider_fakes import OPENAI_KEY, FakeOpenAIModels, assert_not_leaked, endless

KEPT = ["gpt-5.4", "gpt-4o", "gpt-4o-mini", "gpt-4.1-nano", "o1", "o3-mini", "o4-mini",
        "chatgpt-4o-latest", "gpt-3.5-turbo"]
DROPPED = ["text-embedding-3-small", "whisper-1", "tts-1", "dall-e-3", "gpt-image-1",
           "omni-moderation-latest", "gpt-4o-realtime-preview", "gpt-4o-audio-preview",
           "gpt-4o-transcribe", "gpt-4o-search-preview", "gpt-3.5-turbo-instruct",
           "codex-mini-latest", "o1-pro", "o3-deep-research", "ft:gpt-4o-mini:x", "babbage-002",
           "davinci-002", "gpt-4o-mini-tts", "computer-use-preview", "", "omni"]


@pytest.mark.parametrize("model_id", KEPT)
def test_chat_models_kept(model_id):
    assert is_chat_model(model_id)


@pytest.mark.parametrize("model_id", DROPPED)
def test_other_models_dropped(model_id):
    assert not is_chat_model(model_id)


def _list(fake):
    return openai_models.list_models(Credential(api_key=OPENAI_KEY), timeout_seconds=5,
                                     sdk_client=fake)


def test_listing_filters():
    fake = FakeOpenAIModels(KEPT + DROPPED)
    assert _list(fake) == [ModelInfo(i, None) for i in KEPT]


def test_listing_skips_non_string_ids():
    from types import SimpleNamespace

    fake = FakeOpenAIModels()
    fake.models.list = lambda: iter([SimpleNamespace(id=None), SimpleNamespace(id="gpt-5.4")])
    assert _list(fake) == [ModelInfo("gpt-5.4", None)]


def test_listing_is_bounded():
    fake = FakeOpenAIModels()
    fake.models.list = lambda: endless(lambda n: openai.types.Model(
        id=f"gpt-{n}", created=0, object="model", owned_by="t"))
    assert len(_list(fake)) == MAX_RAW_MODELS


def test_listing_failure(caplog):
    request = httpx2.Request("GET", "https://api.openai.com/v1/models")
    error = openai.AuthenticationError(f"Incorrect API key provided: {OPENAI_KEY}",
                                       response=httpx2.Response(401, request=request), body=None)
    caplog.set_level(logging.DEBUG)
    with pytest.raises(LLMError) as info:
        _list(FakeOpenAIModels(error=error))
    assert type(info.value) is LLMError and str(info.value) == ERROR_LIST_FAILED
    assert_not_leaked(OPENAI_KEY, exc=info.value, records=caplog.records)


def test_listing_builds_a_real_client(monkeypatch):
    built = {}

    class Recorder(FakeOpenAIModels):
        def __init__(self, **kwargs):
            built.update(kwargs)
            super().__init__(["gpt-5.4"])

    monkeypatch.setattr(openai, "OpenAI", Recorder)
    found = openai_models.list_models(Credential(api_key=OPENAI_KEY), timeout_seconds=6)
    assert found == [ModelInfo("gpt-5.4", None)]
    assert built == {"api_key": OPENAI_KEY, "timeout": 6, "max_retries": 1}
