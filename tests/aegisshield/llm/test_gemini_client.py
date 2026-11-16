import logging

import httpx
import pytest
from google.genai import types

from aegisshield.core.errors import LLMError, LLMResponseError, ValidationError
from aegisshield.llm import gemini_client
from aegisshield.llm.base import (
    ERROR_FILTERED,
    ERROR_IMAGE_REFUSED,
    ERROR_LIST_FAILED,
    ERROR_NO_ANSWER,
    ERROR_STREAM_CUT,
    ERROR_TRUNCATED,
    JSON_SYSTEM_SUFFIX,
    MAX_RAW_MODELS,
    LLMClient,
    LLMImageError,
    ModelInfo,
)
from aegisshield.llm.gemini_client import GeminiClient
from aegisshield.llm.json_extract import UNREADABLE
from aegisshield.llm.providers import Credential

from .provider_fakes import (
    GEMINI_KEY,
    FakeGenai,
    assert_not_leaked,
    endless,
    gemini_model,
    gemini_response,
    genai_client_error,
)

STREAM = lambda _t: None  # noqa: E731


def make(reply=None, **kwargs):
    sdk = FakeGenai(reply, **kwargs)
    return GeminiClient(GEMINI_KEY, sdk_client=sdk), sdk


def test_implements_protocol_and_repr_hides_key():
    client, _ = make()
    assert isinstance(client, LLMClient)
    assert repr(client) == "GeminiClient()"
    assert_not_leaked(GEMINI_KEY, client=client)


def test_requires_key_without_sdk_client():
    with pytest.raises(LLMError):
        GeminiClient("")


def test_real_sdk_client_uses_only_the_visitor_key(monkeypatch):
    monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "true")
    monkeypatch.setenv("GOOGLE_API_KEY", "server-" + "google-key")
    monkeypatch.setenv("GEMINI_API_KEY", "server-" + "gemini-key")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "server-project")
    monkeypatch.setenv("GOOGLE_CLOUD_LOCATION", "us-central1")
    client = GeminiClient(GEMINI_KEY, timeout_seconds=5, max_retries=0)
    api = client._sdk._api_client
    assert api.vertexai is False
    assert api.api_key == GEMINI_KEY
    assert_not_leaked(GEMINI_KEY, client=client)


def test_text_request_shape():
    client, sdk = make()
    assert client.chat_text(system="sys", user="usr", model="g1", max_tokens=55) == "Hello world"
    (name, call), = sdk.calls
    assert name == "generate_content"
    assert call["model"] == "g1" and call["contents"] == "usr"
    config = call["config"]
    assert config.model_dump(exclude_none=True) == {"max_output_tokens": 55,
                                                    "system_instruction": "sys"}


def test_empty_system_not_sent():
    client, sdk = make()
    client.chat_text(system="", user="u", model="m")
    assert sdk.calls[0][1]["config"].model_dump(exclude_none=True) == {"max_output_tokens": 8192}


def test_streamed_text():
    chunks = [gemini_response(("a",), None), gemini_response(("b",), None),
              gemini_response(("c",), "STOP")]
    client, sdk = make(chunks=chunks)
    seen = []
    assert client.chat_text(system="s", user="u", model="m", on_text=seen.append) == "abc"
    assert seen == ["a", "b", "c"]
    assert sdk.calls[0][0] == "generate_content_stream"


def test_thought_parts_are_not_read():
    client, _ = make(chunks=[gemini_response(("answer",), "STOP", thought="private")])
    seen = []
    assert client.chat_text(system="s", user="u", model="m", on_text=seen.append) == "answer"
    assert seen == ["answer"]


def test_stream_chunk_without_candidates_is_skipped():
    chunks = [gemini_response(candidates=False), gemini_response(("x",), "STOP")]
    client, _ = make(chunks=chunks)
    assert client.chat_text(system="s", user="u", model="m", on_text=STREAM) == "x"


def test_failing_on_text_does_not_fail_the_call():
    chunks = [gemini_response(("a",), None), gemini_response(("b",), "STOP")]
    client, _ = make(chunks=chunks)

    def bad(_text):
        raise RuntimeError("display broke")

    assert client.chat_text(system="s", user="u", model="m", on_text=bad) == "ab"


@pytest.mark.parametrize("text", ['{"ok": true}', '```json\n{"ok": true}\n```'])
def test_json(text):
    client, sdk = make(gemini_response((text,)))
    assert client.chat_json(system="Be exact.", user="u", model="m") == {"ok": True}
    config = sdk.calls[0][1]["config"]
    assert config.system_instruction == f"Be exact.\n\n{JSON_SYSTEM_SUFFIX}"
    assert config.max_output_tokens == 16000


def test_json_streamed():
    chunks = [gemini_response(('{"a"',), None), gemini_response((": 1}",), "STOP")]
    client, _ = make(chunks=chunks)
    seen = []
    assert client.chat_json(system="", user="u", model="m", on_text=seen.append) == {"a": 1}
    assert "".join(seen) == '{"a": 1}'


def test_image_request_shape():
    client, sdk = make(gemini_response(("a diagram",)))
    out = client.describe_image(image_bytes=b"\x89PNG", media_type="png", prompt="look",
                                model="m")
    assert out == "a diagram"
    call = sdk.calls[0][1]
    image, prompt = call["contents"]
    assert isinstance(image, types.Part)
    assert image.inline_data.data == b"\x89PNG" and image.inline_data.mime_type == "image/png"
    assert prompt == "look"
    assert call["config"].model_dump(exclude_none=True) == {"max_output_tokens": 4096}


def test_image_rejects_other_types():
    client, sdk = make()
    with pytest.raises(ValidationError):
        client.describe_image(image_bytes=b"x", media_type="image/webp", prompt="p", model="m")
    assert sdk.calls == []


def test_image_refused(caplog):
    client, _ = make(error=genai_client_error(400, GEMINI_KEY, "INVALID_ARGUMENT"))
    caplog.set_level(logging.DEBUG)
    with pytest.raises(LLMImageError) as info:
        client.describe_image(image_bytes=b"x", media_type="jpeg", prompt="p", model="m")
    assert str(info.value) == ERROR_IMAGE_REFUSED
    assert_not_leaked(GEMINI_KEY, exc=info.value, records=caplog.records, client=client)


def test_empty_answer():
    client, _ = make(gemini_response(()))
    assert client.chat_text(system="s", user="u", model="m") == ""
    with pytest.raises(LLMResponseError) as info:
        client.chat_json(system="s", user="u", model="m")
    assert str(info.value) == UNREADABLE


def test_no_candidates_is_no_answer():
    client, _ = make(gemini_response(candidates=False))
    with pytest.raises(LLMResponseError) as info:
        client.chat_text(system="s", user="u", model="m")
    assert str(info.value) == ERROR_NO_ANSWER


def test_truncated(caplog):
    client, _ = make(gemini_response(("partial",), "MAX_TOKENS"))
    with caplog.at_level(logging.WARNING):
        assert client.chat_text(system="s", user="u", model="m") == "partial"
    assert "max_tokens" in caplog.text
    client, _ = make(gemini_response(('{"a": [1',), "MAX_TOKENS"))
    with pytest.raises(LLMResponseError) as info:
        client.chat_json(system="s", user="u", model="m")
    assert str(info.value) == ERROR_TRUNCATED


@pytest.mark.parametrize("finish", ["SAFETY", "RECITATION", "PROHIBITED_CONTENT"])
def test_declined_finish(finish):
    client, _ = make(gemini_response(("x",), finish))
    with pytest.raises(LLMResponseError) as info:
        client.chat_text(system="s", user="u", model="m")
    assert str(info.value) == ERROR_FILTERED


@pytest.mark.parametrize("streamed", [False, True])
def test_prompt_blocked(streamed):
    reply = gemini_response(candidates=False, block=types.BlockedReason.SAFETY)
    client, _ = make(reply)
    with pytest.raises(LLMResponseError) as info:
        client.chat_text(system="s", user="u", model="m", on_text=STREAM if streamed else None)
    assert str(info.value) == ERROR_FILTERED


def test_unexpected_finish(caplog):
    client, _ = make(gemini_response(("x",), "MALFORMED_FUNCTION_CALL"))
    with caplog.at_level(logging.WARNING), pytest.raises(LLMResponseError) as info:
        client.chat_text(system="s", user="u", model="m")
    assert str(info.value) == ERROR_NO_ANSWER
    assert "MALFORMED_FUNCTION_CALL" in caplog.text


def test_stream_cut_without_finish_reason():
    chunks = [gemini_response(("half",), None), gemini_response((" more",), None)]
    client, _ = make(chunks=chunks)
    with pytest.raises(LLMError) as info:
        client.chat_text(system="s", user="u", model="m", on_text=STREAM)
    assert type(info.value) is LLMError and str(info.value) == ERROR_STREAM_CUT


def _failures():
    return [
        ("rate limit", genai_client_error(429, GEMINI_KEY), None),
        ("auth 401", genai_client_error(401, GEMINI_KEY, "UNAUTHENTICATED"), None),
        ("auth 403", genai_client_error(403, GEMINI_KEY, "PERMISSION_DENIED"), None),
        ("timeout", httpx.ReadTimeout(f"timed out {GEMINI_KEY}"), None),
    ]


def _cases():
    cases = [(label, error, None, streamed) for label, error, _ in _failures()
             for streamed in (False, True)]
    return cases + [
        ("mid-stream", None, genai_client_error(429, GEMINI_KEY), True),
        ("mid-stream timeout", None, httpx.ReadTimeout(f"cut {GEMINI_KEY}"), True),
    ]


@pytest.mark.parametrize(("label", "error", "stream_error", "streamed"), _cases(),
                         ids=[f"{c[0]}-{'stream' if c[3] else 'once'}" for c in _cases()])
def test_provider_failure_is_fixed_sentence_and_leaks_nothing(caplog, label, error,
                                                               stream_error, streamed):
    client, _ = make(error=error, stream_error=stream_error,
                     chunks=[gemini_response(("a",), None)])
    caplog.set_level(logging.DEBUG)
    with pytest.raises(LLMError) as info:
        client.chat_text(system="s", user="u", model="m", on_text=STREAM if streamed else None)
    assert type(info.value) is LLMError and str(info.value) == ERROR_NO_ANSWER
    assert_not_leaked(GEMINI_KEY, exc=info.value, records=caplog.records, client=client)


# ------------------------------------------------------------------ listing


def _list(fake):
    return gemini_client.list_models(Credential(api_key=GEMINI_KEY), timeout_seconds=5,
                                     sdk_client=fake)


def test_listing_keeps_generate_content_models():
    fake = FakeGenai(models=[
        gemini_model("models/gemini-x-pro"),
        gemini_model("models/text-embedding-x", ("embedContent",)),
        gemini_model("models/gemini-y", ("generateContent",)),
        types.Model(name=None, supported_actions=["generateContent"]),
        types.Model(name="models/no-actions"),
        gemini_model("tunedModels/t1"),
    ])
    assert _list(fake) == [ModelInfo("gemini-x-pro", None), ModelInfo("gemini-y", None),
                           ModelInfo("tunedModels/t1", None)]


def test_listing_is_bounded():
    fake = FakeGenai()
    fake.models.list = lambda: endless(lambda n: gemini_model(f"models/g-{n}"))
    assert len(_list(fake)) == MAX_RAW_MODELS


@pytest.mark.parametrize("error", [genai_client_error(401, GEMINI_KEY, "UNAUTHENTICATED"),
                                   httpx.ConnectTimeout(f"no route {GEMINI_KEY}")])
def test_listing_failure(caplog, error):
    caplog.set_level(logging.DEBUG)
    with pytest.raises(LLMError) as info:
        _list(FakeGenai(list_error=error))
    assert type(info.value) is LLMError and str(info.value) == ERROR_LIST_FAILED
    assert_not_leaked(GEMINI_KEY, exc=info.value, records=caplog.records)


def test_listing_builds_its_own_client(monkeypatch):
    built = {}

    def fake_build(api_key, timeout_seconds, max_retries):
        built.update(key=api_key, timeout=timeout_seconds, retries=max_retries)
        return FakeGenai(models=[gemini_model("models/g")])

    monkeypatch.setattr(gemini_client, "_build", fake_build)
    found = gemini_client.list_models(Credential(api_key=GEMINI_KEY), timeout_seconds=4)
    assert found == [ModelInfo("g", None)]
    assert built == {"key": GEMINI_KEY, "timeout": 4, "retries": 1}
