import base64
import logging

import httpx2 as httpx  # the HTTP library the installed openai SDK uses
import openai
import pytest

from aegisshield.core.errors import LLMError, LLMResponseError, ValidationError
from aegisshield.llm.base import JSON_SYSTEM_SUFFIX, LLMClient
from aegisshield.llm.openai_client import OpenAIClient

from .fakes import FakeSDK, FakeStream, chunk, completion

KEY = "sk-test-0123456789abcdefSECRET"


def client(reply=None, error=None):
    sdk = FakeSDK(reply=reply, error=error)
    return OpenAIClient(KEY, sdk_client=sdk), sdk


def test_implements_protocol():
    c, _ = client()
    assert isinstance(c, LLMClient)


def test_real_sdk_client_built_without_network():
    c = OpenAIClient(KEY, timeout_seconds=5, max_retries=0)
    assert KEY not in repr(c)
    assert repr(c) == "OpenAIClient()"


def test_requires_key_without_sdk_client():
    with pytest.raises(LLMError) as info:
        OpenAIClient("")
    assert "key" in str(info.value)


def test_chat_text_call_shape():
    c, sdk = client(completion("  hello  "))
    assert c.chat_text(system="sys", user="usr", model="gpt-5.4", max_tokens=123) == "hello"
    call = sdk.calls[0]
    assert call == {
        "model": "gpt-5.4",
        "messages": [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "usr"},
        ],
        "max_completion_tokens": 123,
    }


def test_chat_text_defaults_and_empty_system():
    c, sdk = client(completion(None))
    assert c.chat_text(system="", user="u", model="m") == ""
    assert sdk.calls[0]["messages"] == [{"role": "user", "content": "u"}]
    assert sdk.calls[0]["max_completion_tokens"] == 8192


def test_chat_text_length_is_logged_not_raised(caplog):
    c, _ = client(completion("partial", finish_reason="length"))
    with caplog.at_level(logging.WARNING):
        assert c.chat_text(system="s", user="u", model="m") == "partial"
    assert "max_tokens" in caplog.text


def test_chat_json_uses_json_mode_and_suffix():
    c, sdk = client(completion('{"ok": true}'))
    assert c.chat_json(system="Be precise.", user="u", model="m") == {"ok": True}
    call = sdk.calls[0]
    assert call["response_format"] == {"type": "json_object"}
    assert call["max_completion_tokens"] == 16000
    system = call["messages"][0]["content"]
    assert system.startswith("Be precise.") and system.endswith(JSON_SYSTEM_SUFFIX)
    assert "JSON" in system


def test_chat_json_truncated_raises():
    c, _ = client(completion('{"a": [1, 2', finish_reason="length"))
    with pytest.raises(LLMResponseError):
        c.chat_json(system="s", user="u", model="m")


def test_chat_json_unreadable_raises():
    c, _ = client(completion("not json"))
    with pytest.raises(LLMResponseError):
        c.chat_json(system="s", user="u", model="m")


def test_content_filter_raises():
    c, _ = client(completion("", finish_reason="content_filter"))
    with pytest.raises(LLMResponseError):
        c.chat_text(system="s", user="u", model="m")


def test_no_choices_raises():
    from types import SimpleNamespace

    c, _ = client(SimpleNamespace(choices=[]))
    with pytest.raises(LLMResponseError):
        c.chat_text(system="s", user="u", model="m")


def test_streaming_text():
    stream = FakeStream(
        [chunk(empty=True), chunk("Hel"), chunk(None), chunk("lo"), chunk(None, "stop"), chunk(empty=True)]
    )
    c, sdk = client(stream)
    seen = []
    assert c.chat_text(system="s", user="u", model="m", on_text=seen.append) == "Hello"
    assert seen == ["Hel", "lo"]
    assert sdk.calls[0]["stream"] is True
    assert stream.closed


def test_streaming_json():
    stream = FakeStream([chunk('{"a"'), chunk(": 1}", "stop")])
    c, sdk = client(stream)
    seen = []
    assert c.chat_json(system="s", user="u", model="m", on_text=seen.append) == {"a": 1}
    assert "".join(seen) == '{"a": 1}'
    assert sdk.calls[0]["response_format"] == {"type": "json_object"}


def test_stream_without_finish_reason_raises():
    stream = FakeStream([chunk("partial answer")])
    c, _ = client(stream)
    with pytest.raises(LLMError) as info:
        c.chat_text(system="s", user="u", model="m", on_text=lambda _t: None)
    assert not isinstance(info.value, LLMResponseError)
    assert stream.closed


def test_stream_truncated_json_raises():
    stream = FakeStream([chunk('{"a": [1,', "length")])
    c, _ = client(stream)
    with pytest.raises(LLMResponseError):
        c.chat_json(system="s", user="u", model="m", on_text=lambda _t: None)


def test_failing_callback_does_not_fail_call(caplog):
    stream = FakeStream([chunk("a"), chunk("b"), chunk("c", "stop")])
    c, _ = client(stream)
    calls = []

    def bad(text):
        calls.append(text)
        raise RuntimeError("display broke")

    with caplog.at_level(logging.WARNING):
        assert c.chat_text(system="s", user="u", model="m", on_text=bad) == "abc"
    assert calls == ["a"]
    assert "on_text callback failed" in caplog.text


def _auth_error():
    request = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    response = httpx.Response(401, request=request)
    return openai.AuthenticationError(
        f"Incorrect API key provided: {KEY}.", response=response, body=None
    )


@pytest.mark.parametrize("stream", [False, True])
def test_sdk_error_hides_key(caplog, stream):
    c, _ = client(error=_auth_error())
    with caplog.at_level(logging.DEBUG), pytest.raises(LLMError) as info:
        c.chat_text(
            system="s", user="u", model="m", on_text=(lambda _t: None) if stream else None
        )
    exc = info.value
    assert KEY not in str(exc) and KEY not in repr(exc)
    assert exc.__cause__ is None and exc.__suppress_context__
    assert KEY not in caplog.text
    assert "AuthenticationError" in caplog.text and "401" in caplog.text


def test_error_mid_stream_wrapped():
    request = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    stream = FakeStream([chunk("a")], error=openai.APIConnectionError(request=request))
    c, _ = client(stream)
    with pytest.raises(LLMError):
        c.chat_text(system="s", user="u", model="m", on_text=lambda _t: None)
    assert stream.closed


@pytest.mark.parametrize(
    ("given", "mime"),
    [("png", "image/png"), ("image/png", "image/png"), ("JPG", "image/jpeg"), ("image/jpeg", "image/jpeg")],
)
def test_describe_image(given, mime):
    c, sdk = client(completion("a diagram"))
    out = c.describe_image(image_bytes=b"\x89PNG", media_type=given, prompt="look", model="m")
    assert out == "a diagram"
    call = sdk.calls[0]
    assert call["max_completion_tokens"] == 4096
    assert "response_format" not in call
    (message,) = call["messages"]
    text_part, image_part = message["content"]
    assert text_part == {"type": "text", "text": "look"}
    encoded = base64.b64encode(b"\x89PNG").decode()
    assert image_part == {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{encoded}"}}


def test_describe_image_rejects_other_types():
    c, sdk = client(completion("x"))
    with pytest.raises(ValidationError):
        c.describe_image(image_bytes=b"GIF8", media_type="image/gif", prompt="p", model="m")
    assert sdk.calls == []
