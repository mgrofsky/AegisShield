import base64
import logging

import pytest

from aegisshield.core.errors import LLMError, LLMResponseError, ValidationError
from aegisshield.llm import anthropic_client
from aegisshield.llm.anthropic_client import AnthropicClient
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
from aegisshield.llm.json_extract import UNREADABLE
from aegisshield.llm.providers import Credential

from .provider_fakes import (
    CLAUDE_KEY,
    FakeAnthropic,
    anthropic_status_error,
    anthropic_timeout,
    assert_not_leaked,
    claude_events,
    claude_model,
    endless,
)


def make(events=None, **kwargs):
    sdk = FakeAnthropic(events, **kwargs)
    return AnthropicClient(CLAUDE_KEY, sdk_client=sdk), sdk


def test_implements_protocol_and_repr_hides_key():
    client, _ = make()
    assert isinstance(client, LLMClient)
    assert repr(client) == "AnthropicClient()"
    assert CLAUDE_KEY not in repr(client)


def test_requires_key_without_sdk_client():
    with pytest.raises(LLMError):
        AnthropicClient("")


def test_real_sdk_client_uses_only_the_visitor_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "server-" + "auth-token")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "server-" + "api-key")
    client = AnthropicClient(CLAUDE_KEY, timeout_seconds=5, max_retries=0)
    assert client._sdk.api_key == CLAUDE_KEY
    assert client._sdk.auth_token is None
    assert client._sdk.max_retries == 0
    assert_not_leaked(CLAUDE_KEY, client=client)


def test_text_request_shape():
    client, sdk = make()
    assert client.chat_text(system="sys", user="usr", model="m1", max_tokens=99) == "Hello world"
    (call,) = sdk.calls
    assert call == {"model": "m1", "max_tokens": 99, "system": "sys",
                    "messages": [{"role": "user", "content": "usr"}]}
    for absent in ("temperature", "top_p", "top_k", "thinking"):
        assert absent not in call
    assert sdk.raw.closed


def test_empty_system_is_not_sent_and_default_tokens():
    client, sdk = make()
    client.chat_text(system="", user="u", model="m")
    assert "system" not in sdk.calls[0]
    assert sdk.calls[0]["max_tokens"] == 8192
    assert [m["role"] for m in sdk.calls[0]["messages"]] == ["user"]


def test_streamed_text_reaches_on_text_in_order():
    client, _ = make(claude_events(("a", "b", "c")))
    seen = []
    assert client.chat_text(system="s", user="u", model="m", on_text=seen.append) == "abc"
    assert seen == ["a", "b", "c"]


def test_only_text_blocks_are_read():
    client, _ = make(claude_events(("answer",), thinking="secret reasoning"))
    seen = []
    assert client.chat_text(system="s", user="u", model="m", on_text=seen.append) == "answer"
    assert seen == ["answer"]


def test_failing_on_text_does_not_fail_the_call(caplog):
    client, _ = make(claude_events(("a", "b")))
    calls = []

    def bad(text):
        calls.append(text)
        raise RuntimeError("display broke")

    with caplog.at_level(logging.WARNING):
        assert client.chat_text(system="s", user="u", model="m", on_text=bad) == "ab"
    assert calls == ["a"]


@pytest.mark.parametrize("texts", [('{"ok": ', "true}"), ("```json\n", '{"ok": true}', "\n```")])
def test_json(texts):
    client, sdk = make(claude_events(texts))
    assert client.chat_json(system="Be exact.", user="u", model="m") == {"ok": True}
    call = sdk.calls[0]
    assert call["system"] == f"Be exact.\n\n{JSON_SYSTEM_SUFFIX}"
    assert call["max_tokens"] == 16000


def test_json_streams_to_on_text():
    client, _ = make(claude_events(('{"a"', ": 1}")))
    seen = []
    assert client.chat_json(system="", user="u", model="m", on_text=seen.append) == {"a": 1}
    assert "".join(seen) == '{"a": 1}'


def test_image_request_shape():
    client, sdk = make(claude_events(("a diagram",)))
    out = client.describe_image(image_bytes=b"\x89PNG", media_type="png", prompt="look",
                                model="m")
    assert out == "a diagram"
    call = sdk.calls[0]
    assert "system" not in call
    assert call["max_tokens"] == 4096
    image, text = call["messages"][0]["content"]
    assert image == {"type": "image", "source": {
        "type": "base64", "media_type": "image/png",
        "data": base64.standard_b64encode(b"\x89PNG").decode()}}
    assert text == {"type": "text", "text": "look"}


def test_image_rejects_other_types():
    client, sdk = make()
    with pytest.raises(ValidationError):
        client.describe_image(image_bytes=b"GIF8", media_type="image/gif", prompt="p", model="m")
    assert sdk.calls == []


def test_image_refused(caplog):
    client, _ = make(error=anthropic_status_error(400, CLAUDE_KEY))
    with caplog.at_level(logging.DEBUG), pytest.raises(LLMImageError) as info:
        client.describe_image(image_bytes=b"x", media_type="jpeg", prompt="p", model="m")
    assert str(info.value) == ERROR_IMAGE_REFUSED
    assert_not_leaked(CLAUDE_KEY, exc=info.value, records=caplog.records, client=client)


def test_bad_request_on_text_is_no_answer():
    client, _ = make(error=anthropic_status_error(400, CLAUDE_KEY))
    with pytest.raises(LLMError) as info:
        client.chat_text(system="s", user="u", model="m")
    assert type(info.value) is LLMError and str(info.value) == ERROR_NO_ANSWER


def test_empty_answer():
    client, _ = make(claude_events(()))
    assert client.chat_text(system="s", user="u", model="m") == ""
    with pytest.raises(LLMResponseError) as info:
        client.chat_json(system="s", user="u", model="m")
    assert str(info.value) == UNREADABLE


@pytest.mark.parametrize("stop", ["max_tokens", "model_context_window_exceeded"])
def test_truncated(caplog, stop):
    client, _ = make(claude_events(("partial",), stop))
    with caplog.at_level(logging.WARNING):
        assert client.chat_text(system="s", user="u", model="m") == "partial"
    assert "max_tokens" in caplog.text
    client, _ = make(claude_events(('{"a": [1',), stop))
    with pytest.raises(LLMResponseError) as info:
        client.chat_json(system="s", user="u", model="m")
    assert str(info.value) == ERROR_TRUNCATED


def test_refusal_is_filtered():
    client, _ = make(claude_events(("no",), "refusal"))
    with pytest.raises(LLMResponseError) as info:
        client.chat_text(system="s", user="u", model="m")
    assert str(info.value) == ERROR_FILTERED


def test_unexpected_stop_reason(caplog):
    client, _ = make(claude_events(("x",), "pause_turn"))
    with caplog.at_level(logging.WARNING), pytest.raises(LLMResponseError) as info:
        client.chat_text(system="s", user="u", model="m")
    assert str(info.value) == ERROR_NO_ANSWER
    assert "pause_turn" in caplog.text


@pytest.mark.parametrize("on_text", [None, lambda _t: None])
def test_stream_cut_without_message_delta(on_text):
    client, sdk = make(claude_events(("half",), message_delta=False, message_stop=False))
    with pytest.raises(LLMError) as info:
        client.chat_text(system="s", user="u", model="m", on_text=on_text)
    assert type(info.value) is LLMError and str(info.value) == ERROR_STREAM_CUT
    assert sdk.raw.closed


def test_stream_with_no_events_is_stream_cut():
    client, _ = make([])
    with pytest.raises(LLMError) as caught:
        client.chat_text(system="s", user="u", model="m")
    assert str(caught.value) == ERROR_STREAM_CUT


def _failures():
    return [
        ("rate limit", anthropic_status_error(429, CLAUDE_KEY), None),
        ("auth 401", anthropic_status_error(401, CLAUDE_KEY), None),
        ("auth 403", anthropic_status_error(403, CLAUDE_KEY), None),
        ("timeout", anthropic_timeout(), None),
        ("mid-stream", None, anthropic_status_error(429, CLAUDE_KEY)),
    ]


@pytest.mark.parametrize(("label", "error", "stream_error"), _failures(),
                         ids=[f[0] for f in _failures()])
@pytest.mark.parametrize("streamed", [False, True])
def test_provider_failure_is_fixed_sentence_and_leaks_nothing(caplog, label, error,
                                                               stream_error, streamed):
    client, sdk = make(claude_events(("a",)), error=error, stream_error=stream_error)
    caplog.set_level(logging.DEBUG)
    with pytest.raises(LLMError) as info:
        client.chat_text(system="s", user="u", model="m",
                         on_text=(lambda _t: None) if streamed else None)
    assert type(info.value) is LLMError and str(info.value) == ERROR_NO_ANSWER
    assert_not_leaked(CLAUDE_KEY, exc=info.value, records=caplog.records, client=client)
    if sdk.raw is not None:
        assert sdk.raw.closed


# ------------------------------------------------------------------ listing


def test_list_models_filters_and_reads_vision():
    sdk = FakeAnthropic(models=[
        claude_model("claude-a", True),
        claude_model("claude-b", False),
        claude_model("claude-c", capabilities=False),
        claude_model("claude-d"),
        claude_model("claude-old", True, lifecycle="retired"),
        claude_model("claude-e", True, lifecycle="active"),
    ])
    found = anthropic_client.list_models(Credential(api_key=CLAUDE_KEY), timeout_seconds=5,
                                         sdk_client=sdk)
    assert found == [ModelInfo("claude-a", True), ModelInfo("claude-b", False),
                     ModelInfo("claude-c", None), ModelInfo("claude-d", None),
                     ModelInfo("claude-e", True)]


def test_list_models_reads_capabilities_as_a_mapping():
    from types import SimpleNamespace

    items = [SimpleNamespace(id="m1", capabilities={"image_input": {"supported": True}}),
             SimpleNamespace(id="m2", capabilities={"image_input": {"supported": "yes"}}),
             SimpleNamespace(id=7, capabilities=None)]
    sdk = FakeAnthropic(models=items)
    found = anthropic_client.list_models(Credential(api_key=CLAUDE_KEY), timeout_seconds=5,
                                         sdk_client=sdk)
    assert found == [ModelInfo("m1", True), ModelInfo("m2", None)]


def test_list_models_is_bounded():
    sdk = FakeAnthropic()
    sdk.models.list = lambda: endless(lambda n: claude_model(f"claude-{n}", True))
    found = anthropic_client.list_models(Credential(api_key=CLAUDE_KEY), timeout_seconds=5,
                                         sdk_client=sdk)
    assert len(found) == MAX_RAW_MODELS


def test_list_models_failure(caplog):
    sdk = FakeAnthropic(list_error=anthropic_status_error(401, CLAUDE_KEY))
    caplog.set_level(logging.DEBUG)
    with pytest.raises(LLMError) as info:
        anthropic_client.list_models(Credential(api_key=CLAUDE_KEY), timeout_seconds=5,
                                     sdk_client=sdk)
    assert type(info.value) is LLMError and str(info.value) == ERROR_LIST_FAILED
    assert_not_leaked(CLAUDE_KEY, exc=info.value, records=caplog.records)


def test_list_models_builds_a_real_client(monkeypatch):
    built = {}

    def fake_build(api_key, timeout_seconds, max_retries):
        built.update(key=api_key, timeout=timeout_seconds, retries=max_retries)
        return FakeAnthropic(models=[claude_model("claude-a", True)])

    monkeypatch.setattr(anthropic_client, "_build", fake_build)
    found = anthropic_client.list_models(Credential(api_key=CLAUDE_KEY), timeout_seconds=7)
    assert found == [ModelInfo("claude-a", True)]
    assert built == {"key": CLAUDE_KEY, "timeout": 7, "retries": 1}
