import json
import logging

import pytest

from aegisshield.config import Settings, with_model_choice
from aegisshield.core.errors import LLMError, LLMResponseError, ValidationError
from aegisshield.llm import bedrock_client, get_llm, providers
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
from aegisshield.llm.bedrock_client import BedrockClient
from aegisshield.llm.json_extract import UNREADABLE
from aegisshield.llm.providers import BEDROCK_REGIONS, Credential

from .provider_fakes import (
    OTHER_BEARER,
    SERVER_BEARER,
    SERVER_KEY_ID,
    SERVER_SECRET,
    SERVER_TOKEN,
    VISITOR_BEARER,
    VISITOR_KEY_ID,
    VISITOR_SECRET,
    VISITOR_TOKEN,
    FakeBedrock,
    FakeBedrockRuntime,
    assert_not_leaked,
    client_error,
    converse_events,
    converse_response,
    endless,
    event_stream_error,
    foundation_model,
    inference_profile,
    read_timeout,
)

CRED = Credential(access_key_id=VISITOR_KEY_ID, secret_access_key=VISITOR_SECRET,
                  region="us-east-1")
STREAM = lambda _t: None  # noqa: E731


def make(reply=None, **kwargs):
    sdk = FakeBedrockRuntime(reply, **kwargs)
    return BedrockClient(CRED, sdk_client=sdk), sdk


def test_implements_protocol_and_repr_hides_key():
    client, _ = make()
    assert isinstance(client, LLMClient)
    assert repr(client) == "BedrockClient()"
    assert_not_leaked(VISITOR_SECRET, client=client)
    assert_not_leaked(VISITOR_KEY_ID, client=client)


@pytest.mark.parametrize("cred", [None, Credential(),
                                  Credential(access_key_id="a", secret_access_key="b"),
                                  Credential(access_key_id="a", region="us-east-1")])
def test_requires_credential_without_sdk_client(cred):
    with pytest.raises(LLMError):
        BedrockClient(cred)


def test_text_request_shape():
    client, sdk = make()
    assert client.chat_text(system="sys", user="usr", model="m1", max_tokens=77) == "Hello world"
    (name, call), = sdk.calls
    assert name == "converse"
    assert call == {"modelId": "m1", "system": [{"text": "sys"}],
                    "messages": [{"role": "user", "content": [{"text": "usr"}]}],
                    "inferenceConfig": {"maxTokens": 77}}


def test_empty_system_not_sent():
    client, sdk = make()
    client.chat_text(system="", user="u", model="m")
    assert "system" not in sdk.calls[0][1]
    assert sdk.calls[0][1]["inferenceConfig"] == {"maxTokens": 8192}


def test_streamed_text():
    client, sdk = make(events=converse_events(("a", "b", "c")))
    seen = []
    assert client.chat_text(system="s", user="u", model="m", on_text=seen.append) == "abc"
    assert seen == ["a", "b", "c"]
    assert sdk.calls[0][0] == "converse_stream"
    assert sdk.calls[0][1]["inferenceConfig"] == {"maxTokens": 8192}
    assert sdk.stream.closed


def test_stream_skips_odd_events():
    events = ["junk", {"contentBlockDelta": {"delta": {"toolUse": {}}}}] + converse_events(("x",))
    client, _ = make(events=events)
    assert client.chat_text(system="s", user="u", model="m", on_text=STREAM) == "x"


def test_failing_on_text_does_not_fail_the_call():
    client, _ = make(events=converse_events(("a", "b")))

    def bad(_text):
        raise RuntimeError("display broke")

    assert client.chat_text(system="s", user="u", model="m", on_text=bad) == "ab"


@pytest.mark.parametrize("text", ['{"ok": true}', '```json\n{"ok": true}\n```'])
def test_json(text):
    client, sdk = make(converse_response(text))
    assert client.chat_json(system="Be exact.", user="u", model="m") == {"ok": True}
    call = sdk.calls[0][1]
    assert call["system"] == [{"text": f"Be exact.\n\n{JSON_SYSTEM_SUFFIX}"}]
    assert call["inferenceConfig"] == {"maxTokens": 16000}


def test_json_streamed():
    client, _ = make(events=converse_events(('{"a"', ": 1}")))
    seen = []
    assert client.chat_json(system="", user="u", model="m", on_text=seen.append) == {"a": 1}
    assert "".join(seen) == '{"a": 1}'


@pytest.mark.parametrize(("given", "fmt"), [("png", "png"), ("image/jpeg", "jpeg")])
def test_image_request_shape(given, fmt):
    client, sdk = make(converse_response("a diagram"))
    out = client.describe_image(image_bytes=b"\x89PNG", media_type=given, prompt="look",
                                model="m")
    assert out == "a diagram"
    call = sdk.calls[0][1]
    assert "system" not in call
    assert call["inferenceConfig"] == {"maxTokens": 4096}
    assert call["messages"][0]["content"] == [
        {"image": {"format": fmt, "source": {"bytes": b"\x89PNG"}}}, {"text": "look"}]


def test_image_rejects_other_types():
    client, sdk = make()
    with pytest.raises(ValidationError):
        client.describe_image(image_bytes=b"x", media_type="gif", prompt="p", model="m")
    assert sdk.calls == []


def test_image_refused(caplog):
    client, _ = make(error=client_error(400, "ValidationException", VISITOR_SECRET))
    caplog.set_level(logging.DEBUG)
    with pytest.raises(LLMImageError) as info:
        client.describe_image(image_bytes=b"x", media_type="png", prompt="p", model="m")
    assert str(info.value) == ERROR_IMAGE_REFUSED
    assert_not_leaked(VISITOR_SECRET, exc=info.value, records=caplog.records, client=client)


def test_empty_answer():
    client, _ = make(converse_response(None))
    assert client.chat_text(system="s", user="u", model="m") == ""
    with pytest.raises(LLMResponseError) as info:
        client.chat_json(system="s", user="u", model="m")
    assert str(info.value) == UNREADABLE


def test_missing_output_is_no_answer():
    client, _ = make({"stopReason": "weird"})
    with pytest.raises(LLMResponseError) as info:
        client.chat_text(system="s", user="u", model="m")
    assert str(info.value) == ERROR_NO_ANSWER


@pytest.mark.parametrize("stop", ["max_tokens", "model_context_window_exceeded"])
def test_truncated(caplog, stop):
    client, _ = make(converse_response("partial", stop))
    with caplog.at_level(logging.WARNING):
        assert client.chat_text(system="s", user="u", model="m") == "partial"
    assert "max_tokens" in caplog.text
    client, _ = make(converse_response('{"a": [1', stop))
    with pytest.raises(LLMResponseError) as info:
        client.chat_json(system="s", user="u", model="m")
    assert str(info.value) == ERROR_TRUNCATED


@pytest.mark.parametrize("stop", ["guardrail_intervened", "content_filtered"])
@pytest.mark.parametrize("streamed", [False, True])
def test_declined(stop, streamed):
    client, _ = make(converse_response("x", stop), events=converse_events(("x",), stop))
    with pytest.raises(LLMResponseError) as info:
        client.chat_text(system="s", user="u", model="m", on_text=STREAM if streamed else None)
    assert str(info.value) == ERROR_FILTERED


@pytest.mark.parametrize("stop", ["tool_use", ""])
def test_unexpected_stop(stop):
    client, _ = make(converse_response("x", stop), events=converse_events(("x",), stop))
    for on_text in (None, STREAM):
        with pytest.raises(LLMResponseError) as info:
            client.chat_text(system="s", user="u", model="m", on_text=on_text)
        assert str(info.value) == ERROR_NO_ANSWER


def test_stream_cut_without_message_stop():
    client, sdk = make(events=converse_events(("half",), message_stop=False))
    with pytest.raises(LLMError) as info:
        client.chat_text(system="s", user="u", model="m", on_text=STREAM)
    assert type(info.value) is LLMError and str(info.value) == ERROR_STREAM_CUT
    assert sdk.stream.closed


def test_stream_missing_is_no_answer():
    client, _ = make(stream_missing=True)
    with pytest.raises(LLMError) as info:
        client.chat_text(system="s", user="u", model="m", on_text=STREAM)
    assert str(info.value) == ERROR_NO_ANSWER


def test_error_event_in_stream(caplog):
    events = converse_events(("a",), message_stop=False) + [
        {"throttlingException": {"message": f"slow down {VISITOR_SECRET}"}}]
    events[-1] = {"ThrottlingException": events[-1]["throttlingException"]}
    client, sdk = make(events=events)
    caplog.set_level(logging.DEBUG)
    with pytest.raises(LLMError) as info:
        client.chat_text(system="s", user="u", model="m", on_text=STREAM)
    assert str(info.value) == ERROR_NO_ANSWER
    assert sdk.stream.closed
    assert_not_leaked(VISITOR_SECRET, exc=info.value, records=caplog.records, client=client)


def _failures():
    return [
        ("rate limit", client_error(429, "ThrottlingException", VISITOR_SECRET), None),
        ("auth 401", client_error(401, "UnrecognizedClientException", VISITOR_SECRET), None),
        ("auth 403", client_error(403, "AccessDeniedException", VISITOR_SECRET), None),
        ("timeout", read_timeout(VISITOR_SECRET), None),
    ]


def _cases():
    cases = [(label, error, None, streamed) for label, error, _ in _failures()
             for streamed in (False, True)]
    return cases + [("mid-stream", None, event_stream_error(VISITOR_SECRET), True)]


@pytest.mark.parametrize(("label", "error", "stream_error", "streamed"), _cases(),
                         ids=[f"{c[0]}-{'stream' if c[3] else 'once'}" for c in _cases()])
def test_provider_failure_is_fixed_sentence_and_leaks_nothing(caplog, label, error,
                                                               stream_error, streamed):
    client, sdk = make(error=error, stream_error=stream_error,
                       events=converse_events(("a",), message_stop=False))
    caplog.set_level(logging.DEBUG)
    with pytest.raises(LLMError) as info:
        client.chat_text(system="s", user="u", model="m", on_text=STREAM if streamed else None)
    assert type(info.value) is LLMError and str(info.value) == ERROR_NO_ANSWER
    assert_not_leaked(VISITOR_SECRET, exc=info.value, records=caplog.records, client=client)
    if sdk.stream is not None:
        assert sdk.stream.closed


# ----------------------------------------------- isolation from the server


AWS_VARS = ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_BEARER_TOKEN_BEDROCK",
            "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "AWS_ENDPOINT_URL_BEDROCK",
            "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_REGION",
            "AWS_DEFAULT_REGION", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS",
            "AWS_AUTH_SCHEME_PREFERENCE", "AWS_CA_BUNDLE")


def _clear_aws(monkeypatch):
    for name in AWS_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def server_env(monkeypatch, tmp_path):
    """An environment full of this server's own AWS settings."""
    _clear_aws(monkeypatch)
    aws = tmp_path / ".aws"
    aws.mkdir()
    (aws / "config").write_text(
        "[default]\nregion = eu-west-1\nendpoint_url = http://127.0.0.1:9\n\n"
        "[profile server]\nregion = eu-west-1\nendpoint_url = http://127.0.0.1:9\n"
        "auth_scheme_preference = httpBearerAuth\n")
    (aws / "credentials").write_text(
        f"[default]\naws_access_key_id = {SERVER_KEY_ID}\n"
        f"aws_secret_access_key = {SERVER_SECRET}\n\n"
        f"[server]\naws_access_key_id = {SERVER_KEY_ID}\n"
        f"aws_secret_access_key = {SERVER_SECRET}\naws_session_token = {SERVER_TOKEN}\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(aws / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(aws / "credentials"))
    monkeypatch.setenv("AWS_PROFILE", "server")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", SERVER_KEY_ID)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", SERVER_SECRET)
    monkeypatch.setenv("AWS_SESSION_TOKEN", SERVER_TOKEN)
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", SERVER_BEARER)
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("AWS_ENDPOINT_URL_BEDROCK_RUNTIME", "http://127.0.0.1:9")
    monkeypatch.setenv("AWS_ENDPOINT_URL_BEDROCK", "http://127.0.0.1:9")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    monkeypatch.setenv("AWS_AUTH_SCHEME_PREFERENCE", "httpBearerAuth")
    return tmp_path


class _Raw:
    def __init__(self, body):
        self._body = json.dumps(body).encode()

    def stream(self, **_kwargs):
        yield self._body


def _capture(sdk, body):
    """Answer every request with ``body`` and record its headers, offline."""
    from botocore.awsrequest import AWSResponse

    seen = []

    def before_send(request, **_kwargs):
        seen.append({"url": request.url, "headers": dict(request.headers)})
        return AWSResponse(request.url, 200, {}, _Raw(body))

    sdk.meta.events.register("before-send", before_send)
    return seen


def _header(headers, name):
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value.decode() if isinstance(value, bytes) else value
    return None


def _assert_visitor_signed(request, token):
    auth = _header(request["headers"], "Authorization")
    assert auth.startswith(f"AWS4-HMAC-SHA256 Credential={VISITOR_KEY_ID}/")
    flat = json.dumps({k: str(v) for k, v in request["headers"].items()})
    for server_value in (SERVER_KEY_ID, SERVER_SECRET, SERVER_TOKEN, SERVER_BEARER):
        assert server_value not in flat
    assert "Bearer" not in auth
    assert _header(request["headers"], "X-Amz-Security-Token") == token
    assert "127.0.0.1" not in request["url"]


@pytest.mark.parametrize("token", [None, VISITOR_TOKEN])
def test_runtime_client_uses_only_the_visitor_credential(server_env, token):
    cred = Credential(access_key_id=VISITOR_KEY_ID, secret_access_key=VISITOR_SECRET,
                      session_token=token or "", region="us-east-1")
    client = BedrockClient(cred, timeout_seconds=5, max_retries=0)
    assert client._sdk.meta.endpoint_url == "https://bedrock-runtime.us-east-1.amazonaws.com"
    assert client._sdk.meta.region_name == "us-east-1"
    seen = _capture(client._sdk, {
        "output": {"message": {"role": "assistant", "content": [{"text": "ok"}]}},
        "stopReason": "end_turn", "usage": {"inputTokens": 1, "outputTokens": 1,
                                            "totalTokens": 2},
        "metrics": {"latencyMs": 1}})
    assert client.chat_text(system="s", user="u", model="m") == "ok"
    (request,) = seen
    assert request["url"].startswith("https://bedrock-runtime.us-east-1.amazonaws.com/")
    _assert_visitor_signed(request, token)
    for value in (SERVER_KEY_ID, SERVER_SECRET, SERVER_TOKEN, SERVER_BEARER, VISITOR_SECRET):
        assert value not in repr(client)


@pytest.mark.parametrize("token", [None, VISITOR_TOKEN])
def test_listing_client_uses_only_the_visitor_credential(server_env, token):
    cred = Credential(access_key_id=VISITOR_KEY_ID, secret_access_key=VISITOR_SECRET,
                      session_token=token or "", region="us-east-1")
    sdk = bedrock_client._client(cred, "bedrock", 5, 0)
    assert sdk.meta.endpoint_url == "https://bedrock.us-east-1.amazonaws.com"
    from botocore.awsrequest import AWSResponse

    seen = []

    def before_send(request, **_kwargs):
        seen.append({"url": request.url, "headers": dict(request.headers)})
        body = ({"modelSummaries": []} if "foundation-models" in request.url
                else {"inferenceProfileSummaries": []})
        return AWSResponse(request.url, 200, {}, _Raw(body))

    sdk.meta.events.register("before-send", before_send)
    assert bedrock_client.list_models(cred, timeout_seconds=5, sdk_client=sdk) == []
    assert len(seen) == 2
    for request in seen:
        _assert_visitor_signed(request, token)


# ------------------------------------------------- a visitor's Bedrock API key


_ANSWER = {"output": {"message": {"role": "assistant", "content": [{"text": "ok"}]}},
           "stopReason": "end_turn", "usage": {"inputTokens": 1, "outputTokens": 1,
                                               "totalTokens": 2},
           "metrics": {"latencyMs": 1}}


def _key_cred(key=VISITOR_BEARER, **extra):
    return Credential(api_key=key, region="us-east-1", **extra)


def _assert_bearer(request, key):
    auth = _header(request["headers"], "Authorization")
    assert auth == f"Bearer {key}"
    flat = json.dumps({k: str(v) for k, v in request["headers"].items()})
    for value in (SERVER_KEY_ID, SERVER_SECRET, SERVER_TOKEN, SERVER_BEARER, VISITOR_KEY_ID,
                  VISITOR_SECRET):
        assert value not in flat
    assert "AWS4-HMAC-SHA256" not in flat
    assert _header(request["headers"], "X-Amz-Date") is None
    assert _header(request["headers"], "X-Amz-Security-Token") is None
    assert "127.0.0.1" not in request["url"]


def test_api_key_runtime_sends_only_the_visitors_bearer_token(server_env):
    client = BedrockClient(_key_cred(), timeout_seconds=5, max_retries=0)
    assert client._sdk.meta.endpoint_url == "https://bedrock-runtime.us-east-1.amazonaws.com"
    seen = _capture(client._sdk, _ANSWER)
    assert client.chat_text(system="s", user="u", model="m") == "ok"
    (request,) = seen
    assert request["url"].startswith("https://bedrock-runtime.us-east-1.amazonaws.com/")
    _assert_bearer(request, VISITOR_BEARER)
    assert_not_leaked(VISITOR_BEARER, client=client)


def test_api_key_stream_sends_only_the_visitors_bearer_token(server_env, caplog):
    """``converse_stream`` is signed the same way. The canned answer is a
    refusal, so the call fails with the fixed sentence after the request
    was captured."""
    client = BedrockClient(_key_cred(), timeout_seconds=5, max_retries=0)
    from botocore.awsrequest import AWSResponse

    seen = []

    def refuse(request, **_kwargs):
        seen.append({"url": request.url, "headers": dict(request.headers)})
        return AWSResponse(request.url, 400, {"x-amzn-ErrorType": "ValidationException"},
                           _Raw({"message": "no"}))

    client._sdk.meta.events.register("before-send", refuse)
    caplog.set_level(logging.DEBUG)
    with pytest.raises(LLMError) as info:
        client.chat_text(system="s", user="u", model="m", on_text=STREAM)
    assert str(info.value) == ERROR_NO_ANSWER
    (request,) = seen
    assert "/converse-stream" in request["url"]
    _assert_bearer(request, VISITOR_BEARER)


def test_api_key_listing_sends_only_the_visitors_bearer_token(server_env):
    cred = _key_cred()
    sdk = bedrock_client._client(cred, "bedrock", 5, 0)
    assert sdk.meta.endpoint_url == "https://bedrock.us-east-1.amazonaws.com"
    from botocore.awsrequest import AWSResponse

    seen = []

    def before_send(request, **_kwargs):
        seen.append({"url": request.url, "headers": dict(request.headers)})
        body = ({"modelSummaries": []} if "foundation-models" in request.url
                else {"inferenceProfileSummaries": []})
        return AWSResponse(request.url, 200, {}, _Raw(body))

    sdk.meta.events.register("before-send", before_send)
    assert bedrock_client.list_models(cred, timeout_seconds=5, sdk_client=sdk) == []
    assert len(seen) == 2
    for request in seen:
        _assert_bearer(request, VISITOR_BEARER)


def test_api_key_wins_over_access_keys(server_env):
    cred = _key_cred(access_key_id=VISITOR_KEY_ID, secret_access_key=VISITOR_SECRET,
                     session_token=VISITOR_TOKEN)
    client = BedrockClient(cred, timeout_seconds=5, max_retries=0)
    seen = _capture(client._sdk, _ANSWER)
    client.chat_text(system="s", user="u", model="m")
    _assert_bearer(seen[0], VISITOR_BEARER)


def test_api_key_session_reads_no_server_credential(server_env):
    session = bedrock_client.visitor_session(_key_cred())
    assert session.get_credentials() is None
    core = session._session
    assert core.get_auth_token().token == VISITOR_BEARER
    assert core.get_auth_token(signing_name="bedrock").token == VISITOR_BEARER
    assert core.get_auth_token(signing_name="other").token == VISITOR_BEARER


def test_two_visitors_keys_never_cross(server_env):
    one = BedrockClient(_key_cred(VISITOR_BEARER), timeout_seconds=5, max_retries=0)
    two = BedrockClient(_key_cred(OTHER_BEARER), timeout_seconds=5, max_retries=0)
    signed = BedrockClient(CRED, timeout_seconds=5, max_retries=0)
    seen_one, seen_two = _capture(one._sdk, _ANSWER), _capture(two._sdk, _ANSWER)
    seen_signed = _capture(signed._sdk, _ANSWER)
    for _ in range(2):
        for client in (one, two, signed):
            client.chat_text(system="s", user="u", model="m")
    assert len(seen_one) == len(seen_two) == len(seen_signed) == 2
    for request in seen_one:
        _assert_bearer(request, VISITOR_BEARER)
        assert OTHER_BEARER not in json.dumps({k: str(v) for k, v in request["headers"].items()})
    for request in seen_two:
        _assert_bearer(request, OTHER_BEARER)
        assert VISITOR_BEARER not in json.dumps({k: str(v) for k, v in request["headers"].items()})
    for request in seen_signed:
        _assert_visitor_signed(request, None)
        flat = json.dumps({k: str(v) for k, v in request["headers"].items()})
        assert VISITOR_BEARER not in flat and OTHER_BEARER not in flat


def test_api_key_failure_leaks_nothing(server_env, caplog):
    client = BedrockClient(_key_cred(), timeout_seconds=5, max_retries=0)
    from botocore.awsrequest import AWSResponse

    def refuse(request, **_kwargs):
        return AWSResponse(request.url, 403, {"x-amzn-ErrorType": "AccessDeniedException"},
                           _Raw({"message": f"denied for {VISITOR_BEARER}"}))

    client._sdk.meta.events.register("before-send", refuse)
    caplog.set_level(logging.DEBUG, logger="aegisshield")
    with pytest.raises(LLMError) as info:
        client.chat_text(system="s", user="u", model="m")
    assert str(info.value) == ERROR_NO_ANSWER
    assert_not_leaked(VISITOR_BEARER, exc=info.value,
                      records=[r for r in caplog.records if r.name.startswith("aegisshield")],
                      client=client)


def test_api_key_listing_refused_is_the_fixed_sentence(server_env, caplog):
    """A key whose principal may not list models gets the plain sentence."""
    cred = _key_cred()
    sdk = bedrock_client._client(cred, "bedrock", 5, 0)
    from botocore.awsrequest import AWSResponse

    def refuse(request, **_kwargs):
        return AWSResponse(request.url, 403, {"x-amzn-ErrorType": "AccessDeniedException"},
                           _Raw({"message": f"no {VISITOR_BEARER}"}))

    sdk.meta.events.register("before-send", refuse)
    caplog.set_level(logging.DEBUG, logger="aegisshield")
    with pytest.raises(LLMError) as info:
        bedrock_client.list_models(cred, timeout_seconds=5, sdk_client=sdk)
    assert str(info.value) == ERROR_LIST_FAILED
    assert_not_leaked(VISITOR_BEARER, exc=info.value,
                      records=[r for r in caplog.records if r.name.startswith("aegisshield")])


@pytest.mark.parametrize("cred", [Credential(api_key="k"), Credential(api_key="  ", region="us-east-1")])
def test_api_key_needs_a_region(cred):
    with pytest.raises(LLMError):
        BedrockClient(cred)


def test_plain_boto3_session_would_use_the_server_bearer_token(server_env):
    """The control: without ``visitor_session`` a bearer-signed client
    takes this server's ``AWS_BEARER_TOKEN_BEDROCK``."""
    import boto3
    from botocore.config import Config

    runtime = boto3.session.Session().client(
        "bedrock-runtime", region_name="us-east-1",
        endpoint_url="https://bedrock-runtime.us-east-1.amazonaws.com",
        config=Config(signature_version="bearer"))
    seen = _capture(runtime, _ANSWER)
    runtime.converse(modelId="m", messages=[{"role": "user", "content": [{"text": "u"}]}])
    assert _header(seen[0]["headers"], "Authorization") == f"Bearer {SERVER_BEARER}"


def test_plain_boto3_session_would_use_the_server_settings(server_env):
    """The control: without ``visitor_session`` boto3 reads this server's
    profile, endpoint, and keys."""
    import boto3

    session = boto3.session.Session()
    assert session.profile_name == "server"
    assert session.get_credentials().access_key == SERVER_KEY_ID
    runtime = session.client("bedrock-runtime", region_name="us-east-1")
    assert runtime.meta.endpoint_url == "http://127.0.0.1:9"


def test_no_credential_never_builds_a_client(monkeypatch):
    def boom(*_args, **_kwargs):
        raise AssertionError("a client was built")

    monkeypatch.setattr(bedrock_client, "_client", boom)
    monkeypatch.setattr(bedrock_client, "visitor_session", boom)
    settings = with_model_choice(Settings(), provider="bedrock", model="anthropic.m-v1:0")
    sentence = providers.missing_credential("bedrock", Credential())
    assert "access key ID" in sentence
    with pytest.raises(LLMError) as info:
        get_llm(settings, Credential())
    assert str(info.value) == sentence
    with pytest.raises(LLMError) as info:
        get_llm(settings, None)
    assert str(info.value) == sentence
    with pytest.raises(LLMError) as info:
        providers.list_models("bedrock", Credential())
    assert str(info.value) == sentence


def test_bedrock_regions_match_botocore(monkeypatch, tmp_path):
    import botocore.session

    _clear_aws(monkeypatch)
    monkeypatch.setenv("HOME", str(tmp_path))
    expected = sorted(botocore.session.Session().get_available_regions("bedrock"))
    assert list(BEDROCK_REGIONS) == expected


# ------------------------------------------------------------------ listing


def _list(fake):
    return bedrock_client.list_models(CRED, timeout_seconds=5, sdk_client=fake)


def test_listing_filters_foundation_models():
    fake = FakeBedrock([
        foundation_model("a.text-v1:0"),
        foundation_model("a.vision-v1:0", inputs=("TEXT", "IMAGE")),
        foundation_model("a.embed-v1:0", outputs=("EMBEDDING",)),
        foundation_model("a.embed2-v1:0", outputs=("TEXT", "EMBEDDING")),
        foundation_model("a.image-v1:0", inputs=("TEXT",), outputs=("IMAGE",)),
        foundation_model("a.legacy-v1:0", status="LEGACY"),
        foundation_model("a.nostream-v1:0", streaming=False),
        foundation_model("a.nostream2-v1:0", streaming=None),
        foundation_model("a.imgin-v1:0", inputs=("IMAGE",)),
        foundation_model("a.provisioned-v1:0", inference=("PROVISIONED",)),
        foundation_model("a.profileonly-v1:0", inference=("INFERENCE_PROFILE",)),
        "not a dict",
        {**foundation_model("x"), "modelId": 5},
    ])
    assert _list(fake) == [ModelInfo("a.text-v1:0", False), ModelInfo("a.vision-v1:0", True)]
    assert fake.foundation_calls == [{"byOutputModality": "TEXT"}]
    assert fake.profile_calls == [{"maxResults": 1000}]


def test_listing_inference_profiles():
    summaries = [
        foundation_model("a.text-v1:0", inputs=("TEXT", "IMAGE"),
                         inference=("INFERENCE_PROFILE",)),
        foundation_model("b.text-v1:0", inference=("INFERENCE_PROFILE",)),
        foundation_model("c.vision-v1:0", inputs=("TEXT", "IMAGE"),
                         inference=("INFERENCE_PROFILE",)),
        foundation_model("d.legacy-v1:0", status="LEGACY", inference=("INFERENCE_PROFILE",)),
    ]
    profiles = [
        inference_profile("us.a.text-v1:0", ["a.text-v1:0", "a.text-v1:0"]),
        inference_profile("us.mixed", ["a.text-v1:0", "b.text-v1:0"]),
        inference_profile("us.c.vision-v1:0", ["c.vision-v1:0"]),
        inference_profile("us.d.legacy-v1:0", ["d.legacy-v1:0"]),
        inference_profile("us.half", ["a.text-v1:0", "unknown-v1:0"]),
        inference_profile("us.empty", []),
        inference_profile("us.off", ["a.text-v1:0"], status="INACTIVE"),
        inference_profile("app-profile", ["b.text-v1:0"], kind="APPLICATION"),
        {**inference_profile("x", ["a.text-v1:0"]), "inferenceProfileId": None},
        {**inference_profile("y", []), "models": [{"modelArn": "arn:aws:bedrock:::other/z"}]},
        "not a dict",
    ]
    fake = FakeBedrock(summaries, [{"inferenceProfileSummaries": profiles}])
    assert _list(fake) == [
        ModelInfo("us.a.text-v1:0", True), ModelInfo("us.mixed", False),
        ModelInfo("us.c.vision-v1:0", True), ModelInfo("app-profile", False)]


def test_listing_follows_next_token():
    summaries = [foundation_model("a.text-v1:0", inference=("INFERENCE_PROFILE",))]
    pages = [
        {"inferenceProfileSummaries": [inference_profile("p1", ["a.text-v1:0"])],
         "nextToken": "tok-2"},
        {"inferenceProfileSummaries": [inference_profile("p2", ["a.text-v1:0"])],
         "nextToken": ""},
    ]
    fake = FakeBedrock(summaries, pages)
    assert [m.id for m in _list(fake)] == ["p1", "p2"]
    assert fake.profile_calls == [{"maxResults": 1000},
                                  {"maxResults": 1000, "nextToken": "tok-2"}]


def test_listing_pages_are_bounded():
    fake = FakeBedrock([], endless_pages=True)
    assert _list(fake) == []
    assert len(fake.profile_calls) == 5


def test_listing_raw_entries_are_bounded():
    fake = FakeBedrock(endless(lambda n: foundation_model(f"a.m{n}-v1:0")))
    assert len(_list(fake)) == MAX_RAW_MODELS


@pytest.mark.parametrize("error", [
    client_error(403, "AccessDeniedException", VISITOR_SECRET, "ListFoundationModels"),
    read_timeout(VISITOR_SECRET),
])
def test_listing_failure(caplog, error):
    caplog.set_level(logging.DEBUG)
    with pytest.raises(LLMError) as info:
        _list(FakeBedrock(error=error))
    assert type(info.value) is LLMError and str(info.value) == ERROR_LIST_FAILED
    assert_not_leaked(VISITOR_SECRET, exc=info.value, records=caplog.records)


def test_listing_builds_its_own_client(monkeypatch):
    built = {}

    def fake_client(cred, service, timeout, retries):
        built.update(service=service, timeout=timeout, retries=retries, cred=cred)
        return FakeBedrock([foundation_model("a.text-v1:0")])

    monkeypatch.setattr(bedrock_client, "_client", fake_client)
    assert bedrock_client.list_models(CRED, timeout_seconds=9) == [ModelInfo("a.text-v1:0", False)]
    assert built == {"service": "bedrock", "timeout": 9, "retries": 1, "cred": CRED}
