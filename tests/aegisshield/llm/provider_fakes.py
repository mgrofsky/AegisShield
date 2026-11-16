"""Fakes of the Claude, Bedrock, Gemini, and OpenAI SDK slices the backends use.

Every response is built from the SDK's own types (or, for Bedrock, the dict
shapes in botocore's service model), so a test fails when an SDK changes the
shape a backend reads. Key-shaped strings are built from parts at run time so
a secret scanner does not flag this file.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

# Key-shaped test values. None of them is a real credential.
CLAUDE_KEY = "sk-ant-" + "api03-" + "x" * 24
GEMINI_KEY = "AIza" + "Sy" + "Q" * 33
OPENAI_KEY = "sk-" + "proj-" + "z" * 24
VISITOR_KEY_ID = "AKIA" + "TESTVISITOR0001"
VISITOR_SECRET = "visitor" + "Secret" + "S" * 28
VISITOR_TOKEN = "visitor" + "SessionToken" + "T" * 20
SERVER_KEY_ID = "AKIA" + "TESTSERVER00001"
SERVER_SECRET = "server" + "Secret" + "V" * 29
SERVER_TOKEN = "server" + "SessionToken" + "W" * 20
SERVER_BEARER = "ABSK" + "serverBearer" + "B" * 30
# Bedrock API keys in the two shapes AWS documents: long-term keys start
# with "ABSKQmVkcm9ja0FQSUtleS" and short-term keys with "bedrock-api-key-".
VISITOR_BEARER = "ABSK" + "QmVkcm9ja0FQSUtleS" + "visitorOne" + "A1+/" * 24 + "="
OTHER_BEARER = "bedrock-api-key-" + "visitorTwo" + "B2+/" * 40 + "=="


# --------------------------------------------------------------- leak checks


def exception_chain(exc: BaseException | None):
    """``exc`` and every exception Python would print with it."""
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        if exc.__cause__ is not None:
            exc = exc.__cause__
        elif not exc.__suppress_context__:
            exc = exc.__context__
        else:
            exc = None


def assert_not_leaked(secret: str, *, exc: BaseException | None = None, records=(),
                      client: object = None) -> None:
    """``secret`` is in no log record, no exception in the chain, and no repr."""
    for record in records:
        assert secret not in record.getMessage()
        assert secret not in str(record.args)
        if record.exc_info:
            assert secret not in logging.Formatter().formatException(record.exc_info)
    for item in exception_chain(exc):
        assert secret not in str(item)
        assert secret not in repr(item)
        assert secret not in repr(item.args)
    if exc is not None:
        assert exc.__cause__ is None
        assert exc.__suppress_context__ or exc.__context__ is None
    if client is not None:
        assert secret not in repr(client)
        assert secret not in str(client)


# ------------------------------------------------------------------- Claude


def claude_events(texts=("Hello", " world"), stop_reason="end_turn", *, thinking=None,
                  message_delta=True, message_stop=True):
    """A Messages API event stream of the SDK's own event types."""
    from anthropic.types import (
        Message,
        MessageDeltaUsage,
        RawContentBlockDeltaEvent,
        RawContentBlockStartEvent,
        RawContentBlockStopEvent,
        RawMessageDeltaEvent,
        RawMessageStartEvent,
        RawMessageStopEvent,
        TextBlock,
        TextDelta,
        ThinkingBlock,
        ThinkingDelta,
        Usage,
    )
    from anthropic.types.raw_message_delta_event import Delta

    message = Message(id="msg_test", type="message", role="assistant", model="test-model",
                      content=[], stop_reason=None, stop_sequence=None,
                      usage=Usage(input_tokens=3, output_tokens=0))
    events = [RawMessageStartEvent(type="message_start", message=message)]
    index = 0
    if thinking is not None:
        events += [
            RawContentBlockStartEvent(type="content_block_start", index=index,
                                      content_block=ThinkingBlock(type="thinking", thinking="",
                                                                  signature="sig")),
            RawContentBlockDeltaEvent(type="content_block_delta", index=index,
                                      delta=ThinkingDelta(type="thinking_delta",
                                                          thinking=thinking)),
            RawContentBlockStopEvent(type="content_block_stop", index=index),
        ]
        index += 1
    events.append(RawContentBlockStartEvent(type="content_block_start", index=index,
                                            content_block=TextBlock(type="text", text="")))
    for piece in texts:
        events.append(RawContentBlockDeltaEvent(type="content_block_delta", index=index,
                                                delta=TextDelta(type="text_delta", text=piece)))
    events.append(RawContentBlockStopEvent(type="content_block_stop", index=index))
    if message_delta:
        events.append(RawMessageDeltaEvent(type="message_delta",
                                           delta=Delta(stop_reason=stop_reason,
                                                       stop_sequence=None),
                                           usage=MessageDeltaUsage(output_tokens=5)))
    if message_stop:
        events.append(RawMessageStopEvent(type="message_stop"))
    return events


class FakeRawStream:
    """What ``MessageStream`` wraps: an iterable of events with ``close``."""

    def __init__(self, events, error=None):
        self._events = events
        self._error = error
        self.closed = False

    def __iter__(self):
        yield from self._events
        if self._error is not None:
            raise self._error

    def close(self):
        self.closed = True


class FakeAnthropic:
    """``messages.stream`` returning a real ``MessageStream``, and ``models.list``."""

    def __init__(self, events=None, *, error=None, stream_error=None, models=None,
                 list_error=None):
        self.calls = []
        self.raw = None
        self._events = claude_events() if events is None else events
        self._error = error
        self._stream_error = stream_error
        self._models = models or []
        self._list_error = list_error
        self.messages = SimpleNamespace(stream=self._stream)
        self.models = SimpleNamespace(list=self._list)

    def _stream(self, **kwargs):
        import anthropic
        from anthropic.lib.streaming import MessageStream

        self.calls.append(kwargs)
        if self._error is not None:
            raise self._error
        self.raw = FakeRawStream(self._events, self._stream_error)
        return MessageStream(self.raw, anthropic.NOT_GIVEN)

    def _list(self):
        if self._list_error is not None:
            raise self._list_error
        return iter(self._models)


def anthropic_status_error(status: int, secret: str):
    import anthropic
    import httpx2

    request = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    response = httpx2.Response(status, request=request,
                               json={"error": {"message": f"bad key {secret}"}})
    classes = {400: anthropic.BadRequestError, 401: anthropic.AuthenticationError,
               403: anthropic.PermissionDeniedError, 429: anthropic.RateLimitError}
    return classes[status](f"Error code: {status} - key {secret}", response=response,
                           body={"error": {"message": f"key {secret}"}})


def anthropic_timeout():
    import anthropic
    import httpx2

    return anthropic.APITimeoutError(
        request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages"))


def claude_model(model_id, image=None, *, lifecycle=None, capabilities=True):
    """A real ``anthropic.types.ModelInfo``."""
    from anthropic.types import ModelCapabilities, ModelInfo

    caps = None
    if capabilities:
        caps = ModelCapabilities.model_construct(
            image_input=SimpleNamespace(supported=image) if image is not None else None)
    fields = {"id": model_id, "type": "model", "display_name": model_id,
              "created_at": "2026-01-01T00:00:00Z", "capabilities": caps}
    if lifecycle is not None:
        fields["lifecycle"] = lifecycle
    return ModelInfo.model_construct(**fields)


# ------------------------------------------------------------------ Bedrock


def converse_response(text="Hello world", stop="end_turn"):
    content = [{"text": text}] if text is not None else []
    return {
        "output": {"message": {"role": "assistant", "content": content}},
        "stopReason": stop,
        "usage": {"inputTokens": 3, "outputTokens": 5, "totalTokens": 8},
        "metrics": {"latencyMs": 10},
    }


def converse_events(texts=("Hello", " world"), stop="end_turn", *, message_stop=True):
    events = [{"messageStart": {"role": "assistant"}}]
    events += [{"contentBlockDelta": {"delta": {"text": t}, "contentBlockIndex": 0}}
               for t in texts]
    events.append({"contentBlockStop": {"contentBlockIndex": 0}})
    if message_stop:
        events.append({"messageStop": {"stopReason": stop}})
        events.append({"metadata": {"usage": {"inputTokens": 3, "outputTokens": 5,
                                              "totalTokens": 8},
                                    "metrics": {"latencyMs": 10}}})
    return events


class FakeEventStream(FakeRawStream):
    """botocore's ``EventStream``: iterable, with ``close``."""


class FakeBedrockRuntime:
    def __init__(self, reply=None, *, events=None, error=None, stream_error=None,
                 stream_missing=False):
        self.calls = []
        self.stream = None
        self._reply = converse_response() if reply is None else reply
        self._events = converse_events() if events is None else events
        self._error = error
        self._stream_error = stream_error
        self._stream_missing = stream_missing

    def converse(self, **kwargs):
        self.calls.append(("converse", kwargs))
        if self._error is not None:
            raise self._error
        return self._reply

    def converse_stream(self, **kwargs):
        self.calls.append(("converse_stream", kwargs))
        if self._error is not None:
            raise self._error
        if self._stream_missing:
            return {"ResponseMetadata": {}}
        self.stream = FakeEventStream(self._events, self._stream_error)
        return {"stream": self.stream}


def client_error(status: int, code: str, secret: str, operation="Converse"):
    from botocore.exceptions import ClientError

    return ClientError(
        error_response={"Error": {"Code": code, "Message": f"credential {secret} refused"},
                        "ResponseMetadata": {"HTTPStatusCode": status}},
        operation_name=operation)


def event_stream_error(secret: str):
    from botocore.exceptions import EventStreamError

    return EventStreamError(
        {"Error": {"Code": "ModelStreamErrorException", "Message": f"stream {secret}"}},
        "ConverseStream")


def read_timeout(secret: str):
    from botocore.exceptions import ReadTimeoutError

    return ReadTimeoutError(endpoint_url=f"https://bedrock-runtime.us-east-1.amazonaws.com/{secret}")


def foundation_model(model_id, *, inputs=("TEXT",), outputs=("TEXT",), streaming=True,
                     status="ACTIVE", inference=("ON_DEMAND",)):
    return {
        "modelArn": f"arn:aws:bedrock:us-east-1::foundation-model/{model_id}",
        "modelId": model_id,
        "modelName": model_id,
        "providerName": "Test",
        "inputModalities": list(inputs),
        "outputModalities": list(outputs),
        "responseStreamingSupported": streaming,
        "customizationsSupported": [],
        "inferenceTypesSupported": list(inference),
        "modelLifecycle": {"status": status},
    }


def inference_profile(profile_id, routed, *, status="ACTIVE", kind="SYSTEM_DEFINED"):
    return {
        "inferenceProfileName": profile_id,
        "inferenceProfileArn": f"arn:aws:bedrock:us-east-1:123456789012:inference-profile/{profile_id}",
        "inferenceProfileId": profile_id,
        "status": status,
        "type": kind,
        "models": [{"modelArn": f"arn:aws:bedrock:us-west-2::foundation-model/{m}"}
                   for m in routed],
    }


class FakeBedrock:
    """The ``bedrock`` control-plane slice: foundation models and profiles."""

    def __init__(self, summaries=(), pages=None, *, error=None, endless_pages=False):
        self.summaries = summaries
        self.pages = pages if pages is not None else [{"inferenceProfileSummaries": []}]
        self.error = error
        self.endless_pages = endless_pages
        self.foundation_calls = []
        self.profile_calls = []

    def list_foundation_models(self, **kwargs):
        self.foundation_calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return {"modelSummaries": self.summaries}

    def list_inference_profiles(self, **kwargs):
        self.profile_calls.append(kwargs)
        if self.endless_pages:
            return {"inferenceProfileSummaries": [], "nextToken": f"t{len(self.profile_calls)}"}
        return self.pages[len(self.profile_calls) - 1]


# ------------------------------------------------------------------- Gemini


def gemini_response(texts=("Hello world",), finish="STOP", *, thought=None, block=None,
                    candidates=True):
    from google.genai import types

    feedback = None
    if block is not None:
        feedback = types.GenerateContentResponsePromptFeedback(block_reason=block)
    if not candidates:
        return types.GenerateContentResponse(candidates=[], prompt_feedback=feedback)
    parts = []
    if thought is not None:
        parts.append(types.Part(text=thought, thought=True))
    parts += [types.Part(text=t) for t in texts]
    candidate = types.Candidate(
        content=types.Content(role="model", parts=parts),
        finish_reason=types.FinishReason(finish) if finish else None,
        index=0)
    return types.GenerateContentResponse(candidates=[candidate], prompt_feedback=feedback)


class FakeGenai:
    def __init__(self, reply=None, *, chunks=None, error=None, stream_error=None, models=None,
                 list_error=None):
        self.calls = []
        self._reply = gemini_response() if reply is None else reply
        self._chunks = chunks
        self._error = error
        self._stream_error = stream_error
        self._models = models or []
        self._list_error = list_error
        self.models = SimpleNamespace(generate_content=self._generate,
                                      generate_content_stream=self._stream,
                                      list=self._list)

    def _generate(self, **kwargs):
        self.calls.append(("generate_content", kwargs))
        if self._error is not None:
            raise self._error
        return self._reply

    def _stream(self, **kwargs):
        self.calls.append(("generate_content_stream", kwargs))
        if self._error is not None:
            raise self._error
        return self._iterate()

    def _iterate(self):
        yield from (self._chunks if self._chunks is not None else [self._reply])
        if self._stream_error is not None:
            raise self._stream_error

    def _list(self):
        if self._list_error is not None:
            raise self._list_error
        return iter(self._models)


def genai_client_error(status: int, secret: str, status_name="RESOURCE_EXHAUSTED"):
    from google.genai import errors

    body = {"error": {"code": status, "message": f"API key {secret} rejected",
                      "status": status_name}}
    return errors.ClientError(status, body)


def gemini_model(name, actions=("generateContent", "countTokens")):
    from google.genai import types

    return types.Model(name=name, supported_actions=list(actions))


# ------------------------------------------------------------------- OpenAI


class FakeOpenAIModels:
    def __init__(self, ids=(), *, error=None):
        self._ids = ids
        self._error = error
        self.models = SimpleNamespace(list=self._list)

    def _list(self):
        if self._error is not None:
            raise self._error
        import openai

        return iter(openai.types.Model(id=i, created=0, object="model", owned_by="test")
                    for i in self._ids)


def endless(make):
    """A listing that never ends."""
    count = 0
    while True:
        count += 1
        yield make(count)


# --------------------------------------------------- answering fakes, all four
#
# One fake per provider whose every request is answered by ``answer(system,
# user)``, read back out of that provider's request shape, and returned in
# its real response shape: streamed in chunks of ``sizes`` (cycled; 0 means
# the whole answer in one chunk) when the backend streams. ``emitted`` counts
# the characters handed to the backend so far, so a test can see how far
# the live view is behind the model. ``error`` is raised on every call.


def canned_answer(system: str, user: object) -> str:
    """What ``MockLLM`` answers for this request, as the model's text: a JSON
    request (the app's JSON suffix ends its system text) gets the canned
    object as JSON; an image request gets the canned description."""
    import json

    from aegisshield.llm.base import JSON_SYSTEM_SUFFIX
    from aegisshield.llm.mock import MOCK_IMAGE_DESCRIPTION, MockLLM

    if not isinstance(user, str):
        return MOCK_IMAGE_DESCRIPTION
    mock = MockLLM()
    if system.endswith(JSON_SYSTEM_SUFFIX):
        base = system[: -len(JSON_SYSTEM_SUFFIX)].strip()
        return json.dumps(mock.chat_json(system=base, user=user, model="canned"), indent=2)
    return mock.chat_text(system=system, user=user, model="canned")


def chunked(text: str, sizes=(40,)) -> list[str]:
    """``text`` cut in pieces whose lengths cycle through ``sizes``."""
    pieces: list[str] = []
    start = 0
    index = 0
    while start < len(text):
        size = sizes[index % len(sizes)] or len(text)
        pieces.append(text[start:start + size])
        start += size
        index += 1
    return pieces


class _Answering:
    """What the four answering fakes share."""

    def __init__(self, answer=canned_answer, *, sizes=(40,), error=None):
        self.answer = answer
        self.sizes = sizes
        self.error = error
        self.calls: list[dict] = []
        self.asked: list[tuple[str, object]] = []
        self.emitted = 0

    def _reply(self, system: str, user: object, kwargs: dict) -> str:
        self.calls.append(kwargs)
        self.asked.append((system, user))
        if self.error is not None:
            raise self.error
        return self.answer(system, user)

    def _count(self, piece: str) -> None:
        self.emitted += len(piece)


class AnsweringAnthropic(_Answering):
    """``messages.stream`` returning a real ``MessageStream`` over raw events."""

    def __init__(self, answer=canned_answer, **kwargs):
        super().__init__(answer, **kwargs)
        self.messages = SimpleNamespace(stream=self._stream)

    def _stream(self, **kwargs):
        import anthropic
        from anthropic.lib.streaming import MessageStream

        content = kwargs["messages"][0]["content"]
        user = content if isinstance(content, str) else [
            b for b in content if b.get("type") == "text"]
        text = self._reply(kwargs.get("system", ""), user, kwargs)
        return MessageStream(_CountingRaw(self, claude_events(chunked(text, self.sizes)),
                                          _claude_piece), anthropic.NOT_GIVEN)


def _claude_piece(event) -> str:
    if getattr(event, "type", None) != "content_block_delta":
        return ""
    return getattr(event.delta, "text", None) or ""


class _CountingRaw(FakeRawStream):
    """An event stream that counts the text it hands over as it goes."""

    def __init__(self, owner, events, piece_of):
        super().__init__(events)
        self._owner = owner
        self._piece_of = piece_of

    def __iter__(self):
        for event in self._events:
            self._owner._count(self._piece_of(event))
            yield event


class AnsweringOpenAI(_Answering):
    """``chat.completions.create`` returning real ``ChatCompletion`` objects,
    or a stream of real ``ChatCompletionChunk`` objects when asked to stream."""

    def __init__(self, answer=canned_answer, **kwargs):
        super().__init__(answer, **kwargs)
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        from openai.types.chat import ChatCompletion, ChatCompletionChunk, ChatCompletionMessage
        from openai.types.chat import chat_completion as cc
        from openai.types.chat import chat_completion_chunk as ccc

        messages = kwargs["messages"]
        system = next((m["content"] for m in messages if m["role"] == "system"), "")
        user = next(m["content"] for m in messages if m["role"] == "user")
        if not isinstance(user, str):
            user = [b for b in user if b.get("type") == "text"]
        text = self._reply(system, user, kwargs)
        if not kwargs.get("stream"):
            return ChatCompletion(
                id="chatcmpl-test", object="chat.completion", created=0, model=kwargs["model"],
                choices=[cc.Choice(index=0, finish_reason="stop", message=ChatCompletionMessage(
                    role="assistant", content=text))])

        def chunk(content, finish):
            return ChatCompletionChunk(
                id="chatcmpl-test", object="chat.completion.chunk", created=0,
                model=kwargs["model"], choices=[ccc.Choice(
                    index=0, delta=ccc.ChoiceDelta(content=content), finish_reason=finish)])

        chunks = [chunk(p, None) for p in chunked(text, self.sizes)] + [chunk(None, "stop")]
        return _CountingRaw(self, chunks, lambda c: c.choices[0].delta.content or "")


class AnsweringBedrock(_Answering):
    """``converse`` and ``converse_stream`` with botocore's dict shapes."""

    def converse(self, **kwargs):
        system, user = self._read(kwargs)
        return converse_response(self._reply(system, user, kwargs))

    def converse_stream(self, **kwargs):
        system, user = self._read(kwargs)
        text = self._reply(system, user, kwargs)
        events = converse_events(chunked(text, self.sizes))
        return {"stream": _CountingRaw(self, events, _bedrock_piece)}

    @staticmethod
    def _read(kwargs):
        system = "".join(b["text"] for b in kwargs.get("system") or [])
        content = kwargs["messages"][0]["content"]
        if any("image" in b for b in content):
            return system, [b for b in content if "text" in b]
        return system, "".join(b["text"] for b in content)


def _bedrock_piece(event) -> str:
    return ((event.get("contentBlockDelta") or {}).get("delta") or {}).get("text") or ""


class AnsweringGenai(_Answering):
    """``models.generate_content`` and ``generate_content_stream`` returning
    real ``GenerateContentResponse`` objects; a stream's last chunk alone
    carries the finish reason, as the API sends it."""

    def __init__(self, answer=canned_answer, **kwargs):
        super().__init__(answer, **kwargs)
        self.models = SimpleNamespace(generate_content=self._generate,
                                      generate_content_stream=self._stream)

    def _read(self, kwargs):
        config = kwargs.get("config")
        system = getattr(config, "system_instruction", None) or ""
        contents = kwargs["contents"]
        return system, contents if isinstance(contents, str) else [
            c for c in contents if isinstance(c, str)]

    def _generate(self, **kwargs):
        system, user = self._read(kwargs)
        return gemini_response((self._reply(system, user, kwargs),))

    def _stream(self, **kwargs):
        system, user = self._read(kwargs)
        pieces = chunked(self._reply(system, user, kwargs), self.sizes) or [""]
        chunks = [gemini_response((p,), finish=None) for p in pieces[:-1]]
        chunks.append(gemini_response((pieces[-1],)))
        return iter(_CountingRaw(self, chunks, lambda r: r.candidates[0].content.parts[0].text))


ANSWERING = {
    "openai": AnsweringOpenAI,
    "claude": AnsweringAnthropic,
    "bedrock": AnsweringBedrock,
    "gemini": AnsweringGenai,
}


def answering_client(provider: str, fake):
    """The provider's real client class built on ``fake``."""
    if provider == "claude":
        from aegisshield.llm.anthropic_client import AnthropicClient

        return AnthropicClient("unused", sdk_client=fake)
    if provider == "bedrock":
        from aegisshield.llm.bedrock_client import BedrockClient

        return BedrockClient(None, sdk_client=fake)
    if provider == "gemini":
        from aegisshield.llm.gemini_client import GeminiClient

        return GeminiClient("unused", sdk_client=fake)
    from aegisshield.llm.openai_client import OpenAIClient

    return OpenAIClient("unused", sdk_client=fake)


def rate_limit_error(provider: str, secret: str = "s3cret-in-provider-text"):
    """The provider's own rate-limit error, as its SDK raises it."""
    if provider == "claude":
        return anthropic_status_error(429, secret)
    if provider == "bedrock":
        return client_error(429, "ThrottlingException", secret)
    if provider == "gemini":
        return genai_client_error(429, secret)
    import httpx2
    import openai

    request = httpx2.Request("POST", "https://api.openai.com/v1/chat/completions")
    return openai.RateLimitError(f"rate limited {secret}", response=httpx2.Response(
        429, request=request), body=None)
