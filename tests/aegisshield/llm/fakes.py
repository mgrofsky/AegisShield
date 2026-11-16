"""A fake of the slice of the OpenAI SDK that ``OpenAIClient`` uses."""

from types import SimpleNamespace


def completion(content, finish_reason="stop"):
    message = SimpleNamespace(content=content)
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason=finish_reason)])


def chunk(content=None, finish_reason=None, empty=False):
    if empty:
        return SimpleNamespace(choices=[])
    delta = SimpleNamespace(content=content)
    return SimpleNamespace(choices=[SimpleNamespace(delta=delta, finish_reason=finish_reason)])


class FakeStream:
    def __init__(self, chunks, error=None):
        self._chunks = chunks
        self._error = error
        self.closed = False

    def __iter__(self):
        yield from self._chunks
        if self._error is not None:
            raise self._error

    def close(self):
        self.closed = True


class FakeSDK:
    """Records every ``chat.completions.create`` call and returns a canned reply."""

    def __init__(self, reply=None, error=None):
        self.calls = []
        self.reply = reply
        self.error = error
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.reply
