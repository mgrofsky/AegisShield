import pytest

from aegisshield.core.retry import retry_call


class Flaky:
    def __init__(self, failures, exc=ConnectionError):
        self.failures = failures
        self.exc = exc
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.calls <= self.failures:
            raise self.exc("boom")
        return "ok"


def test_returns_first_success_without_sleeping():
    sleeps = []
    assert retry_call(Flaky(0), 3, 1.0, (ConnectionError,), sleep=sleeps.append) == "ok"
    assert sleeps == []


def test_exponential_backoff_with_jitter():
    sleeps = []
    fn = Flaky(2)
    result = retry_call(fn, 3, 1.0, (ConnectionError,), sleep=sleeps.append, jitter=lambda: 0.25)
    assert result == "ok"
    assert fn.calls == 3
    assert sleeps == [1.25, 2.25]


def test_raises_last_exception_after_all_attempts():
    sleeps = []
    fn = Flaky(5)
    with pytest.raises(ConnectionError):
        retry_call(fn, 3, 0.5, (ConnectionError,), sleep=sleeps.append, jitter=lambda: 0.0)
    assert fn.calls == 3
    assert sleeps == [0.5, 1.0]


def test_other_exceptions_not_retried():
    fn = Flaky(1, exc=KeyError)
    with pytest.raises(KeyError):
        retry_call(fn, 3, 0.0, (ConnectionError,), sleep=lambda _s: None)
    assert fn.calls == 1


def test_default_jitter_in_range():
    sleeps = []
    retry_call(Flaky(1), 2, 0.0, (ConnectionError,), sleep=sleeps.append)
    assert 0.0 <= sleeps[0] <= 0.3


def test_rejects_zero_retries():
    with pytest.raises(ValueError):
        retry_call(lambda: 1, 0, 0.0, (ConnectionError,))
