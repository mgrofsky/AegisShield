"""Retry a call with exponential backoff and jitter."""

from __future__ import annotations

import random
import time
from collections.abc import Callable


def retry_call[T](
    func: Callable[[], T],
    max_retries: int,
    base_delay_seconds: float,
    retry_exceptions: tuple[type[Exception], ...],
    *,
    sleep: Callable[[float], None] = time.sleep,
    jitter: Callable[[], float] | None = None,
) -> T:
    """Call ``func`` up to ``max_retries`` times, sleeping between failures.

    Only exceptions in ``retry_exceptions`` are retried; anything else is
    raised at once. The wait before attempt ``n + 1`` is
    ``base_delay_seconds * 2 ** (n - 1)`` plus up to 0.3 seconds of jitter.
    The last exception is raised when every attempt fails. ``sleep`` and
    ``jitter`` are injectable so tests run without waiting.
    """
    if max_retries < 1:
        raise ValueError("max_retries must be at least 1")
    # Jitter spaces retries out; it is not used for anything secret.
    pick_jitter = jitter or (lambda: random.uniform(0.0, 0.3))  # noqa: S311
    attempt = 1
    while True:
        try:
            return func()
        except retry_exceptions:
            if attempt >= max_retries:
                raise
            sleep(base_delay_seconds * (2 ** (attempt - 1)) + pick_jitter())
            attempt += 1
