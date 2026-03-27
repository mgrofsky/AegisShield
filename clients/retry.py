"""
Unified retry logic with exponential backoff.

Replaces duplicated retry implementations across threat_model.py, nvd_search.py,
alientvault_search.py, and inline retry loops in step modules.
"""

import logging
import time
from collections.abc import Callable

from config import RETRY_CONFIG

logger = logging.getLogger(__name__)


class APIRetryError(Exception):
    """Raised when all retry attempts are exhausted."""


def retry_with_backoff[T](
    func: Callable[[], T],
    max_retries: int | None = None,
    initial_delay: float | None = None,
    backoff_multiplier: float | None = None,
    on_retry: Callable[[int, Exception], None] | None = None,
) -> T:
    """
    Execute a function with exponential backoff retry logic.

    Args:
        func: Zero-argument callable to execute.
        max_retries: Override for RETRY_CONFIG.max_retries.
        initial_delay: Override for RETRY_CONFIG.initial_delay.
        backoff_multiplier: Override for RETRY_CONFIG.backoff_multiplier.
        on_retry: Optional callback invoked on each retry with (attempt, exception).

    Returns:
        The return value of func.

    Raises:
        APIRetryError: If all retry attempts fail.
    """
    retries = max_retries if max_retries is not None else RETRY_CONFIG.max_retries
    delay = initial_delay if initial_delay is not None else RETRY_CONFIG.initial_delay
    multiplier = backoff_multiplier if backoff_multiplier is not None else RETRY_CONFIG.backoff_multiplier

    last_exception: Exception | None = None

    for attempt in range(retries):
        try:
            return func()
        except Exception as e:
            last_exception = e
            if attempt < retries - 1:
                logger.warning(
                    "Attempt %d/%d failed: %s. Retrying in %.1fs...",
                    attempt + 1, retries, e, delay,
                )
                if on_retry:
                    on_retry(attempt + 1, e)
                time.sleep(delay)
                delay *= multiplier
            else:
                logger.error("All %d attempts failed. Last error: %s", retries, e)

    raise APIRetryError(
        f"Failed after {retries} attempts. Last error: {last_exception}"
    ) from last_exception
