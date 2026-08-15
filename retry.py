"""Unified retry utility with exponential backoff."""

import logging
import time

from requests.exceptions import RequestException, Timeout

from config import INITIAL_RETRY_DELAY, MAX_RETRIES
from error_handler import handle_exception

logger = logging.getLogger(__name__)


def retry_with_backoff(
    func,
    max_retries: int = MAX_RETRIES,
    initial_delay: float = INITIAL_RETRY_DELAY,
    exceptions: tuple = (RequestException, Timeout),
    error_message: str = "API request failed",
):
    """Retry a function with exponential backoff.

    Args:
        func: Zero-argument callable to retry.
        max_retries: Maximum number of attempts.
        initial_delay: Seconds to wait before the first retry (doubles each time).
        exceptions: Tuple of exception types that trigger a retry.
        error_message: Message passed to handle_exception on final failure.

    Returns:
        The return value of *func* on success, or None if all retries fail.
    """
    delay = initial_delay

    for attempt in range(max_retries):
        try:
            return func()
        except exceptions as e:
            if attempt < max_retries - 1:
                logger.warning(
                    f"Attempt {attempt + 1} failed: {e}. Retrying in {delay}s..."
                )
                time.sleep(delay)
                delay *= 2
            else:
                handle_exception(e, f"{error_message} after {max_retries} attempts")
                return None
