"""The AlienVault OTX client with a timeout on every request.

``OTXv2`` (the vendor's package) sends its requests with no timeout, so a
connection that stalls would hold a job thread, and the job slot it counts
against, until the process restarts. ``BoundedOTXv2`` is the same client
whose ``requests`` session fills in ``OTX_TIMEOUT`` on any request that does
not set its own. Everything else, including the vendor's retry adapter, is
left as the package builds it.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

import requests
from OTXv2 import OTXv2

# (connect, read) seconds for each HTTP request. The read timeout bounds each
# wait for bytes, not a whole download. The vendor's adapter retries a failed
# GET up to five times with a 1, 2, 4, 8, 16 second backoff, so one request
# that keeps stalling gives up after about 6 x 20 + 31 = 151 seconds.
OTX_TIMEOUT: tuple[float, float] = (10.0, 20.0)


def _with_default_timeout(
    request: Callable[..., requests.Response], timeout: tuple[float, float]
) -> Callable[..., requests.Response]:
    @functools.wraps(request)
    def send(method: str, url: str, **kwargs: Any) -> requests.Response:
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = timeout
        return request(method, url, **kwargs)

    return send


class BoundedOTXv2(OTXv2):
    """``OTXv2`` whose every request (get, post, patch) has ``OTX_TIMEOUT``."""

    def session(self) -> requests.Session:
        """The client's session, built by ``OTXv2`` and given the default timeout once."""
        if self.request_session is None:
            session = super().session()
            session.request = _with_default_timeout(session.request, OTX_TIMEOUT)  # type: ignore[method-assign]
        return self.request_session
