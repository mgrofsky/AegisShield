"""Every request the OTX client makes carries a timeout (no network: a fake
transport adapter answers)."""

from __future__ import annotations

import json

import pytest
from requests import Response
from requests.adapters import BaseAdapter, HTTPAdapter

from aegisshield.core.otx import OTX_TIMEOUT, BoundedOTXv2


class RecordingAdapter(BaseAdapter):
    def __init__(self) -> None:
        super().__init__()
        self.timeouts: list[object] = []

    def send(self, request, **kwargs):  # noqa: ANN001 - requests' adapter signature
        self.timeouts.append(kwargs.get("timeout"))
        response = Response()
        response.status_code = 200
        response._content = json.dumps({"results": [], "next": None}).encode()
        response.request = request
        response.url = request.url
        return response

    def close(self) -> None:
        pass


@pytest.fixture
def client() -> tuple[BoundedOTXv2, RecordingAdapter]:
    otx = BoundedOTXv2("not-a-real-key")
    session = otx.session()
    # The vendor's retry adapter is kept.
    kept = session.get_adapter("https://otx.alienvault.com/")
    assert isinstance(kept, HTTPAdapter) and kept.max_retries.total == 5
    adapter = RecordingAdapter()
    session.mount("https://", adapter)
    return otx, adapter


def test_get_post_patch_and_search_all_send_the_timeout(client) -> None:
    otx, adapter = client
    otx.get("/api/v1/pulses/subscribed")
    otx.post("/api/v1/pulses/create", body={"name": "x"})
    otx.patch("/api/v1/pulses/1", body={"name": "x"})
    otx.search_pulses("checkout", max_results=10)
    assert len(adapter.timeouts) == 4
    assert all(t == OTX_TIMEOUT for t in adapter.timeouts)


def test_an_explicit_timeout_is_kept_and_the_session_is_built_once(client) -> None:
    otx, adapter = client
    assert otx.session() is otx.session()
    otx.session().get("https://otx.alienvault.com/api/v1/x", timeout=3)
    assert adapter.timeouts == [3]
