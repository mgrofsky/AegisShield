"""OTX service unit tests.

Covers the offline short circuit: when ``offline`` is set (it comes from
``Settings.offline``), the OTX lookup returns at once WITHOUT
constructing an OTXv2 client or touching the network, and the mock model
switch (``Settings.mock_llm``) alone does NOT mute the feed.
"""

from __future__ import annotations

import pytest

from aegisshield.config import Settings
from aegisshield.pipeline import otx_service, workflow_service


def _fetch_otx_data(api_key, industry, days, max_results, max_retries, base_delay_seconds, *,  # noqa: ANN001, ANN202
                    offline=False):
    """``lookup_otx`` then ``otx_text``, as the threat-model run composes them."""
    lookup = otx_service.lookup_otx(api_key, industry, days, max_results, max_retries,
                                    base_delay_seconds, offline=offline)
    return otx_service.otx_text(lookup, industry)


def _fail_if_client_built(monkeypatch):
    """Make OTXv2(...) explode so any network path is a hard test failure."""

    def _boom(*_args, **_kwargs):
        raise AssertionError("OTXv2 client constructed in offline mode")

    monkeypatch.setattr(otx_service, "BoundedOTXv2", _boom)


def test_offline_lookup_short_circuits(monkeypatch) -> None:
    # The one switch is ``offline``, checked through ``lookup_otx`` directly;
    # there is no separate OTX flag for this path.
    _fail_if_client_built(monkeypatch)
    lookup = otx_service.lookup_otx(
        api_key="x",
        industry="Retail",
        days=2920,
        max_results=10,
        max_retries=3,
        base_delay_seconds=1.0,
        offline=True,
    )
    assert lookup.state == "off"
    assert "offline" in otx_service.otx_text(lookup, "Retail").lower()


def test_offline_short_circuits(monkeypatch) -> None:
    # The app-wide offline switch mutes the feed too.
    _fail_if_client_built(monkeypatch)
    out = _fetch_otx_data(
        api_key="x",
        industry="Retail",
        days=2920,
        max_results=10,
        max_retries=3,
        base_delay_seconds=1.0,
        offline=True,
    )
    assert "offline" in out.lower()


def test_mock_llm_does_not_mute_feed(monkeypatch) -> None:
    # The mock model stands in for the paid model, NOT for the keyed live feed.
    # With only that set, the OTX step must attempt to build the client.
    _fail_if_client_built(monkeypatch)
    with pytest.raises(AssertionError, match="OTXv2 client constructed"):
        _fetch_otx_data(
            api_key="x",
            industry="Retail",
            days=2920,
            max_results=10,
            max_retries=3,
            base_delay_seconds=1.0,
        )
    # and through the enrichment, which reads offline from Settings
    built: list[str] = []

    class _Client:
        def __init__(self, key: str) -> None:
            built.append(key)

        def search_pulses(self, _query: str, max_results: int = 0) -> dict:
            return {"results": []}

    monkeypatch.setattr(otx_service, "BoundedOTXv2", _Client)
    workflow_service.gather_enrichment(
        nvd_api_key=None,
        otx_api_key="test-otx-key",
        app_details={"app_type": "Web application", "industry_sector": "Retail"},
        app_description="An online retail checkout service.",
        settings=Settings(mock_llm=True),
    )
    assert built == ["test-otx-key"]
