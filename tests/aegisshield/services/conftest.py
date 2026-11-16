"""Fixtures for the vulnerability lookup tests: no network, clean caches.

Neither fixture is autouse, so other service tests are unaffected. Lookup
test modules apply ``lookup_no_network`` with ``pytestmark``: each feed's HTTP call
and both NVD calls fail loudly unless a test replaces them, every source flag
is cleared, and every process-wide cache is reset before and after the test.
"""

from __future__ import annotations

import pytest
import requests

from aegisshield.services import (
    eol_service,
    epss_service,
    exploitdb_service,
    kev_service,
    vuln_lookup,
)
from aegisshield.services.lookup_switches import OFFLINE_FLAG, SOURCE_FLAGS


def _no_network(*_args, **_kwargs):
    raise AssertionError("a test tried to reach the network")


def _reset() -> None:
    kev_service.reset_cache_for_tests()
    exploitdb_service.reset_cache_for_tests()
    eol_service.reset_cache_for_tests()


@pytest.fixture
def lookup_no_network(monkeypatch):
    for flag in (*SOURCE_FLAGS.values(), OFFLINE_FLAG):
        monkeypatch.delenv(flag, raising=False)
    monkeypatch.setattr(requests, "get", _no_network)
    monkeypatch.setattr(epss_service, "_http_get", _no_network)
    monkeypatch.setattr(vuln_lookup, "_nvd_search_cpe", _no_network)
    monkeypatch.setattr(vuln_lookup, "_nvd_search_cve", _no_network)
    _reset()
    yield
    _reset()


@pytest.fixture
def quiet_feeds(monkeypatch):
    """Every secondary feed off, so a test exercises only the NVD path."""
    for name in ("KEV", "EPSS", "EXPLOITDB", "EOL"):
        monkeypatch.setenv(f"AEGIS_DISABLE_{name}", "1")
