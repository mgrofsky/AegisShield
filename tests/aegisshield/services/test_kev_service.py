"""CISA KEV adapter: cached lookup, switches, download and parse, failures."""

from __future__ import annotations

import pytest
from requests.exceptions import Timeout

from aegisshield.config import Settings
from aegisshield.core.errors import IntelLookupError
from aegisshield.services import kev_service
from aegisshield.services.kev_service import KevConfig, KevRecord

pytestmark = pytest.mark.usefixtures("lookup_no_network")

_FAST = KevConfig(max_retries=2, base_delay_seconds=0.0, timeout_seconds=1.0)


def _record(cve_id: str) -> KevRecord:
    return KevRecord(
        cve_id=cve_id,
        vendor_project="Acme",
        product="Checkout",
        vulnerability_name="RCE",
        date_added="2024-01-01",
        short_description="Remote code execution",
        required_action="Patch",
        due_date="2024-01-15",
        known_ransomware_campaign_use="Known",
    )


class _Resp:
    status_code = 200

    def __init__(self, payload) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self):
        return self._payload


def _respond_with(monkeypatch, payload) -> None:
    monkeypatch.setattr(kev_service.requests, "get", lambda *a, **k: _Resp(payload))


def test_seeded_lookup_is_case_insensitive() -> None:
    kev_service.seed_cache_for_tests({"CVE-2024-1234": _record("CVE-2024-1234")})
    assert kev_service.is_known_exploited("cve-2024-1234") is True
    record = kev_service.lookup("CVE-2024-1234")
    assert record is not None and record.product == "Checkout"
    assert kev_service.is_known_exploited("CVE-2000-0000") is False
    assert kev_service.lookup("") is None


def test_disable_flag_short_circuits(monkeypatch) -> None:
    kev_service.seed_cache_for_tests({"CVE-2024-1234": _record("CVE-2024-1234")})
    monkeypatch.setenv("AEGIS_DISABLE_KEV", "1")
    assert kev_service.is_known_exploited("CVE-2024-1234") is False
    assert kev_service.lookup("CVE-2024-1234") is None
    assert kev_service.catalog_snapshot(_FAST) is None


def test_mock_llm_does_not_mute_the_feed() -> None:
    # KEV is free and keyless: mock mode stands in for the paid model only.
    kev_service.seed_cache_for_tests({"CVE-2024-1234": _record("CVE-2024-1234")})
    settings = Settings(mock_llm=True)
    assert kev_service.is_known_exploited("CVE-2024-1234", settings=settings) is True


def test_aegis_offline_short_circuits(monkeypatch) -> None:
    kev_service.seed_cache_for_tests({"CVE-2024-1234": _record("CVE-2024-1234")})
    monkeypatch.setenv("AEGIS_OFFLINE", "1")
    assert kev_service.is_known_exploited("CVE-2024-1234") is False
    assert kev_service.lookup("CVE-2024-1234") is None
    assert kev_service.refresh_catalog(_FAST) == 0


def test_settings_offline_short_circuits() -> None:
    kev_service.seed_cache_for_tests({"CVE-2024-1234": _record("CVE-2024-1234")})
    offline = Settings(offline=True)
    assert kev_service.lookup("CVE-2024-1234", settings=offline) is None
    assert kev_service.catalog_snapshot(_FAST, settings=offline) is None
    assert kev_service.refresh_catalog(_FAST, settings=offline) == 0


def test_successful_fetch_parses_catalog(monkeypatch) -> None:
    _respond_with(
        monkeypatch,
        {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "vendorProject": "VendorA",
                    "product": "ProductA",
                    "vulnerabilityName": "Auth bypass",
                    "dateAdded": "2024-02-01",
                    "shortDescription": "desc",
                    "requiredAction": "patch",
                    "dueDate": "2024-02-15",
                    "knownRansomwareCampaignUse": "Unknown",
                }
            ]
        },
    )
    assert kev_service.refresh_catalog(_FAST) == 1
    assert kev_service.is_known_exploited("CVE-2024-0001") is True
    assert kev_service.lookup("CVE-2024-0001").to_dict()["vendor_project"] == "VendorA"


# A 200 with an empty or malformed catalog is a failed download, never
# "nothing is known exploited".
_BAD_CATALOGS = [
    {"vulnerabilities": []},
    {"title": "CISA Catalog"},
    {"vulnerabilities": None},
    {"vulnerabilities": "nope"},
    {"vulnerabilities": [{"cveID": ""}, "x"]},
    [],
]


@pytest.mark.parametrize("payload", _BAD_CATALOGS)
def test_an_empty_or_malformed_catalog_is_a_failed_download(monkeypatch, payload) -> None:
    _respond_with(monkeypatch, payload)
    with pytest.raises(IntelLookupError):
        kev_service.refresh_catalog(_FAST)
    assert kev_service.catalog_snapshot(_FAST) is None


@pytest.mark.parametrize("payload", _BAD_CATALOGS)
def test_an_empty_catalog_keeps_a_young_cache(monkeypatch, payload) -> None:
    kev_service.seed_cache_for_tests({"CVE-2024-1234": _record("CVE-2024-1234")})
    monkeypatch.setattr(
        kev_service, "_cache_built_at", kev_service.time.time() - kev_service.CACHE_TTL_SECONDS - 1
    )
    _respond_with(monkeypatch, payload)
    snapshot = kev_service.catalog_snapshot(_FAST)
    assert snapshot is not None and "CVE-2024-1234" in snapshot


def test_timeout_raises_on_refresh_without_the_error_text(monkeypatch) -> None:
    def _boom(*a, **k):
        raise Timeout("slow https://example.invalid/?token=abc")

    monkeypatch.setattr(kev_service.requests, "get", _boom)
    with pytest.raises(IntelLookupError) as caught:
        kev_service.refresh_catalog(_FAST)
    assert "token" not in str(caught.value)


def test_lookup_tolerates_fetch_failure(monkeypatch) -> None:
    def _boom(*a, **k):
        raise Timeout("slow")

    monkeypatch.setattr(kev_service.requests, "get", _boom)
    assert kev_service.lookup("CVE-2024-0001", _FAST) is None
