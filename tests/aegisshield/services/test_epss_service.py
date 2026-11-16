"""FIRST EPSS adapter: batched parse, single score, switches, failures."""

from __future__ import annotations

import pytest
from requests.exceptions import Timeout

from aegisshield.config import Settings
from aegisshield.core.errors import IntelLookupError
from aegisshield.services import epss_service
from aegisshield.services.epss_service import EpssConfig

pytestmark = pytest.mark.usefixtures("lookup_no_network")

_FAST = EpssConfig(max_retries=2, base_delay_seconds=0.0, timeout_seconds=1.0)


def _answer(*rows):
    return lambda params, timeout: {"data": list(rows)}


def test_batched_success_parse(monkeypatch) -> None:
    def fake_get(params, timeout):
        assert params["cve"] == "CVE-2024-0001,CVE-2024-0002"
        return {
            "data": [
                {"cve": "CVE-2024-0001", "epss": "0.94312", "percentile": "0.99", "date": "2024-06-01"},
                {"cve": "CVE-2024-0002", "epss": "0.01000", "percentile": "0.40", "date": "2024-06-01"},
                {"cve": "", "epss": "0.5"},
                "junk",
            ]
        }

    monkeypatch.setattr(epss_service, "_http_get", fake_get)
    scores = epss_service.fetch_scores(["CVE-2024-0002", "cve-2024-0001", " "], _FAST)
    assert set(scores) == {"CVE-2024-0001", "CVE-2024-0002"}
    assert scores["CVE-2024-0001"].epss == pytest.approx(0.94312)
    assert scores["CVE-2024-0001"].percentile == pytest.approx(0.99)
    assert scores["CVE-2024-0002"].to_dict()["epss"] == pytest.approx(0.01)


def test_unreadable_numbers_read_as_zero(monkeypatch) -> None:
    monkeypatch.setattr(epss_service, "_http_get", _answer({"cve": "CVE-2024-0001", "epss": "n/a"}))
    assert epss_service.fetch_scores(["CVE-2024-0001"], _FAST)["CVE-2024-0001"].epss == 0.0


def test_fetch_single_score(monkeypatch) -> None:
    monkeypatch.setattr(
        epss_service,
        "_http_get",
        _answer({"cve": "CVE-2024-0001", "epss": "0.5", "percentile": "0.8", "date": "2024-06-01"}),
    )
    score = epss_service.fetch_score("cve-2024-0001", _FAST)
    assert score is not None and score.cve_id == "CVE-2024-0001"


def test_empty_data_returns_empty(monkeypatch) -> None:
    monkeypatch.setattr(epss_service, "_http_get", _answer())
    assert epss_service.fetch_scores(["CVE-2024-9999"], _FAST) == {}
    monkeypatch.setattr(epss_service, "_http_get", lambda params, timeout: ["not", "a", "dict"])
    assert epss_service.fetch_scores(["CVE-2024-9999"], _FAST) == {}


def test_empty_input_returns_empty() -> None:
    assert epss_service.fetch_scores([]) == {}
    assert epss_service.fetch_score("") is None


@pytest.mark.parametrize("flag", ["AEGIS_DISABLE_EPSS", "AEGIS_OFFLINE"])
def test_switched_off_short_circuits(monkeypatch, flag) -> None:
    monkeypatch.setenv(flag, "1")
    assert epss_service.fetch_scores(["CVE-2024-0001"]) == {}


def test_settings_offline_short_circuits() -> None:
    assert epss_service.fetch_scores(["CVE-2024-0001"], settings=Settings(offline=True)) == {}


def test_mock_llm_does_not_mute_the_feed(monkeypatch) -> None:
    monkeypatch.setattr(
        epss_service, "_http_get", _answer({"cve": "CVE-2024-0001", "epss": "0.7", "percentile": "0.9"})
    )
    scores = epss_service.fetch_scores(["CVE-2024-0001"], _FAST, settings=Settings(mock_llm=True))
    assert scores["CVE-2024-0001"].epss == pytest.approx(0.7)


def test_get_epss_probability(monkeypatch) -> None:
    monkeypatch.setattr(
        epss_service, "_http_get", _answer({"cve": "CVE-2024-0001", "epss": "0.42", "percentile": "0.8"})
    )
    assert epss_service.get_epss_probability("cve-2024-0001", _FAST) == pytest.approx(0.42)


def test_get_epss_probability_unscored(monkeypatch) -> None:
    monkeypatch.setattr(epss_service, "_http_get", _answer())
    assert epss_service.get_epss_probability("CVE-2024-9999", _FAST) is None
    assert epss_service.get_epss_probability("") is None


def test_timeout_raises(monkeypatch) -> None:
    def _boom(params, timeout):
        raise Timeout("slow")

    monkeypatch.setattr(epss_service, "_http_get", _boom)
    with pytest.raises(IntelLookupError):
        epss_service.fetch_scores(["CVE-2024-0001"], _FAST)


def test_default_http_get_calls_the_api(monkeypatch) -> None:
    seen = {}

    class _Resp:
        def raise_for_status(self) -> None:
            return None

        def json(self):
            return {"data": []}

    def fake_get(url, params=None, timeout=None):
        seen.update(url=url, params=params, timeout=timeout)
        return _Resp()

    monkeypatch.setattr(epss_service.requests, "get", fake_get)
    assert epss_service._default_http_get({"cve": "CVE-1"}, 3.0) == {"data": []}
    assert seen == {"url": epss_service.EPSS_API_URL, "params": {"cve": "CVE-1"}, "timeout": 3.0}
