"""FIRST EPSS (Exploit Prediction Scoring System) adapter.

FIRST publishes a free, keyless API that returns, per CVE, the probability
(0 to 1) that it will be exploited in the next 30 days and that score's
percentile across all scored CVEs. A lookup uses it to rank CVEs: a high
score means "likely to be used soon" even before a CVE reaches CISA KEV.

The API takes many CVEs per request (``?cve=CVE-1,CVE-2``), so a lookup asks
once per job. Switched off by ``Settings.offline`` or ``AEGIS_DISABLE_EPSS`` /
``AEGIS_OFFLINE``; mock LLM mode does not switch it off.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests
from requests.exceptions import RequestException

from aegisshield.config import Settings
from aegisshield.core.errors import IntelLookupError
from aegisshield.core.retry import retry_call
from aegisshield.services.lookup_switches import source_disabled

EPSS_API_URL = "https://api.first.org/data/v1/epss"


@dataclass(frozen=True)
class EpssConfig:
    """Retry and timeout settings for one EPSS request."""

    max_retries: int = 3
    base_delay_seconds: float = 1.0
    timeout_seconds: float = 15.0


@dataclass(frozen=True)
class EpssScore:
    """An EPSS scoring row for one CVE."""

    cve_id: str
    epss: float  # probability of exploitation in the next 30 days (0 to 1)
    percentile: float  # rank of this score among all scored CVEs (0 to 1)
    date: str

    def to_dict(self) -> dict:
        """The score as a JSON-ready dict."""
        return {
            "cve_id": self.cve_id,
            "epss": self.epss,
            "percentile": self.percentile,
            "date": self.date,
        }


def _default_http_get(params: dict, timeout: float) -> dict:
    response = requests.get(EPSS_API_URL, params=params, timeout=timeout)
    response.raise_for_status()
    return response.json()


# The one call that reaches FIRST. Tests replace it.
_http_get = _default_http_get


def _to_float(value: object) -> float:
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return 0.0


def fetch_scores(
    cve_ids: list[str], config: EpssConfig | None = None, *, settings: Settings | None = None
) -> dict[str, EpssScore]:
    """A CVE id to ``EpssScore`` map for the given CVEs, in one request.

    Unscored CVEs are absent from the result. Switched off and empty input
    both return ``{}``. A failed request raises ``IntelLookupError``.
    """
    cleaned = sorted({c.strip().upper() for c in cve_ids if c and c.strip()})
    if not cleaned or source_disabled("epss", settings):
        return {}

    cfg = config or EpssConfig()
    params = {"cve": ",".join(cleaned)}
    try:
        payload = retry_call(
            lambda: _http_get(params, cfg.timeout_seconds),
            max_retries=cfg.max_retries,
            base_delay_seconds=cfg.base_delay_seconds,
            retry_exceptions=(RequestException,),
        )
    except (RequestException, ValueError) as exc:
        raise IntelLookupError("EPSS scores could not be downloaded.") from exc

    out: dict[str, EpssScore] = {}
    rows = payload.get("data") if isinstance(payload, dict) else None
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        cve_id = str(row.get("cve") or "").strip().upper()
        if not cve_id:
            continue
        out[cve_id] = EpssScore(
            cve_id=cve_id,
            epss=_to_float(row.get("epss")),
            percentile=_to_float(row.get("percentile")),
            date=str(row.get("date") or ""),
        )
    return out


def fetch_score(
    cve_id: str, config: EpssConfig | None = None, *, settings: Settings | None = None
) -> EpssScore | None:
    """The score for one CVE, or None when it is unscored or switched off."""
    if not cve_id:
        return None
    return fetch_scores([cve_id], config, settings=settings).get(cve_id.strip().upper())


def get_epss_probability(
    cve_id: str, config: EpssConfig | None = None, *, settings: Settings | None = None
) -> float | None:
    """Just the exploitation probability (0 to 1) for one CVE, or None."""
    score = fetch_score(cve_id, config, settings=settings)
    return score.epss if score is not None else None
