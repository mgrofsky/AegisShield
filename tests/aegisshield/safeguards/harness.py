"""Shared pieces for the safeguards tests: stubbed lookups, runs, and counters.

The NVD and OTX stubs answer like the services' clients; their text can be
set per test, so an attack can arrive through the real lookup step.
"""

from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from aegisshield.config import Settings
from aegisshield.llm.base import LLMClient
from aegisshield.llm.mock import MockLLM
from aegisshield.pipeline import nvd_service, otx_service
from aegisshield.pipeline.run import run_threat_model
from aegisshield.pipeline.schemas import ThreatModelRequest
from aegisshield.safeguards import Safeguards

PROFILE: dict[str, Any] = {
    "app_type": "Web application",
    "industry_sector": "Retail",
    "sensitive_data": "Payment card data",
    "internet_facing": "Yes",
    "num_employees": "51-200",
    "authentication": ["OAuth2", "MFA"],
    "compliance_requirements": ["PCI DSS"],
    "technical_ability": "Medium",
    "selected_technologies": {
        "nginx": "cpe:2.3:a:f5:nginx:",
        "PostgreSQL": "cpe:2.3:a:postgresql:postgresql:",
    },
    "selected_versions": {"nginx": "1.24.0", "PostgreSQL": "15.4"},
}
DESCRIPTION = (
    "An online checkout service for a retail store. Shoppers sign in, keep saved cards with "
    "the payment provider, apply coupons, and place orders. Staff issue refunds from an "
    "admin console."
)
ADDONS = ["mitigations", "dread", "test_cases"]

DEFAULT_CVE_TEXT = "A flaw in {product} ({cve}) lets a remote attacker read memory."
DEFAULT_PULSES: list[dict[str, Any]] = [
    {
        "name": "Card skimming scripts on online stores",
        "description": "Injected scripts copy card numbers from checkout forms.",
        "modified": "2026-10-02T08:00:00.000",
        "public": 1,
        "TLP": "white",
        "adversary": "",
        "malware_families": ["Magecart"],
    },
]


class Lookups:
    """Stubbed NVD and OTX clients whose answers a test may change."""

    def __init__(self) -> None:
        self.cve_text = DEFAULT_CVE_TEXT
        self.pulses = copy.deepcopy(DEFAULT_PULSES)

    def install(self, monkeypatch: pytest.MonkeyPatch) -> Lookups:
        lookups = self

        def search_cpe(cpeMatchString: str, key: str) -> list[SimpleNamespace]:  # noqa: N803
            return [SimpleNamespace(cpeName=cpeMatchString, deprecated=False)]

        def search_cve(cpeName: str, key: str, limit: int | None = None) -> list[SimpleNamespace]:  # noqa: N803
            product = cpeName.split(":")[4]
            cve = "CVE-2024-10979" if product == "postgresql" else "CVE-2023-44487"
            return [SimpleNamespace(
                id=cve, score=["V31", 8.8, "HIGH"], published="2024-11-14T13:15:04.000",
                descriptions=[SimpleNamespace(value=lookups.cve_text.format(product=product, cve=cve))],
                metrics=None,
            )]

        class FakeOtx:
            def __init__(self, api_key: str) -> None:
                self.api_key = api_key

            def search_pulses(self, query: str, max_results: int) -> dict[str, Any]:
                return {"results": copy.deepcopy(lookups.pulses)}

        monkeypatch.setattr(nvd_service.nvdlib, "searchCPE", search_cpe)
        monkeypatch.setattr(nvd_service.nvdlib, "searchCVE", search_cve)
        monkeypatch.setattr(otx_service, "BoundedOTXv2", FakeOtx)
        return self


class Sink:
    """A progress sink that keeps every record."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def set(self, record: dict[str, Any]) -> None:
        self.records.append(record)

    def cancelled(self) -> bool:
        return False


class Counting:
    """An ``LLMClient`` that counts the calls it passes to ``inner``."""

    def __init__(self, inner: LLMClient | None = None) -> None:
        self.inner: LLMClient = inner if inner is not None else MockLLM()
        self.calls: list[str] = []
        self.simulated = bool(getattr(self.inner, "simulated", False))

    def chat_text(self, **kwargs: Any) -> str:
        self.calls.append("text")
        return self.inner.chat_text(**kwargs)

    def chat_json(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("json")
        return self.inner.chat_json(**kwargs)

    def describe_image(self, **kwargs: Any) -> str:
        self.calls.append("image")
        return self.inner.describe_image(**kwargs)


def request(description: str = DESCRIPTION, *, agentic: bool = False,
            profile: dict[str, Any] | None = None, **extra: Any) -> ThreatModelRequest:
    return ThreatModelRequest(app_profile=profile or PROFILE, app_description=description,
                              addons=ADDONS, agentic=agentic, **extra)


def run(req: ThreatModelRequest, *, llm: LLMClient | None = None,
        safeguards: Safeguards | None = None, settings: Settings | None = None,
        keys: bool = True) -> dict[str, Any]:
    """One threat model through ``run_threat_model``, as the page runs it."""
    return run_threat_model(
        req, llm=llm if llm is not None else MockLLM(), settings=settings or Settings(),
        progress=Sink(), nvd_api_key="test-nvd-key" if keys else None,
        otx_api_key="test-otx-key" if keys else None, safeguards=safeguards,
    )


def statuses(report: dict[str, Any]) -> dict[str, int]:
    """Counts of each status in a report."""
    return {k: v for k, v in report["counts"].items() if k != "total"}


def checks(report: dict[str, Any], rail_set: str) -> list[dict[str, Any]]:
    return [c for c in report["checks"] if c["rail_set"] == rail_set]


TSHARK_FIXTURES = Path(__file__).resolve().parents[1] / "services" / "fixtures" / "tshark"
