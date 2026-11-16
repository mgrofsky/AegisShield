"""Threat-model records for the page tests: a real mock run and hand-made ones."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from aegisshield.config import get_settings
from aegisshield.llm.mock import MockLLM
from aegisshield.pipeline.run import run_threat_model
from aegisshield.pipeline.schemas import AppProfile, ThreatModelRequest

PROFILE: dict[str, Any] = {
    "app_type": "Web application",
    "industry_sector": "Retail",
    "sensitive_data": "High",
    "internet_facing": "Yes",
    "num_employees": "101-1000",
    "technical_ability": "Medium",
    "compliance_requirements": ["PCI DSS v4.0"],
    "authentication": ["OAuth 2.0"],
    "selected_technologies": {"PostgreSQL": "cpe:2.3:a:postgresql:postgresql:"},
    "selected_versions": {"PostgreSQL": "15.4"},
}
DESCRIPTION = "An online retail checkout service that takes card payments and stores orders."

DREAD_HEADER = (
    "| ID | Damage Potential | Reproducibility | Exploitability | Affected Users | "
    "Discoverability | Risk Score |\n|----|----|----|----|----|----|----|\n"
)


class _Quiet:
    def set(self, record: dict[str, Any]) -> None:
        pass

    def cancelled(self) -> bool:
        return False


@lru_cache(maxsize=1)
def _mock_result() -> tuple[tuple[str, Any], ...]:
    request = ThreatModelRequest(
        app_profile=AppProfile(**PROFILE),
        app_description=DESCRIPTION,
        addons=["mitigations", "dread", "test_cases"],
    )
    result = run_threat_model(request, llm=MockLLM(), settings=get_settings({}), progress=_Quiet())
    payload = {**result, "profile": request.app_profile.model_dump(), "description": DESCRIPTION}
    return tuple(payload.items())


def mock_payload() -> dict[str, Any]:
    """A stored payload from a real mock run (profile and description added)."""
    import copy

    return copy.deepcopy(dict(_mock_result()))


def dread_payload(*scores: float) -> dict[str, Any]:
    """A minimal payload whose DREAD table holds one row per risk score."""
    rows = "".join(f"| TC-S0{i} | 5 | 5 | 5 | 5 | 5 | {s:.2f} |\n" for i, s in enumerate(scores, 1))
    return {"profile": dict(PROFILE), "dread_assessment_markdown": DREAD_HEADER + rows,
            "threat_model": [{"ID": f"TC-S0{i}"} for i in range(1, len(scores) + 1)]}
