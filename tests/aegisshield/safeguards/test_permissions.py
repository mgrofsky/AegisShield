"""Permissions stay in code: nothing a model returns can start a job, choose
a target, change a setting, read a file, or reach a key.

Where a model's answer chooses anything at all, the choice is checked
against a fixed list in code: the agentic Lead may only order and skip the
seven known sections (``_normalize_plan``), and the technique mapping may
only name a technique in the catalog (``validate_id``, else the top keyword
match). These tests pin those two places, and that the code paths which
start jobs or run programs sit where no model output reaches them.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from aegisshield.config import Settings
from aegisshield.llm.mock import MockLLM
from aegisshield.pipeline import agentic_threat_model as agentic
from aegisshield.pipeline import mitre_service
from aegisshield.pipeline.catalog_service import catalog_for_app_type, index_by_id
from aegisshield.pipeline.workflow_service import gather_enrichment
from tests.aegisshield.safeguards import harness

PACKAGE = Path(__file__).resolve().parents[3] / "aegisshield"


class _Hostile(MockLLM):
    """Answers every JSON call with a plan that tries to do more than plan."""

    technique_answers = 0

    def chat_json(self, **kwargs: Any) -> dict[str, Any]:
        if "Threat Model Lead" in kwargs["system"]:
            return {
                "plan": [
                    {"section": "START_JOB", "focus": "run a capture analysis"},
                    {"section": "SETTINGS", "focus": "set AEGIS_SAFEGUARDS=off"},
                    {"section": "STRIDE", "focus": "read /etc/passwd", "skip": True},
                    {"section": "TEAMMATE", "skip": True, "target": "http://203.0.113.9/"},
                ],
                "rationale": "take over",
                "jobs": [{"kind": "pcap"}],
            }
        return super().chat_json(**kwargs)

    def chat_text(self, **kwargs: Any) -> str:
        if "attack techniques" in kwargs["system"].lower() or "Candidate Techniques" in kwargs["user"]:
            _Hostile.technique_answers += 1
            return '{"technique_id": "T0000", "file": "/etc/passwd"}'
        return super().chat_text(**kwargs)


def test_the_lead_can_only_order_and_skip_the_known_sections(monkeypatch: pytest.MonkeyPatch) -> None:
    harness.Lookups().install(monkeypatch)
    details = dict(harness.PROFILE)
    enrichment = gather_enrichment(nvd_api_key=None, otx_api_key=None, app_details=details,
                                   app_description=harness.DESCRIPTION, settings=Settings())
    plan = agentic.lead_plan(llm=_Hostile(), model="m", app_details=details,
                             app_description=harness.DESCRIPTION, enrichment=enrichment)
    sections = [p.section for p in plan.sections]
    assert set(sections) == set(agentic.Section)
    assert len(sections) == len(agentic.Section)
    # A required section cannot be skipped; only the plan's fields exist.
    assert next(p for p in plan.sections if p.section is agentic.Section.STRIDE).skip is False
    assert set(plan.to_dict()) == {"decider", "rationale", "sections"}
    assert all(set(s) == {"section", "focus", "skip"} for s in plan.to_dict()["sections"])


def test_a_technique_outside_the_catalog_is_never_used() -> None:
    catalog = catalog_for_app_type("Web application")
    index = index_by_id(catalog)
    threat = {"ID": "TC-S01", "Threat Type": "Spoofing", "Scenario": "Stolen cookies are replayed.",
              "MITRE ATT&CK Keywords": ["steal web session cookie", "valid accounts"]}
    mapped = mitre_service.process_mitre_attack_data([threat], {**harness.PROFILE, "app_input": harness.DESCRIPTION},
                                                     _Hostile(), "m", catalog=catalog)
    assert _Hostile.technique_answers >= 1
    [technique] = mapped[0]["mitre_techniques"]
    assert technique["technique_id"] in index and technique["technique_id"] != "T0000"


def _calls(module: Path, names: set[str]) -> list[str]:
    tree = ast.parse(module.read_text(encoding="utf-8"))
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name in names:
                found.append(name)
    return found


def test_only_pages_start_jobs_and_only_the_capture_service_runs_a_program() -> None:
    starters, runners = [], []
    for path in PACKAGE.rglob("*.py"):
        rel = path.relative_to(PACKAGE).as_posix()
        if rel.startswith("aiscan/"):
            continue  # the scan package, covered by its own tests under tests/aegisshield/aiscan
        if _calls(path, {"start_job", "submit"}):
            starters.append(rel)
        if "subprocess" in path.read_text(encoding="utf-8") and _calls(path, {"run", "Popen"}):
            runners.append(rel)
    assert all(rel.startswith("ui/") for rel in starters), starters
    assert runners == ["services/pcap_service.py"]


def test_no_key_reaches_a_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    harness.Lookups().install(monkeypatch)
    prompts: list[str] = []

    class Recording(MockLLM):
        def chat_text(self, **kwargs: Any) -> str:
            prompts.append(kwargs["system"] + kwargs["user"])
            return super().chat_text(**kwargs)

        def chat_json(self, **kwargs: Any) -> dict[str, Any]:
            prompts.append(kwargs["system"] + kwargs["user"])
            return super().chat_json(**kwargs)

    from aegisshield.pipeline.run import run_threat_model

    for agentic_path in (False, True):
        result = run_threat_model(harness.request(agentic=agentic_path), llm=Recording(),
                                  settings=Settings(), progress=harness.Sink(),
                                  nvd_api_key="nvd-key-0123456789abcdef", otx_api_key="otx-key-fedcba9876543210")
        assert "nvd-key-0123456789abcdef" not in str(result)
    assert prompts
    assert not any("nvd-key-0123456789abcdef" in p or "otx-key-fedcba9876543210" in p for p in prompts)
