"""Digests of everything a non-AI threat model produces with the canned mock:
every prompt, the stored result, and every export. ``test_atlas_flow`` pins
them to the values this code gave before ATLAS mapping existed, so a non-AI
system's prompts, results, and exports stay byte-for-byte the same.

Only the parts that change from run to run are taken out first: the
safeguards record (timings) and the generation time stamps of the exports.
The module uses only interfaces that existed before the change, so the same
code computed the pinned values.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from aegisshield.config import Settings
from aegisshield.llm.mock import MockLLM
from aegisshield.pipeline.run import run_threat_model
from aegisshield.pipeline.schemas import ThreatModelRequest
from aegisshield.safeguards import REPORT_KEY
from aegisshield.services import export_service, report_service
from aegisshield.storage import RecordKind, Workspace
from aegisshield.ui import threat_model_view

PROFILE: dict[str, Any] = {
    "app_type": "Web application", "industry_sector": "Retail", "sensitive_data": "High",
    "internet_facing": "Yes", "authentication": ["OAuth 2.0"], "compliance_requirements": ["PCI DSS v4.0"],
}
DESCRIPTION = "An online retail checkout service that takes card payments and stores orders."
_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?(?:\+00:00| UTC)")


class Recorder:
    """A ``MockLLM`` that keeps every prompt it is sent, in order."""

    def __init__(self) -> None:
        self.inner = MockLLM()
        self.prompts: list[str] = []
        self.simulated = False

    def chat_text(self, **kwargs: Any) -> str:
        self.prompts.append(f"text\n{kwargs['system']}\n{kwargs['user']}")
        return self.inner.chat_text(**kwargs)

    def chat_json(self, **kwargs: Any) -> dict[str, Any]:
        self.prompts.append(f"json\n{kwargs['system']}\n{kwargs['user']}")
        return self.inner.chat_json(**kwargs)

    def describe_image(self, **kwargs: Any) -> str:
        return self.inner.describe_image(**kwargs)


class _Sink:
    def set(self, record: dict[str, Any]) -> None:
        pass

    def cancelled(self) -> bool:
        return False


def _digest(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(_STAMP.sub("<time>", text).encode("utf-8")).hexdigest()


def run(agentic: bool = False) -> tuple[Recorder, dict[str, Any]]:
    """One non-AI mock run with every add-on; the recorder and the result."""
    llm = Recorder()
    request = ThreatModelRequest.model_validate({
        "app_profile": PROFILE, "app_description": DESCRIPTION,
        "addons": ["mitigations", "dread", "test_cases"], "agentic": agentic,
    })
    result = run_threat_model(request, llm=llm, settings=Settings(), progress=_Sink())
    return llm, result


def digests(agentic: bool = False) -> dict[str, str]:
    """Name to SHA-256 of each prompt list, the result, and each export."""
    llm, result = run(agentic)
    stored = {k: v for k, v in result.items() if k != REPORT_KEY}
    sarif = export_service.to_sarif(stored, PROFILE, DESCRIPTION, tool_version="pin")
    sarif["runs"][0]["invocations"][0].pop("endTimeUtc", None)
    report = export_service.to_json_report(stored, PROFILE, DESCRIPTION)
    report.pop("generated_at", None)
    record = Workspace().add(RecordKind.THREAT_MODELS, "Checkout",
                             {**stored, "profile": PROFILE, "description": DESCRIPTION})
    return {
        "markdown": _digest(threat_model_view.bundle_markdown(record)),
        "prompts": _digest("\n\x00\n".join(llm.prompts)),
        "result": _digest(stored),
        "json": _digest(report),
        "html": _digest(export_service.to_html_report(stored, PROFILE, DESCRIPTION)),
        # Without the logo, so a new logo file does not count as a change.
        "pdf_html": _digest(report_service.build_report_html(stored, PROFILE, DESCRIPTION, logo_base64="")),
        "sarif": _digest(sarif),
    }
