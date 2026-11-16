"""End-to-end style assertions on which model each workflow stage calls.

Replaces every external dependency (model, NVD, OTX) with stubs so we can read
back exactly which ``model`` each stage was handed.
"""

from __future__ import annotations

from aegisshield.config import Settings
from aegisshield.pipeline import threat_model_service, workflow_service
from aegisshield.pipeline.catalog_service import CatalogEntry

# Distinct names so the routing is visible (the defaults are the same model).
_SETTINGS = Settings(architect_model="architect-model", worker_model="worker-model")


class RecordingLLM:
    """Records the model each call was handed, by stage."""

    def __init__(self) -> None:
        self.seen: dict[str, list[str]] = {"stride": [], "mitre": [], "atlas": [], "attack_tree": [],
                                           "image": []}

    def chat_json(self, *, system, user, model, max_tokens=16000, on_text=None) -> dict:
        if '{"atlas": [' in system:
            self.seen["atlas"].append(model)
            return {"atlas": []}
        self.seen["stride"].append(model)
        return {
            "threat_model": [
                {
                    "Threat Type": "Spoofing",
                    "Scenario": "Test",
                    "Assumptions": [],
                    "Potential Impact": "High",
                    "MITRE ATT&CK Keywords": ["execute", "command"],
                }
            ],
            "improvement_suggestions": [],
        }

    def chat_text(self, *, system, user, model, max_tokens=8192, on_text=None) -> str:
        # The MITRE selector and the attack tree both call chat_text. The
        # MITRE prompt includes "Candidate Techniques".
        if "Candidate Techniques" in user:
            self.seen["mitre"].append(model)
            return '{"technique_id": "T1059"}'
        self.seen["attack_tree"].append(model)
        return "graph LR; A-->B"

    def describe_image(self, *, image_bytes, media_type, prompt, model, max_tokens=4096) -> str:
        self.seen["image"].append(model)
        return "Architecture description."


def test_workflow_dispatches_architect_and_worker_models(monkeypatch) -> None:
    fake_catalog = [
        CatalogEntry(
            framework="ATT&CK",
            domain="enterprise",
            technique_id="T1059",
            stix_id="attack-pattern--cmd",
            name="Command and Scripting Interpreter",
            tactic="Execution",
            description="Adversaries execute commands.",
        )
    ]
    # Bypass the real catalog (large): this test only needs routing.
    monkeypatch.setattr(
        workflow_service,
        "catalog_for_app_type",
        lambda *_args, **_kwargs: fake_catalog,
    )
    llm = RecordingLLM()
    # No NVD/OTX keys, so those branches do not run.
    workflow_service.run_threat_model_workflow(
        llm=llm,
        settings=_SETTINGS,
        nvd_api_key=None,
        otx_api_key=None,
        app_details={
            "app_type": "Web application",
            "industry_sector": "Information Technology",
            "authentication": ["MFA"],
            "internet_facing": "Yes",
            "sensitive_data": "High",
        },
        app_description="A regular web application without ML or agents.",
    )

    assert llm.seen["stride"] == [_SETTINGS.architect_model]
    assert llm.seen["mitre"] == [_SETTINGS.worker_model]
    assert llm.seen["attack_tree"] == [_SETTINGS.architect_model]
    # The regex detection finds "ML" and "agents" in this description (it does
    # not read the "without"), so the run counts as an AI system and makes the
    # ATLAS request, on the worker model.
    assert llm.seen["atlas"] == [_SETTINGS.worker_model]


def test_image_analysis_uses_architect() -> None:
    llm = RecordingLLM()
    threat_model_service.analyze_architecture_image(
        llm,
        _SETTINGS.architect_model,
        # 1x1 PNG (transparent) base64
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII=",
    )
    assert llm.seen["image"] == [_SETTINGS.architect_model]
