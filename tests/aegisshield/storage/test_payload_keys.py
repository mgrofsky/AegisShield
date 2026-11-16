"""PAYLOAD_KEYS lists exactly what the pages store, checked against real
mock-mode runs of the services the pages call."""

from __future__ import annotations

from aegisshield.config import Settings
from aegisshield.llm.mock import MockLLM
from aegisshield.pipeline.run import run_threat_model
from aegisshield.pipeline.schemas import ThreatModelRequest
from aegisshield.services.org_profile import LeadershipContact, OrgProfile
from aegisshield.services.policy_service import generate_policy
from aegisshield.storage.workspace import ORG_PROFILE_KEY, PAYLOAD_KEYS, RecordKind
from tests.aegisshield.pipeline.test_run import FakeSink

SETTINGS = Settings(mock_llm=True, offline=True)
REQUEST = {
    "app_profile": {"app_type": "Web application", "industry_sector": "Retail",
                    "sensitive_data": "High", "internet_facing": "Yes"},
    "app_description": "An online retail checkout service that takes card payments.",
}
# The wizard adds these to the job result (threat_model_run.start_run):
# the request's profile and description, and which provider and model
# answered (providers.answered_by).
WIZARD_KEYS = {"profile", "description", "model"}


def _run(**overrides: object) -> set[str]:
    request = ThreatModelRequest.model_validate({**REQUEST, **overrides})
    result = run_threat_model(request, llm=MockLLM(), settings=SETTINGS, progress=FakeSink())
    return set(result) | WIZARD_KEYS


def test_threat_model_keys_are_what_a_linear_and_an_agentic_run_store() -> None:
    linear = _run()
    agentic = _run(agentic=True)
    ai_profile = {**REQUEST["app_profile"], "app_pattern": ["GenAI"]}
    ai = _run(app_profile=ai_profile) | _run(app_profile=ai_profile, agentic=True)
    assert ai - (linear | agentic) == {"atlas_mapping"}
    page_fields = {"ai_scans"}  # added by the scan page when a scan is attached
    assert linear | agentic | ai | page_fields == set(PAYLOAD_KEYS[RecordKind.THREAT_MODELS])
    assert len(PAYLOAD_KEYS[RecordKind.THREAT_MODELS]) == len(set(PAYLOAD_KEYS[RecordKind.THREAT_MODELS]))


def test_policy_keys_are_the_service_result_and_the_page_fields() -> None:
    profile = OrgProfile(legal_name="Example Retail Co", industry="Retail",
                         leadership=(LeadershipContact("CISO", "A. Lee"),))
    result = generate_policy("access_control_policy", profile, llm=MockLLM(), settings=SETTINGS)
    page_fields = {"policy_key", "status", "version", "edited", "model"}
    assert set(result) | page_fields == set(PAYLOAD_KEYS[RecordKind.POLICIES])


def test_org_profile_keys_are_to_dict() -> None:
    assert tuple(OrgProfile(legal_name="Example Retail Co").to_dict()) == PAYLOAD_KEYS[ORG_PROFILE_KEY]


def test_lookup_and_capture_keys() -> None:
    assert PAYLOAD_KEYS[RecordKind.LOOKUPS] == ("request", "result")
    assert PAYLOAD_KEYS[RecordKind.PCAP_ANALYSES] == ("filename", "filesize_bytes", "result", "model")


def test_ai_scan_keys_are_the_scan_record() -> None:
    from aegisshield.aiscan.garak_run import GarakRun
    from aegisshield.aiscan.limits import ScanLimits
    from aegisshield.aiscan.report import parse_report
    from aegisshield.aiscan.service import ScanRequest, build_record

    request = ScanRequest.build(surface_id="s", surface_title="S", probe_ids=["encoding.InjectBase64"],
                                limits=ScanLimits(wall_clock_seconds=300), model_kind="mock", model_name="m",
                                developer=True)
    record = build_record(request, parsed=parse_report(None), run=GarakRun(True, 0, None, 1.0), shim_counts={},
                          limit_hit=False, token="t", garak_version="0.17.1", started_at="a", ended_at="b",
                          planned=5, wall_clock_seconds=60, safeguards_report=None)
    assert tuple(record) == PAYLOAD_KEYS[RecordKind.AI_SCANS]
