"""Whole runs through each of the four model backends.

Each provider's real client class runs on a "canned provider": a fake of its
SDK whose every request is answered by ``MockLLM`` (asked with the system and
user text read back out of the provider-shaped request) and returned in that
SDK's real response shape, streamed in chunks when the backend streams. A
threat model (linear with every add-on, and agentic), a policy, and a capture
analysis complete through each, and the stored record names the provider
and model that answered.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from aegisshield.config import Settings, with_model_choice
from aegisshield.llm import providers
from aegisshield.llm.mock import MOCK_PCAP_ANALYSIS, MOCK_POLICY, MockLLM
from aegisshield.pipeline.run import run_threat_model
from aegisshield.pipeline.schemas import ThreatModelRequest
from aegisshield.services import pcap_service, policy_service
from aegisshield.storage import RecordKind, Workspace
from tests.aegisshield.llm.provider_fakes import ANSWERING, answering_client
from tests.aegisshield.pipeline.test_run import FakeSink

PROVIDERS = ("openai", "claude", "bedrock", "gemini")
ADDONS = ["mitigations", "dread", "test_cases"]
REQUEST = {
    "app_profile": {"app_type": "Web application", "industry_sector": "Retail",
                    "sensitive_data": "High", "internet_facing": "Yes"},
    "app_description": "An online retail checkout service that takes card payments.",
    "addons": ADDONS,
}
ORG = {"legal_name": "Northwind Outfitters Inc.", "industry": "Retail",
       "leadership": [{"role": "CISO", "name": "Sam Patel"}], "compliance_drivers": [],
       "regulatory_notes": "Sells online."}
SUMMARY = {"filesize_bytes": 100, "sip": {"aggregations": {"total_messages": 0}}}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("AEGIS_OFFLINE", "AEGIS_MOCK_LLM", "AEGIS_AGENTIC", "AEGIS_PROVIDERS",
                 "AEGIS_SAFEGUARDS", "AEGIS_SAFEGUARDS_STRICT"):
        monkeypatch.delenv(name, raising=False)


def _settings(provider: str, **extra: Any) -> Settings:
    return with_model_choice(Settings(offline=True, **extra), provider=provider,
                             model="test-model-id")


def _canned(provider: str) -> tuple[Any, Any]:
    fake = ANSWERING[provider](sizes=(5, 64, 300))
    return fake, answering_client(provider, fake)


def _request(**overrides: Any) -> ThreatModelRequest:
    return ThreatModelRequest.model_validate({**REQUEST, **overrides})


def _mock_run(agentic: bool) -> dict[str, Any]:
    return run_threat_model(_request(agentic=agentic), llm=MockLLM(),
                            settings=Settings(mock_llm=True, offline=True), progress=FakeSink())


def _markdown_keys(result: dict[str, Any]) -> list[str]:
    """The markdown sections the mock run filled (offline, the lookups' stay empty)."""
    return [k for k, v in result.items()
            if k.endswith("_markdown") and isinstance(v, str) and v.strip()]


@pytest.mark.parametrize("agentic", [False, True], ids=["linear", "agentic"])
@pytest.mark.parametrize("provider", PROVIDERS)
def test_a_full_threat_model_completes_through_each_backend(provider: str, agentic: bool) -> None:
    fake, client = _canned(provider)
    settings = _settings(provider)
    result = run_threat_model(_request(agentic=agentic), llm=client, settings=settings,
                              progress=FakeSink())
    mock = _mock_run(agentic)

    assert set(result) == set(mock)
    assert result["threat_model"] and result["threat_model"] == mock["threat_model"]
    markdown = _markdown_keys(mock)
    assert markdown
    for key in markdown:
        assert isinstance(result[key], str) and result[key].strip(), key
    if not agentic:
        for key in ("mitigations_markdown", "dread_assessment_markdown", "test_cases_markdown"):
            assert result[key].strip(), key
    # Every call went to the chosen model, and the output rails saw every one.
    assert len(fake.calls) > 5
    models = {c.get("model") or c.get("modelId") for c in fake.calls}
    assert models == {"test-model-id"}
    report = result["safeguards"]
    outputs = [c for c in report["checks"] if c["rail_set"] == "output"]
    assert len(outputs) == len(fake.calls)
    assert report["complete"] is True and report["simulated_model"] is False


@pytest.mark.parametrize("provider", PROVIDERS)
def test_a_policy_completes_through_each_backend(provider: str) -> None:
    fake, client = _canned(provider)
    seen: list[str] = []
    result = policy_service.generate_policy("information_security_policy", ORG, llm=client,
                                            settings=_settings(provider), on_text=seen.append)
    assert result["title"] and result["body_markdown"].strip()
    assert MOCK_POLICY.splitlines()[0].strip("# ") in result["body_markdown"]
    assert len(fake.calls) == 1 and "".join(seen)


@pytest.mark.parametrize("provider", PROVIDERS)
def test_a_capture_analysis_completes_through_each_backend(provider: str) -> None:
    fake, client = _canned(provider)
    seen: list[str] = []
    text = pcap_service.analyze_summary(SUMMARY, llm=client, settings=_settings(provider),
                                        on_text=seen.append)
    assert text.strip() and text == pcap_service.analyze_summary(
        SUMMARY, llm=MockLLM(), settings=Settings(mock_llm=True, offline=True))
    assert MOCK_PCAP_ANALYSIS.strip()[:40] in text
    [(system, user)] = fake.asked
    assert system == pcap_service.ANALYSIS_SYSTEM_PROMPT
    assert "File size: 100 bytes" in user


# ------------------------------------------------------------ the record


def _wizard_payload(result: dict[str, Any], request: ThreatModelRequest,
                    settings: Settings) -> dict[str, Any]:
    """The payload as ``threat_model_run.start_run`` builds it."""
    return {**result, "profile": request.app_profile.model_dump(),
            "description": request.app_description, "model": providers.answered_by(settings)}


@pytest.mark.parametrize("provider", PROVIDERS)
def test_the_record_names_the_provider_and_model_and_round_trips(provider: str) -> None:
    settings = _settings(provider)
    _, client = _canned(provider)
    request = _request()
    result = run_threat_model(request, llm=client, settings=settings, progress=FakeSink())
    payload = _wizard_payload(result, request, settings)
    assert payload["model"] == {"provider": provider, "name": "test-model-id"}
    assert providers.answered_by_words(payload["model"]) == (
        f"{providers.provider_label(provider)}, test-model-id")

    workspace = Workspace()
    record = workspace.add(RecordKind.THREAT_MODELS, "Checkout", payload)
    loaded = Workspace.from_json(workspace.to_json())
    [back] = loaded.list(RecordKind.THREAT_MODELS)
    assert back.id == record.id
    assert back.payload["model"] == {"provider": provider, "name": "test-model-id"}
    assert json.loads(json.dumps(back.payload)) == json.loads(json.dumps(payload))


def test_an_old_record_without_a_model_still_loads() -> None:
    request = _request()
    result = _mock_run(agentic=False)
    payload = {**result, "profile": request.app_profile.model_dump(),
               "description": request.app_description}
    workspace = Workspace()
    workspace.add(RecordKind.THREAT_MODELS, "Older", payload)
    [back] = Workspace.from_json(workspace.to_json()).list(RecordKind.THREAT_MODELS)
    assert "model" not in back.payload
    assert providers.answered_by_words(back.payload.get("model")) is None
    assert providers.answered_by_words(None) is None


_NO_PAGE_CODE = """
import sys
from aegisshield.config import Settings, with_model_choice
from aegisshield.llm import providers
from aegisshield.storage import RecordKind, Workspace

settings = with_model_choice(Settings(offline=True), provider="claude", model="test-model-id")
workspace = Workspace()
workspace.add(RecordKind.THREAT_MODELS, "t", {"model": providers.answered_by(settings)})
[back] = Workspace.from_json(workspace.to_json()).list(RecordKind.THREAT_MODELS)
assert back.payload["model"] == {"provider": "claude", "name": "test-model-id"}
assert providers.answered_by_words(back.payload["model"]) == "Claude (Anthropic), test-model-id"
loaded = sorted(m for m in sys.modules if m == "streamlit" or m.startswith(("streamlit.", "aegisshield.ui")))
print(",".join(loaded))
"""


def test_the_record_needs_no_page_code() -> None:
    """Building, storing, and reading the record imports neither the page
    kit nor Streamlit (checked in a fresh interpreter)."""
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    done = subprocess.run([sys.executable, "-c", _NO_PAGE_CODE], cwd=root, capture_output=True,
                          text=True, check=False)
    assert done.returncode == 0, done.stderr[-2000:]
    assert done.stdout.strip() == ""
