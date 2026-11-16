"""The ATLAS mapping of an AI system through each of the four model backends.

Each provider's real client class runs on a canned provider (a fake of its
SDK answered by ``MockLLM``, in the SDK's real response shapes). The one
extra structured call an AI system's run makes goes through the client's
provider-neutral JSON path (``chat_json``: the app's JSON instruction ends
the system text, and the answer is parsed by the client), and its picks
are kept as the mock's own run keeps them.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegisshield.config import Settings, with_model_choice
from aegisshield.llm.base import JSON_SYSTEM_SUFFIX
from aegisshield.llm.mock import MockLLM
from aegisshield.pipeline import atlas_service
from aegisshield.pipeline.run import run_threat_model
from aegisshield.pipeline.schemas import ThreatModelRequest
from tests.aegisshield.llm.provider_fakes import ANSWERING, answering_client
from tests.aegisshield.pipeline import non_ai_pin
from tests.aegisshield.pipeline.test_run import FakeSink

PROVIDERS = ("openai", "claude", "bedrock", "gemini")
AI_PROFILE = {**non_ai_pin.PROFILE, "app_pattern": ["GenAI"]}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("AEGIS_OFFLINE", "AEGIS_MOCK_LLM", "AEGIS_AGENTIC", "AEGIS_PROVIDERS",
                 "AEGIS_SAFEGUARDS", "AEGIS_SAFEGUARDS_STRICT"):
        monkeypatch.delenv(name, raising=False)


def _request(profile: dict[str, Any], agentic: bool) -> ThreatModelRequest:
    return ThreatModelRequest.model_validate({
        "app_profile": profile, "app_description": non_ai_pin.DESCRIPTION,
        "addons": ["mitigations"], "agentic": agentic,
    })


def _run(provider: str, profile: dict[str, Any], agentic: bool) -> tuple[Any, dict[str, Any]]:
    fake = ANSWERING[provider](sizes=(64,))
    settings = with_model_choice(Settings(offline=True), provider=provider, model="test-model-id")
    result = run_threat_model(_request(profile, agentic), llm=answering_client(provider, fake),
                              settings=settings, progress=FakeSink())
    return fake, result


def _atlas_asks(fake: Any) -> list[str]:
    return [system for system, _ in fake.asked if system.startswith(atlas_service.ATLAS_SYSTEM)]


@pytest.mark.parametrize("agentic", [False, True], ids=["linear", "agentic"])
@pytest.mark.parametrize("provider", PROVIDERS)
def test_an_ai_systems_atlas_call_goes_through_each_backends_json_path(provider: str, agentic: bool) -> None:
    plain_fake, plain = _run(provider, non_ai_pin.PROFILE, agentic)
    fake, result = _run(provider, AI_PROFILE, agentic)
    assert atlas_service.ATLAS_RESULT_KEY not in plain and _atlas_asks(plain_fake) == []
    # Exactly one more request to the provider, and it is the ATLAS request,
    # sent as a JSON request (the app's JSON instruction ends its system text).
    assert len(fake.calls) == len(plain_fake.calls) + 1
    (system,) = _atlas_asks(fake)
    assert system.rstrip().endswith(JSON_SYSTEM_SUFFIX)
    # The provider's JSON answer was parsed and every threat kept its pick,
    # the same picks the mock itself makes.
    mapping = result[atlas_service.ATLAS_RESULT_KEY]
    mock = run_threat_model(_request(AI_PROFILE, agentic), llm=MockLLM(),
                            settings=Settings(mock_llm=True, offline=True), progress=FakeSink())
    assert mapping["call"] == "answered"
    assert [r["status"] for r in mapping["threats"]] == [atlas_service.STATUS_MAPPED] * len(mapping["threats"])
    assert mapping["threats"] == mock[atlas_service.ATLAS_RESULT_KEY]["threats"]
