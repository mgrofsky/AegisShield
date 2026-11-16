"""A workflow scan with a real model uses the visitor's chosen provider,
credential, and model, the way a threat-model run does, for each of the four
providers: the provider's own client answers (a fake of its SDK), each call
asks for at most 1,024 output tokens in that SDK's field, the model and
provider are stored with the scan, and the credential reaches none of
garak's arguments, environment, configuration, the log, or the record."""

from __future__ import annotations

import html
import json
import logging
import time

import pytest

from aegisshield.aiscan import availability as scan_availability_mod
from aegisshield.aiscan import surfaces
from aegisshield.llm import factory, providers
from aegisshield.llm.base import DEFAULT_SDK_RETRIES, ModelInfo
from aegisshield.storage import RecordKind
from aegisshield.ui import tool_parts
from aegisshield.ui.pages import ai_scan as page
from tests.aegisshield.aiscan.garak_fakes import install
from tests.aegisshield.llm.provider_fakes import (
    ANSWERING,
    CLAUDE_KEY,
    GEMINI_KEY,
    OPENAI_KEY,
    OTHER_BEARER,
    VISITOR_BEARER,
    VISITOR_KEY_ID,
    VISITOR_SECRET,
    VISITOR_TOKEN,
    answering_client,
)
from tests.aegisshield.ui.tool_helpers import click_and_finish, fresh_runner, html_of, make_app

__all__ = ["fresh_runner"]

SYSTEM = "You answer billing questions for Example Retail in two sentences or fewer."
# Each provider's model, as its own list would give it; none is in the app's code.
MODELS = {"openai": "test-chat-b", "claude": "test-claude-text", "bedrock": "us.test.text-model-v1:0",
          "gemini": "test-gemini-a"}
# The credential each session holds, and every secret value in it.
CREDS = {
    "openai": {"api_key": OPENAI_KEY},
    "claude": {"api_key": CLAUDE_KEY},
    "gemini": {"api_key": GEMINI_KEY},
    "bedrock": {"api_key": VISITOR_BEARER, "region": "us-east-1"},
    "bedrock-short": {"api_key": OTHER_BEARER, "region": "us-west-2"},
    "bedrock-keys": {"access_key_id": VISITOR_KEY_ID, "secret_access_key": VISITOR_SECRET,
                     "session_token": VISITOR_TOKEN, "region": "us-east-1"},
}
# Where each SDK's request carries the output cap.
CAP = {
    "openai": lambda call: call["max_completion_tokens"],
    "claude": lambda call: call["max_tokens"],
    "bedrock": lambda call: call["inferenceConfig"]["maxTokens"],
    "gemini": lambda call: call["config"].max_output_tokens,
}


@pytest.fixture(autouse=True)
def scans_on(tmp_path, monkeypatch: pytest.MonkeyPatch):
    scan_availability_mod.clear_cache()
    fake = install(tmp_path / "garak-env")
    monkeypatch.delenv("AEGIS_MOCK_LLM", raising=False)
    monkeypatch.delenv("AEGIS_PROVIDERS", raising=False)
    monkeypatch.setenv("AEGIS_AI_SCAN", "1")
    monkeypatch.setenv("AEGIS_GARAK_PYTHON", fake.python)
    monkeypatch.setattr(tool_parts, "MOCK_STREAM_DELAY", 0.0)
    yield fake
    scan_availability_mod.clear_cache()


def _session(name: str) -> dict:
    """Session entries for a visitor who chose ``name``'s provider, gave its
    credential, and picked a model from its list (as the Settings page does)."""
    provider = name.split("-")[0]
    fields = CREDS[name]
    entries: dict = {
        "aegis_provider": provider,
        "aegis_model": {provider: MODELS[provider]},
        "aegis_model_lists": {provider: {"at": time.time(), "models": (ModelInfo(MODELS[provider]),),
                                         "failed": False}},
    }
    if provider == "openai":
        entries["aegis_key_openai"] = fields["api_key"]
    else:
        entries["aegis_creds"] = {provider: dict(fields)}
    return entries


def _secrets(name: str) -> list[str]:
    return [v for k, v in CREDS[name].items() if k != "region"]


def _canned(monkeypatch: pytest.MonkeyPatch, provider: str):
    """The provider's real client on a fake SDK, built through ``get_llm``
    with the credential it was handed recorded."""
    fake = ANSWERING[provider](lambda system, user: "An ordinary answer about invoices.")
    built: list[tuple[str, object]] = []

    def build(chosen, cred):
        built.append((chosen.value, cred))
        return answering_client(chosen.value, fake)

    monkeypatch.setattr(factory, "_build", build)
    return fake, built


def _run_real_scan(at, fresh_runner) -> None:
    at.text_area(key="scan_system_prompt").input(SYSTEM)
    for item in ("latentinjection.LatentInjectionReport", "web_injection.MarkdownImageExfil",
                 "encoding.InjectBase64"):
        at.checkbox(key=f"scan_probe_{item}").uncheck()
    at.number_input(key="scan_limit_prompts").set_value(1)
    at.run()
    assert at.radio(key="scan_model").value == "real"
    click_and_finish(at, "scan_run", fresh_runner)


@pytest.mark.parametrize("name", ["openai", "claude", "bedrock", "bedrock-short", "bedrock-keys", "gemini"])
def test_a_real_scan_uses_the_chosen_provider_credential_and_model(fresh_runner, scans_on, monkeypatch,
                                                                   caplog, name) -> None:
    provider = name.split("-")[0]
    fake, built = _canned(monkeypatch, provider)
    at = make_app(page.PAGE, **_session(name)).run()
    assert not at.exception
    with caplog.at_level(logging.DEBUG):
        _run_real_scan(at, fresh_runner)
    assert not at.exception
    # The provider's own client was built with this session's credential, once.
    ((chosen, cred),) = built
    assert chosen == provider
    for field, value in CREDS[name].items():
        assert getattr(cred, field) == value
    # Every garak request reached that provider, with the chosen model, the
    # visitor's system prompt, and the 1,024-token cap in the SDK's own field.
    assert fake.calls and all(CAP[provider](call) == surfaces.WORKFLOW_MAX_TOKENS == 1024
                              for call in fake.calls)
    assert all(MODELS[provider] in json.dumps(call, default=str) for call in fake.calls)
    assert {system for system, _ in fake.asked} == {SYSTEM}
    (record,) = at.session_state["aegis_workspace"].list(RecordKind.AI_SCANS)
    settings = record.payload["settings"]
    assert settings["model"] == {"kind": "real", "name": MODELS[provider], "provider": provider}
    assert settings["workflow"]["model"] == MODELS[provider]
    # The credential is nowhere but the client.
    (call,) = scans_on.calls()
    garak_side = json.dumps({"argv": call["argv"], "env": call["env"], "config": call["config"]})
    stored = json.dumps(record.payload)
    for secret in _secrets(name):
        assert secret not in garak_side and secret not in caplog.text and secret not in stored
    body = html_of(at)
    for secret in _secrets(name):
        assert secret not in body and html.escape(secret) not in body


# ------------------------------------------------------- what the page says


@pytest.mark.parametrize("name", ["openai", "claude", "bedrock", "gemini"])
def test_the_page_names_the_chosen_provider_and_model_and_its_retry_rule(fresh_runner, name) -> None:
    at = make_app(page.PAGE, **_session(name)).run()
    assert not at.exception
    body = html_of(at)
    label = providers.provider_label(name)
    assert html.escape(f"Model your workflow uses: {label}, {MODELS[name]}") in body
    assert html.escape(page.key_sentence(60, 0, name)) in body
    sentence = page.key_sentence(60, 0, name)
    assert f"your {label} credential" in sentence and f"can reach {label}." in sentence
    assert page.RETRY_RULES[name] in sentence and "180 requests" in sentence
    assert "OpenAI" not in sentence or name == "openai"
    assert html.escape(page.NO_MODEL_NOTE) not in body


def test_without_a_ready_model_only_the_stand_in_is_offered_and_the_page_says_why(fresh_runner) -> None:
    entries = _session("claude")
    entries["aegis_model_lists"] = {}  # the list was never fetched, so no model is chosen
    at = make_app(page.PAGE, **entries).run()
    assert not at.exception
    assert at.radio(key="scan_model").options == ["Simulated stand-in (simulated model, not a real model run)"]
    body = html_of(at)
    assert html.escape(page.NO_MODEL_NOTE) in body and "Model your workflow uses" not in body


def test_an_unknown_provider_gets_the_general_retry_rule() -> None:
    sentence = page.key_sentence(5, 0, "elsewhere")
    assert "Unknown provider answers with an error its SDK treats as passing" in sentence


def test_a_stand_in_scan_shows_that_no_model_answered(fresh_runner, scans_on, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_MOCK_LLM", "1")
    at = make_app(page.PAGE).run()
    at.text_area(key="scan_system_prompt").input(SYSTEM)
    for item in ("latentinjection.LatentInjectionReport", "web_injection.MarkdownImageExfil",
                 "encoding.InjectBase64"):
        at.checkbox(key=f"scan_probe_{item}").uncheck()
    at.number_input(key="scan_limit_prompts").set_value(1)
    at.run()
    click_and_finish(at, "scan_run", fresh_runner)
    assert html.escape("Model: none (the simulated stand-in answered)") in html_of(at)


# The retry rule each provider's client follows, read from the installed SDK
# without sending a request. ``page.RETRY_RULES`` says these in words.


def test_the_openai_and_anthropic_sdks_retry_what_the_page_says() -> None:
    import anthropic
    import httpx2
    import openai

    from aegisshield.llm import anthropic_client

    made: list[dict] = []
    real = anthropic.Anthropic

    def capture(**kwargs):
        made.append(kwargs)
        return real(**kwargs)

    codes = (400, 401, 403, 404, 408, 409, 422, 429, 500, 502, 503, 504)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(anthropic, "Anthropic", capture)
        claude = anthropic_client._build("sk-ant-" + "x" * 24, 30.0, DEFAULT_SDK_RETRIES)
    assert made[0]["max_retries"] == DEFAULT_SDK_RETRIES == 2
    for sdk in (claude, openai.OpenAI(api_key="sk-" + "x" * 24, max_retries=DEFAULT_SDK_RETRIES)):
        retried = {code for code in codes if sdk._should_retry(httpx2.Response(code))}
        assert retried == {408, 409, 429, 500, 502, 503, 504}
        assert sdk.max_retries == 2
    assert page.RETRY_RULES["openai"] == page.RETRY_RULES["claude"] == "status 408, 409, 429, or 500 and above"


def test_the_gemini_sdk_retries_what_the_page_says() -> None:
    from google.genai import _api_client

    from aegisshield.llm import gemini_client

    client = gemini_client._build("AIza" + "Q" * 35, 30.0, DEFAULT_SDK_RETRIES)
    retry = client._api_client._http_options.retry_options
    assert retry.attempts == 1 + DEFAULT_SDK_RETRIES and not retry.http_status_codes
    assert _api_client._RETRY_HTTP_STATUS_CODES == (408, 429, 500, 502, 503, 504)
    assert page.RETRY_RULES["gemini"] == "status 408, 429, 500, 502, 503, or 504"


def test_the_bedrock_client_retries_what_the_page_says() -> None:
    from botocore.retries import standard

    from aegisshield.llm import bedrock_client
    from aegisshield.llm.providers import Credential

    cred = Credential(api_key=VISITOR_BEARER, region="us-east-1")
    client = bedrock_client._client(cred, "bedrock-runtime", 30.0, DEFAULT_SDK_RETRIES)
    retries = client.meta.config.retries
    assert retries == {"total_max_attempts": 1 + DEFAULT_SDK_RETRIES, "mode": "standard"}
    assert standard.TransientRetryableChecker._TRANSIENT_STATUS_CODES == [500, 502, 503, 504]
    assert standard.ThrottlingStatusCodeChecker._THROTTLING_STATUS_CODES == [429]
    assert "ThrottlingException" in standard.ThrottledRetryableChecker._THROTTLED_ERROR_CODES
    assert page.RETRY_RULES["bedrock"] == "a throttling error (status 429) or status 500, 502, 503, or 504"
