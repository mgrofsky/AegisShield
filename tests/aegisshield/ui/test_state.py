"""Session-state accessors: keys, settings, workspace, jobs, deep links."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
import streamlit as st

from aegisshield.config import AVAILABLE_MODELS
from aegisshield.core.errors import JobError
from aegisshield.jobs.runner import JobRunner
from aegisshield.llm import providers
from aegisshield.storage import FileStore, Workspace
from aegisshield.storage.stores import MappingStore
from aegisshield.ui import state
from aegisshield.ui.state import ApiKey
from tests.aegisshield.ui.conftest import REAL_SECRET


@pytest.fixture
def session(monkeypatch: pytest.MonkeyPatch) -> dict:
    fake: dict = {}
    monkeypatch.setattr(st, "session_state", fake)
    return fake


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> JobRunner:
    r = JobRunner(max_concurrent_jobs=4, job_timeout_seconds=30)
    monkeypatch.setattr(state, "get_runner", lambda: r)
    return r


# ---------------------------------------------------------------- keys


def test_keys_live_in_session_only(session: dict) -> None:
    assert state.get_api_key(ApiKey.OPENAI) == ""
    assert state.key_source("openai") == "none"
    assert state.set_api_key("openai", "  sk-test \n") is True
    assert state.get_api_key("openai") == "sk-test"
    assert state.key_source(ApiKey.OPENAI) == "session"
    state.clear_api_key("openai")
    assert state.get_api_key("openai") == ""


def test_empty_or_non_string_key_is_not_stored(session: dict) -> None:
    assert state.set_api_key("nvd", "   ") is False
    assert state.set_api_key("nvd", None) is False  # type: ignore[arg-type]
    assert state.key_source("nvd") == "none"


def test_operator_secrets_back_nvd_and_otx_only(session: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    secrets = {"nvd_api_key": "op-nvd", "alienvault_api_key": "op-otx", "openai_api_key": "op-oa"}
    monkeypatch.setattr(state, "_secret", lambda name: secrets.get(name, ""))
    assert state.get_api_key("nvd") == "op-nvd" and state.key_source("nvd") == "operator"
    assert state.get_api_key("otx") == "op-otx"
    assert state.get_api_key("openai") == ""  # never from secrets
    state.set_api_key("nvd", "mine")
    assert state.get_api_key("nvd") == "mine"
    state.clear_api_key("nvd")
    assert state.get_api_key("nvd") == "op-nvd"


def test_secret_reader_handles_a_missing_secrets_file(monkeypatch: pytest.MonkeyPatch) -> None:
    class Missing:
        def get(self, name):
            raise FileNotFoundError("no secrets.toml")

    class Present:
        def get(self, name):
            return {"nvd_api_key": " abc ", "number": 5}.get(name)

    monkeypatch.setattr(st, "secrets", Missing())
    assert REAL_SECRET("nvd_api_key") == ""
    monkeypatch.setattr(st, "secrets", Present())
    assert REAL_SECRET("nvd_api_key") == "abc"
    assert REAL_SECRET("number") == ""
    assert REAL_SECRET("other") == ""


def test_key_input_callback_stores_and_empties_the_widget(session: dict) -> None:
    widget = state.KEY_INPUT_WIDGETS[ApiKey.OTX]
    session[widget] = "otx-key"
    state.key_input_changed(ApiKey.OTX)
    assert session[widget] == ""
    assert state.get_api_key("otx") == "otx-key"
    assert state.consume_flash() == ("OTX key saved for this session.", "ok")
    assert state.consume_flash() is None


def test_key_input_callback_ignores_blank(session: dict) -> None:
    session[state.KEY_INPUT_WIDGETS[ApiKey.OPENAI]] = "  "
    state.key_input_changed("openai")
    assert state.key_source("openai") == "none" and state.consume_flash() is None


def test_have_llm(session: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    assert state.have_llm() is False
    assert state.llm_blocker() == "Add an OpenAI API key to run this step."
    state.set_api_key("openai", "sk")
    # A key alone is not enough: the model must come from the provider's list.
    assert state.llm_blocker() == providers.ERROR_NO_MODEL
    state.refresh_models("openai")
    assert state.have_llm() is True  # the configured default is listed
    state.clear_api_key("openai")
    monkeypatch.setenv("AEGIS_MOCK_LLM", "1")
    assert state.have_llm() is True


# ------------------------------------------------------- model, agentic


def test_model_and_agentic(session: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    assert state.selected_model() == ""
    state.set_api_key("openai", "sk")
    with pytest.raises(ValueError):  # nothing listed yet
        state.set_selected_model(AVAILABLE_MODELS[0])
    state.refresh_models("openai")
    assert state.selected_model() == AVAILABLE_MODELS[0]
    with pytest.raises(ValueError):
        state.set_selected_model("not-a-model")
    session[state.MODEL_WIDGET] = "test-chat-b"
    state.model_widget_changed()
    assert state.selected_model() == "test-chat-b"
    session[state.MODEL_WIDGET] = "not-listed"
    state.model_widget_changed()  # refused and logged; the choice stays
    assert state.selected_model() == "test-chat-b"
    session["aegis_model"] = {"openai": "something-else"}
    assert state.selected_model() == AVAILABLE_MODELS[0]

    assert state.agentic_enabled() is False
    monkeypatch.setenv("AEGIS_AGENTIC", "1")
    assert state.agentic_enabled() is True
    session[state.AGENTIC_WIDGET] = False
    state.agentic_widget_changed()
    # The operator's AEGIS_AGENTIC wins: every run is agentic (use_agentic).
    assert state.agentic_enabled() is True


# ------------------------------------------------------------ workspace


def test_workspace_in_session_by_default(session: dict) -> None:
    assert isinstance(state.workspace_store(), MappingStore)
    ws = state.get_workspace()
    ws.add("threat_models", "Checkout", {})
    assert state.get_workspace() is ws
    state.save_workspace(Workspace())
    assert state.get_workspace().list("threat_models") == []


def test_workspace_on_disk_with_data_dir(session: dict, tmp_path: Path,
                                         monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path))
    assert isinstance(state.workspace_store(), FileStore)
    ws = state.get_workspace()
    ws.add("policies", "Access control", {})
    state.save_workspace(ws)
    assert [r.title for r in state.get_workspace().list("policies")] == ["Access control"]
    assert "aegis_workspace" not in session


def test_import_uploader_key_rotates(session: dict) -> None:
    first = state.import_uploader_key()
    state.rotate_import_uploader()
    assert state.import_uploader_key() != first


def test_flash_ignores_bad_values(session: dict) -> None:
    session["aegis_flash"] = "not a tuple"
    assert state.consume_flash() is None


# ----------------------------------------------------------------- jobs


def test_one_running_job_per_kind(session: dict, runner: JobRunner) -> None:
    release = threading.Event()
    job_id = state.start_job("threat_model", lambda p: (release.wait(5), {"ok": True})[1])
    assert state.active_job_id("threat_model") == job_id
    assert state.is_job_running("threat_model")
    with pytest.raises(JobError):
        state.start_job("threat_model", lambda p: {})
    other = state.start_job("policy", lambda p: {})  # another kind is fine
    assert other != job_id
    release.set()
    _wait_done(runner, job_id)
    assert not state.is_job_running("threat_model")
    assert state.job_snapshot("threat_model").result == {"ok": True}
    again = state.start_job("threat_model", lambda p: {})  # finished one is replaced
    assert again != job_id and runner.snapshot(job_id) is None


def test_start_job_hands_the_runner_every_secret_the_session_holds(session: dict, runner: JobRunner,
                                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}
    real = runner.submit

    def spy(fn, **kwargs):
        seen.update(kwargs)
        return real(fn, **kwargs)

    monkeypatch.setattr(runner, "submit", spy)
    state.set_api_key(state.ApiKey.NVD, "nvd-key-value-1234")
    state.set_api_key(state.ApiKey.OTX, "otx-key-value-5678")
    state.set_api_key(state.ApiKey.OPENAI, "sk-openai-value")
    state.set_credential_field("bedrock", "access_key_id", "AKIA-value")
    state.set_credential_field("bedrock", "secret_access_key", "aws-secret-value")
    state.set_credential_field("claude", "api_key", "claude-key-value")
    _wait_done(runner, state.start_job("lookup", lambda p: {}))
    assert set(seen["secrets"]) == {"nvd-key-value-1234", "otx-key-value-5678", "sk-openai-value",
                                     "AKIA-value", "aws-secret-value", "claude-key-value"}


def test_forget_and_evicted_jobs(session: dict, runner: JobRunner) -> None:
    assert state.active_job_id("lookup") is None
    job_id = state.start_job("lookup", lambda p: {})
    _wait_done(runner, job_id)
    runner.discard(job_id)
    assert state.active_job_id("lookup") is None  # evicted: forgotten
    assert state.job_snapshot("lookup") is None
    state.start_job("lookup", lambda p: {})
    state.forget_job("lookup")
    assert state.active_job_id("lookup") is None
    state.forget_job("lookup")  # nothing to forget


def test_jobs_store_is_rebuilt_if_corrupted(session: dict, runner: JobRunner) -> None:
    session["aegis_jobs"] = "bad"
    assert state.active_job_id("x") is None


def _wait_done(runner: JobRunner, job_id: str) -> None:
    for _ in range(200):
        snap = runner.snapshot(job_id)
        if snap is None or snap.done:
            return
        threading.Event().wait(0.01)
    raise AssertionError("job did not finish")


# ----------------------------------------------------------- deep links


@pytest.mark.parametrize(("params", "expected"), [
    ({"id": "abcDEF_12-3"}, "abcDEF_12-3"),
    ({}, None),
    ({"id": ""}, None),
    ({"id": "../etc"}, None),
    ({"id": "<script>"}, None),
    ({"id": "x" * 65}, None),
])
def test_requested_record_id(monkeypatch: pytest.MonkeyPatch, params: dict, expected) -> None:
    monkeypatch.setattr(st, "query_params", params)
    assert state.requested_record_id() == expected


def test_agentic_enabled_follows_the_operator_first(monkeypatch) -> None:
    import streamlit as st

    from aegisshield.ui import state

    session: dict = {}
    monkeypatch.setattr(st, "session_state", session)
    monkeypatch.delenv("AEGIS_AGENTIC", raising=False)
    assert state.agentic_enabled() is False and state.agentic_locked_on() is False
    state.set_agentic(True)
    assert state.agentic_enabled() is True
    state.set_agentic(False)
    monkeypatch.setenv("AEGIS_AGENTIC", "1")
    assert state.agentic_locked_on() is True and state.agentic_enabled() is True


# ------------------------------------------------- provider and credential


def test_provider_choice_and_offer(session: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    assert state.selected_provider().value == "openai"
    state.set_provider("bedrock")
    assert state.selected_provider().value == "bedrock"
    monkeypatch.setenv("AEGIS_PROVIDERS", "claude,gemini")
    # Neither Bedrock nor OpenAI is offered now, so the first offered one is chosen.
    assert state.selected_provider().value == "claude"
    with pytest.raises(ValueError):
        state.set_provider("openai")
    session[state.PROVIDER_WIDGET] = "openai"
    state.provider_widget_changed()  # refused and logged
    assert state.selected_provider().value == "claude"
    session[state.PROVIDER_WIDGET] = "gemini"
    state.provider_widget_changed()
    assert state.selected_provider().value == "gemini"


def test_credential_fields_are_cleaned_held_and_cleared(session: dict) -> None:
    secret = "AKIA" + "TESTVISITOR00001"
    assert state.set_credential_field("bedrock", "access_key_id", f"  {secret}\n") is True
    assert state.set_credential_field("bedrock", "secret_access_key", "s e c") is True
    assert state.set_credential_field("bedrock", "region", "mars-north-1") is False
    assert state.set_credential_field("bedrock", "region", " us-east-1 ") is True
    assert state.set_credential_field("bedrock", "no_such_field", "x") is False
    assert state.set_credential_field("bedrock", "session_token", "   ") is False
    assert state.set_credential_field("openai", "access_key_id", "x") is False
    cred = state.credential("bedrock")
    assert (cred.access_key_id, cred.secret_access_key, cred.region) == (secret, "sec", "us-east-1")
    assert secret not in repr(cred) and secret not in str(cred)
    assert state.credential_is_set("bedrock", "region")
    state.refresh_models("bedrock")
    assert state.model_listing("bedrock") is not None
    state.set_credential_field("bedrock", "secret_access_key", "changed")
    assert state.model_listing("bedrock") is None  # a new credential asks again
    state.clear_credential("bedrock")
    assert state.credential("bedrock").access_key_id == ""
    state.clear_credential("bedrock")  # clearing twice is harmless


def test_credential_input_empties_the_widget(session: dict) -> None:
    widget = state.CREDENTIAL_WIDGETS[("claude", "api_key")]
    session[widget] = "test-claude-key"
    state.credential_input_changed("claude", "api_key")
    assert session[widget] == ""
    assert state.credential("claude").api_key == "test-claude-key"
    assert state.consume_flash() == ("Claude (Anthropic) API key saved for this session.", "ok")
    session[state.REGION_WIDGET] = "eu-west-1"
    state.region_widget_changed()
    assert state.credential("bedrock").region == "eu-west-1"


def test_listing_cache_ttl_force_and_failure(session: dict, model_lists) -> None:
    state.set_provider("gemini")
    assert state.refresh_models("gemini") is None  # no key: not asked
    state.set_credential_field("gemini", "api_key", "test-gemini-key")
    first = state.refresh_models("gemini", now=1000.0)
    assert state.refresh_models("gemini", now=1000.0 + state.MODEL_LIST_TTL_SECONDS - 1) is first
    state.refresh_models("gemini", now=1000.0 + state.MODEL_LIST_TTL_SECONDS)
    assert model_lists.calls == ["gemini", "gemini"]
    model_lists.failing.add("gemini")
    failed = state.refresh_models("gemini", force=True, now=5000.0)
    assert failed["failed"] is True and failed["models"] == ()
    assert state.refresh_models("gemini", now=9999.0) is failed  # a failure waits for a refresh
    assert state.model_choice() is None
    assert state.llm_blocker() == providers.ERROR_NO_MODEL
    assert "ModelChoice" in repr(state.ModelChoice("gemini", "m", None))


def test_choice_and_settings_carry_the_model(session: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    state.set_provider("bedrock")
    for field, value in (("access_key_id", "id"), ("secret_access_key", "s"), ("region", "us-east-1")):
        state.set_credential_field("bedrock", field, value)
    state.refresh_models("bedrock")
    assert state.model_choice() is None  # Bedrock preselects nothing
    assert state.get_settings().architect_model == ""
    state.set_model_choice("bedrock", "us.test.vision-model-v1:0")
    settings = state.get_settings()
    assert (settings.provider, settings.architect_model, settings.worker_model, settings.model_vision) == (
        "bedrock", "us.test.vision-model-v1:0", "us.test.vision-model-v1:0", True)
    with pytest.raises(ValueError):
        state.set_model_choice("bedrock", "anthropic.not-listed-v1:0")
    monkeypatch.setattr(providers, "sdk_available", lambda _p: False)
    assert state.llm_blocker() == providers.ERROR_PROVIDER_UNAVAILABLE


def test_bedrock_api_key_is_a_secret_field_and_wins(session: dict, model_lists) -> None:
    key = "ABSK" + "QmVkcm9ja0FQSUtleS" + "stateTest+/" * 6 + "="
    widget = state.CREDENTIAL_WIDGETS[("bedrock", "api_key")]
    session[widget] = f" {key} "
    state.credential_input_changed("bedrock", "api_key")
    assert session[widget] == ""
    assert state.consume_flash() == ("Amazon Bedrock API key saved for this session.", "ok")
    assert state.credential("bedrock").api_key == key
    assert key not in repr(state.credential("bedrock"))
    state.set_provider("bedrock")
    assert state.llm_blocker() == "Choose an AWS region for Amazon Bedrock to run this step."
    state.set_credential_field("bedrock", "region", "us-east-1")
    assert state.llm_blocker() == providers.ERROR_NO_MODEL
    # Access keys beside the key are held but not used.
    state.set_credential_field("bedrock", "access_key_id", "id")
    assert state.bedrock_auth() == state.BEDROCK_AUTH_API_KEY
    state.refresh_models("bedrock")
    assert state.model_listing("bedrock") is not None
    state.clear_credential_field("bedrock", "api_key")
    assert state.credential("bedrock").api_key == ""
    assert state.credential("bedrock").access_key_id == "id"
    assert state.model_listing("bedrock") is None  # a changed credential asks again
    state.clear_credential_field("bedrock", "region")  # not a secret field: kept
    assert state.credential("bedrock").region == "us-east-1"
    state.clear_credential("bedrock")
    assert state.credential("bedrock").api_key == ""


def test_bedrock_auth_choice(session: dict) -> None:
    assert state.bedrock_auth() == state.BEDROCK_AUTH_ACCESS_KEYS  # nothing held
    state.set_credential_field("bedrock", "api_key", "k")
    assert state.bedrock_auth() == state.BEDROCK_AUTH_API_KEY  # follows what is held
    session[state.BEDROCK_AUTH_WIDGET] = state.BEDROCK_AUTH_ACCESS_KEYS
    state.bedrock_auth_widget_changed()
    assert state.bedrock_auth() == state.BEDROCK_AUTH_ACCESS_KEYS  # the visitor's choice
    session[state.BEDROCK_AUTH_WIDGET] = "something else"
    state.bedrock_auth_widget_changed()
    assert state.bedrock_auth() == state.BEDROCK_AUTH_ACCESS_KEYS  # refused, kept
    assert state.credential("bedrock").api_key == "k"  # choosing never clears a value
