from pathlib import Path

import pytest

import aegisshield
from aegisshield.config import (
    AVAILABLE_MODELS,
    DEFAULT_MODEL_NAME,
    Settings,
    get_settings,
)


def test_version():
    assert isinstance(aegisshield.__version__, str)


def test_model_list_matches_top_level_config():
    assert AVAILABLE_MODELS == ("gpt-5.4",)
    assert DEFAULT_MODEL_NAME == "gpt-5.4"


def test_defaults_with_empty_env():
    s = get_settings({})
    assert s == Settings()
    assert s.architect_model == s.worker_model == DEFAULT_MODEL_NAME
    assert not (s.mock_llm or s.offline or s.agentic)
    assert s.data_dir is None
    assert s.max_concurrent_jobs == 4
    assert s.job_timeout_seconds == 1800


def test_flags_and_overrides():
    env = {
        "AEGIS_MOCK_LLM": "1",
        "AEGIS_OFFLINE": "true",
        "AEGIS_AGENTIC": "yes",
        "AEGIS_ARCHITECT_MODEL": "gpt-5.4",
        "AEGIS_WORKER_MODEL": " gpt-5.4 ",
        "AEGIS_DATA_DIR": "/tmp/aegis-data",
        "AEGIS_MAX_CONCURRENT_JOBS": "6",
        "AEGIS_JOB_TIMEOUT_SECONDS": "60",
    }
    s = get_settings(env)
    assert s.mock_llm and s.offline and s.agentic
    assert s.worker_model == "gpt-5.4"
    assert s.data_dir == Path("/tmp/aegis-data")
    assert s.max_concurrent_jobs == 6
    assert s.job_timeout_seconds == 60


@pytest.mark.parametrize("value", ["0", "false", "", "maybe"])
def test_flags_off(value):
    assert get_settings({"AEGIS_MOCK_LLM": value}).mock_llm is False


def test_unknown_model_falls_back(caplog):
    s = get_settings({"AEGIS_ARCHITECT_MODEL": "made-up-model"})
    assert s.architect_model == DEFAULT_MODEL_NAME
    assert "AEGIS_ARCHITECT_MODEL" in caplog.text


@pytest.mark.parametrize("value", ["abc", "0", "-3"])
def test_bad_numbers_fall_back(value):
    s = get_settings({"AEGIS_MAX_CONCURRENT_JOBS": value, "AEGIS_JOB_TIMEOUT_SECONDS": value})
    assert s.max_concurrent_jobs == 4
    assert s.job_timeout_seconds == 1800


def test_reads_os_environ_each_call(monkeypatch):
    monkeypatch.setenv("AEGIS_MOCK_LLM", "1")
    assert get_settings().mock_llm is True
    monkeypatch.delenv("AEGIS_MOCK_LLM")
    assert get_settings().mock_llm is False


def test_settings_frozen():
    with pytest.raises(AttributeError):
        get_settings({}).mock_llm = True  # type: ignore[misc]


def test_job_kind_limits_name_the_kinds_the_pages_submit() -> None:
    from aegisshield.ui import state
    from aegisshield.ui.pages import ai_scan, pcap_analysis, policies, vulnerability_lookup

    kinds = {pcap_analysis.JOB_KIND, policies.JOB_KIND, vulnerability_lookup.JOB_KIND,
             state.THREAT_MODEL_JOB, ai_scan.JOB_KIND}
    assert {kind for kind, _ in get_settings({}).job_kind_limits} == kinds


def test_ai_scan_settings() -> None:
    assert get_settings({}).ai_scan is False and get_settings({}).garak_python is None
    s = get_settings({"AEGIS_AI_SCAN": "1", "AEGIS_GARAK_PYTHON": " /opt/garak/bin/python "})
    assert s.ai_scan is True and s.garak_python == "/opt/garak/bin/python"
    assert dict(s.job_kind_limits)["ai_scan"] == 1


# ------------------------------------------------------------- providers


def test_providers_default_to_all_four():
    from aegisshield.config import DEFAULT_PROVIDER, PROVIDER_NAMES

    s = get_settings({})
    assert s.providers == PROVIDER_NAMES == ("claude", "bedrock", "openai", "gemini")
    assert s.provider == DEFAULT_PROVIDER == "openai"
    assert s.model_vision is None
    assert get_settings({"AEGIS_PROVIDERS": "   "}).providers == PROVIDER_NAMES


@pytest.mark.parametrize(("value", "expected"), [
    ("openai", ("openai",)),
    ("gemini, Claude", ("claude", "gemini")),
    (" BEDROCK ,,openai,bedrock", ("bedrock", "openai")),
])
def test_providers_subset_in_page_order(value, expected):
    assert get_settings({"AEGIS_PROVIDERS": value}).providers == expected


def test_unknown_provider_names_ignored(caplog):
    with caplog.at_level("WARNING"):
        s = get_settings({"AEGIS_PROVIDERS": "claude,acme,<b>x</b>"})
    assert s.providers == ("claude",)
    assert "2 unknown" in caplog.text
    assert "acme" not in caplog.text and "<b>" not in caplog.text


@pytest.mark.parametrize("value", ["acme", ",,", "none"])
def test_providers_naming_none_fall_back_to_all(caplog, value):
    from aegisshield.config import PROVIDER_NAMES

    with caplog.at_level("WARNING"):
        assert get_settings({"AEGIS_PROVIDERS": value}).providers == PROVIDER_NAMES


def test_provider_choice_is_never_read_from_env():
    s = get_settings({"AEGIS_PROVIDER": "claude", "AEGIS_ARCHITECT_MODEL": "claude-x"})
    assert s.provider == "openai"
    assert s.architect_model == DEFAULT_MODEL_NAME


def test_with_model_choice():
    from aegisshield.config import with_model_choice

    base = get_settings({"AEGIS_MOCK_LLM": "1", "AEGIS_PROVIDERS": "claude,gemini"})
    s = with_model_choice(base, provider="gemini", model="gemini-x", vision=True)
    assert (s.provider, s.architect_model, s.worker_model, s.model_vision) == (
        "gemini", "gemini-x", "gemini-x", True)
    assert s.mock_llm is True and s.providers == ("claude", "gemini")
    assert base.provider == "openai" and base.architect_model == DEFAULT_MODEL_NAME
    empty = with_model_choice(base, provider="claude", model="")
    assert empty.architect_model == "" and empty.model_vision is None


def test_preselected_claude_model_is_a_constant():
    from aegisshield import config

    assert isinstance(config.PRESELECTED_CLAUDE_MODEL, str) and config.PRESELECTED_CLAUDE_MODEL
