"""``tools/provider_smoke.py`` with fake listing and client (the real check
runs only when a developer passes ``--real`` with a credential)."""

from __future__ import annotations

import io
import logging

import pytest

from aegisshield.core.errors import LLMError
from aegisshield.llm.base import ModelInfo
from aegisshield.llm.providers import Credential, Provider
from tools import provider_smoke

from .provider_fakes import VISITOR_BEARER

ENV = {"AEGIS_SMOKE_BEDROCK_API_KEY": VISITOR_BEARER, "AEGIS_SMOKE_BEDROCK_REGION": "us-east-1",
       "AWS_BEARER_TOKEN_BEDROCK": "server-token-not-read"}


class FakeClient:
    def __init__(self, answer="Hello.", error=None):
        self.answer, self.error, self.calls = answer, error, []

    def chat_text(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.answer


MODELS = (ModelInfo("a.text-v1:0"), ModelInfo("b.text-v1:0"))


class Fakes:
    def __init__(self, models=MODELS, client=None, list_error=None):
        self.models, self.client, self.list_error = models, client or FakeClient(), list_error
        self.listed, self.built = [], []

    def list_models(self, provider, cred):
        self.listed.append((provider, cred))
        if self.list_error:
            raise self.list_error
        return self.models

    def get_llm(self, settings, cred):
        self.built.append((settings, cred))
        return self.client


def _run(argv, env=ENV, fakes=None):
    fakes = fakes or Fakes()
    out = io.StringIO()
    code = provider_smoke.main(argv, stdout=out, env=env, list_models=fakes.list_models,
                               get_llm=fakes.get_llm)
    return code, out.getvalue(), fakes


def test_refuses_without_real():
    code, text, fakes = _run(["--provider", "bedrock"])
    assert code == 2 and text.strip() == provider_smoke.NEEDS_REAL
    assert fakes.listed == [] and fakes.built == []


def test_help_states_the_cost(capsys):
    with pytest.raises(SystemExit):
        provider_smoke.main(["--help"])
    help_text = capsys.readouterr().out
    assert "Cost:" in help_text and "64" in help_text and "--real" in help_text
    assert "AEGIS_SMOKE_BEDROCK_API_KEY" in help_text


def test_bedrock_pass_with_the_key_from_its_own_variables(caplog):
    caplog.set_level(logging.DEBUG)
    code, text, fakes = _run(["--provider", "bedrock", "--real"])
    assert code == 0
    assert "provider: Amazon Bedrock" in text and "model: a.text-v1:0" in text
    assert "models listed: 2" in text and "result: pass" in text
    assert "token counts: not reported" in text
    (provider, cred), = fakes.listed
    assert provider is Provider.BEDROCK
    assert (cred.api_key, cred.region) == (VISITOR_BEARER, "us-east-1")
    settings, built_cred = fakes.built[0]
    assert (settings.provider, settings.architect_model, settings.mock_llm) == (
        "bedrock", "a.text-v1:0", False)
    assert built_cred is cred
    (call,) = fakes.client.calls
    assert call["max_tokens"] == 64 and call["model"] == "a.text-v1:0"
    assert VISITOR_BEARER not in text and VISITOR_BEARER not in caplog.text


def test_model_from_its_variable_must_be_listed():
    env = {**ENV, "AEGIS_SMOKE_BEDROCK_MODEL": "b.text-v1:0"}
    code, text, _ = _run(["--provider", "bedrock", "--real"], env=env)
    assert code == 0 and "model: b.text-v1:0" in text
    env = {**ENV, "AEGIS_SMOKE_BEDROCK_MODEL": "not.listed-v1:0"}
    code, text, fakes = _run(["--provider", "bedrock", "--real"], env=env)
    assert code == 1 and "result: fail" in text and fakes.built == []


def test_empty_list_fails():
    code, text, _ = _run(["--provider", "bedrock", "--real"], fakes=Fakes(models=()))
    assert code == 1 and "none usable" in text


def test_empty_answer_fails():
    code, text, _ = _run(["--provider", "bedrock", "--real"], fakes=Fakes(client=FakeClient("  ")))
    assert code == 1 and "result: fail" in text


@pytest.mark.parametrize(("error", "shown"), [
    (LLMError("The model provider did not answer."), "The model provider did not answer."),
    (RuntimeError(f"boom {VISITOR_BEARER}"), "RuntimeError"),
])
def test_failures_show_the_sentence_or_class_only(caplog, error, shown):
    caplog.set_level(logging.DEBUG)
    code, text, _ = _run(["--provider", "bedrock", "--real"],
                         fakes=Fakes(client=FakeClient(error=error)))
    assert code == 1 and f"error: {shown}" in text and "result: fail" in text
    assert VISITOR_BEARER not in text and VISITOR_BEARER not in caplog.text


def test_listing_failure_is_reported():
    code, text, fakes = _run(["--provider", "bedrock", "--real"],
                             fakes=Fakes(list_error=LLMError("listing failed")))
    assert code == 1 and "error: listing failed" in text and fakes.built == []


def test_other_providers_read_their_own_variable():
    env = {"AEGIS_SMOKE_CLAUDE_API_KEY": "test-claude-key"}
    code, _, fakes = _run(["--provider", "claude", "--real"], env=env)
    assert code == 0
    assert fakes.listed[0][1].api_key == "test-claude-key" and fakes.listed[0][1].region == ""
    assert provider_smoke.credential_from_env(Provider.GEMINI, {}) == Credential()


def test_uses_the_apps_own_functions_by_default(monkeypatch):
    from aegisshield.llm import factory, providers

    seen = []
    monkeypatch.setattr(providers, "list_models", lambda p, c: seen.append("list") or ())
    monkeypatch.setattr(factory, "get_llm", lambda s, c: seen.append("build"))
    out = io.StringIO()
    assert provider_smoke.main(["--provider", "bedrock", "--real"], stdout=out, env=ENV) == 1
    assert seen == ["list"]
