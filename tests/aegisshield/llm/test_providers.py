import importlib.util
import logging
from dataclasses import replace

import pytest

from aegisshield import config
from aegisshield.config import Settings
from aegisshield.core.errors import LLMError
from aegisshield.llm import providers
from aegisshield.llm.base import ERROR_LIST_FAILED, ModelInfo
from aegisshield.llm.providers import (
    BEDROCK_REGIONS,
    ERROR_PROVIDER_UNAVAILABLE,
    MAX_MODELS,
    Credential,
    Provider,
    answered_by,
    answered_by_words,
    clean_models,
    credential_fields,
    missing_credential,
    offered_providers,
    preselected_model,
    provider_label,
    sdk_available,
    valid_model_id,
)

from .provider_fakes import (
    CLAUDE_KEY,
    GEMINI_KEY,
    OPENAI_KEY,
    VISITOR_KEY_ID,
    VISITOR_SECRET,
    FakeAnthropic,
    FakeBedrock,
    FakeGenai,
    FakeOpenAIModels,
    anthropic_status_error,
    assert_not_leaked,
    claude_model,
    foundation_model,
    gemini_model,
)

BEDROCK = Credential(access_key_id=VISITOR_KEY_ID, secret_access_key=VISITOR_SECRET,
                     region="us-east-1")


def test_provider_values_match_config():
    assert tuple(p.value for p in Provider) == config.PROVIDER_NAMES


def test_credential_shows_nothing():
    cred = Credential(api_key=CLAUDE_KEY, access_key_id=VISITOR_KEY_ID,
                      secret_access_key=VISITOR_SECRET, session_token="tok" + "en" * 10,
                      region="us-east-1")
    assert repr(cred) == str(cred) == "Credential()"
    assert f"{cred}" == "Credential()" and f"{cred!r}" == "Credential()"
    for value in (CLAUDE_KEY, VISITOR_KEY_ID, VISITOR_SECRET):
        assert value not in repr(cred) and value not in str([cred])


def test_credential_fields():
    assert credential_fields("claude") == ("api_key",)
    assert credential_fields(Provider.BEDROCK) == ("access_key_id", "secret_access_key", "region")


@pytest.mark.parametrize("provider", ["claude", "openai", "gemini"])
def test_missing_api_key(provider):
    assert "key" in missing_credential(provider, None)
    assert "key" in missing_credential(provider, Credential(api_key="   "))
    assert missing_credential(provider, Credential(api_key="k")) is None


@pytest.mark.parametrize(("cred", "word"), [
    (Credential(secret_access_key="s", region="us-east-1"), "access key ID"),
    (Credential(access_key_id="a", region="us-east-1"), "secret access key"),
    (Credential(access_key_id="a", secret_access_key="s"), "region"),
    (Credential(access_key_id="a", secret_access_key="s", region="mars-north-1"), "region"),
])
def test_missing_bedrock_field(cred, word):
    assert word in missing_credential("bedrock", cred)


@pytest.mark.parametrize("cred", [None, Credential(), Credential(region="us-east-1"),
                                  Credential(api_key="  ", session_token="t", region="us-east-1")])
def test_bedrock_with_nothing_names_both_ways(cred):
    sentence = missing_credential("bedrock", cred)
    assert sentence == ("Add a Bedrock API key, or an AWS access key ID and secret access key, "
                        "for Amazon Bedrock to run this step.")


@pytest.mark.parametrize("region", ["", "mars-north-1"])
def test_bedrock_api_key_needs_a_region(region):
    sentence = missing_credential("bedrock", Credential(api_key="k", region=region))
    assert sentence == "Choose an AWS region for Amazon Bedrock to run this step."


def test_bedrock_api_key_is_complete_with_a_region():
    assert missing_credential("bedrock", Credential(api_key="k", region="us-east-1")) is None
    # The key wins, so half a pair of access keys beside it does not matter.
    assert missing_credential("bedrock", Credential(api_key="k", access_key_id="a",
                                                    region="us-east-1")) is None
    assert providers.bedrock_uses_api_key(Credential(api_key="k", access_key_id="a",
                                                     secret_access_key="s"))
    assert not providers.bedrock_uses_api_key(Credential(api_key=" ", access_key_id="a"))
    assert not providers.bedrock_uses_api_key(None)


def test_complete_bedrock_credential():
    assert missing_credential("bedrock", BEDROCK) is None
    assert missing_credential("bedrock", replace(BEDROCK, region=" us-west-2 ")) is None


def test_bedrock_regions_sorted_and_unique():
    assert list(BEDROCK_REGIONS) == sorted(set(BEDROCK_REGIONS))


def test_provider_label():
    assert provider_label("claude") == "Claude (Anthropic)"
    assert provider_label("mock") == providers.MOCK_WORDS
    assert provider_label("nope") == "Unknown provider"


@pytest.mark.parametrize("provider", list(Provider))
def test_sdk_available(provider):
    assert sdk_available(provider) is True


def test_sdk_unavailable(monkeypatch):
    monkeypatch.setattr(importlib.util, "find_spec", lambda _name: None)
    assert not any(sdk_available(p) for p in Provider)

    def broken(_name):
        raise ImportError("broken install")

    monkeypatch.setattr(importlib.util, "find_spec", broken)
    assert not any(sdk_available(p) for p in Provider)
    assert sdk_available("not-a-provider") is False


def test_offered_providers_in_page_order():
    settings = replace(Settings(), providers=("gemini", "claude"))
    assert offered_providers(settings) == (Provider.CLAUDE, Provider.GEMINI)
    assert offered_providers(Settings()) == tuple(Provider)


# ---------------------------------------------------------------- cleaning


@pytest.mark.parametrize("bad", [
    "<script>alert(1)</script>", "has space", "line\nbreak", "path/model", 'q"uote',
    "a" * 129, "", "-leading", ".leading", "tab\tid", "ünïcode", None, 5,
])
def test_hostile_ids_dropped(bad):
    assert not valid_model_id(bad)
    assert clean_models([ModelInfo(bad), ModelInfo("ok-1", True)]) == (ModelInfo("ok-1", True),)


@pytest.mark.parametrize("good", ["gpt-5.4", "anthropic.example-v1:0", "us.a.b-v2:0",
                                  "gemini_x", "a" * 128, "9lives"])
def test_good_ids_kept(good):
    assert valid_model_id(good)


def test_clean_models_dedupes_sorts_and_bounds():
    found = [ModelInfo("b", True), ModelInfo("a", None), ModelInfo("b", False), "junk",
             ModelInfo("c", "yes")]
    assert clean_models(found) == (ModelInfo("a", None), ModelInfo("b", True),
                                   ModelInfo("c", None))
    many = clean_models(ModelInfo(f"m{n:03d}") for n in range(500))
    assert len(many) == MAX_MODELS
    assert many[0].id == "m000" and many[-1].id == f"m{MAX_MODELS - 1:03d}"


# ----------------------------------------------------------------- listing


def test_list_models_cleans_the_provider_list():
    fake = FakeOpenAIModels(["gpt-b", "gpt-<script>", "gpt-a", "gpt-a", "gpt-has space",
                             "gpt-" + "x" * 130, "whisper-1"])
    found = providers.list_models("openai", Credential(api_key=OPENAI_KEY), sdk_client=fake)
    assert found == (ModelInfo("gpt-a"), ModelInfo("gpt-b"))


@pytest.mark.parametrize(("provider", "cred", "fake", "expected"), [
    ("claude", Credential(api_key=CLAUDE_KEY),
     FakeAnthropic(models=[claude_model("claude-x", True)]), (ModelInfo("claude-x", True),)),
    ("gemini", Credential(api_key=GEMINI_KEY),
     FakeGenai(models=[gemini_model("models/g-1")]), (ModelInfo("g-1"),)),
    ("bedrock", BEDROCK, FakeBedrock([foundation_model("a.b-v1:0")]),
     (ModelInfo("a.b-v1:0", False),)),
])
def test_list_models_each_provider(provider, cred, fake, expected):
    assert providers.list_models(provider, cred, sdk_client=fake) == expected


@pytest.mark.parametrize("provider", list(Provider))
def test_list_models_missing_credential(provider):
    with pytest.raises(LLMError) as info:
        providers.list_models(provider, Credential())
    assert str(info.value) == missing_credential(provider, Credential())


def test_list_models_sdk_missing(monkeypatch):
    monkeypatch.setattr(providers, "sdk_available", lambda _p: False)
    with pytest.raises(LLMError) as info:
        providers.list_models("claude", Credential(api_key=CLAUDE_KEY))
    assert str(info.value) == ERROR_PROVIDER_UNAVAILABLE


def test_list_models_failure_hides_key(caplog):
    caplog.set_level(logging.DEBUG)
    fake = FakeAnthropic(list_error=anthropic_status_error(401, CLAUDE_KEY))
    with pytest.raises(LLMError) as info:
        providers.list_models("claude", Credential(api_key=CLAUDE_KEY), sdk_client=fake)
    assert str(info.value) == ERROR_LIST_FAILED
    assert_not_leaked(CLAUDE_KEY, exc=info.value, records=caplog.records)


# ------------------------------------------------------------ preselection


def test_preselected_model():
    settings = Settings()
    listed = [ModelInfo(settings.architect_model), ModelInfo(config.PRESELECTED_CLAUDE_MODEL),
              ModelInfo("other")]
    assert preselected_model("openai", listed, settings) == settings.architect_model
    assert preselected_model("claude", listed, settings) == config.PRESELECTED_CLAUDE_MODEL
    assert preselected_model("bedrock", listed, settings) is None
    assert preselected_model("gemini", listed, settings) is None
    assert preselected_model("openai", [ModelInfo("other")], settings) is None
    assert preselected_model("claude", [ModelInfo("other")], settings) is None


# ------------------------------------------------------------- answered by


def test_answered_by():
    assert answered_by(replace(Settings(), mock_llm=True)) == {"provider": "mock", "name": "mock"}
    settings = config.with_model_choice(Settings(), provider="claude", model="claude-x")
    assert answered_by(settings) == {"provider": "claude", "name": "claude-x"}


@pytest.mark.parametrize(("record", "words"), [
    ({"provider": "claude", "name": "claude-x"}, "Claude (Anthropic), claude-x"),
    ({"provider": "bedrock", "name": "us.a.b-v1:0"}, "Amazon Bedrock, us.a.b-v1:0"),
    ({"provider": "mock", "name": "mock"}, providers.MOCK_WORDS),
    (None, None),
    ({}, None),
    ("claude", None),
    ({"provider": "acme", "name": "m"}, None),
    ({"provider": "openai", "name": "<b>bold</b>"}, None),
    ({"provider": "openai", "name": 5}, None),
    ({"provider": "openai"}, None),
])
def test_answered_by_words(record, words):
    assert answered_by_words(record) == words


def test_an_unexpected_listing_error_is_the_fixed_sentence(monkeypatch, caplog):
    """An error outside the SDK's own classes still shows only the fixed
    sentence, with no cause chain, and its message is not logged."""
    import logging

    from aegisshield.core.errors import LLMError
    from aegisshield.llm import openai_models, providers
    from aegisshield.llm.base import ERROR_LIST_FAILED

    planted = "sk-" + "proj-" + "q" * 30

    def broken(*_args, **_kwargs):
        raise ValueError(f"unexpected shape near {planted}")

    monkeypatch.setattr(openai_models, "list_models", broken)
    caplog.set_level(logging.DEBUG)
    with pytest.raises(LLMError) as caught:
        providers.list_models("openai", providers.Credential(api_key="k"), sdk_client=object())
    assert str(caught.value) == ERROR_LIST_FAILED
    assert caught.value.__cause__ is None and caught.value.__suppress_context__
    assert all(planted not in r.getMessage() for r in caplog.records)
    assert any("kind=ValueError" in r.getMessage() for r in caplog.records)
