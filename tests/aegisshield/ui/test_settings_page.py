"""The settings page under AppTest: keys, model, workspace export/import/clear."""

from __future__ import annotations

import json

import pytest
from streamlit.testing.v1 import AppTest

from aegisshield.config import DEFAULT_MODEL_NAME, PRESELECTED_CLAUDE_MODEL
from aegisshield.llm import providers as _providers
from aegisshield.llm.base import ERROR_LIST_FAILED, ModelInfo
from aegisshield.storage import Workspace
from aegisshield.ui.pages import settings

# The real listing, kept before the UI fixtures replace it with a fake.
REAL_LIST_MODELS = _providers.list_models


def _esc(text: str) -> str:
    import html

    return html.escape(text)


def _settings_app() -> None:
    import streamlit as st

    from aegisshield.ui import routes
    from aegisshield.ui.pages import settings

    st.navigation(routes.build_navigation(with_tshark=True), position="hidden")
    settings.render()


def _run(**session) -> AppTest:
    at = AppTest.from_function(_settings_app, default_timeout=30)
    for k, v in session.items():
        at.session_state[k] = v
    return at.run()


def _html(at: AppTest) -> str:
    return "\n".join(h.proto.body for h in at.get("html"))


def _workspace(at: AppTest) -> Workspace:
    return at.session_state["aegis_workspace"]


def _button(at: AppTest, key: str):
    return at.button(key=key)


def test_page_renders_sections() -> None:
    at = _run()
    assert not at.exception
    body = _html(at)
    for title in ("Model provider", "Lookup keys", "Threat modeling", "Workspace", "About"):
        assert f'<h2 class="ax-section-title">{title}</h2>' in body
    assert "this browser session only" in body
    assert "Google Fonts" in body and "CISA KEV" in body and "ExploitDB" in body
    provider = at.selectbox(key="aegis_provider_widget")
    assert provider.options == ["Claude (Anthropic)", "Amazon Bedrock", "OpenAI", "Gemini (Google)"]
    assert provider.value == "openai"
    # No credential yet: no model list is asked for and none is shown.
    assert "Add an OpenAI API key to run this step." in "".join(c.value for c in at.caption)
    assert body.count("Not set") >= 3
    assert '<dt>MITRE ATT&amp;CK data</dt><dd class="ax-mono">20.1</dd>' in body
    assert '<dt>MITRE ATLAS data</dt><dd class="ax-mono">2026.10</dd>' in body
    # AGPL section 13: the page offers the source to every visitor.
    assert any("https://github.com/mgrofsky/AegisShield" in c.value and "AGPL" in c.value for c in at.caption)


def test_set_and_clear_a_key(model_lists) -> None:
    at = _run()
    at.text_input(key="aegis_key_input_openai").input("sk-test-123").run()
    assert at.session_state["aegis_key_openai"] == "sk-test-123"
    assert at.text_input(key="aegis_key_input_openai").value == ""
    body = _html(at)
    assert "OpenAI key saved for this session." in body and "sk-test-123" not in body
    assert model_lists.calls == ["openai"]
    box = at.selectbox(key="aegis_model_widget")
    assert box.options == [DEFAULT_MODEL_NAME, "test-chat-b"]
    assert box.value == DEFAULT_MODEL_NAME  # the configured default is preselected
    assert f"OpenAI, {DEFAULT_MODEL_NAME}" in _html(at)
    at.button(key="settings_clear_cred_openai").click().run()
    assert "aegis_key_openai" not in at.session_state
    assert not [b for b in at.selectbox if b.key == "aegis_model_widget"]


def test_session_sentence_without_data_dir() -> None:
    body = _html(_run())
    assert "kept only in this browser session" in body
    assert "shared by everyone" not in body


def _with_openai_key(at: AppTest) -> AppTest:
    at.text_input(key="aegis_key_input_openai").input("sk-test-123").run()
    return at


def test_choosing_a_model_and_refreshing(model_lists) -> None:
    at = _with_openai_key(_run())
    at.selectbox(key="aegis_model_widget").set_value("test-chat-b").run()
    assert at.session_state["aegis_model"] == {"openai": "test-chat-b"}
    assert "OpenAI, test-chat-b" in _html(at)
    # The list is cached in the session: a rerun does not ask again.
    at.run()
    assert model_lists.calls == ["openai"]
    model_lists.models["openai"] = (ModelInfo("test-chat-c"),)
    at.button(key="settings_refresh_models").click().run()
    assert model_lists.calls == ["openai", "openai"]
    box = at.selectbox(key="aegis_model_widget")
    assert box.options == ["test-chat-c"] and box.value is None
    assert settings.CHOOSE_MODEL_SENTENCE in "".join(c.value for c in at.caption)


def test_claude_preselects_its_default_and_bedrock_must_choose(model_lists) -> None:
    at = _run()
    at.selectbox(key="aegis_provider_widget").set_value("claude").run()
    at.text_input(key="aegis_cred_input_claude_api_key").input("test-claude-key").run()
    assert at.selectbox(key="aegis_model_widget").value == PRESELECTED_CLAUDE_MODEL
    body = _html(at)
    assert "test-claude-key" not in body
    assert "Yes, the provider says so" in body
    at.selectbox(key="aegis_provider_widget").set_value("bedrock").run()
    for field, value in (("access_key_id", "test-access-id"), ("secret_access_key", "test-secret"),
                         ("session_token", "test-session")):
        at.text_input(key=f"aegis_cred_input_bedrock_{field}").input(value).run()
        assert at.text_input(key=f"aegis_cred_input_bedrock_{field}").value == ""
    assert model_lists.calls == ["claude"]  # no region yet: not asked
    assert "Choose an AWS region for Amazon Bedrock" in "".join(c.value for c in at.caption)
    at.selectbox(key="aegis_bedrock_region_widget").set_value("us-west-2").run()
    assert model_lists.calls == ["claude", "bedrock"]
    box = at.selectbox(key="aegis_model_widget")
    assert box.value is None  # Bedrock has no preselected model
    box.set_value("us.test.vision-model-v1:0").run()
    body = _html(at)
    assert "Amazon Bedrock, us.test.vision-model-v1:0" in body
    for secret in ("test-access-id", "test-secret", "test-session"):
        assert secret not in body
        assert all(secret != w.value for w in at.text_input)


_BEDROCK_KEY = "ABSK" + "QmVkcm9ja0FQSUtleS" + "pageTest+/" * 6 + "="


def _captions(at: AppTest) -> str:
    return "\n".join(c.value for c in at.caption)


def test_bedrock_offers_both_ways_and_a_key_lists_models(model_lists) -> None:
    at = _run()
    at.selectbox(key="aegis_provider_widget").set_value("bedrock").run()
    choice = at.radio(key="aegis_bedrock_auth_widget")
    assert choice.options == ["AWS access keys", "Bedrock API key"]
    assert choice.value == "access_keys"
    assert at.text_input(key="aegis_cred_input_bedrock_access_key_id") is not None
    assert settings.ACCESS_KEYS_NOTE in _captions(at)
    assert ("Add a Bedrock API key, or an AWS access key ID and secret access key, for Amazon "
            "Bedrock to run this step.") in _captions(at)
    choice.set_value("api_key").run()
    keys = [w.key for w in at.text_input]
    assert "aegis_cred_input_bedrock_api_key" in keys
    assert "aegis_cred_input_bedrock_access_key_id" not in keys
    assert settings.API_KEY_NOTE in _captions(at)
    assert "12 hours" in settings.API_KEY_NOTE
    at.text_input(key="aegis_cred_input_bedrock_api_key").input(_BEDROCK_KEY).run()
    assert at.text_input(key="aegis_cred_input_bedrock_api_key").value == ""
    assert model_lists.calls == []  # no region yet: not asked
    at.selectbox(key="aegis_bedrock_region_widget").set_value("us-west-2").run()
    assert model_lists.calls == ["bedrock"]
    at.selectbox(key="aegis_model_widget").set_value("us.test.vision-model-v1:0").run()
    body = _html(at)
    assert "Amazon Bedrock, us.test.vision-model-v1:0" in body
    assert _BEDROCK_KEY not in body and _BEDROCK_KEY not in _captions(at)
    assert all(_BEDROCK_KEY != w.value for w in at.text_input)


def test_bedrock_says_the_api_key_wins_and_can_forget_it(model_lists) -> None:
    at = _run()
    at.selectbox(key="aegis_provider_widget").set_value("bedrock").run()
    for field, value in (("access_key_id", "test-access-id"), ("secret_access_key", "test-secret")):
        at.text_input(key=f"aegis_cred_input_bedrock_{field}").input(value).run()
    assert settings.KEY_WINS_SENTENCE not in _captions(at)
    at.radio(key="aegis_bedrock_auth_widget").set_value("api_key").run()
    at.text_input(key="aegis_cred_input_bedrock_api_key").input(_BEDROCK_KEY).run()
    assert settings.KEY_WINS_SENTENCE in _captions(at)
    at.radio(key="aegis_bedrock_auth_widget").set_value("access_keys").run()
    assert settings.KEY_WINS_SENTENCE in _captions(at)
    at.button(key="settings_forget_bedrock_api_key").click().run()
    assert settings.KEY_WINS_SENTENCE not in _captions(at)
    cred = at.session_state["aegis_creds"]["bedrock"]
    assert "api_key" not in cred and cred["access_key_id"] == "test-access-id"


def test_a_failed_listing_shows_one_fixed_sentence(model_lists) -> None:
    model_lists.failing.add("openai")
    at = _with_openai_key(_run())
    assert ERROR_LIST_FAILED in _html(at)
    assert not [b for b in at.selectbox if b.key == "aegis_model_widget"]
    model_lists.failing.clear()
    at.button(key="settings_refresh_models").click().run()
    assert at.selectbox(key="aegis_model_widget").value == DEFAULT_MODEL_NAME


def test_an_empty_list_says_so(model_lists) -> None:
    model_lists.models["openai"] = ()
    at = _with_openai_key(_run())
    assert settings.NO_MODELS_SENTENCE in _html(at)
    assert not [b for b in at.selectbox if b.key == "aegis_model_widget"]


def test_hostile_model_ids_are_never_shown(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real listing path: ids from a hostile provider are dropped."""
    from aegisshield.llm import openai_models, providers

    monkeypatch.setattr(providers, "list_models", REAL_LIST_MODELS)
    monkeypatch.setattr(providers, "sdk_available", lambda _p: True)
    hostile = ["<script>alert(1)</script>", "gpt-<b>x</b>", "gpt-a b", "gpt-" + "x" * 200,
               "gpt-ok-1"]
    monkeypatch.setattr(openai_models, "list_models",
                        lambda *_a, **_k: [ModelInfo(m) for m in hostile])
    at = _with_openai_key(_run())
    assert at.selectbox(key="aegis_model_widget").options == ["gpt-ok-1"]
    body = _html(at)
    assert "<script>alert" not in body and "<b>x</b>" not in body


def test_unavailable_sdk_is_marked(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisshield.llm import providers

    monkeypatch.setattr(providers, "sdk_available", lambda p: providers.Provider(p).value != "gemini")
    at = _run()
    assert "Gemini (Google) (not installed on this server)" in at.selectbox(
        key="aegis_provider_widget").options
    at.selectbox(key="aegis_provider_widget").set_value("gemini").run()
    at.text_input(key="aegis_cred_input_gemini_api_key").input("test-gemini-key").run()
    assert _esc(providers.ERROR_PROVIDER_UNAVAILABLE) in _html(at)


def test_operator_can_offer_fewer_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_PROVIDERS", "gemini,claude")
    at = _run()
    box = at.selectbox(key="aegis_provider_widget")
    assert box.options == ["Claude (Anthropic)", "Gemini (Google)"]
    assert box.value == "claude"


def test_mock_mode_says_the_provider_is_not_used(monkeypatch: pytest.MonkeyPatch, model_lists) -> None:
    monkeypatch.setenv("AEGIS_MOCK_LLM", "1")
    at = _run()
    assert _esc(settings.MOCK_PROVIDER_SENTENCE) in _html(at)
    assert at.selectbox(key="aegis_provider_widget").disabled
    assert at.selectbox(key="settings_mock_model").disabled
    assert model_lists.calls == []


class _OversizedUpload:
    """An uploaded file that says it is too large and fails if it is read."""

    name = "big.json"

    def __init__(self, size: int) -> None:
        self.size = size

    def getvalue(self) -> bytes:
        raise AssertionError("an oversized upload must not be read")


def test_an_oversized_import_is_refused_before_it_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    import streamlit as st

    from aegisshield.ui.pages import settings as page

    seen: dict = {}

    def fake_uploader(*args, **kwargs):
        seen.update(kwargs)
        return _OversizedUpload(page.MAX_WORKSPACE_BYTES + 1)

    monkeypatch.setattr(st, "file_uploader", fake_uploader)
    existing = Workspace()
    existing.add("lookups", "nginx 1.25", {})
    at = _run(aegis_workspace=existing)
    _button(at, "settings_import").click().run()
    assert not at.exception
    assert seen["max_upload_size"] == page.MAX_WORKSPACE_BYTES // (1024 * 1024) == 10
    assert page.IMPORT_TOO_LARGE in _html(at)
    assert [r.title for r in _workspace(at).list("lookups")] == ["nginx 1.25"]


def test_a_workspace_too_large_to_export_says_so_instead_of_failing() -> None:
    from aegisshield.storage import workspace as ws_mod

    big = Workspace()
    for index in range(ws_mod.MAX_RECORDS + 1):
        big.add("lookups", f"l{index}", {})
    at = _run(aegis_workspace=big)
    assert not at.exception
    assert "The workspace cannot be exported" in _html(at)


def test_operator_key_is_shown_as_such(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisshield.ui import state

    monkeypatch.setattr(state, "_secret", lambda name: "op" if name == "nvd_api_key" else "")
    at = _run()
    assert "Set by the operator" in _html(at)
    assert _button(at, "settings_clear_nvd").disabled


def test_agentic_toggle() -> None:
    at = _run()
    toggle = at.toggle(key="aegis_agentic_widget")
    assert toggle.value is False
    toggle.set_value(True).run()
    assert at.session_state["aegis_agentic"] is True


def test_operator_agentic_setting_locks_the_switch_on(monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisshield.ui.pages import settings as page

    monkeypatch.setenv("AEGIS_AGENTIC", "1")
    # A session that had turned it off before the operator set the variable.
    at = _run(aegis_agentic=False)
    assert not at.exception
    toggle = at.toggle(key="aegis_agentic_widget")
    assert toggle.value is True and toggle.disabled
    assert page.AGENTIC_LOCKED in "".join(c.value for c in at.caption)
    at.run()
    assert at.toggle(key="aegis_agentic_widget").value is True


def test_without_the_operator_setting_the_switch_is_free() -> None:
    from aegisshield.ui.pages import settings as page

    at = _run()
    toggle = at.toggle(key="aegis_agentic_widget")
    assert not toggle.disabled
    assert page.AGENTIC_LOCKED not in "".join(c.value for c in at.caption)


def test_export_import_round_trip() -> None:
    source = Workspace()
    source.add("threat_models", "Checkout service", {"threat_model": []})
    source.add("policies", "Access control", {"policy_markdown": "x"})
    data = source.to_json()

    at = _run()
    assert at.get("download_button")[0].proto.label == "Export workspace"
    assert _button(at, "settings_import").disabled
    at.get("file_uploader")[0].set_value(("ws.json", data, "application/json"))
    at.run()
    _button(at, "settings_import").click().run()
    assert not at.exception
    ws = _workspace(at)
    assert [r.title for r in ws.list("threat_models")] == ["Checkout service"]
    assert json.loads(ws.to_json()) == json.loads(data)
    assert "Workspace imported: 2 items." in _html(at)
    # the uploader was replaced, so the file is not applied again
    assert at.get("file_uploader")[0].proto.id != "" and _button(at, "settings_import").disabled


def test_bad_import_shows_the_error_and_keeps_the_workspace() -> None:
    existing = Workspace()
    existing.add("lookups", "nginx 1.25", {})
    at = _run(aegis_workspace=existing)
    at.get("file_uploader")[0].set_value(("bad.json", b"{not json", "application/json"))
    at.run()
    _button(at, "settings_import").click().run()
    body = _html(at)
    assert "That file could not be imported: The workspace file is not valid JSON." in body
    assert [r.title for r in _workspace(at).list("lookups")] == ["nginx 1.25"]


def test_clear_asks_first() -> None:
    existing = Workspace()
    existing.add("threat_models", "Checkout service", {})
    at = _run(aegis_workspace=existing)
    assert not _button(at, "settings_clear_danger").disabled
    _button(at, "settings_clear_danger").click().run()
    texts = " ".join(m.value for m in at.markdown)
    assert "This removes all 1 items from this session" in texts
    assert len(_workspace(at).list("threat_models")) == 1  # nothing removed yet

    _button(at, "settings_clear_cancel").click().run()
    assert len(_workspace(at).list("threat_models")) == 1

    _button(at, "settings_clear_danger").click().run()
    _button(at, "settings_clear_confirm_danger").click().run()
    assert _workspace(at).list("threat_models") == []
    assert "Workspace cleared." in _html(at)


def test_clear_is_disabled_when_empty() -> None:
    at = _run()
    assert _button(at, "settings_clear_danger").disabled


def test_data_dir_sentence(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path))
    body = _html(_run())
    assert "saved on this server" in body
    assert "shared by everyone who can open this app" in body
