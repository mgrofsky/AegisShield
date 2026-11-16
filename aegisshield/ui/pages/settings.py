"""Settings: the model provider, its credential, and the model; API keys; the
agentic path; the workspace; and what the app contacts."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

import streamlit as st

from aegisshield import __version__
from aegisshield.core.errors import WorkspaceError
from aegisshield.llm import providers
from aegisshield.llm.base import ERROR_LIST_FAILED
from aegisshield.llm.providers import Provider
from aegisshield.pipeline.catalog_service import atlas_version, attack_version
from aegisshield.storage import RecordKind, Workspace
from aegisshield.storage.workspace import MAX_WORKSPACE_BYTES
from aegisshield.ui import kit, safeguards_view, state, tool_parts
from aegisshield.ui.state import ApiKey
from aegisshield.ui.theme import Area, Tone


@dataclass(frozen=True)
class _KeyInfo:
    service: ApiKey
    label: str
    sent_to: str
    optional: str


_KEY_INFO = (
    _KeyInfo(ApiKey.NVD, "NVD API key",
             "Sent only to the NIST National Vulnerability Database.",
             "Optional. Vulnerability lookups work without it, more slowly; threat models skip "
             "the NVD step without it."),
    _KeyInfo(ApiKey.OTX, "AlienVault OTX API key",
             "Sent only to AlienVault OTX, during threat models and vulnerability lookups.",
             "Optional. Without it, threat intelligence from OTX is skipped."),
)

_SOURCE_WORDS = {
    "session": ("Set for this session", Tone.OK),
    "operator": ("Set by the operator", Tone.INFO),
    "none": ("Not set", Tone.NEUTRAL),
}

AGENTIC_LOCKED = "The operator has turned agentic threat modeling on for every run on this server."
SHARED_WORKSPACE_SENTENCE = (
    "The operator set AEGIS_DATA_DIR, so this workspace is saved on this server and kept between "
    "sessions. It is shared by everyone who can open this app: they see, change, and clear the "
    "same items you do."
)
MAX_IMPORT_MB = MAX_WORKSPACE_BYTES // (1024 * 1024)
IMPORT_TOO_LARGE = f"That file could not be imported: it is larger than {MAX_IMPORT_MB} MB."

_KIND_LABELS = (
    (RecordKind.THREAT_MODELS, "Threat models"),
    (RecordKind.POLICIES, "Policies"),
    (RecordKind.LOOKUPS, "Lookups"),
    (RecordKind.PCAP_ANALYSES, "PCAP analyses"),
    (RecordKind.AI_SCANS, "AI workflow scans"),
)

_SERVICES = (
    ("Model provider (the one you choose: Claude, Amazon Bedrock, OpenAI, or Gemini)",
     "When you run a threat model, policy, or analysis, and when it lists its models for "
     "your credential. Never in mock mode."),
    ("NVD (NIST)", "During vulnerability lookups, and during threat models when an NVD key is set."),
    ("AlienVault OTX", "During threat models and vulnerability lookups, only when an OTX key is set."),
    ("CISA KEV", "During vulnerability lookups, for the known exploited vulnerabilities list."),
    ("FIRST EPSS", "During vulnerability lookups, for exploit prediction scores."),
    ("endoflife.date", "During vulnerability lookups, for product support dates."),
    ("ExploitDB", "During vulnerability lookups, for its public index of exploits (from GitLab)."),
    ("Google Fonts", "From your browser when a page loads, for the Geist and JetBrains Mono fonts."),
)


def _record_count(workspace: Workspace) -> int:
    total = sum(len(workspace.list(kind)) for kind, _ in _KIND_LABELS)
    return total + (1 if workspace.org_profile is not None else 0)


def _keys_section() -> None:
    kit.section("Lookup keys", "Keys stay in this browser session only. They are never saved to the "
                "workspace, a file, a log, or a link, and they are gone when the session ends.")
    for info in _KEY_INFO:
        source = state.key_source(info.service)
        word, tone = _SOURCE_WORDS[source]
        with kit.card(f"key_{info.service.value}"):
            left, right = st.columns([3, 2], vertical_alignment="center")
            with left:
                st.html(f'<div class="ax-key-head"><strong>{info.label}</strong> '
                        f"{kit.badge_html(word, tone=tone)}</div>")
                st.caption(f"{info.sent_to} {info.optional}")
            with right:
                field, clear = st.columns([4, 1], vertical_alignment="bottom")
                placeholder = "Paste a new key to replace it" if source == "session" else "Paste key"
                field.text_input(
                    info.label, type="password", key=state.KEY_INPUT_WIDGETS[info.service],
                    placeholder=placeholder, label_visibility="collapsed",
                    on_change=state.key_input_changed, args=(info.service,),
                    autocomplete="off",
                )
                clear.button(
                    "Clear", key=f"settings_clear_{info.service.value}", type="tertiary",
                    disabled=source != "session", on_click=state.clear_api_key,
                    args=(info.service,), help=f"Forget the {info.label} for this session",
                )


MOCK_PROVIDER_SENTENCE = ("Mock mode is on: every answer is a canned example and no model provider "
                          "is called, so the provider and model below are not used.")
NO_MODELS_SENTENCE = "The provider listed no models this app can use."
CHOOSE_MODEL_SENTENCE = "Choose a model to run threat models, policies, and analyses."
_VISION_WORDS = {True: "Yes, the provider says so", False: "No, the provider says so",
                 None: "Not stated by the provider; an image is tried and a refusal is shown"}


@dataclass(frozen=True)
class _FieldInfo:
    name: str
    label: str
    optional: bool = False


_PROVIDER_FIELDS: dict[Provider, tuple[_FieldInfo, ...]] = {
    Provider.CLAUDE: (_FieldInfo("api_key", "Claude API key"),),
    Provider.OPENAI: (_FieldInfo("api_key", "OpenAI API key"),),
    Provider.GEMINI: (_FieldInfo("api_key", "Gemini API key"),),
    Provider.BEDROCK: (
        _FieldInfo("access_key_id", "AWS access key ID"),
        _FieldInfo("secret_access_key", "AWS secret access key"),
        _FieldInfo("session_token", "AWS session token", optional=True),
    ),
}
_BEDROCK_API_KEY_FIELD = _FieldInfo("api_key", "Bedrock API key")
_BEDROCK_AUTH_LABELS = {state.BEDROCK_AUTH_ACCESS_KEYS: "AWS access keys",
                        state.BEDROCK_AUTH_API_KEY: "Bedrock API key"}
ACCESS_KEYS_NOTE = ("An access key ID and secret access key, with a session token if they are "
                    "temporary. They sign each request to Bedrock.")
# Lifetime from AWS's Bedrock user guide ("How Amazon Bedrock API keys work").
API_KEY_NOTE = ("A Bedrock API key, sent as the bearer token of each request to Bedrock. A "
                "short-term key expires after at most 12 hours, or sooner when the session that "
                "made it ends, and works only in the region where it was made. Bedrock accepts "
                "API keys in fewer regions than access keys; where it does not, the model list "
                "fails.")
KEY_WINS_SENTENCE = ("A Bedrock API key and AWS access keys are both held for this session. The "
                     "API key is used; forget it to use the access keys.")
_SENT_TO = {
    Provider.CLAUDE: "Sent only to Anthropic, with each model call and model list the app asks for you.",
    Provider.OPENAI: "Sent only to OpenAI, with each model call and model list the app asks for you.",
    Provider.GEMINI: "Sent only to Google's Gemini API, with each model call and model list the app "
                     "asks for you.",
    Provider.BEDROCK: "Used only for requests to Amazon Bedrock in the region you choose. The app "
                      "never uses AWS credentials or a Bedrock API key from this server.",
}


def _provider_label(provider: Provider) -> str:
    label = providers.PROVIDER_LABELS[provider]
    return label if providers.sdk_available(provider) else f"{label} (not installed on this server)"


def _credential_field(provider: Provider, info: _FieldInfo) -> None:
    is_set = state.credential_is_set(provider, info.name)
    word, tone = _SOURCE_WORDS["session" if is_set else "none"]
    optional = " Optional." if info.optional else ""
    st.html(f'<div class="ax-key-head"><strong>{info.label}</strong> '
            f"{kit.badge_html(word, tone=tone)}</div>")
    if optional:
        st.caption(optional.strip())
    placeholder = "Paste a new value to replace it" if is_set else "Paste value"
    if provider is Provider.OPENAI:
        st.text_input(info.label, type="password", key=state.KEY_INPUT_WIDGETS[ApiKey.OPENAI],
                      placeholder=placeholder, label_visibility="collapsed",
                      on_change=state.key_input_changed, args=(ApiKey.OPENAI,), autocomplete="off")
        return
    st.text_input(info.label, type="password",
                  key=state.CREDENTIAL_WIDGETS[(provider.value, info.name)],
                  placeholder=placeholder, label_visibility="collapsed",
                  on_change=state.credential_input_changed, args=(provider, info.name),
                  autocomplete="off")


def _bedrock_fields() -> None:
    """Bedrock's two ways in: a choice of which fields to show, then those
    fields. A held API key wins, and the page says so."""
    way = state.bedrock_auth()
    state.set_widget(state.BEDROCK_AUTH_WIDGET, way)
    st.radio("Sign in to Amazon Bedrock with", list(_BEDROCK_AUTH_LABELS),
             key=state.BEDROCK_AUTH_WIDGET, format_func=_BEDROCK_AUTH_LABELS.__getitem__,
             horizontal=True, on_change=state.bedrock_auth_widget_changed)
    if way == state.BEDROCK_AUTH_API_KEY:
        st.caption(API_KEY_NOTE)
        _credential_field(Provider.BEDROCK, _BEDROCK_API_KEY_FIELD)
    else:
        st.caption(ACCESS_KEYS_NOTE)
        for info in _PROVIDER_FIELDS[Provider.BEDROCK]:
            _credential_field(Provider.BEDROCK, info)
    cred = state.credential(Provider.BEDROCK)
    if providers.bedrock_uses_api_key(cred) and (cred.access_key_id or cred.secret_access_key):
        st.caption(KEY_WINS_SENTENCE)
        st.button("Forget the Bedrock API key", key="settings_forget_bedrock_api_key",
                  type="tertiary", on_click=state.clear_credential_field,
                  args=(Provider.BEDROCK, "api_key"))
    _region_field()


def _region_field() -> None:
    current = state.credential(Provider.BEDROCK).region
    state.set_widget(state.REGION_WIDGET, current or None)
    st.selectbox("AWS region", providers.BEDROCK_REGIONS, index=None, key=state.REGION_WIDGET,
                 placeholder="Choose a region", on_change=state.region_widget_changed)


def _model_picker(provider: Provider) -> None:
    missing = providers.missing_credential(provider, state.credential(provider))
    if missing:
        st.caption(missing)
        return
    if not providers.sdk_available(provider):
        kit.notice(providers.ERROR_PROVIDER_UNAVAILABLE, tone=Tone.WARN)
        return
    with st.spinner("Asking the provider for its models"):
        entry = state.refresh_models(provider)
    if entry is None or entry.get("failed"):
        kit.notice(ERROR_LIST_FAILED, tone=Tone.CRIT)
    else:
        ids = [m.id for m in entry["models"]]
        if not ids:
            kit.notice(NO_MODELS_SENTENCE, tone=Tone.WARN)
        else:
            choice = state.model_choice()
            state.set_widget(state.MODEL_WIDGET, choice.model if choice else None)
            st.selectbox("Model", ids, index=None, key=state.MODEL_WIDGET,
                         placeholder="Choose a model", on_change=state.model_widget_changed)
            if choice is None:
                st.caption(CHOOSE_MODEL_SENTENCE)
            else:
                kit.key_value_list({"In use": f"{providers.PROVIDER_LABELS[provider]}, {choice.model}",
                                    "Reads images": _VISION_WORDS[choice.vision]})
    if st.button("Refresh list", key="settings_refresh_models", icon=":material/refresh:"):
        state.refresh_models(provider, force=True)
        st.rerun()


def _provider_section() -> None:
    kit.section("Model provider", "Choose who answers, give that provider's credential, and pick a "
                "model from the list the provider returns for it. The credential stays in this "
                "browser session only: it is never saved to the workspace, a file, a log, or a "
                "link, and it is gone when the session ends.")
    settings = state.get_settings()
    offered = providers.offered_providers(settings)
    with kit.card("provider"):
        if settings.mock_llm:
            kit.notice(MOCK_PROVIDER_SENTENCE, tone=Tone.WARN)
        provider = state.selected_provider()
        state.set_widget(state.PROVIDER_WIDGET, provider.value)
        st.selectbox("Provider", [p.value for p in offered], key=state.PROVIDER_WIDGET,
                     format_func=lambda v: _provider_label(Provider(v)),
                     on_change=state.provider_widget_changed, disabled=settings.mock_llm)
        if settings.mock_llm:
            st.selectbox("Model", ["Mock model (canned answers)"], disabled=True,
                         key="settings_mock_model")
            return
        st.caption(_SENT_TO[provider])
        if provider is Provider.BEDROCK:
            _bedrock_fields()
        else:
            for info in _PROVIDER_FIELDS[provider]:
                _credential_field(provider, info)
        st.button("Clear credential", key=f"settings_clear_cred_{provider.value}", type="tertiary",
                  on_click=state.clear_credential, args=(provider,),
                  help=f"Forget the {providers.PROVIDER_LABELS[provider]} credential for this session")
        _model_picker(provider)


def _model_section() -> None:
    kit.section("Threat modeling")
    with kit.card("model"):
        locked = state.agentic_locked_on()
        if locked:
            # The widget keeps no value of its own while it is locked on.
            st.session_state.pop(state.AGENTIC_WIDGET, None)
        st.toggle(
            "Agentic threat modeling", value=state.agentic_enabled(), key=state.AGENTIC_WIDGET,
            on_change=state.agentic_widget_changed, disabled=locked,
        )
        st.caption("When on, a lead agent plans the threat model and specialist agents write each "
                   "section; when off, the steps run in a fixed order.")
        if locked:
            st.caption(AGENTIC_LOCKED)


def _storage_sentence() -> str:
    data_dir = state.get_settings().data_dir
    if data_dir is not None:
        return SHARED_WORKSPACE_SENTENCE
    return ("Your work is kept only in this browser session. Export it to keep it, and import "
            "it later to pick up where you left off.")


def _import_workspace(data: bytes) -> None:
    try:
        workspace = Workspace.from_json(data)
    except WorkspaceError as exc:
        kit.notice(f"That file could not be imported: {exc}", tone=Tone.CRIT)
        return
    state.save_workspace(workspace)
    state.rotate_import_uploader()
    state.flash(f"Workspace imported: {_record_count(workspace)} items.", "ok")
    st.rerun()


def _clear_workspace() -> None:
    """``on_click`` of the dialog's confirm button: runs before the rerun, so
    the clear happens even though the dialog body itself is not run again."""
    state.save_workspace(Workspace())
    state.rotate_import_uploader()
    state.flash("Workspace cleared.", "ok")


@st.dialog("Clear the workspace?")
def _confirm_clear(count: int) -> None:
    st.write(f"This removes all {count} items from this session. It cannot be undone. "
             "Export the workspace first if you want to keep them.")
    cancel, confirm = st.columns(2)
    if cancel.button("Cancel", key="settings_clear_cancel", width="stretch"):
        st.rerun()
    if confirm.button("Clear workspace", key="settings_clear_confirm_danger", type="primary",
                      width="stretch", on_click=_clear_workspace):
        st.rerun()


def _workspace_section() -> None:
    workspace = state.get_workspace()
    kit.section("Workspace", _storage_sentence())
    tiles = [kit.Tile(label, len(workspace.list(kind))) for kind, label in _KIND_LABELS]
    tiles.append(kit.Tile("Organization profile", "Set" if workspace.org_profile else "Not set"))
    kit.stat_row(tiles)
    count = _record_count(workspace)

    with kit.card("workspace_actions"):
        export_col, clear_col = st.columns([4, 1], vertical_alignment="center")
        with export_col:
            try:
                exported = workspace.to_json()
            except WorkspaceError as exc:
                kit.notice(f"The workspace cannot be exported: {exc}", tone=Tone.WARN)
            else:
                st.download_button(
                    "Export workspace", data=exported,
                    file_name=f"aegisshield-workspace-{dt.date.today():%Y%m%d}.json",
                    mime="application/json", key="settings_export", icon=":material/download:",
                    on_click="ignore",
                )
        with clear_col:
            if st.button("Clear workspace", key="settings_clear_danger", disabled=count == 0,
                         icon=":material/delete:"):
                _confirm_clear(count)

    with kit.card("workspace_import"):
        uploaded = st.file_uploader(
            "Import a workspace file", type=["json"], key=state.import_uploader_key(),
            help="A file exported from this app. It replaces what this session holds now.",
            max_upload_size=MAX_IMPORT_MB,
        )
        if count:
            st.caption("Importing replaces the items this session holds now.")
        if st.button("Import", key="settings_import", type="primary", disabled=uploaded is None):
            if tool_parts.upload_too_large(uploaded, MAX_WORKSPACE_BYTES):
                kit.notice(IMPORT_TOO_LARGE, tone=Tone.CRIT)
            else:
                _import_workspace(uploaded.getvalue())


def _safeguards_section() -> None:
    kit.section("Safeguards", "Checks NeMo Guardrails runs on every model call this server makes.")
    with kit.card("safeguards"):
        safeguards_view.render_status(state.get_settings())


# Where the running code's source is published (AGPL v3, section 13).
SOURCE_URL = "https://github.com/mgrofsky/AegisShield"


def _about_section() -> None:
    kit.section("About")
    with kit.card("about"):
        kit.key_value_list({"Version": __version__, "MITRE ATT&CK data": attack_version(),
                            "MITRE ATLAS data": atlas_version()}, mono=True)
        st.html('<p class="ax-lead">Outside services the app contacts, and when</p>')
        kit.key_value_list(_SERVICES)
        st.caption("Nothing is sent to the systems you describe or look up: the app never probes "
                   "or scans a target. With AEGIS_OFFLINE set, no outside lookups are made.")
        st.caption(f"AegisShield is free software under the GNU AGPL v3. Source code: [{SOURCE_URL}]({SOURCE_URL})")


def render() -> None:
    """The settings page."""
    kit.page_header("Settings", "Model provider, keys, and the work this session holds.",
                    area=Area.NEUTRAL)
    message = state.consume_flash()
    if message:
        kit.notice(message[0], tone=message[1])
    _provider_section()
    _keys_section()
    _model_section()
    _workspace_section()
    _safeguards_section()
    _about_section()
