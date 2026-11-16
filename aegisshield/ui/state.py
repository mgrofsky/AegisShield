"""Per-visitor state on ``st.session_state``.

This is the only module that names session-state keys. Pages call these
accessors and never read or write ``st.session_state`` themselves.

Rules this module keeps:

- API keys (NVD, OTX) and the model provider credential (Claude, OpenAI, or
  Gemini key; Bedrock access key id, secret access key, and session token)
  live in session state only. They are never put in the workspace, a file, a
  log line, or a URL. NVD and OTX fall back to ``st.secrets`` when the
  operator configured them; no operator setting holds a provider credential.
- The visitor's provider and model choice is applied to the settings every
  page reads (``get_settings``), so every model call uses it. A model is
  chosen only from the list the provider returned for the visitor's
  credential (``set_model_choice`` refuses anything else).
- The workspace lives in session state (``MappingStore``) unless the operator
  set ``AEGIS_DATA_DIR``, in which case it is a ``FileStore`` on disk.
- A session runs at most one job of each kind at a time.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from enum import StrEnum
from typing import Any

import streamlit as st

from aegisshield import safeguards
from aegisshield.config import DEFAULT_PROVIDER, Settings, with_model_choice
from aegisshield.config import get_settings as _read_settings
from aegisshield.core.errors import JobError, LLMError
from aegisshield.jobs import JobSnapshot, ProgressSink, get_runner
from aegisshield.jobs.runner import DEFAULT_TTL_SECONDS
from aegisshield.llm import providers
from aegisshield.llm.base import ModelInfo
from aegisshield.llm.providers import Credential, Provider
from aegisshield.storage import Workspace
from aegisshield.storage.stores import (
    DEFAULT_SESSION_KEY,
    MappingStore,
    WorkspaceStore,
    file_store_from_settings,
)

__all__ = [
    "DEEP_LINK_PARAM",
    "KEY_INPUT_WIDGETS",
    "ApiKey",
    "active_job_id",
    "AGENTIC_WIDGET",
    "MODEL_WIDGET",
    "PROVIDER_WIDGET",
    "REGION_WIDGET",
    "CREDENTIAL_WIDGETS",
    "ModelChoice",
    "BEDROCK_AUTH_ACCESS_KEYS",
    "BEDROCK_AUTH_API_KEY",
    "BEDROCK_AUTH_WIDGET",
    "bedrock_auth",
    "bedrock_auth_widget_changed",
    "clear_credential",
    "clear_credential_field",
    "credential",
    "credential_input_changed",
    "credential_is_set",
    "llm_blocker",
    "model_choice",
    "model_listing",
    "provider_widget_changed",
    "refresh_models",
    "region_widget_changed",
    "selected_provider",
    "set_credential_field",
    "set_model_choice",
    "set_provider",
    "agentic_enabled",
    "agentic_locked_on",
    "agentic_widget_changed",
    "consume_flash",
    "flash",
    "import_uploader_key",
    "key_input_changed",
    "model_widget_changed",
    "rotate_import_uploader",
    "clear_api_key",
    "forget_job",
    "get_api_key",
    "get_settings",
    "get_workspace",
    "have_llm",
    "is_job_running",
    "job_snapshot",
    "key_source",
    "requested_record_id",
    "save_workspace",
    "selected_model",
    "set_agentic",
    "set_api_key",
    "set_selected_model",
    "start_job",
    "workspace_store",
    # threat-model pages
    "THREAT_MODEL_JOB",
    "ADOPT_AFTER_END_SECONDS",
    "adopt_job",
    "RUN_PARAM",
    "requested_run_id",
    "set_run_param",
    "cancel_job",
    "drop_widget",
    "replace_wizard_draft",
    "seed_widget",
    "session_memo",
    "set_threat_model_run",
    "set_widget",
    "threat_model_run",
    "widget_value",
    "wizard_draft",
    # AI workflow scan page
    "keep_scan_files",
    "scan_files",
]

logger = logging.getLogger(__name__)


class ApiKey(StrEnum):
    """The outside services a visitor can give a key for."""

    OPENAI = "openai"
    NVD = "nvd"
    OTX = "otx"


# Session-state keys. Every name the app uses is here.
_WORKSPACE = DEFAULT_SESSION_KEY
_KEYS = {k: f"aegis_key_{k.value}" for k in ApiKey}
_MODEL = "aegis_model"  # {provider: model id}
_PROVIDER = "aegis_provider"
_CREDS = "aegis_creds"  # {provider: {field: value}}; OpenAI's key is _KEYS[OPENAI]
_LISTINGS = "aegis_model_lists"  # {provider: {"at", "models", "failed"}}
_AGENTIC = "aegis_agentic"
_JOBS = "aegis_jobs"
_FLASH = "aegis_flash"
_IMPORT_NONCE = "aegis_import_nonce"

# Widget keys on the settings page.
AGENTIC_WIDGET = "aegis_agentic_widget"
MODEL_WIDGET = "aegis_model_widget"
PROVIDER_WIDGET = "aegis_provider_widget"
REGION_WIDGET = "aegis_bedrock_region_widget"
BEDROCK_AUTH_WIDGET = "aegis_bedrock_auth_widget"

# The two ways a visitor can give a Bedrock credential. The choice only
# says which fields the page shows; whatever is held, a Bedrock API key
# wins (``providers.bedrock_uses_api_key``).
BEDROCK_AUTH_API_KEY = "api_key"
BEDROCK_AUTH_ACCESS_KEYS = "access_keys"
_BEDROCK_AUTH = "aegis_bedrock_auth"

# Widget keys for the masked inputs on the settings page. The input is
# emptied as soon as a key is stored, so the key is kept in one place only.
KEY_INPUT_WIDGETS: dict[ApiKey, str] = {k: f"aegis_key_input_{k.value}" for k in ApiKey}

# Masked inputs for the provider credentials, emptied once a value is
# stored. OpenAI's key uses KEY_INPUT_WIDGETS[ApiKey.OPENAI].
_SECRET_FIELDS = ("api_key", "access_key_id", "secret_access_key", "session_token")
CREDENTIAL_WIDGETS: dict[tuple[str, str], str] = {
    (p.value, f): f"aegis_cred_input_{p.value}_{f}"
    for p in Provider for f in _SECRET_FIELDS if p is not Provider.OPENAI
}
_FIELD_WORDS = {
    "api_key": "API key", "access_key_id": "AWS access key ID",
    "secret_access_key": "AWS secret access key", "session_token": "AWS session token",
}
# A model list is asked again after this long, or when the visitor asks.
MODEL_LIST_TTL_SECONDS = 600.0

# Names the operator may use in .streamlit/secrets.toml.
_KEY_LABELS = {ApiKey.OPENAI: "OpenAI", ApiKey.NVD: "NVD", ApiKey.OTX: "OTX"}
_SECRET_NAMES: dict[ApiKey, str] = {ApiKey.NVD: "nvd_api_key", ApiKey.OTX: "alienvault_api_key"}

# Deep links put a record id in this query parameter, for example
# ``/threat-model?id=<record id>``.
DEEP_LINK_PARAM = "id"
_RECORD_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
_MAX_KEY_CHARS = 512


# ---------------------------------------------------------------- settings


def get_settings() -> Settings:
    """The runtime settings, read from the environment on each call, with
    this session's provider and model applied (``with_model_choice``).

    Outside mock mode the provider is the one the visitor chose, and the
    model is the one they chose from that provider's list, used for every
    model call; with no model chosen it is empty, and ``get_llm`` refuses to
    build a client. This reads the session's cached list only; it never
    asks a provider.
    """
    base = _read_settings()
    if base.mock_llm:
        return base
    choice = model_choice(base)
    if choice is not None:
        return with_model_choice(base, provider=choice.provider, model=choice.model,
                                 vision=choice.vision)
    return with_model_choice(base, provider=selected_provider(base).value, model="")


class ModelChoice:
    """The provider, model, and image support this session uses."""

    __slots__ = ("model", "provider", "vision")

    def __init__(self, provider: str, model: str, vision: bool | None) -> None:
        self.provider = provider
        self.model = model
        self.vision = vision

    def __repr__(self) -> str:
        return f"ModelChoice({self.provider!r}, {self.model!r}, vision={self.vision!r})"


def selected_provider(settings: Settings | None = None) -> Provider:
    """The provider this session uses: the visitor's choice when the server
    offers it, else OpenAI when offered, else the first one offered."""
    offered = providers.offered_providers(settings or _read_settings())
    value = st.session_state.get(_PROVIDER)
    for provider in offered:
        if provider.value == value:
            return provider
    for provider in offered:
        if provider.value == DEFAULT_PROVIDER:
            return provider
    return offered[0]


def set_provider(provider: Provider | str) -> None:
    """Choose a provider the server offers; raises ``ValueError`` otherwise."""
    chosen = Provider(provider)
    if chosen not in providers.offered_providers(_read_settings()):
        raise ValueError("provider not offered")
    st.session_state[_PROVIDER] = chosen.value


def _choices() -> dict[str, str]:
    value = st.session_state.get(_MODEL)
    if not isinstance(value, dict):
        value = {}
        st.session_state[_MODEL] = value
    return value


def model_listing(provider: Provider | str) -> dict[str, Any] | None:
    """This session's cached model list for ``provider``: ``at`` (when it
    was asked), ``models`` (a tuple of ``ModelInfo``), and ``failed``; or
    None when it was never asked or the credential changed since."""
    listings = st.session_state.get(_LISTINGS)
    entry = listings.get(Provider(provider).value) if isinstance(listings, dict) else None
    return entry if isinstance(entry, dict) else None


def _drop_listing(provider: Provider | str) -> None:
    listings = st.session_state.get(_LISTINGS)
    if isinstance(listings, dict):
        listings.pop(Provider(provider).value, None)


def refresh_models(provider: Provider | str, *, force: bool = False,
                   now: float | None = None) -> dict[str, Any] | None:
    """Ask ``provider`` for its models with this session's credential, when
    the cached list is missing, older than ``MODEL_LIST_TTL_SECONDS``, or
    ``force`` is set; return the (possibly new) cached entry.

    Returns None without asking when the credential is incomplete. A failed
    listing is cached as ``failed`` (shown as one fixed sentence) and is
    asked again only when forced or once the credential changes.
    """
    provider = Provider(provider)
    cred = credential(provider)
    if providers.missing_credential(provider, cred):
        return None
    stamp = time.time() if now is None else now
    entry = model_listing(provider)
    fresh = entry is not None and (entry.get("failed") or stamp - entry["at"] < MODEL_LIST_TTL_SECONDS)
    if fresh and not force:
        return entry
    try:
        models = providers.list_models(provider, cred)
        entry = {"at": stamp, "models": models, "failed": False}
    except LLMError:
        entry = {"at": stamp, "models": (), "failed": True}
    listings = st.session_state.get(_LISTINGS)
    if not isinstance(listings, dict):
        listings = {}
        st.session_state[_LISTINGS] = listings
    listings[provider.value] = entry
    return entry


def _listed(provider: Provider) -> tuple[ModelInfo, ...]:
    entry = model_listing(provider)
    if entry is None or entry.get("failed"):
        return ()
    return tuple(entry.get("models") or ())


def set_model_choice(provider: Provider | str, model: str) -> None:
    """Choose ``model`` for ``provider``. Raises ``ValueError`` unless the
    provider's latest list for this session's credential holds it."""
    provider = Provider(provider)
    if model not in {m.id for m in _listed(provider)}:
        raise ValueError("model not in the provider's list")
    _choices()[provider.value] = model


def model_choice(settings: Settings | None = None) -> ModelChoice | None:
    """The provider and model this session uses, or None when no model is
    chosen: the visitor's pick when the provider's latest list still holds
    it, else the preselected model when listed (``preselected_model``)."""
    settings = settings or _read_settings()
    provider = selected_provider(settings)
    if providers.missing_credential(provider, credential(provider)):
        return None
    models = _listed(provider)
    by_id = {m.id: m for m in models}
    picked = _choices().get(provider.value)
    if picked not in by_id:
        picked = providers.preselected_model(provider, models, settings)
    if picked is None:
        return None
    return ModelChoice(provider.value, picked, by_id[picked].vision)


def selected_model() -> str:
    """The model this session uses, or "" when none is chosen."""
    choice = model_choice()
    return choice.model if choice else ""


def set_selected_model(model: str) -> None:
    """Choose ``model`` for the selected provider (``set_model_choice``)."""
    set_model_choice(selected_provider(), model)


# ------------------------------------------------------ provider credential


def _creds(provider: Provider) -> dict[str, str]:
    store = st.session_state.get(_CREDS)
    if not isinstance(store, dict):
        store = {}
        st.session_state[_CREDS] = store
    fields = store.get(provider.value)
    if not isinstance(fields, dict):
        fields = {}
        store[provider.value] = fields
    return fields


def credential(provider: Provider | str | None = None) -> Credential:
    """This session's credential for ``provider`` (the selected one when
    None), passed by value into the client that needs it."""
    provider = Provider(provider) if provider is not None else selected_provider()
    if provider is Provider.OPENAI:
        return Credential(api_key=_session_key(ApiKey.OPENAI))
    fields = _creds(provider)
    return Credential(**{name: fields[name] for name in (*_SECRET_FIELDS, "region")
                         if isinstance(fields.get(name), str)})


def credential_is_set(provider: Provider | str, field: str) -> bool:
    """True when this session holds a value for ``field`` of ``provider``."""
    return bool(getattr(credential(provider), field, ""))


def set_credential_field(provider: Provider | str, field: str, value: str) -> bool:
    """Store one credential field for this session. Returns False for an
    empty value or a region outside ``BEDROCK_REGIONS``. A change drops the
    provider's cached model list, so the list is asked again with the new
    credential."""
    provider = Provider(provider)
    if field == "region":
        cleaned = value.strip() if isinstance(value, str) else ""
        if cleaned not in providers.BEDROCK_REGIONS:
            return False
    else:
        cleaned = "".join(value.split())[:_MAX_KEY_CHARS] if isinstance(value, str) else ""
        if not cleaned or field not in _SECRET_FIELDS:
            return False
    if provider is Provider.OPENAI:
        if field != "api_key":
            return False
        st.session_state[_KEYS[ApiKey.OPENAI]] = cleaned
    else:
        _creds(provider)[field] = cleaned
    _drop_listing(provider)
    return True


def clear_credential_field(provider: Provider | str, field: str) -> None:
    """Forget one secret field of ``provider``'s credential for this session
    (a region is kept), and drop its model list."""
    provider = Provider(provider)
    if field not in _SECRET_FIELDS or provider is Provider.OPENAI:
        return
    _creds(provider).pop(field, None)
    _drop_listing(provider)


def bedrock_auth() -> str:
    """Which Bedrock fields the page shows: the visitor's choice, or, before
    one is made, the API key when one is held and access keys otherwise."""
    chosen = st.session_state.get(_BEDROCK_AUTH)
    if chosen in (BEDROCK_AUTH_API_KEY, BEDROCK_AUTH_ACCESS_KEYS):
        return chosen
    if providers.bedrock_uses_api_key(credential(Provider.BEDROCK)):
        return BEDROCK_AUTH_API_KEY
    return BEDROCK_AUTH_ACCESS_KEYS


def clear_credential(provider: Provider | str) -> None:
    """Forget this session's credential, model list, and model choice for
    ``provider``."""
    provider = Provider(provider)
    if provider is Provider.OPENAI:
        st.session_state.pop(_KEYS[ApiKey.OPENAI], None)
    else:
        store = st.session_state.get(_CREDS)
        if isinstance(store, dict):
            store.pop(provider.value, None)
    _drop_listing(provider)
    _choices().pop(provider.value, None)


def llm_blocker() -> str | None:
    """The fixed sentence saying why model calls cannot run in this session
    (a missing credential field, a missing SDK, or no model chosen), or
    None when they can (always None in mock mode)."""
    settings = _read_settings()
    if settings.mock_llm:
        return None
    provider = selected_provider(settings)
    missing = providers.missing_credential(provider, credential(provider))
    if missing:
        return missing
    if not providers.sdk_available(provider):
        return providers.ERROR_PROVIDER_UNAVAILABLE
    if model_choice(settings) is None:
        return providers.ERROR_NO_MODEL
    return None


def agentic_locked_on() -> bool:
    """True when the operator set ``AEGIS_AGENTIC``: every run takes the
    agentic path (``pipeline.run.use_agentic``), whatever this session chose."""
    return get_settings().agentic


def agentic_enabled() -> bool:
    """Whether this session's runs take the agentic threat-model path."""
    if agentic_locked_on():
        return True
    return bool(st.session_state.get(_AGENTIC, False))


def set_agentic(enabled: bool) -> None:
    """Turn the agentic path on or off for this session."""
    st.session_state[_AGENTIC] = bool(enabled)


# ---------------------------------------------------------------- API keys


def _secret(name: str) -> str:
    """An operator secret from ``st.secrets``, or "" when none is configured.

    A missing secrets file raises inside ``st.secrets``; that is the normal
    case for a visitor-only deployment, so it is treated as "not set".
    """
    try:
        value = st.secrets.get(name)
    except (FileNotFoundError, KeyError, st.errors.StreamlitSecretNotFoundError):
        return ""
    return value.strip() if isinstance(value, str) else ""


def _session_key(service: ApiKey) -> str:
    value = st.session_state.get(_KEYS[ApiKey(service)])
    return value if isinstance(value, str) else ""


def get_api_key(service: ApiKey | str) -> str:
    """The key to use for ``service``: the visitor's, else the operator's, else ""."""
    service = ApiKey(service)
    own = _session_key(service)
    if own:
        return own
    name = _SECRET_NAMES.get(service)
    return _secret(name) if name else ""


def key_source(service: ApiKey | str) -> str:
    """Where the key for ``service`` comes from: "session", "operator", or "none"."""
    service = ApiKey(service)
    if _session_key(service):
        return "session"
    name = _SECRET_NAMES.get(service)
    if name and _secret(name):
        return "operator"
    return "none"


def set_api_key(service: ApiKey | str, value: str) -> bool:
    """Store a visitor's key for this session. Returns False for an empty value."""
    cleaned = "".join(value.split())[:_MAX_KEY_CHARS] if isinstance(value, str) else ""
    if not cleaned:
        return False
    st.session_state[_KEYS[ApiKey(service)]] = cleaned
    return True


def clear_api_key(service: ApiKey | str) -> None:
    """Forget the visitor's key for ``service``. An operator key still applies."""
    st.session_state.pop(_KEYS[ApiKey(service)], None)


def have_llm() -> bool:
    """True when model calls can run: mock mode, or the chosen provider has
    a complete credential, its SDK, and a chosen model."""
    return llm_blocker() is None


# --------------------------------------------------------------- workspace


def workspace_store(settings: Settings | None = None) -> WorkspaceStore:
    """The store for this session: on disk when ``AEGIS_DATA_DIR`` is set."""
    settings = settings or get_settings()
    store = file_store_from_settings(settings)
    if store is not None:
        return store
    return MappingStore(st.session_state, _WORKSPACE)


def get_workspace() -> Workspace:
    """This session's workspace (a new empty one on first use)."""
    return workspace_store().load()


def save_workspace(workspace: Workspace) -> None:
    """Store ``workspace``: after a page changed it, or to replace it whole."""
    workspace_store().save(workspace)


# ------------------------------------------------------------------- jobs


def _jobs() -> dict[str, str]:
    jobs = st.session_state.get(_JOBS)
    if not isinstance(jobs, dict):
        jobs = {}
        st.session_state[_JOBS] = jobs
    return jobs


def active_job_id(kind: str) -> str | None:
    """The id of this session's job of ``kind``, running or finished.

    Returns None when there is none, or when the runner has evicted it.
    """
    jobs = _jobs()
    job_id = jobs.get(kind)
    if job_id is None:
        return None
    if get_runner().snapshot(job_id) is None:
        jobs.pop(kind, None)
        return None
    return job_id


def job_snapshot(kind: str) -> JobSnapshot | None:
    """The state of this session's job of ``kind``, or None."""
    job_id = active_job_id(kind)
    return None if job_id is None else get_runner().snapshot(job_id)


def is_job_running(kind: str) -> bool:
    """True while this session has an unfinished job of ``kind``."""
    snap = job_snapshot(kind)
    return snap is not None and not snap.done


def session_secrets() -> tuple[str, ...]:
    """Every credential value this session can hand a job: each provider's
    secret fields, and the OpenAI, NVD, and OTX keys (the visitor's or the
    operator's). The runner removes them from a failed job's log line."""
    values = [get_api_key(service) for service in ApiKey]
    for provider in Provider:
        if provider is not Provider.OPENAI:
            fields = _creds(provider)
            values.extend(fields.get(name, "") for name in _SECRET_FIELDS)
    return tuple(dict.fromkeys(v for v in values if isinstance(v, str) and v))


def start_job(kind: str, fn: Callable[[ProgressSink], dict[str, Any]], *,
              shown_errors: frozenset[str] = frozenset()) -> str:
    """Submit ``fn`` as this session's job of ``kind`` and return its id.

    ``shown_errors`` are the service's own fixed sentences a failure may show
    as they are (``JobRunner.submit``); the safeguards' sentences
    (``safeguards.JOB_ERRORS``) are always among them.

    Raises ``JobError`` if a job of that kind is still running for this
    session, or when the server is at its job limit. A finished job of the
    same kind is discarded first.
    """
    if is_job_running(kind):
        raise JobError("A job of this kind is already running. Wait for it to finish or cancel it.")
    forget_job(kind)
    job_id = get_runner().submit(fn, kind=kind,
                                 shown_errors=frozenset(shown_errors) | safeguards.JOB_ERRORS,
                                 secrets=session_secrets())
    _jobs()[kind] = job_id
    return job_id


def forget_job(kind: str) -> None:
    """Drop this session's job of ``kind`` (cancelling it if it still runs)."""
    job_id = _jobs().pop(kind, None)
    if job_id is not None:
        runner = get_runner()
        runner.cancel(job_id)
        runner.discard(job_id)


# -------------------------------------------------------------- deep links


def requested_record_id() -> str | None:
    """The record id in the page URL (``?id=...``), or None if absent or malformed."""
    value = st.query_params.get(DEEP_LINK_PARAM)
    if isinstance(value, str) and _RECORD_ID.fullmatch(value):
        return value
    return None


# ---------------------------------------------------- settings page widgets


def key_input_changed(service: ApiKey | str) -> None:
    """``on_change`` for a masked key input: store the key, then empty the
    input so the key is held in one place only."""
    widget = KEY_INPUT_WIDGETS[ApiKey(service)]
    if set_api_key(service, st.session_state.get(widget, "")):
        if ApiKey(service) is ApiKey.OPENAI:
            _drop_listing(Provider.OPENAI)
        flash(f"{_KEY_LABELS[ApiKey(service)]} key saved for this session.", "ok")
    st.session_state[widget] = ""


def credential_input_changed(provider: Provider | str, field: str) -> None:
    """``on_change`` for a masked credential input: store the value, then
    empty the input so the value is held in one place only."""
    provider = Provider(provider)
    widget = CREDENTIAL_WIDGETS[(provider.value, field)]
    if set_credential_field(provider, field, st.session_state.get(widget, "")):
        flash(f"{providers.PROVIDER_LABELS[provider]} {_FIELD_WORDS[field]} saved for this "
              "session.", "ok")
    st.session_state[widget] = ""


def provider_widget_changed() -> None:
    """``on_change`` for the provider select box."""
    value = st.session_state.get(PROVIDER_WIDGET)
    try:
        set_provider(value)
    except ValueError:
        logger.info("ignoring a provider the server does not offer")


def bedrock_auth_widget_changed() -> None:
    """``on_change`` for the Bedrock sign-in choice. It changes which fields
    the page shows and never clears a held value."""
    value = st.session_state.get(BEDROCK_AUTH_WIDGET)
    if value in (BEDROCK_AUTH_API_KEY, BEDROCK_AUTH_ACCESS_KEYS):
        st.session_state[_BEDROCK_AUTH] = value


def region_widget_changed() -> None:
    """``on_change`` for the Bedrock region select box (a region is not a
    secret, so the widget keeps its value)."""
    set_credential_field(Provider.BEDROCK, "region", st.session_state.get(REGION_WIDGET, ""))


def agentic_widget_changed() -> None:
    """``on_change`` for the agentic toggle."""
    set_agentic(bool(st.session_state.get(AGENTIC_WIDGET)))


def model_widget_changed() -> None:
    """``on_change`` for the model select box. A value the provider did not
    list is refused (``set_model_choice``) and the choice is left as it was."""
    try:
        set_selected_model(st.session_state.get(MODEL_WIDGET, ""))
    except ValueError:
        logger.info("ignoring a model the provider did not list")


def import_uploader_key() -> str:
    """The workspace-import uploader's key. It changes after each import or
    clear, which empties the uploader so the same file is not applied again."""
    return f"aegis_import_{st.session_state.get(_IMPORT_NONCE, 0)}"


def rotate_import_uploader() -> None:
    """Give the import uploader a fresh, empty widget."""
    st.session_state[_IMPORT_NONCE] = int(st.session_state.get(_IMPORT_NONCE, 0)) + 1


# ------------------------------------------------------------------ flash


def flash(message: str, tone: str = "ok") -> None:
    """A one-time message for the next run of the page (after ``st.rerun``)."""
    st.session_state[_FLASH] = (message, tone)


def consume_flash() -> tuple[str, str] | None:
    """The pending one-time message, removed as it is read."""
    value = st.session_state.pop(_FLASH, None)
    return value if isinstance(value, tuple) and len(value) == 2 else None


# ------------------------------------------------- threat-model pages
# Added for the threat-model wizard, list, detail, and dashboard pages.
# Widget values that must survive a step change or a page switch are copied
# into a draft dict, because Streamlit drops a widget's state once the
# widget is not rendered.

_TM_DRAFT = "aegis_tm_draft"
_TM_RUN = "aegis_tm_run"
_MEMO = "aegis_memo"
_MEMO_MAX = 16

THREAT_MODEL_JOB = "threat_model"


def wizard_draft() -> dict[str, Any]:
    """The wizard's saved inputs for this session (a mutable dict)."""
    draft = st.session_state.get(_TM_DRAFT)
    if not isinstance(draft, dict):
        draft = {}
        st.session_state[_TM_DRAFT] = draft
    return draft


def replace_wizard_draft(values: dict[str, Any]) -> None:
    """Start the wizard over with ``values`` (an empty dict clears it)."""
    st.session_state[_TM_DRAFT] = dict(values)


def seed_widget(key: str, value: Any) -> None:
    """Give widget ``key`` a starting value unless it already holds one."""
    if key not in st.session_state:
        st.session_state[key] = value


def set_widget(key: str, value: Any) -> None:
    """Set widget ``key``'s value before the widget is drawn this run."""
    st.session_state[key] = value


def drop_widget(key: str) -> None:
    """Forget widget ``key``'s value, so it is seeded again next time."""
    st.session_state.pop(key, None)


def threat_model_run() -> dict[str, Any] | None:
    """This session's latest threat-model run: ``job_id``, ``agentic``,
    ``final`` (the settled deck record once the job ended), and
    ``record_id`` (the saved record, set exactly once)."""
    run = st.session_state.get(_TM_RUN)
    return run if isinstance(run, dict) else None


def set_threat_model_run(run: dict[str, Any] | None) -> None:
    """Replace (or with None, forget) this session's threat-model run."""
    if run is None:
        st.session_state.pop(_TM_RUN, None)
    else:
        st.session_state[_TM_RUN] = run


def cancel_job(kind: str) -> bool:
    """Ask this session's job of ``kind`` to stop, keeping its record so the
    page can show it as cancelled. True if a running job was asked."""
    job_id = active_job_id(kind)
    return bool(job_id) and get_runner().cancel(job_id)


def session_memo(name: str, key: str, build: Callable[[], Any]) -> Any:
    """``build()``'s value, computed once per ``(name, key)`` in this session.

    For values derived from one visitor's records (such as a CSF report),
    which must not go in a process-wide cache. The oldest entries are
    dropped past a small limit.
    """
    memo = st.session_state.get(_MEMO)
    if not isinstance(memo, dict):
        memo = {}
        st.session_state[_MEMO] = memo
    slot = f"{name}::{key}"
    if slot not in memo:
        while len(memo) >= _MEMO_MAX:
            memo.pop(next(iter(memo)))
        memo[slot] = build()
    return memo[slot]


# A job that ended this recently can still be adopted, so a reload that
# lands just as the job ends still shows and saves its result. After that a
# link to it opens nothing.
ADOPT_AFTER_END_SECONDS = 30.0


def adopt_job(kind: str, job_id: str) -> bool:
    """Make a job this session's job of ``kind`` again, after a reload.

    The id comes from the page URL; it is a long random token only the
    session that started the job was given. True if the runner still holds
    a job of that kind under that id and the job is running or ended at
    most ``ADOPT_AFTER_END_SECONDS`` ago.
    """
    runner = get_runner()
    snap = runner.snapshot(job_id) if _RECORD_ID_LONG.fullmatch(job_id or "") else None
    if snap is None or snap.kind != kind:
        return False
    if snap.done and runner.seconds_since_end(snap) > ADOPT_AFTER_END_SECONDS:
        return False
    _jobs()[kind] = job_id
    return True


_RECORD_ID_LONG = re.compile(r"[A-Za-z0-9_-]{16,64}")

RUN_PARAM = "run"


def requested_run_id() -> str | None:
    """The running job named in the page URL (``?run=...``), or None."""
    value = st.query_params.get(RUN_PARAM)
    return value if isinstance(value, str) and _RECORD_ID_LONG.fullmatch(value) else None


def set_run_param(job_id: str | None) -> None:
    """Put the running job's id in the URL, so a reload can find it again,
    or remove it once the run has settled."""
    if job_id:
        if st.query_params.get(RUN_PARAM) != job_id:
            st.query_params[RUN_PARAM] = job_id
    elif RUN_PARAM in st.query_params:
        del st.query_params[RUN_PARAM]


def widget_value(key: str, default: Any = None) -> Any:
    """Widget ``key``'s current value (for an ``on_click`` callback)."""
    return st.session_state.get(key, default)


# ------------------------------------------------------ AI workflow scans

_SCAN_FILES = "aegis_scan_files"
# garak's own files from a finished scan are kept in this session for a
# download as long as the job runner keeps a finished job, then dropped.
# They are never written to the workspace.
SCAN_FILES_TTL_SECONDS = DEFAULT_TTL_SECONDS
_SCAN_FILES_MAX = 3
# The most bytes of garak files one session keeps. One scan's files are at
# most about 32 MB (a 16 MB report and 8 MB each for the hit log and HTML).
SCAN_FILES_MAX_BYTES = 32 * 1024 * 1024
# Dropped first when one scan's files are over the byte limit on their own.
_DROP_ORDER = ("garak.report.html", "garak.hitlog.jsonl")


def _size(files: dict[str, bytes]) -> int:
    return sum(len(data) for data in files.values())


def keep_scan_files(record_id: str, files: dict[str, bytes], *, now: float | None = None) -> None:
    """Keep a scan's garak files for download in this session, for up to
    ``SCAN_FILES_TTL_SECONDS``.

    At most a few scans' files and ``SCAN_FILES_MAX_BYTES`` in all are kept;
    the oldest scans go first, and a scan whose files are over the limit on
    their own keeps its report and drops the HTML summary, then the hit log.
    Expired files are dropped whenever this session keeps or reads files.
    """
    stamp = time.time() if now is None else now
    files = dict(files)
    for name in _DROP_ORDER:
        if _size(files) > SCAN_FILES_MAX_BYTES:
            files.pop(name, None)
    if _size(files) > SCAN_FILES_MAX_BYTES:
        files = {}
    kept = _live_scan_files(stamp)
    while kept and (len(kept) >= _SCAN_FILES_MAX
                    or _size(files) + sum(_size(v[1]) for v in kept.values()) > SCAN_FILES_MAX_BYTES):
        kept.pop(next(iter(kept)))
    kept[record_id] = (stamp + SCAN_FILES_TTL_SECONDS, files)


def scan_files(record_id: str, *, now: float | None = None) -> dict[str, bytes] | None:
    """The kept garak files of a scan, or None once they expired or were never kept."""
    entry = _live_scan_files(time.time() if now is None else now).get(record_id)
    return dict(entry[1]) if entry else None


def _live_scan_files(now: float) -> dict[str, tuple[float, dict[str, bytes]]]:
    kept = st.session_state.get(_SCAN_FILES)
    if not isinstance(kept, dict):
        kept = {}
    kept = {k: v for k, v in kept.items() if isinstance(v, tuple) and v[0] > now}
    st.session_state[_SCAN_FILES] = kept
    return kept
