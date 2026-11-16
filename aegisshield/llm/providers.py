"""The four model providers, a visitor's credential, and the live model list.

A visitor chooses a provider, gives that provider's credential, and picks a
model from the list the provider returns for that credential. Nothing here
names a model except the preselection rule (``preselected_model``), whose
names come from ``aegisshield.config``.

Every SDK is imported only inside its own client module, so the app starts
when one is missing and that provider shows as unavailable.
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from aegisshield.config import PRESELECTED_CLAUDE_MODEL, PROVIDER_NAMES, Settings
from aegisshield.core.errors import LLMError
from aegisshield.llm.base import ERROR_LIST_FAILED, LIST_TIMEOUT_SECONDS, ModelInfo

logger = logging.getLogger(__name__)

__all__ = [
    "BEDROCK_REGIONS",
    "Credential",
    "ERROR_NOT_LISTED",
    "ERROR_NO_MODEL",
    "ERROR_PROVIDER_OFF",
    "ERROR_PROVIDER_UNAVAILABLE",
    "IMAGE_UNSUPPORTED",
    "MAX_MODELS",
    "MAX_MODEL_ID_CHARS",
    "MOCK_PROVIDER",
    "ModelInfo",
    "PROVIDER_LABELS",
    "Provider",
    "answered_by",
    "answered_by_words",
    "bedrock_uses_api_key",
    "clean_models",
    "credential_fields",
    "list_models",
    "missing_credential",
    "offered_providers",
    "preselected_model",
    "provider_label",
    "sdk_available",
]


class Provider(StrEnum):
    """The model providers the app can call."""

    CLAUDE = "claude"
    BEDROCK = "bedrock"
    OPENAI = "openai"
    GEMINI = "gemini"


PROVIDER_LABELS: dict[Provider, str] = {
    Provider.CLAUDE: "Claude (Anthropic)",
    Provider.BEDROCK: "Amazon Bedrock",
    Provider.OPENAI: "OpenAI",
    Provider.GEMINI: "Gemini (Google)",
}
# The record and page name for the canned answers of mock mode.
MOCK_PROVIDER = "mock"
MOCK_WORDS = "Mock mode (canned answers)"

# The import each provider's client needs; ``sdk_available`` asks for it
# without importing it.
_SDK_MODULES: dict[Provider, str] = {
    Provider.CLAUDE: "anthropic",
    Provider.BEDROCK: "boto3",
    Provider.OPENAI: "openai",
    Provider.GEMINI: "google.genai",
}
_CLIENT_MODULES: dict[Provider, str] = {
    Provider.CLAUDE: "aegisshield.llm.anthropic_client",
    Provider.BEDROCK: "aegisshield.llm.bedrock_client",
    Provider.OPENAI: "aegisshield.llm.openai_models",
    Provider.GEMINI: "aegisshield.llm.gemini_client",
}

# The AWS regions a visitor may choose for Bedrock: the commercial regions
# where botocore 1.44.3's packaged endpoint data lists the ``bedrock``
# service (``Session().get_available_regions("bedrock")``), copied here so
# the list is fixed in code. A test holds it to botocore's data. A region
# where the visitor's account has no Bedrock access fails at listing time
# with the fixed sentence.
BEDROCK_REGIONS: tuple[str, ...] = (
    "af-south-1", "ap-east-2", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3",
    "ap-southeast-4", "ap-southeast-5", "ap-southeast-6", "ap-southeast-7", "ca-central-1",
    "ca-west-1", "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "il-central-1", "me-central-1", "me-south-1",
    "mx-central-1", "sa-east-1", "us-east-1", "us-east-2", "us-west-1", "us-west-2",
)

ERROR_NO_MODEL = "Choose a model in Settings to run this step."
ERROR_PROVIDER_OFF = "That model provider is not offered on this server."
ERROR_PROVIDER_UNAVAILABLE = "That model provider's software is not installed on this server."
ERROR_NOT_LISTED = "Choose a model from the provider's list."
IMAGE_UNSUPPORTED = ("The chosen model cannot read images, so the diagram was not described. "
                     "Describe it in the text, or choose a model that reads images.")

# A model id is shown and sent only when it is this shape: a letter or
# digit, then letters, digits, dots, underscores, colons, or hyphens. That
# covers every id shape the four providers use (Bedrock's
# ``anthropic.example-v1:0`` and ``us.`` profile ids among them) and nothing
# that can carry markup, a path, or whitespace.
MAX_MODEL_ID_CHARS = 128
_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
# The most models a list keeps, after filtering and sorting.
MAX_MODELS = 200


@dataclass(frozen=True, repr=False)
class Credential:
    """One visitor's credential for one provider, passed by value.

    Claude, OpenAI, and Gemini use ``api_key``. Bedrock takes a
    ``region`` (one of ``BEDROCK_REGIONS``; a region is not a secret) and
    either ``api_key``, holding a Bedrock API key, or ``access_key_id``,
    ``secret_access_key``, and the optional ``session_token``. When a
    Bedrock credential holds an API key, the API key is used and any
    access keys beside it are not (``bedrock_uses_api_key``). ``repr``
    and ``str`` show no value, so a credential that reaches a log line or
    an exception shows nothing.
    """

    api_key: str = ""
    access_key_id: str = ""
    secret_access_key: str = ""
    session_token: str = ""
    region: str = ""

    def __repr__(self) -> str:
        return "Credential()"

    __str__ = __repr__


# What each provider needs, in the order the page asks for it, with the
# fixed sentence a run gets when that field is missing. Bedrock's entry is
# the access-key way; a Bedrock API key replaces its two key fields
# (``missing_credential``).
_FIELDS: dict[Provider, tuple[tuple[str, str], ...]] = {
    Provider.CLAUDE: (("api_key", "Add a Claude API key to run this step."),),
    Provider.OPENAI: (("api_key", "Add an OpenAI API key to run this step."),),
    Provider.GEMINI: (("api_key", "Add a Gemini API key to run this step."),),
    Provider.BEDROCK: (
        ("access_key_id", "Add an AWS access key ID for Amazon Bedrock to run this step."),
        ("secret_access_key", "Add an AWS secret access key for Amazon Bedrock to run this step."),
        ("region", "Choose an AWS region for Amazon Bedrock to run this step."),
    ),
}
_BEDROCK_NOTHING = ("Add a Bedrock API key, or an AWS access key ID and secret access key, for "
                    "Amazon Bedrock to run this step.")


def bedrock_uses_api_key(credential: Credential | None) -> bool:
    """True when a Bedrock credential holds an API key. The key then wins:
    it is used, and any access keys beside it are not."""
    return bool(credential is not None and credential.api_key.strip())


def credential_fields(provider: Provider | str) -> tuple[str, ...]:
    """The required credential fields of ``provider``, in page order (for
    Bedrock, the access-key way)."""
    return tuple(name for name, _ in _FIELDS[Provider(provider)])


def missing_credential(provider: Provider | str, credential: Credential | None) -> str | None:
    """The fixed sentence naming the first missing field, or None when the
    credential is complete. A Bedrock region outside ``BEDROCK_REGIONS``
    counts as missing. Bedrock is complete with a region and either an API
    key or an access key ID and secret access key; with neither, the
    sentence names both ways."""
    cred = credential or Credential()
    fields = _FIELDS[Provider(provider)]
    if Provider(provider) is Provider.BEDROCK:
        if bedrock_uses_api_key(cred):
            fields = fields[2:]
        elif not (cred.access_key_id.strip() or cred.secret_access_key.strip()):
            return _BEDROCK_NOTHING
    for name, sentence in fields:
        value = getattr(cred, name).strip()
        if not value or (name == "region" and value not in BEDROCK_REGIONS):
            return sentence
    return None


def provider_label(provider: str) -> str:
    """The provider's name for the page; "Mock mode (canned answers)" for
    the mock and "Unknown provider" for anything else."""
    if provider == MOCK_PROVIDER:
        return MOCK_WORDS
    try:
        return PROVIDER_LABELS[Provider(provider)]
    except ValueError:
        return "Unknown provider"


def sdk_available(provider: Provider | str) -> bool:
    """True when the SDK ``provider`` needs can be imported (asked without
    importing it)."""
    try:
        return importlib.util.find_spec(_SDK_MODULES[Provider(provider)]) is not None
    except (ImportError, ValueError):
        return False


def offered_providers(settings: Settings) -> tuple[Provider, ...]:
    """The providers this server offers (``AEGIS_PROVIDERS``), in page order."""
    return tuple(p for p in Provider if p.value in settings.providers)


def valid_model_id(value: object) -> bool:
    """True for a model id of the allowed shape and length."""
    return isinstance(value, str) and len(value) <= MAX_MODEL_ID_CHARS and bool(
        _MODEL_ID.fullmatch(value))


def clean_models(found: Iterable[ModelInfo]) -> tuple[ModelInfo, ...]:
    """The models to offer: ids of the allowed shape only, one entry per id
    (the first seen), sorted, and at most ``MAX_MODELS``."""
    kept: dict[str, ModelInfo] = {}
    for model in found:
        if not isinstance(model, ModelInfo) or not valid_model_id(model.id):
            continue
        vision = model.vision if isinstance(model.vision, bool) else None
        kept.setdefault(model.id, ModelInfo(model.id, vision))
    return tuple(kept[key] for key in sorted(kept))[:MAX_MODELS]


def list_models(provider: Provider | str, credential: Credential, *,
                timeout_seconds: float = LIST_TIMEOUT_SECONDS,
                sdk_client: Any | None = None) -> tuple[ModelInfo, ...]:
    """Ask ``provider`` for its models with the visitor's ``credential``.

    Returns the cleaned list (``clean_models``). Raises ``LLMError`` with a
    fixed sentence when the credential is incomplete, the SDK is missing,
    or the listing fails; the provider's own text never reaches the
    sentence. ``sdk_client`` lets tests pass a fake SDK client.
    """
    provider = Provider(provider)
    missing = missing_credential(provider, credential)
    if missing:
        raise LLMError(missing)
    if sdk_client is None and not sdk_available(provider):
        raise LLMError(ERROR_PROVIDER_UNAVAILABLE)
    module = importlib.import_module(_CLIENT_MODULES[provider])
    try:
        found = module.list_models(credential, timeout_seconds=timeout_seconds, sdk_client=sdk_client)
        return clean_models(found)
    except LLMError:
        raise
    # An SDK can raise outside its own error classes (an unexpected response
    # shape, a parse error). This runs in the page's thread, where an
    # uncaught error is logged with its message, which may quote request
    # details; so only the class is logged and the fixed sentence raised.
    except Exception as exc:
        logger.warning("%s model list failed unexpectedly kind=%s", provider.value, type(exc).__name__)
        raise LLMError(ERROR_LIST_FAILED) from None


def preselected_model(provider: Provider | str, models: Iterable[ModelInfo],
                      settings: Settings) -> str | None:
    """The model to preselect when the list holds it: the configured
    architect model for OpenAI, ``PRESELECTED_CLAUDE_MODEL`` for Claude,
    and none for Bedrock and Gemini."""
    ids = {m.id for m in models}
    provider = Provider(provider)
    wanted = {Provider.OPENAI: settings.architect_model,
              Provider.CLAUDE: PRESELECTED_CLAUDE_MODEL}.get(provider)
    return wanted if wanted in ids else None


def answered_by(settings: Settings) -> dict[str, str]:
    """The record of which provider and model answer a job's calls, stored
    with its result: ``{"provider": ..., "name": ...}``."""
    if settings.mock_llm:
        return {"provider": MOCK_PROVIDER, "name": MOCK_PROVIDER}
    return {"provider": settings.provider, "name": settings.architect_model}


def answered_by_words(record: object) -> str | None:
    """A stored ``answered_by`` record in words for the page, or None when
    the record is missing (an older record) or malformed. Only a known
    provider and a model id of the allowed shape are shown."""
    if not isinstance(record, dict):
        return None
    provider = record.get("provider")
    name = record.get("name")
    if provider == MOCK_PROVIDER:
        return MOCK_WORDS
    if provider not in PROVIDER_NAMES or not valid_model_id(name):
        return None
    return f"{provider_label(provider)}, {name}"
