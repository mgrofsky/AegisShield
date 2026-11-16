"""Runtime settings read from the environment.

``get_settings()`` builds a fresh frozen ``Settings`` on every call, so there
is no module-level mutable state and tests can change the environment freely.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

logger = logging.getLogger(__name__)

# The models the app offers. Never add, rename, or guess a model name here.
# These are OpenAI's: AEGIS_ARCHITECT_MODEL and AEGIS_WORKER_MODEL may name
# one of them. Every other model a visitor uses comes from the provider's own
# list at run time (aegisshield.llm.providers).
DEFAULT_MODEL_NAME = "gpt-5.4"
AVAILABLE_MODELS: tuple[str, ...] = ("gpt-5.4",)

# The model providers a visitor can choose, in the order the page offers
# them. AEGIS_PROVIDERS may name a subset.
PROVIDER_NAMES: tuple[str, ...] = ("claude", "bedrock", "openai", "gemini")
DEFAULT_PROVIDER = "openai"
# The model preselected when a provider's own list holds it. For OpenAI it
# is the configured architect model (DEFAULT_MODEL_NAME unless
# AEGIS_ARCHITECT_MODEL names another); Bedrock and Gemini have none, so the
# visitor must choose.
PRESELECTED_CLAUDE_MODEL = "claude-opus-5-5"

# Jobs that may run at once in the whole process, across every visitor. A
# session already runs at most one job of each kind (state.start_job), and
# most of a job's time is spent waiting on the model or a lookup source, not
# on this machine's CPU. Two meant one visitor running a threat model and a
# lookup filled the server; four leaves room for a second visitor while
# still bounding the threads and the outside calls one process makes.
DEFAULT_MAX_CONCURRENT_JOBS = 4
# Jobs of one kind that may run at once, on top of the total above, so that
# no one kind can take every slot. Sessions are free to open, so one visitor
# with several tabs could otherwise fill the server with the cheapest job to
# start: a vulnerability lookup needs no key and can run for five minutes,
# and a capture analysis runs tshark on this machine before a bad model key
# is noticed. The numbers sum past the total on purpose; each only stops one
# kind from crowding out the rest.
# - pcap 1: the only job that uses this machine's CPU and memory (tshark).
# - lookup 2 and policy 2: half the slots each.
# - threat_model 3: the app's main job, and the longest; one slot is always
#   left for another kind.
# - ai_scan 1: an AI workflow scan runs garak, a second kind of subprocess,
#   on this machine for up to its wall-clock limit, and sends up to its
#   request limit of model calls through one visitor's key. One at a time in
#   the whole process keeps that cost to one visitor and one process.
# A kind not listed here is limited by the total only. Keys are the job kind
# names the pages submit (tests/aegisshield/test_config.py checks them).
DEFAULT_JOB_KIND_LIMITS: tuple[tuple[str, int], ...] = (
    ("pcap", 1),
    ("lookup", 2),
    ("policy", 2),
    ("threat_model", 3),
    ("ai_scan", 1),
)
# A threat-model run is stopped after 30 minutes.
DEFAULT_JOB_TIMEOUT_SECONDS = 1800

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


@dataclass(frozen=True)
class Settings:
    """Settings for one run of the app. Build it with ``get_settings()``."""

    architect_model: str = DEFAULT_MODEL_NAME
    worker_model: str = DEFAULT_MODEL_NAME
    mock_llm: bool = False
    offline: bool = False
    agentic: bool = False
    data_dir: Path | None = None
    # AI workflow scans (aegisshield.aiscan): off unless the operator sets
    # AEGIS_AI_SCAN, and only where AEGIS_GARAK_PYTHON names the Python of an
    # environment with garak installed (never the app's own environment).
    ai_scan: bool = False
    garak_python: str | None = None
    max_concurrent_jobs: int = DEFAULT_MAX_CONCURRENT_JOBS
    job_timeout_seconds: float = DEFAULT_JOB_TIMEOUT_SECONDS
    job_kind_limits: tuple[tuple[str, int], ...] = DEFAULT_JOB_KIND_LIMITS
    # The NeMo Guardrails checks on every model call (aegisshield.safeguards).
    # On unless the operator turns them off; a visitor cannot.
    safeguards: bool = True
    # When on, an input check that could not run stops the step instead of
    # letting it continue marked "not fully checked". An answer that could not
    # be checked is withheld in either mode.
    safeguards_strict: bool = False
    # The providers this server offers (AEGIS_PROVIDERS; all four by default).
    providers: tuple[str, ...] = PROVIDER_NAMES
    # The visitor's choice, set by ``with_model_choice`` for one session's
    # work and never read from the environment: the provider that answers,
    # and whether its chosen model takes images (None: not known).
    provider: str = DEFAULT_PROVIDER
    model_vision: bool | None = None


def _flag(env: Mapping[str, str], name: str) -> bool:
    return env.get(name, "").strip().lower() in _TRUE


def _on_unless_off(env: Mapping[str, str], name: str) -> bool:
    """True unless ``name`` is set to 0, false, no, or off."""
    return env.get(name, "").strip().lower() not in _FALSE


def _model(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        return DEFAULT_MODEL_NAME
    if value not in AVAILABLE_MODELS:
        logger.warning("ignoring %s: model is not in AVAILABLE_MODELS", name)
        return DEFAULT_MODEL_NAME
    return value


def _providers(env: Mapping[str, str]) -> tuple[str, ...]:
    """The providers named in ``AEGIS_PROVIDERS``, in the page's order.

    Unknown names are ignored; a value that names none of the four falls
    back to all four, so a typo never leaves a server with no provider.
    """
    raw = env.get("AEGIS_PROVIDERS", "").strip()
    if not raw:
        return PROVIDER_NAMES
    named = {part.strip().lower() for part in raw.split(",") if part.strip()}
    unknown = named - set(PROVIDER_NAMES)
    if unknown:
        logger.warning("ignoring %d unknown name(s) in AEGIS_PROVIDERS", len(unknown))
    chosen = tuple(name for name in PROVIDER_NAMES if name in named)
    if not chosen:
        logger.warning("ignoring AEGIS_PROVIDERS: it names no known provider")
        return PROVIDER_NAMES
    return chosen


def with_model_choice(settings: Settings, *, provider: str, model: str,
                      vision: bool | None = None) -> Settings:
    """``settings`` with one visitor's choice applied: ``model`` answers
    every call (architect and worker alike) through ``provider``.

    An empty ``model`` means no model is chosen yet; ``get_llm`` then
    refuses to build a client. The caller checks that ``model`` is one the
    provider listed.
    """
    return replace(settings, provider=provider, architect_model=model, worker_model=model,
                   model_vision=vision)


def _positive_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("ignoring %s: not a whole number", name)
        return default
    if value < 1:
        logger.warning("ignoring %s: must be at least 1", name)
        return default
    return value


def get_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Read settings from ``env`` (default ``os.environ``).

    Model overrides are accepted only when they name a model in
    ``AVAILABLE_MODELS``; anything else falls back to the default model.
    ``AEGIS_MAX_CONCURRENT_JOBS`` and ``AEGIS_JOB_TIMEOUT_SECONDS`` may tune
    the job runner; bad values fall back to the defaults.
    ``AEGIS_AI_SCAN`` turns AI workflow scans on, and ``AEGIS_GARAK_PYTHON``
    names the interpreter that runs garak (checked in ``aegisshield.aiscan``).
    ``AEGIS_SAFEGUARDS`` is on unless set to 0, false, no, or off, and
    ``AEGIS_SAFEGUARDS_STRICT`` is off unless set to 1, true, yes, or on.
    ``AEGIS_PROVIDERS`` limits the model providers offered (``_providers``).
    """
    env = os.environ if env is None else env
    data_dir = env.get("AEGIS_DATA_DIR", "").strip()
    return Settings(
        architect_model=_model(env, "AEGIS_ARCHITECT_MODEL"),
        worker_model=_model(env, "AEGIS_WORKER_MODEL"),
        mock_llm=_flag(env, "AEGIS_MOCK_LLM"),
        offline=_flag(env, "AEGIS_OFFLINE"),
        agentic=_flag(env, "AEGIS_AGENTIC"),
        data_dir=Path(data_dir).expanduser() if data_dir else None,
        ai_scan=_flag(env, "AEGIS_AI_SCAN"),
        garak_python=env.get("AEGIS_GARAK_PYTHON", "").strip() or None,
        max_concurrent_jobs=_positive_int(
            env, "AEGIS_MAX_CONCURRENT_JOBS", DEFAULT_MAX_CONCURRENT_JOBS
        ),
        job_timeout_seconds=_positive_int(
            env, "AEGIS_JOB_TIMEOUT_SECONDS", DEFAULT_JOB_TIMEOUT_SECONDS
        ),
        safeguards=_on_unless_off(env, "AEGIS_SAFEGUARDS"),
        safeguards_strict=_flag(env, "AEGIS_SAFEGUARDS_STRICT"),
        providers=_providers(env),
    )
