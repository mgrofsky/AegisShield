"""Which public data sources a vulnerability lookup may call.

Every source answers to two switches: the app-wide offline switch
(``Settings.offline``, read from ``AEGIS_OFFLINE``) and its own disable flag.
The flag names (``AEGIS_DISABLE_*``) stay fixed, so an existing deployment's
configuration keeps working. Flags are read when the lookup runs, so tests and
operators can change them without rebuilding ``Settings``. Every flag accepts
the same values (``1``, ``true``, ``yes``, ``on``).
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from aegisshield.config import Settings

OFFLINE_FLAG = "AEGIS_OFFLINE"

SOURCE_FLAGS: dict[str, str] = {
    "nvd": "AEGIS_DISABLE_NVD",
    "kev": "AEGIS_DISABLE_KEV",
    "epss": "AEGIS_DISABLE_EPSS",
    "otx": "AEGIS_DISABLE_OTX",
    "exploitdb": "AEGIS_DISABLE_EXPLOITDB",
    "eol": "AEGIS_DISABLE_EOL",
}

_TRUE = {"1", "true", "yes", "on"}


def _flag(env: Mapping[str, str], name: str) -> bool:
    return env.get(name, "").strip().lower() in _TRUE


def offline(settings: Settings | None = None, env: Mapping[str, str] | None = None) -> bool:
    """True when the app-wide offline switch is on, in ``settings`` or in
    the environment (``env`` defaults to ``os.environ``)."""
    env = os.environ if env is None else env
    return (settings is not None and settings.offline) or _flag(env, OFFLINE_FLAG)


def source_disabled(
    source: str, settings: Settings | None = None, env: Mapping[str, str] | None = None
) -> bool:
    """True when ``source`` (a key of ``SOURCE_FLAGS``) must not be called.

    Offline in ``settings`` or in the environment, or the source's own flag,
    switches it off. ``env`` defaults to ``os.environ``.
    """
    if source not in SOURCE_FLAGS:
        raise ValueError(f"unknown lookup source: {source}")
    env = os.environ if env is None else env
    return offline(settings, env) or _flag(env, SOURCE_FLAGS[source])
