"""The rails engine: NeMo Guardrails configuration, actions, and checks.

``build_engine()`` builds one job's ``LLMRails`` from the packaged
configuration (``rails/config.yml`` and ``rails/rails.co``) with no model,
and registers that job's actions (``rails/actions.py``). ``check`` runs one
rail set through ``LLMRails.check_async`` on supplied text: input rails for
typed text, the gated retrieved-content flows (also input rails, see the
configuration) for everything else, and output rails for answers. Nothing
here calls a model, downloads anything, or opens a connection.

NeMo is imported only here, lazily, after ``NEMO_GUARDRAILS_NO_USAGE_STATS``
is set. When it is missing, ``build_engine`` raises ``EngineUnavailable``
and every check reads ``not_checked``.
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import importlib.util
import itertools
import logging
import os
import threading
from dataclasses import dataclass, field
from importlib import resources
from typing import TYPE_CHECKING, Any, Protocol

from aegisshield.safeguards import detect
from aegisshield.safeguards.rails.actions import (
    OUTPUT_ACTIONS,
    RAIL_LEAK,
    Collector,
    make_actions,
)

if TYPE_CHECKING:
    from aegisshield.safeguards.core import CheckStatus, RailSet

logger = logging.getLogger(__name__)

ENGINE_NAME = "NeMo Guardrails"
_RAILS_PACKAGE = "aegisshield.safeguards.rails"


class EngineUnavailable(Exception):  # noqa: N818 (reads as a state, like StopIteration)
    """The rails cannot be built here; the message says why, for the record."""


@dataclass
class Finding:
    """What one rail found. ``excerpt`` is short and never holds a secret."""

    rail: str
    reason: str
    excerpt: str | None = None


@dataclass
class EngineResult:
    """The result of one check through the rails."""

    status: CheckStatus
    content: str
    rail: str | None = None
    reason: str = ""
    findings: list[Finding] = field(default_factory=list)


class Engine(Protocol):
    """What ``Safeguards`` needs from the rails."""

    def check(self, rail_set: RailSet, text: str, context: dict[str, Any]) -> EngineResult:
        """Run one rail set on ``text``."""
        ...

    def clean(self, text: str) -> str:
        """``text`` with what the output rails remove removed."""
        ...

    def stream_trip(self, text: str, context: dict[str, Any]) -> bool:
        """True when partial answer text already trips an output rail."""
        ...

    def demands_in(self, text: str) -> list[str]:
        """Strings that an instruction in ``text`` tells the model to output."""
        ...


def nemo_available() -> bool:
    """True when NeMo Guardrails is installed (found without importing it)."""
    return importlib.util.find_spec("nemoguardrails") is not None


def nemo_version() -> str | None:
    """The installed NeMo Guardrails version, or None."""
    try:
        return importlib.metadata.version("nemoguardrails")
    except importlib.metadata.PackageNotFoundError:
        return None


def engine_name() -> str:
    """The name of the rails engine, for the record and the Settings page."""
    return ENGINE_NAME


def rails_files() -> tuple[str, str]:
    """The packaged rails configuration: ``(config.yml, rails.co)`` text."""
    root = resources.files(_RAILS_PACKAGE)
    return (root.joinpath("config.yml").read_text(encoding="utf-8"),
            root.joinpath("rails.co").read_text(encoding="utf-8"))


class NemoEngine:
    """One job's rails: an ``LLMRails`` with no model and that job's actions."""

    def __init__(self) -> None:
        os.environ["NEMO_GUARDRAILS_NO_USAGE_STATS"] = "1"
        try:
            from nemoguardrails import LLMRails, RailsConfig
            from nemoguardrails.rails.llm.options import RailStatus, RailType
        except ImportError:
            # Only a package that cannot be found is "not installed", the one
            # state in which answers pass unchecked. An installed package
            # that fails to import is a build failure: answers are withheld.
            if not nemo_available():
                raise EngineUnavailable("NeMo Guardrails is not installed.") from None
            raise
        # NeMo logs the text under check at INFO and DEBUG; keep it out of
        # the app's logs.
        logging.getLogger("nemoguardrails").setLevel(logging.WARNING)
        self._status = RailStatus
        self._types = RailType
        yaml_text, colang_text = rails_files()
        config = RailsConfig.from_content(yaml_content=yaml_text, colang_content=colang_text)
        self._rails = LLMRails(config)
        self._collector = Collector()
        for name, fn in make_actions(self._collector).items():
            self._rails.register_action(fn, name)
        self._ids = itertools.count(1)
        self._ids_lock = threading.Lock()

    def _next_id(self) -> str:
        with self._ids_lock:
            return f"check-{next(self._ids)}"

    def check(self, rail_set: RailSet, text: str, context: dict[str, Any]) -> EngineResult:
        """Run ``rail_set`` on ``text``; see ``Engine.check``.

        Runs its own event loop, so it is called from a plain thread.
        """
        from aegisshield.safeguards.core import CheckStatus, RailSet

        check_id = self._next_id()
        ctx = {**context, "aegis_rail_set": rail_set.value, "aegis_check": check_id}
        messages: list[dict[str, Any]] = [{"role": "context", "content": ctx}]
        if rail_set is RailSet.OUTPUT:
            # An output check needs a user turn before the answer, or NeMo
            # skips the output rails and returns an empty result.
            messages += [{"role": "user", "content": "."}, {"role": "assistant", "content": text}]
            types = [self._types.OUTPUT]
            expected: tuple[str, ...] = OUTPUT_ACTIONS
        else:
            messages.append({"role": "user", "content": text})
            types = [self._types.INPUT]
            expected = ("aegis_typed_instructions",) if rail_set is RailSet.INPUT else (
                "aegis_retrieved_instructions",)
        result = asyncio.run(self._rails.check_async(messages, rail_types=types))
        ran, found = self._collector.pop(check_id)
        findings = [Finding(f.rail, f.reason, f.excerpt) for f in found]
        if result.status == self._status.BLOCKED:
            blocking = [f for f in found if f.blocked]
            if not blocking:
                return EngineResult(CheckStatus.NOT_CHECKED, text, result.rail,
                                    "A rail stopped the answer without saying why.", findings)
            first = blocking[0]
            ordered = [Finding(first.rail, first.reason, first.excerpt)] + [
                f for f in findings if f.rail != first.rail]
            return EngineResult(CheckStatus.BLOCKED, text, result.rail, first.reason, ordered)
        missing = [name for name in expected if name not in ran]
        if missing:
            return EngineResult(CheckStatus.NOT_CHECKED, text, None,
                                "The rail did not run.", findings)
        if any(f.modified for f in found):
            return EngineResult(CheckStatus.MODIFIED, result.content, None,
                                next(f.reason for f in found if f.modified), findings)
        # Our actions changed nothing, so the text is used as it was given,
        # whatever NeMo did to the message on its way through.
        return EngineResult(CheckStatus.PASSED, text, None, "", findings)

    def clean(self, text: str) -> str:
        """``text`` with secrets and exfiltration markup removed."""
        return detect.clean_answer(text)

    def stream_trip(self, text: str, context: dict[str, Any]) -> bool:
        """True when partial answer text already trips an output rail."""
        # The prompt's word runs are worked out once per streamed answer.
        if "aegis_print" not in context:
            context["aegis_print"] = detect.prompt_print(str(context.get("aegis_system") or ""))
        return detect.stream_trips(text, context["aegis_print"],
                                   [str(d) for d in context.get("aegis_demands") or []])

    def demands_in(self, text: str) -> list[str]:
        """Strings an unquoted instruction in ``text`` tells the model to output."""
        return detect.demands_in(text)


def build_engine() -> Engine:
    """The rails for one job. Raises ``EngineUnavailable`` when NeMo is missing."""
    return NemoEngine()


__all__ = [
    "ENGINE_NAME",
    "RAIL_LEAK",
    "Engine",
    "EngineResult",
    "EngineUnavailable",
    "Finding",
    "NemoEngine",
    "build_engine",
    "engine_name",
    "nemo_available",
    "nemo_version",
    "rails_files",
]
