"""``Safeguards``: one job's checks, its record, and the guarded model client.

The rails themselves (NeMo Guardrails configuration and actions) live in
``aegisshield.safeguards.engine``; this module decides when they run, what
a result means for the step, and what is recorded.

States are exact. A check that did not run, raised, or ran past its time
limit is ``not_checked``, never ``passed``. For input and retrieved text the
step goes on by default, marked not fully checked, and stops in strict mode.
A model answer that could not be checked is withheld and the step fails, in
every mode: an unchecked answer is the one thing that must not pass. The one
exception is a deployment where NeMo Guardrails is not installed at all;
the app then works and every record says the safeguards were unavailable.
"""

from __future__ import annotations

import logging
import re
import threading
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from aegisshield.config import Settings
from aegisshield.core.errors import AegisError
from aegisshield.llm.base import (
    DEFAULT_IMAGE_MAX_TOKENS,
    DEFAULT_JSON_MAX_TOKENS,
    DEFAULT_TEXT_MAX_TOKENS,
    LLMClient,
    OnText,
    SafeText,
)
from aegisshield.safeguards import detect
from aegisshield.safeguards import engine as engine_mod
from aegisshield.safeguards.engine import Engine, EngineResult, EngineUnavailable
from aegisshield.safeguards.rails.actions import RAIL_EXFILTRATION

logger = logging.getLogger(__name__)

# The key the record goes under in a job result and a stored record.
REPORT_KEY = "safeguards"
REPORT_VERSION = 1

# A check takes a few milliseconds; this is far above that and still short
# enough that a stuck check cannot hold a step for long.
CHECK_TIME_LIMIT_SECONDS = 2.0

# The fixed sentences a stopped step shows. They name the reason and never
# quote the rail's internals or the matched text.
BLOCKED_LEAK = (
    "The AI's answer was withheld because it repeated the app's own instructions to the AI."
)
BLOCKED_INJECTION = (
    "The AI's answer was withheld because it followed an instruction found in the input."
)
NOT_CHECKED_INPUT = (
    "Some of the input could not be checked by the safeguards, and this server "
    "requires every check to run."
)
NOT_CHECKED_ANSWER = (
    "The AI's answer was withheld because the safeguards could not check it."
)
TOO_MANY_STUCK = (
    "The safeguards stopped this step because too many of its checks did not finish in time."
)
# The sentences a job may show as they are (``jobs.runner.plain_error``).
JOB_ERRORS = frozenset({BLOCKED_LEAK, BLOCKED_INJECTION, NOT_CHECKED_INPUT, NOT_CHECKED_ANSWER,
                        TOO_MANY_STUCK})
# The record's reason for a JSON answer whose removable markup spans two of
# its strings, which is withheld because no one string can be cleaned.
SPLIT_MARKUP = "The markup spans two strings of the answer, so it could not be removed."
# The record's reason for an answer that never arrived: the model call raised.
FAILED_CALL = "The model call failed before its answer could be checked."
# A check past its time limit is abandoned on its thread, which Python cannot
# stop. One job may leave at most this many behind; the next check after
# that fails the step instead of starting another thread.
MAX_ABANDONED_CHECKS = 2


class Source(StrEnum):
    """Where a piece of text came from."""

    DESCRIPTION = "description"   # typed by the visitor
    DIAGRAM = "diagram"           # a model's description of an uploaded image
    CAPTURE = "capture"           # text derived from an uploaded packet capture
    LOOKUP = "lookup"             # results from NVD and the other lookup sources
    THREAT_INTEL = "threat_intel"  # OTX reports
    PROFILE = "profile"           # organization profile and wizard selections
    IMPORT = "import"             # text from an imported workspace record
    POLICY = "policy"             # policy text a visitor edited
    WORKFLOW_MESSAGE = "workflow_message"  # the user turn of a visitor's workflow in a scan
    SAMPLE_CONTEXT = "sample_context"      # sample context a visitor gave for that workflow


class RailSet(StrEnum):
    """The three rail sets."""

    INPUT = "input"          # text the visitor typed
    RETRIEVED = "retrieved"  # text from anywhere else that reaches a prompt
    OUTPUT = "output"        # every model answer


class CheckStatus(StrEnum):
    """The result of one check."""

    PASSED = "passed"
    MODIFIED = "modified"
    BLOCKED = "blocked"
    NOT_CHECKED = "not_checked"


TYPED_SOURCES = frozenset({Source.DESCRIPTION, Source.PROFILE, Source.POLICY, Source.WORKFLOW_MESSAGE})

SOURCE_LABELS: dict[Source, str] = {
    Source.DESCRIPTION: "the description",
    Source.DIAGRAM: "the diagram description",
    Source.CAPTURE: "the capture",
    Source.LOOKUP: "the lookup results",
    Source.THREAT_INTEL: "the threat intelligence",
    Source.PROFILE: "the profile",
    Source.IMPORT: "the imported record",
    Source.POLICY: "the policy text",
    Source.WORKFLOW_MESSAGE: "the message",
    Source.SAMPLE_CONTEXT: "the sample context",
}


def rail_set_for(source: Source) -> RailSet:
    """Input rails for typed text, retrieved-content rails for the rest."""
    return RailSet.INPUT if source in TYPED_SOURCES else RailSet.RETRIEVED


class SafeguardsStopped(AegisError):
    """A step stopped by the safeguards. The message is one of ``JOB_ERRORS``."""


@dataclass
class _Check:
    rail_set: RailSet
    status: CheckStatus
    source: Source | None = None
    step: str | None = None
    rail: str | None = None
    reason: str = ""
    excerpt: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rail_set": self.rail_set.value,
            "source": self.source.value if self.source else None,
            "step": self.step,
            "status": self.status.value,
            "rail": self.rail,
            "reason": self.reason,
            "excerpt": self.excerpt,
        }


@dataclass
class _Outcome:
    status: CheckStatus
    content: str
    result: EngineResult | None = None
    reason: str = ""


@dataclass
class _JobState:
    """What one ``Safeguards`` object holds: its record, how many calls it
    saw, and the demands in text the visitor typed."""

    checks: list[_Check] = field(default_factory=list)
    calls: int = 0
    typed_demands: set[str] = field(default_factory=set)
    simulated: bool = False
    abandoned: list[threading.Thread] = field(default_factory=list)


class Safeguards:
    """The checks for one job. Build it with ``from_settings``."""

    def __init__(
        self,
        *,
        enabled: bool,
        strict: bool = False,
        engine_factory: Callable[[], Engine] | None = None,
        time_limit_seconds: float = CHECK_TIME_LIMIT_SECONDS,
    ) -> None:
        self._enabled = enabled
        self._strict = strict
        self._factory = engine_factory or engine_mod.build_engine
        self._time_limit = time_limit_seconds
        self._lock = threading.Lock()
        self._state = _JobState()
        self._engine: Engine | None = None
        self._unavailable: str | None = None
        # True when NeMo itself is missing: the deployment's configuration,
        # under which answers still pass (marked), unlike a per-check failure.
        self._not_installed = False

    @classmethod
    def from_settings(cls, settings: Settings, *, enabled: bool | None = None) -> Safeguards:
        """A job's safeguards as the deployment sets them; ``enabled`` overrides."""
        on = settings.safeguards if enabled is None else enabled
        return cls(enabled=on, strict=settings.safeguards_strict)

    @property
    def enabled(self) -> bool:
        """False when switched off; every method is then a pass through."""
        return self._enabled

    @property
    def not_installed(self) -> bool:
        """True when NeMo itself is missing (the deployment runs unchecked, marked)."""
        self._get_engine()
        return self._not_installed

    @property
    def strict(self) -> bool:
        """True when a check that could not run stops the step."""
        return self._strict

    # ------------------------------------------------------------ public

    def screen(self, source: Source, text: str) -> str:
        """The text to use in a prompt; records what the check found.

        Raises ``SafeguardsStopped`` only in strict mode, when the check could
        not run. Empty text is returned as it is and not recorded.
        """
        if not self._enabled or not text or not text.strip():
            return text
        source = Source(source)
        rail_set = rail_set_for(source)
        outcome = self._run(rail_set, text, {"aegis_source": source.value,
                                             "aegis_source_label": SOURCE_LABELS[source]})
        self._record(rail_set, outcome, source=source)
        if source in TYPED_SOURCES:
            self._note_typed_demands(text)
        if outcome.status is CheckStatus.NOT_CHECKED:
            if self._strict:
                raise SafeguardsStopped(NOT_CHECKED_INPUT)
            return text
        return outcome.content

    def screen_values(self, source: Source, values: Mapping[str, Any]) -> dict[str, Any]:
        """``values`` with every string value screened, and inside nested
        mappings the keys too; the top-level keys are field names and stay."""
        return {k: self._screen_any(source, v) for k, v in values.items()}

    def wrap(self, llm: LLMClient) -> LLMClient:
        """A client whose every call passes the output rails (``llm`` when off)."""
        if not self._enabled:
            return llm
        if isinstance(llm, GuardedLLM) and llm.safeguards is self:
            return llm
        if getattr(llm, "simulated", False):
            with self._lock:
                self._state.simulated = True
        return GuardedLLM(llm, self)

    def report(self) -> dict[str, Any]:
        """A JSON-safe record of every check this object ran."""
        with self._lock:
            checks = [c.to_dict() for c in self._state.checks]
            simulated = self._state.simulated
        counts = {s.value: 0 for s in CheckStatus}
        for check in checks:
            counts[check["status"]] += 1
        return {
            "version": REPORT_VERSION,
            "status": self._status(),
            "enabled": self._enabled,
            "strict": self._strict,
            "engine": engine_mod.engine_name(),
            "engine_version": engine_mod.nemo_version(),
            "simulated_model": simulated,
            "checks": checks,
            "counts": {"total": len(checks), **counts},
            "complete": counts[CheckStatus.NOT_CHECKED.value] == 0,
        }

    # ------------------------------------------------------------ internals

    def _status(self) -> str:
        if not self._enabled:
            return "off"
        if self._unavailable is not None or not engine_mod.nemo_available():
            return "unavailable"
        return "on"

    def _screen_any(self, source: Source, value: Any) -> Any:
        if isinstance(value, str):
            return self.screen(source, value)
        if isinstance(value, Mapping):
            return {self.screen(source, k) if isinstance(k, str) else k: self._screen_any(source, v)
                    for k, v in value.items()}
        if isinstance(value, list):
            return [self._screen_any(source, v) for v in value]
        return value

    def _get_engine(self) -> Engine | None:
        with self._lock:
            if self._engine is not None or self._unavailable is not None:
                return self._engine
            try:
                self._engine = self._factory()
            except EngineUnavailable as exc:
                self._unavailable = str(exc) or "The rails could not be built."
                # Decided by whether the package can be found, never by the
                # exception alone: only then may answers pass unchecked.
                self._not_installed = not engine_mod.nemo_available()
            # Building the rails runs third-party code that can fail in any
            # way; the job goes on and every check reads not_checked.
            except Exception as exc:
                logger.warning("safeguards engine build failed kind=%s", type(exc).__name__)
                self._unavailable = "The rails could not be built."
            return self._engine

    def _run(self, rail_set: RailSet, text: str, context: dict[str, Any]) -> _Outcome:
        """Run one check on a helper thread, bounded by the time limit."""
        engine = self._get_engine()
        if engine is None:
            return _Outcome(CheckStatus.NOT_CHECKED, text, reason=self._unavailable or "")
        with self._lock:
            self._state.abandoned = [t for t in self._state.abandoned if t.is_alive()]
            if len(self._state.abandoned) >= MAX_ABANDONED_CHECKS:
                raise SafeguardsStopped(TOO_MANY_STUCK)
        box: dict[str, Any] = {}

        def work() -> None:
            try:
                box["result"] = engine.check(rail_set, text, context)
            # A rail is third-party code plus ours; any failure means the
            # check did not run, which is recorded, never read as passed.
            except Exception as exc:
                logger.warning("safeguards check failed rail_set=%s kind=%s",
                               rail_set.value, type(exc).__name__)
                box["error"] = exc

        thread = threading.Thread(target=work, name="aegis-safeguards-check", daemon=True)
        thread.start()
        thread.join(self._time_limit)
        if thread.is_alive():
            with self._lock:
                self._state.abandoned.append(thread)
            return _Outcome(CheckStatus.NOT_CHECKED, text, reason="The check ran past its time limit.")
        if "error" in box:
            return _Outcome(CheckStatus.NOT_CHECKED, text, reason="The check raised an error.")
        result: EngineResult = box["result"]
        if result.status is CheckStatus.NOT_CHECKED:
            return _Outcome(CheckStatus.NOT_CHECKED, text, result=result,
                            reason=result.reason or "The rail did not run.")
        return _Outcome(result.status, result.content, result=result, reason=result.reason)

    def _record(self, rail_set: RailSet, outcome: _Outcome, *, source: Source | None = None,
                step: str | None = None) -> None:
        findings = outcome.result.findings if outcome.result is not None else []
        first = findings[0] if findings else None
        reason = outcome.reason or (first.reason if first else "")
        if outcome.status is CheckStatus.PASSED and not reason:
            reason = "Nothing found."
        check = _Check(
            rail_set=rail_set,
            status=outcome.status,
            source=source,
            step=step,
            rail=first.rail if first else (outcome.result.rail if outcome.result else None),
            reason=reason,
            excerpt=first.excerpt if first else None,
        )
        with self._lock:
            self._state.checks.append(check)

    def _withhold_last(self, step: str, rail: str, reason: str) -> None:
        """Record ``step``'s output check as blocked: its answer was withheld
        after the check, so the record must not say it was modified."""
        with self._lock:
            for check in reversed(self._state.checks):
                if check.step == step and check.rail_set is RailSet.OUTPUT:
                    check.status, check.rail, check.reason = CheckStatus.BLOCKED, rail, reason
                    return

    def _next_step(self, kind: str) -> str:
        with self._lock:
            self._state.calls += 1
            return f"model call {self._state.calls} ({kind})"

    def _note_typed_demands(self, text: str) -> None:
        """Remember the demands in one piece of typed text, decided on that
        piece alone: a quoted example the visitor typed is not one."""
        engine = self._get_engine()
        if engine is None:
            return
        found = engine.demands_in(text)
        if found:
            with self._lock:
                self._state.typed_demands.update(found)

    def _call_demands(self, engine: Engine | None, user: str) -> list[str]:
        """Demands the visitor typed that this call's own user text carries.

        A demand counts only when the visitor typed it: it must be among the
        demands found in typed text (``screen`` on a typed source, decided
        on that piece alone) and also be found in the call's assembled
        prompt. Text from every other source adds nothing, however the
        prompt builders surround it, so no third party can make an answer be
        withheld by demanding a word, quoted or not. A demand the visitor
        typed costs only that visitor's own answer, and only in a call whose
        prompt carries it. Quoted instructions are examples and do not count
        (``detect.demands_in``).
        """
        if engine is None:
            return []
        with self._lock:
            typed = set(self._state.typed_demands)
        if not typed:
            return []
        return [d for d in engine.demands_in(user) if d in typed]

    def check_answer(
        self, *, step: str, system: str, user: str, answer: str
    ) -> tuple[CheckStatus, str, EngineResult | None]:
        """Run the output rails on one answer and record the result.

        Returns the status and the text to use. Raises ``SafeguardsStopped``
        for a blocked answer, and for an unchecked one in every mode unless
        NeMo is not installed for the deployment (then strict mode only).
        """
        engine = self._get_engine()
        context = {"aegis_system": system, "aegis_demands": self._call_demands(engine, user)}
        outcome = self._run(RailSet.OUTPUT, answer, context)
        self._record(RailSet.OUTPUT, outcome, step=step)
        if outcome.status is CheckStatus.BLOCKED:
            rail = outcome.result.findings[0].rail if outcome.result and outcome.result.findings else ""
            raise SafeguardsStopped(BLOCKED_LEAK if rail == engine_mod.RAIL_LEAK else BLOCKED_INJECTION)
        if outcome.status is CheckStatus.NOT_CHECKED:
            if self._strict or not self._not_installed:
                raise SafeguardsStopped(NOT_CHECKED_ANSWER)
            return outcome.status, answer, outcome.result
        return outcome.status, outcome.content, outcome.result

    def stream_context(self, *, system: str, user: str) -> tuple[Engine | None, dict[str, Any]]:
        """The engine and context the streaming guard checks partial text with."""
        engine = self._get_engine()
        return engine, {"aegis_system": system, "aegis_demands": self._call_demands(engine, user)}

    def clean_leaf(self, text: str) -> str:
        """One string of a JSON answer with what the output rails remove removed."""
        engine = self._get_engine()
        return engine.clean(text) if engine is not None else text


# Text that may reach the live view: everything but the last
# ``STREAM_HOLDBACK`` characters, and nothing from the start of markup that
# has not closed (``detect.stream_hold``). A pattern is not always shorter
# than this: a prompt leak can be spread out, a token or a tag can run to
# thousands of characters. So the guard keeps state across checks: the last
# words already shown (for the leak rule, which counts words), a
# whitespace-collapsed tail as long as the longest demand, and the raw tail;
# it holds open markup until it closes, and it trips on the start of a token.
# The part of an answer that completes a pattern never reaches the view;
# earlier words of a spread-out leak can, and are retracted when the final
# check withholds the answer.
STREAM_HOLDBACK = 256
# How much new text to gather before checking again, so a long answer is
# checked a bounded number of times.
_STREAM_STEP = 32
# Held text past this length stops the live view (the answer is still
# checked whole): markup that never closes cannot hold text without bound.
_STREAM_MAX_HELD = 8192
_WHITESPACE_RE = re.compile(r"\s+")


class StreamGuard:
    """An ``on_text`` that passes text on only once the output rails allow it.

    The deltas are passed on unchanged and in order, each only once at least
    ``STREAM_HOLDBACK`` characters have arrived after it and no open markup
    starts before its end. Each time ``_STREAM_STEP`` new characters have
    gathered, the held text is checked together with what was already passed
    on: its last words, its collapsed tail, and its raw tail. Once a pattern
    trips, nothing more is passed on. ``finish(release)`` passes on the held
    tail only when the final check allows it.
    """

    def __init__(self, on_text: OnText, engine: Engine, context: dict[str, Any]) -> None:
        self._out = SafeText(on_text)
        self._engine = engine
        self._context = context
        self._held: deque[str] = deque()
        self._held_len = 0
        self._since_check = 0
        self._tail = ""
        self._words: deque[str] = deque(maxlen=detect.LEAK_RUN_WORDS)
        self._collapsed = ""
        self._demands = [str(d) for d in context.get("aegis_demands") or []]
        self._collapsed_len = 1 + max((len(" ".join(d.split())) for d in self._demands), default=0)
        self.tripped = False

    def __call__(self, delta: str) -> None:
        if self.tripped or not delta:
            return
        self._held.append(delta)
        self._held_len += len(delta)
        self._since_check += len(delta)
        if self._since_check < _STREAM_STEP:
            return
        self._since_check = 0
        held = "".join(self._held)
        words = " ".join(self._words)
        if (self._held_len > _STREAM_MAX_HELD
                or self._engine.stream_trip(f"{words} {self._tail}{held}", self._context)
                or detect.stream_carries(self._collapsed + held, self._demands)):
            self.tripped = True
            self._held.clear()
            return
        hold = detect.stream_hold(held)
        released = 0
        while self._held and self._held_len - len(self._held[0]) >= STREAM_HOLDBACK \
                and released + len(self._held[0]) <= hold:
            delta = self._held.popleft()
            self._held_len -= len(delta)
            released += len(delta)
            self._remember(delta)
            self._out(delta)

    def _remember(self, delta: str) -> None:
        """Keep what the next checks need of text passed on."""
        self._collapsed = _WHITESPACE_RE.sub(" ", self._collapsed + delta)[-self._collapsed_len:]
        full = self._tail + delta
        cut = len(full) - STREAM_HOLDBACK
        if cut <= 0:
            self._tail = full
            return
        # Cut where no word (or JSON escape) is split, so the words kept
        # are the words the final check reads.
        floor = max(0, cut - STREAM_HOLDBACK)
        while cut > floor and (full[cut - 1].isalnum() or full[cut - 1] == "\\"):
            cut -= 1
        self._words.extend(detect.stream_words(full[:cut]))
        self._tail = full[cut:]

    def finish(self, release: bool) -> None:
        """Pass on the held tail when the answer may be shown and nothing tripped."""
        while release and not self.tripped and self._held:
            self._out(self._held.popleft())
        self._held.clear()


def _leaves(value: Any, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, Mapping):
        for k, v in value.items():
            if isinstance(k, str):
                out.append(k)
            _leaves(v, out)
    elif isinstance(value, list):
        for item in value:
            _leaves(item, out)


def _clean_tree(value: Any, clean: Callable[[str], str]) -> Any:
    if isinstance(value, str):
        return clean(value)
    if isinstance(value, Mapping):
        return {clean(k) if isinstance(k, str) else k: _clean_tree(v, clean) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean_tree(item, clean) for item in value]
    return value


def _discard(text: str) -> None:
    """An ``on_text`` that shows nothing: the answer cannot be shown unchecked."""


class GuardedLLM:
    """An ``LLMClient`` around any backend; every answer passes the output rails."""

    def __init__(self, inner: LLMClient, safeguards: Safeguards) -> None:
        self._inner = inner
        self.safeguards = safeguards
        self.simulated = bool(getattr(inner, "simulated", False))

    def _guard(self, on_text: OnText | None, system: str, user: str) -> OnText | None:
        """``on_text`` behind a ``StreamGuard``; unchanged when no rails can run."""
        if on_text is None:
            return None
        engine, context = self.safeguards.stream_context(system=system, user=user)
        if engine is None:
            # Without NeMo the deployment runs unchecked by the operator's
            # choice, and the answer streams as before. If the rails failed
            # to build, the answer will be withheld, so none of it may show.
            return on_text if self.safeguards.not_installed else _discard
        return StreamGuard(on_text, engine, context)

    @staticmethod
    def _finish(guard: OnText | None, status: CheckStatus) -> None:
        if isinstance(guard, StreamGuard):
            guard.finish(status in (CheckStatus.PASSED, CheckStatus.NOT_CHECKED))

    @staticmethod
    def _retract(guard: OnText | None, on_text: OnText | None) -> None:
        """Tell the live view to drop what it showed of this answer.

        The view's owner may offer ``retract()``: the threat model's stage
        stream does, and the tool pages pass ``progress.on_text``, a bound
        method whose object does. A view without it is left as it is.
        """
        if isinstance(guard, StreamGuard):
            guard.finish(False)
        owner = getattr(on_text, "__self__", on_text)
        retract = getattr(owner, "retract", None)
        if callable(retract):
            try:
                retract()
            # A display can fail in any way; the call's own outcome stands.
            except Exception as exc:
                logger.warning("live view retract failed kind=%s", type(exc).__name__)

    def _failed_call(self, step: str, guard: OnText | None, on_text: OnText | None) -> None:
        """The wrapped call raised: drop what streamed, record the answer unchecked."""
        self._retract(guard, on_text)
        self.safeguards._record(RailSet.OUTPUT, _Outcome(CheckStatus.NOT_CHECKED, "", reason=FAILED_CALL),
                                step=step)

    def chat_text(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int = DEFAULT_TEXT_MAX_TOKENS,
        on_text: OnText | None = None,
    ) -> str:
        """The inner answer after the output rails (see ``LLMClient.chat_text``)."""
        step = self.safeguards._next_step("text")
        guard = self._guard(on_text, system, user)
        try:
            answer = self._inner.chat_text(system=system, user=user, model=model,
                                           max_tokens=max_tokens, on_text=guard)
        except BaseException:
            self._failed_call(step, guard, on_text)
            raise
        try:
            status, text, _ = self.safeguards.check_answer(step=step, system=system, user=user,
                                                           answer=answer)
        except BaseException:
            self._retract(guard, on_text)
            raise
        self._finish(guard, status)
        return text

    def chat_json(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int = DEFAULT_JSON_MAX_TOKENS,
        on_text: OnText | None = None,
    ) -> dict[str, Any]:
        """The inner object after the output rails, checked string by string."""
        step = self.safeguards._next_step("JSON")
        guard = self._guard(on_text, system, user)
        try:
            value = self._inner.chat_json(system=system, user=user, model=model,
                                          max_tokens=max_tokens, on_text=guard)
        except BaseException:
            self._failed_call(step, guard, on_text)
            raise
        parts: list[str] = []
        _leaves(value, parts)
        try:
            status, _, _ = self.safeguards.check_answer(step=step, system=system, user=user,
                                                        answer="\n".join(parts))
        except BaseException:
            self._retract(guard, on_text)
            raise
        self._finish(guard, status)
        if status is CheckStatus.MODIFIED:
            cleaned = _clean_tree(value, self.safeguards.clean_leaf)
            left: list[str] = []
            _leaves(cleaned, left)
            joined = "\n".join(left)
            if self.safeguards.clean_leaf(joined) != joined:
                # What the check removed spans two strings, so no string can
                # be cleaned on its own: the answer is withheld instead.
                self.safeguards._withhold_last(step, RAIL_EXFILTRATION, SPLIT_MARKUP)
                self._retract(guard, on_text)
                raise SafeguardsStopped(BLOCKED_INJECTION)
            return cleaned if isinstance(cleaned, dict) else value
        return value

    def describe_image(
        self,
        *,
        image_bytes: bytes,
        media_type: str,
        prompt: str,
        model: str,
        max_tokens: int = DEFAULT_IMAGE_MAX_TOKENS,
    ) -> str:
        """The inner description after the output rails; the prompt is its instructions."""
        step = self.safeguards._next_step("image")
        try:
            answer = self._inner.describe_image(image_bytes=image_bytes, media_type=media_type,
                                                prompt=prompt, model=model, max_tokens=max_tokens)
        except BaseException:
            self._failed_call(step, None, None)
            raise
        _, text, _ = self.safeguards.check_answer(step=step, system=prompt, user="", answer=answer)
        return text


def safeguards_status(settings: Settings) -> dict[str, Any]:
    """On, off, or unavailable, with versions. Holds no visitor data."""
    if not settings.safeguards:
        status = "off"
    elif not engine_mod.nemo_available():
        status = "unavailable"
    else:
        status = "on"
    return {
        "status": status,
        "strict": settings.safeguards_strict,
        "engine": engine_mod.engine_name(),
        "engine_version": engine_mod.nemo_version(),
        "time_limit_seconds": CHECK_TIME_LIMIT_SECONDS,
    }
