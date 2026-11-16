"""The Python actions the AegisShield rails call (registered by ``engine``).

Each action is local and deterministic (``aegisshield.safeguards.detect``),
reads what it needs from NeMo context variables, and records what it found
in the job's ``Collector`` under the check's id, so the record can say which
rail fired and why without the action's verdict carrying it. The actions are
made per job (``make_actions``), so one job's findings never reach another's.
"""

from __future__ import annotations

import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from aegisshield.safeguards import detect

RAIL_TYPED = "instruction in typed text"
RAIL_RETRIEVED = "instruction in retrieved content"
RAIL_LEAK = "system prompt leak"
RAIL_INJECTION = "injected instruction followed"
RAIL_SECRETS = "key-shaped secret"
RAIL_EXFILTRATION = "markup that sends data elsewhere"

OUTPUT_ACTIONS = (
    "aegis_answer_leak",
    "aegis_answer_injection",
    "aegis_answer_secrets",
    "aegis_answer_exfiltration",
)

_KIND_WORDS = {
    "override": "an instruction to set aside the model's instructions",
    "role": "an instruction to replace the model's role",
    "reveal": "a request for the model's instructions or secrets",
    "demand": "an instruction telling the model what to output",
    "markup": "an instruction to add a link or image",
    "addressed": "text addressed to an AI model",
    "template": "a chat template marker",
}


@dataclass
class Found:
    """One finding an action recorded."""

    rail: str
    reason: str
    excerpt: str | None = None
    blocked: bool = False
    modified: bool = False


@dataclass
class _Entry:
    ran: list[str] = field(default_factory=list)
    found: list[Found] = field(default_factory=list)


class Collector:
    """Findings per check id, for one job. Thread safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, _Entry] = {}

    def add(self, check_id: str, action: str, found: list[Found]) -> None:
        with self._lock:
            entry = self._entries.setdefault(check_id, _Entry())
            entry.ran.append(action)
            entry.found.extend(found)

    def pop(self, check_id: str) -> tuple[list[str], list[Found]]:
        with self._lock:
            entry = self._entries.pop(check_id, _Entry())
        return entry.ran, entry.found


def _check_id(context: dict[str, Any] | None) -> str:
    return str((context or {}).get("aegis_check") or "")


def _verdict(text: str, *, blocked: bool = False) -> dict[str, Any]:
    return {"blocked": blocked, "text": text}


def _describe(hits: list[detect.Hit]) -> str:
    kinds = []
    for hit in hits:
        words = _KIND_WORDS.get(hit.kind, hit.kind)
        if words not in kinds:
            kinds.append(words)
    return "; ".join(kinds)


Action = Callable[..., Awaitable[dict[str, Any]]]


def make_actions(collector: Collector) -> dict[str, Action]:
    """The six actions for one job, bound to its ``collector``."""

    async def aegis_typed_instructions(text: str = "", context: dict[str, Any] | None = None,
                                       **_: Any) -> dict[str, Any]:
        label = str((context or {}).get("aegis_source_label") or "the text")
        hits = [h for h in detect.find_instructions(text, typed=True) if not h.quoted]
        found: list[Found] = []
        if hits:
            first = hits[0]
            found.append(Found(RAIL_TYPED, f"Fenced as data: {_describe(hits)}.",
                               detect.excerpt(text[first.start:first.end + 40]), modified=True))
            text = detect.fence(text, label)
        collector.add(_check_id(context), "aegis_typed_instructions", found)
        return _verdict(text)

    async def aegis_retrieved_instructions(text: str = "", context: dict[str, Any] | None = None,
                                           **_: Any) -> dict[str, Any]:
        label = str((context or {}).get("aegis_source_label") or "the content")
        hits = detect.find_instructions(text, typed=False)
        acted = [h for h in hits if not h.quoted]
        quoted = [h for h in hits if h.quoted]
        found: list[Found] = []
        if acted:
            first = acted[0]
            found.append(Found(RAIL_RETRIEVED, f"Removed for review: {_describe(acted)}.",
                               detect.excerpt(text[first.start:first.end + 40]), modified=True))
            # A demand removed here is not remembered: the model never sees
            # it, so an answer that happens to use the word followed nothing.
            text = detect.neutralize(text, acted, label)
        elif quoted:
            first = quoted[0]
            found.append(Found(RAIL_RETRIEVED,
                               f"Left as it is because it is quoted: {_describe(quoted)}.",
                               detect.excerpt(text[first.start:first.end + 40])))
        collector.add(_check_id(context), "aegis_retrieved_instructions", found)
        return _verdict(text)

    async def aegis_answer_leak(text: str = "", context: dict[str, Any] | None = None,
                                **_: Any) -> dict[str, Any]:
        system = str((context or {}).get("aegis_system") or "")
        found: list[Found] = []
        if detect.leaks_prompt(text, system):
            found.append(Found(RAIL_LEAK, "The answer repeats the step's instructions to the model.",
                               blocked=True))
        collector.add(_check_id(context), "aegis_answer_leak", found)
        return _verdict(text, blocked=bool(found))

    async def aegis_answer_injection(text: str = "", context: dict[str, Any] | None = None,
                                     **_: Any) -> dict[str, Any]:
        demands = [str(d) for d in (context or {}).get("aegis_demands") or []]
        carried = detect.carried_demand(text, demands)
        found: list[Found] = []
        if carried is not None:
            found.append(Found(RAIL_INJECTION,
                               "The answer carries out an instruction found in the input.",
                               detect.excerpt(carried), blocked=True))
        collector.add(_check_id(context), "aegis_answer_injection", found)
        return _verdict(text, blocked=bool(found))

    async def aegis_answer_secrets(text: str = "", context: dict[str, Any] | None = None,
                                   **_: Any) -> dict[str, Any]:
        spans = detect.find_secrets(text)
        found: list[Found] = []
        if spans:
            kinds = sorted({kind for kind, _, _ in spans})
            found.append(Found(RAIL_SECRETS, f"Removed {', '.join(kinds)} from the answer.",
                               modified=True))
            text = detect.redact_secrets(text)
        collector.add(_check_id(context), "aegis_answer_secrets", found)
        return _verdict(text)

    async def aegis_answer_exfiltration(text: str = "", context: dict[str, Any] | None = None,
                                        **_: Any) -> dict[str, Any]:
        spans = detect.find_exfiltration(text)
        found: list[Found] = []
        if spans:
            kinds = sorted({kind for kind, _, _ in spans})
            first = spans[0]
            found.append(Found(RAIL_EXFILTRATION, f"Removed {', '.join(kinds)}.",
                               detect.excerpt(text[first[1]:first[2]]), modified=True))
            text = detect.strip_exfiltration(text)
        collector.add(_check_id(context), "aegis_answer_exfiltration", found)
        return _verdict(text)

    return {
        "aegis_typed_instructions": aegis_typed_instructions,
        "aegis_retrieved_instructions": aegis_retrieved_instructions,
        "aegis_answer_leak": aegis_answer_leak,
        "aegis_answer_injection": aegis_answer_injection,
        "aegis_answer_secrets": aegis_answer_secrets,
        "aegis_answer_exfiltration": aegis_answer_exfiltration,
    }


__all__ = [
    "OUTPUT_ACTIONS",
    "RAIL_EXFILTRATION",
    "RAIL_INJECTION",
    "RAIL_LEAK",
    "RAIL_RETRIEVED",
    "RAIL_SECRETS",
    "RAIL_TYPED",
    "Collector",
    "Found",
    "make_actions",
]
