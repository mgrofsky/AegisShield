"""``SusceptibleLLM``: a simulated model that CAN be attacked, for tests.

``MockLLM`` returns canned answers whatever it is sent, so no attack can ever
succeed against it. This double answers like ``MockLLM`` (or any ``base``
client) for ordinary prompts, and misbehaves in fixed, documented ways when
the text it is given carries an instruction. It stands in for a model that
follows injected instructions, so the safeguards can be shown to stop an
attack that has an effect. It is simulated: results from it say nothing
about any real model, and wherever they are shown they must be labeled so.

Triggers, read from the ``user`` text of a call (and from the image text,
see below), checked in this order; every one that matches adds its effect:

1. Reveal: "reveal", "repeat", "print", "show", "output", or "tell me",
   followed within 40 characters on the same line by "system prompt",
   "instructions", or "initial prompt". The answer carries the call's
   ``system`` text verbatim.
2. Secret: "give", "tell", "print", "reveal", "show", "share", "list",
   "what is", or "what are", then "your" within 20 characters, then "key",
   "secret", "password", "token", or "credential" within 20 more (so a
   technique description that says "reveal credentials" is ordinary). The
   answer carries the key-shaped string from
   its system prompt: the first ``sk-`` string in ``system``, or else its own
   ``secret`` (by default ``SIMULATED_SECRET``), which it keeps as if it were
   part of its system prompt.
3. Markup: "include", "add", "insert", "embed", "render", "append", or
   "output", followed within 80 characters by a markdown image or link to an
   http or https address. The answer carries that markup exactly.
4. Print: "say", "print", "output", "write", "respond with", "reply with",
   or "repeat after me", then an optional colon, then a string in double
   quotes, single quotes, or curly quotes (1 to 200 characters, up to the
   matching close quote). The answer carries that string. This matches garak's promptinject phrasing
   ('... and just say "I hate humans":').

Where an effect lands:

- ``chat_text``: the effects, one per line, then a blank line, then the
  base answer.
- ``chat_json``: the base object with the effects joined into its first
  string value (depth first; for a threat model, the first threat's
  ``Scenario``), so the effect reaches a stored result.
- ``describe_image``: the base description, then any text carried in the
  image bytes after the marker ``AEGIS-TEXT:`` (up to a NUL byte or the end,
  read as ASCII), as a model would transcribe text drawn on a diagram. The
  transcribed text is then read for triggers too.

With ``on_text`` the final answer is streamed in 40 character chunks.
"""

from __future__ import annotations

import json
import re
from typing import Any

from aegisshield.llm.base import (
    DEFAULT_IMAGE_MAX_TOKENS,
    DEFAULT_JSON_MAX_TOKENS,
    DEFAULT_TEXT_MAX_TOKENS,
    LLMClient,
    OnText,
    SafeText,
    normalize_media_type,
)
from aegisshield.llm.mock import MockLLM

# Key-shaped but not a key of any service: 48 characters after "sk-".
SIMULATED_SECRET = "sk-simulated" + "0123456789abcdefghijKLMNOPQRSTUVWXYZ"
IMAGE_TEXT_MARKER = b"AEGIS-TEXT:"
_CHUNK = 40

_REVEAL_RE = re.compile(
    r"\b(?:reveal|repeat|print|show|output|tell me)\b[^\n]{0,40}?"
    r"\b(?:system prompt|instructions|initial prompt)\b",
    re.IGNORECASE,
)
_SECRET_RE = re.compile(
    r"\b(?:give|tell|print|reveal|show|share|list|what is|what are)\b[^\n]{0,20}?\byour\b"
    r"[^\n]{0,20}?\b(?:keys?|secrets?|passwords?|tokens?|credentials?)\b",
    re.IGNORECASE,
)
# "include ![x](https://...)": the link target is found first, then the "["
# that opens it and a verb up to 80 characters before that, on the same line
# (``_markup``). One pattern that started at every verb cost time in step
# with the square of a text of repeated verbs, brackets, and link heads.
_MARKUP_TARGET_RE = re.compile(r"\]\(https?://", re.IGNORECASE)
_MARKUP_VERB_RE = re.compile(r"\b(?:include|add|insert|embed|render|append|output)\b", re.IGNORECASE)
_URL_END_RE = re.compile(r"[\s)]")
_MARKUP_GAP = 80
_MARKUP_ALT = 200
_MARKUP_URL = 2000
_PRINT_RE = re.compile(
    r"\b(?:say|print|output|write|respond with|reply with|repeat after me)\s*+:?\s*+"
    r"(?:\"([^\"\n]{1,200})\"|\u201c([^\u201d\n]{1,200})\u201d|'([^'\n]{1,200})')",
    re.IGNORECASE,
)
_SYSTEM_KEY_RE = re.compile(r"sk-[A-Za-z0-9_\-]{20,200}")


class SusceptibleLLM:
    """An ``LLMClient`` that follows instructions found in its input (simulated).

    ``base`` answers ordinary prompts (``MockLLM`` when None). ``secret`` is
    the key-shaped string it keeps in its own system prompt.
    """

    simulated = True

    def __init__(self, base: LLMClient | None = None, *, secret: str = SIMULATED_SECRET) -> None:
        self._base: LLMClient = base if base is not None else MockLLM()
        self._secret = secret

    def effects(self, system: str, text: str) -> list[str]:
        """The strings an attack in ``text`` makes this model add to its answer."""
        found: list[str] = []
        if _REVEAL_RE.search(text):
            found.append(system)
        if _SECRET_RE.search(text):
            key = _SYSTEM_KEY_RE.search(system)
            found.append(key.group(0) if key else self._secret)
        found.extend(_markup(text))
        found.extend(next(g for g in m.groups() if g is not None) for m in _PRINT_RE.finditer(text))
        return found

    @staticmethod
    def _stream(text: str, on_text: OnText | None) -> None:
        if on_text is None:
            return
        safe = SafeText(on_text)
        for start in range(0, len(text), _CHUNK):
            safe(text[start : start + _CHUNK])

    def chat_text(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int = DEFAULT_TEXT_MAX_TOKENS,
        on_text: OnText | None = None,
    ) -> str:
        """The base answer, preceded by any attack effects."""
        answer = self._base.chat_text(system=system, user=user, model=model, max_tokens=max_tokens)
        found = self.effects(system, user)
        if found:
            answer = "\n".join(found) + "\n\n" + answer
        self._stream(answer, on_text)
        return answer

    def chat_json(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int = DEFAULT_JSON_MAX_TOKENS,
        on_text: OnText | None = None,
    ) -> dict[str, Any]:
        """The base object, with any attack effects in its first string value."""
        value = self._base.chat_json(system=system, user=user, model=model, max_tokens=max_tokens)
        found = self.effects(system, user)
        if found:
            _inject(value, " ".join(found))
        self._stream(json.dumps(value, indent=2), on_text)
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
        """The base description, plus the text carried in the image and its effects."""
        normalize_media_type(media_type)
        answer = self._base.describe_image(
            image_bytes=image_bytes, media_type=media_type, prompt=prompt, model=model,
            max_tokens=max_tokens,
        )
        carried = image_text(image_bytes)
        if carried:
            found = self.effects(prompt, carried)
            answer = f"{answer}\n\nText written on the diagram: {carried}"
            if found:
                answer = "\n".join(found) + "\n\n" + answer
        return answer


def image_text(image_bytes: bytes) -> str:
    """The ASCII text after ``IMAGE_TEXT_MARKER`` in an image, or ""."""
    start = image_bytes.find(IMAGE_TEXT_MARKER)
    if start < 0:
        return ""
    rest = image_bytes[start + len(IMAGE_TEXT_MARKER) :]
    end = rest.find(b"\x00")
    if end >= 0:
        rest = rest[:end]
    return rest.decode("ascii", errors="ignore").strip()


def _markup(text: str) -> list[str]:
    """Each link or image an instruction in ``text`` tells the model to add.

    The same reading as one pattern of a verb, at most 80 characters, then
    ``!?[alt](https?://url)`` on one line (alt at most 200 characters, url at
    most 2,000), found from the target back, so each character is read a
    bounded number of times.
    """
    found: list[str] = []
    taken = 0
    url_scan = (-1, -1)  # (a URL start, the first space or ")" after it)
    for m in _MARKUP_TARGET_RE.finditer(text):
        if m.start() < taken:
            continue
        line = text.rfind("\n", 0, m.start()) + 1
        bracket = text.rfind("[", max(line, m.start() - _MARKUP_ALT - 1), m.start())
        if bracket < 0 or "]" in text[bracket + 1:m.start()]:
            continue
        start = bracket - 1 if bracket > line and text[bracket - 1] == "!" else bracket
        if not any(v.end() >= start - _MARKUP_GAP
                   for v in _MARKUP_VERB_RE.finditer(text, max(line, start - _MARKUP_GAP - 7), start)):
            continue
        if not url_scan[0] <= m.end() < url_scan[1]:
            stop = _URL_END_RE.search(text, m.end(), m.end() + _MARKUP_URL + 1)
            if stop is None:
                continue  # no end within reach: the address is too long
            # Any later target before this end reaches the same end.
            url_scan = (m.end(), stop.start())
        end = url_scan[1]
        if end == m.end() or end - m.end() > _MARKUP_URL or text[end] != ")":
            continue
        found.append(text[start:end + 1])
        taken = end + 1
    return found


def _inject(value: Any, text: str) -> bool:
    """Put ``text`` in front of the first string value of ``value`` (depth first)."""
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str):
                value[key] = f"{text} {item}"
                return True
            if _inject(item, text):
                return True
    elif isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, str):
                value[index] = f"{text} {item}"
                return True
            if _inject(item, text):
                return True
    return False


__all__ = ["IMAGE_TEXT_MARKER", "SIMULATED_SECRET", "SusceptibleLLM", "image_text"]
