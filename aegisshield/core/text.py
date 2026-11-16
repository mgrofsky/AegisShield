"""Text sanitation applied to visitor and model text before it is stored or shown.

Pure functions, standard library only.
"""

from __future__ import annotations

import html
import re

# C0 control characters except tab and newline. NUL breaks JSON storage, and
# none of these belong in display text.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f]")
# Bidirectional controls make text read in a different order than it is written.
# Zero-width and direction marks, line and paragraph separators, the byte order
# mark, DEL, the C1 controls, and the bidirectional controls.
_INVISIBLE_RE = re.compile(
    "[\u200b-\u200f\u061c\u2028\u2029\ufeff\x7f-\x9f\u202a-\u202e\u2066-\u2069]"
)
_LINE_SPACE_RE = re.compile("[\n\t]")
# Things that look like API keys (OpenAI and Claude ``sk-...``, bearer tokens,
# AWS access key ids, Google API keys, and the two Bedrock API key shapes AWS
# documents: long-term keys start "ABSKQmVkcm9ja0FQSUtleS" and short-term
# keys "bedrock-api-key-", each followed by base64). Used to scrub provider
# error text before it reaches a log line. Every branch is linear in its input.
_KEY_RE = re.compile(r"(sk-[A-Za-z0-9_*\-]{6,}|Bearer\s+[A-Za-z0-9._\-]{8,}"
                     r"|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|AIza[A-Za-z0-9_\-]{35}"
                     r"|ABSKQmVkcm9ja0FQSUtleS[A-Za-z0-9+/=]*|bedrock-api-key-[A-Za-z0-9+/=]*)")
# A value labeled as a key, secret, or token: the label, an optional quote,
# "=" or ":", an optional quote, then at least 16 key characters. This is how
# an AWS secret access key (40 base64 characters), an NVD key (a UUID), and
# an OTX key (64 hex digits) show up in a request or header dump; unlabeled,
# those shapes are ordinary ids and hashes and are left alone. The label is
# kept and only the value is replaced. Linear: no repeated group, and every
# run is followed by a character it cannot contain.
_LABELED_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9])((?:x-otx-api-key|(?:otx|nvd)[_-]?api[_-]?key|api[_-]?key"
    r"|(?:aws[_-]?)?secret[_-]?access[_-]?key|session[_-]?token|token))"
    r"([\"']?\s*[=:]\s*[\"']?)([A-Za-z0-9/+=_.\-]{16,})",
    re.IGNORECASE,
)
_ELLIPSIS = "..."


def clean_text(text: str | None) -> str:
    """``text`` without NUL or other C0 control characters (tab and newline stay)."""
    return _CONTROL_RE.sub("", text or "")


def strip_invisible(text: str | None) -> str:
    """``text`` without zero-width, direction, separator, BOM, DEL, and C1 characters."""
    return _INVISIBLE_RE.sub("", text or "")


def clip_words(text: str | None, limit: int) -> str:
    """Clip ``text`` to at most ``limit`` characters on a word boundary.

    A clipped string ends with "..." so it reads as shortened on purpose.
    Control characters are removed first (see ``clean_text``).
    """
    text = clean_text(text).strip()
    if len(text) <= limit:
        return text
    if limit <= len(_ELLIPSIS):
        return text[: max(limit, 0)]
    keep = limit - len(_ELLIPSIS)
    cut = text[:keep].rstrip()
    # Back off to the last space only when the cut lands inside a word.
    if not text[keep].isspace() and " " in cut:
        cut = cut.rsplit(" ", 1)[0].rstrip()
    return f"{cut}{_ELLIPSIS}"


def clip_tail(text: str | None, limit: int) -> str:
    """Keep the last ``limit`` characters of ``text``, starting on a word boundary.

    Used for the live "still being written" view of streamed text. Control
    characters are removed first (see ``clean_text``).
    """
    text = clean_text(text)
    if len(text) <= limit:
        return text
    if limit <= len(_ELLIPSIS):
        return text[-limit:] if limit > 0 else ""
    keep = limit - len(_ELLIPSIS)
    cut = text[-keep:]
    starts_mid_word = not text[-keep - 1].isspace()
    rest = cut.split(" ", 1)[1] if starts_mid_word and " " in cut else ""
    return f"{_ELLIPSIS}{rest or cut}"


def single_line(value: object, limit: int) -> str:
    """One display line from untrusted text (a lookup result or a title).

    Newline and tab read as a space; bidirectional, invisible, C0, and C1
    controls are removed; the result is clipped on a word. Anything that is
    not a string becomes "".
    """
    text = value if isinstance(value, str) else ""
    return clip_words(strip_invisible(_LINE_SPACE_RE.sub(" ", text)), limit)


def sanitize_user_markdown(text: str | None, max_chars: int | None = None) -> str:
    """Multi-line visitor or model text, safe to store and render as markdown.

    Line endings become ``\\n``; line and paragraph separators become a
    newline; NUL, other C0 controls, C1 controls, and bidirectional and
    zero-width characters are removed; the result is stripped and, when
    ``max_chars`` is given, clipped on a word.
    """
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("\u2028", "\n").replace("\u2029", "\n")
    text = strip_invisible(clean_text(text)).strip()
    if max_chars is not None:
        text = clip_words(text, max_chars)
    return text


SAFE_LINK_SCHEMES = frozenset({"http", "https", "mailto"})
_SCHEME_RE = re.compile(r"([a-z][a-z0-9+.\-]*):")
_LINK_NOISE_RE = re.compile(r"[\x00-\x20\x7f-\x9f]+")


def is_safe_link(href: str | None) -> bool:
    """True when a link target may stay a link: ``http``, ``https``,
    ``mailto``, or a fragment (``#name``) on this page.

    An allowlist: anything else (``javascript:``, ``vbscript:``, ``data:``,
    ``file:``, a relative path, a scheme-relative ``//host``) is refused.
    HTML entities are decoded and whitespace, control, and invisible
    characters removed first, the way a browser reads the attribute.
    """
    value = _LINK_NOISE_RE.sub("", strip_invisible(html.unescape(href or ""))).lower()
    if value.startswith("#"):
        return len(value) > 1
    match = _SCHEME_RE.match(value)
    return match is not None and match.group(1) in SAFE_LINK_SCHEMES


def redact_keys(text: str | None, *secrets: str) -> str:
    """``text`` with each of ``secrets``, anything shaped like an API key,
    and any value labeled as a key, secret, or token replaced.

    For log lines only: exception text from a provider SDK can quote part of
    the key that was sent. Pass the caller's own credential values as
    ``secrets``: an NVD key (a UUID) or an OTX key (64 hex digits) is found
    by shape only when it is labeled.
    """
    text = text or ""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[redacted]")
    text = _KEY_RE.sub("[redacted]", text)
    return _LABELED_KEY_RE.sub(r"\1\2[redacted]", text)


__all__ = [
    "clean_text",
    "clip_tail",
    "clip_words",
    "is_safe_link",
    "redact_keys",
    "sanitize_user_markdown",
    "single_line",
    "strip_invisible",
]
