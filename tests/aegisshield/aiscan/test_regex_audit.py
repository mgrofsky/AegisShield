"""Every regular expression in the scan package and the scan page is linear
on hostile text: timed under the stall probe on the literal it starts with
followed by 100,000 spaces, tabs, or repeated copies of itself."""

from __future__ import annotations

import importlib
import pkgutil
import re
import string

import pytest

import aegisshield.aiscan as aiscan_pkg
from tests.aegisshield.stall import STALL_LIMIT_S, least_stall

SIZE = 100_000
_MODULES = ["aegisshield.ui.pages.ai_scan"] + [
    f"{aiscan_pkg.__name__}.{m.name}" for m in pkgutil.iter_modules(aiscan_pkg.__path__)
]


def _patterns() -> list[tuple[str, re.Pattern[str]]]:
    found = []
    for module_name in sorted(_MODULES):
        module = importlib.import_module(module_name)
        for name, value in sorted(vars(module).items()):
            if isinstance(value, re.Pattern):
                found.append((f"{module_name.rsplit('.', 1)[-1]}.{name}", value))
    return found


def _start_literal(pattern: re.Pattern[str]) -> str:
    """The first printable character the pattern can start a match with."""
    for char in string.printable:
        if pattern.match(char):
            return char
    raise AssertionError(f"no printable start for {pattern.pattern!r}")


def inputs(pattern: re.Pattern[str]) -> dict[str, str]:
    """The four hostile texts for ``pattern``."""
    lit = _start_literal(pattern)
    source = pattern.pattern
    return {
        "spaces": lit + " " * SIZE,
        "tabs": lit + "\t" * SIZE,
        "copies of the pattern": lit + source * (SIZE // len(source) + 1),
        "copies of the literal": lit * (SIZE + 1),
    }


def _ops(pattern: re.Pattern[str]):
    return {"search": pattern.search, "fullmatch": pattern.fullmatch, "sub": lambda t: pattern.sub("-", t)}


PATTERNS = _patterns()


def test_every_pattern_is_found():
    assert {name for name, _ in PATTERNS} == {"availability._VERSION_RE", "ai_scan._SLUG_RE", "ai_scan._KEY_RE"}


@pytest.mark.parametrize(("name", "pattern"), PATTERNS, ids=[n for n, _ in PATTERNS])
def test_pattern_is_linear_on_hostile_text(name, pattern):
    for label, text in inputs(pattern).items():
        for op_name, op in _ops(pattern).items():
            stall = least_stall(op, text, repeats=2).stall
            assert stall < STALL_LIMIT_S, (name, label, op_name, stall)
