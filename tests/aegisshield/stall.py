"""Measure how long a call keeps a second thread from running.

Python holds the interpreter lock for the whole of one C-level call (one
pattern match, one ``json.loads``), so a slow one freezes every visitor's
session in the shared Streamlit process. A watcher thread sleeps for a
millisecond at a time, the way Streamlit's mostly idle server thread waits
for events, and notes how late it wakes: to wake it must take the lock back,
so the longest delay is the longest stall. (A watcher that spins instead
takes the lock in 5 ms turns and starves a thread that often gives it up,
which slowed a Streamlit page run from 0.4 s to over a minute.)
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

_TICK_S = 0.001

# The bound was set and measured on one machine. A stall is one C-level call,
# so on a slower processor every stall grows in step. To keep these tests
# about the code and not about the machine, time one fixed C-level call here
# and stretch the limit by how much slower it runs than on the reference
# machine (never below 1, and at most ``_MAX_FACTOR`` so a real regression
# still fails on a slow machine).
_REFERENCE_CALL_S = 0.0075
_MAX_FACTOR = 6.0


def _machine_factor() -> float:
    payload = "[" + "0," * 400_000 + "0]"
    best = float("inf")
    for _ in range(5):
        start = time.perf_counter()
        json.loads(payload)
        best = min(best, time.perf_counter() - start)
    return min(max(best / _REFERENCE_CALL_S, 1.0), _MAX_FACTOR)


MACHINE_FACTOR = _machine_factor()

# The bound the app promises on the reference machine (about 0.25 s), scaled
# for this one. Tests assert well under it so that a loaded machine running
# the suite under coverage still passes.
STALL_LIMIT_S = 0.25 * MACHINE_FACTOR


@dataclass(frozen=True)
class Measured:
    """One timed call: its total time, the longest stall, and its result."""

    total: float
    stall: float
    result: Any


def measure(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Measured:
    """Run ``fn`` once while a watcher thread records its longest gap."""
    longest = [0.0]
    stop = threading.Event()
    ready = threading.Event()

    def watch() -> None:
        ready.set()
        while not stop.is_set():
            before = time.perf_counter()
            time.sleep(_TICK_S)
            longest[0] = max(longest[0], time.perf_counter() - before - _TICK_S)

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    ready.wait()
    start = time.perf_counter()
    try:
        result = fn(*args, **kwargs)
    finally:
        total = time.perf_counter() - start
        stop.set()
        watcher.join()
    return Measured(total, longest[0], result)


def least_stall(fn: Callable[..., Any], *args: Any, repeats: int = 3, **kwargs: Any) -> Measured:
    """The run with the smallest stall out of ``repeats``.

    Scheduling noise only ever adds to a stall, so the smallest of a few
    runs is the fairest reading of what the call itself does.
    """
    runs = [measure(fn, *args, **kwargs) for _ in range(repeats)]
    return min(runs, key=lambda run: run.stall)
