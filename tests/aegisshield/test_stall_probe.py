"""The stall probe the hostile-text tests rely on sees a long C-level call
and does not mistake ordinary Python work for one."""

from __future__ import annotations

from tests.aegisshield.stall import measure


def test_the_probe_sees_one_long_call_that_holds_the_lock() -> None:
    run = measure(sum, range(20_000_000))  # one C call, no chance to switch threads
    assert run.stall > 0.5 * run.total > 0.02


def test_the_probe_sees_little_stall_in_python_code_of_the_same_length() -> None:
    def loop() -> int:
        total = 0
        for i in range(5_000_000):
            total += i
        return total

    run = measure(loop)
    assert run.stall < 0.25 * run.total
