"""The limits of one scan: each has a default and a hard maximum in code.

A visitor may lower a limit or raise it up to its maximum, never past it.
The numbers, and why:

- ``GENERATIONS``: answers garak asks for per prompt. Each one is a separate
  request (garak's REST generator sends one per generation), so this
  multiplies the cost; 3 is enough to see an answer that varies.
- ``PROMPTS_PER_PROBE``: garak's ``soft_probe_prompt_cap``. A few probes send
  a fixed number instead (``probes.Probe.fixed_prompts``).
- ``TOTAL_REQUESTS``: the most model calls the scan may make through the
  visitor's key. The shim refuses every request past it. A scan whose plan
  needs more is refused before it starts.
- ``REQUEST_TIMEOUT_SECONDS``: how long the shim waits for one answer from
  the workflow. A threat-model step through a real model can take a minute
  or more.
- ``WALL_CLOCK_SECONDS``: the whole scan. Its maximum stays below the job
  runner's default 30 minute timeout, so the runner never stops a scan
  before the scan can stop itself and keep what it found.

A scan that needs no key (the simulated stand-in, the canned mock) has lower
hard maximums, ``KEYLESS_MAX_REQUESTS`` and ``KEYLESS_MAX_WALL_SECONDS``:
any visitor can start one, and while it runs it holds the one scan slot of
the whole process. This makes holding the slot cost more requests to the
page; it does not stop a visitor who keeps starting scans from new sessions.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from aegisshield.aiscan.probes import probe
from aegisshield.core.errors import ValidationError


@dataclass(frozen=True)
class Limit:
    """One limit's default and its allowed range, inclusive."""

    label: str
    default: int
    minimum: int
    maximum: int

    def check(self, value: object) -> int:
        """``value`` when it is a whole number in range; else ``ValidationError``."""
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationError(f"{self.label} must be a whole number.")
        if not self.minimum <= value <= self.maximum:
            raise ValidationError(f"{self.label} must be between {self.minimum} and {self.maximum}.")
        return value


GENERATIONS = Limit("Answers per prompt", 1, 1, 3)
PROMPTS_PER_PROBE = Limit("Prompts per probe", 5, 1, 20)
TOTAL_REQUESTS = Limit("Request limit", 60, 1, 300)
REQUEST_TIMEOUT_SECONDS = Limit("Time per request (seconds)", 120, 10, 300)
WALL_CLOCK_SECONDS = Limit("Time for the whole scan (seconds)", 900, 60, 1500)
SEED = Limit("Seed", 0, 0, 2**31 - 1)

KEYLESS_MAX_REQUESTS = 60
KEYLESS_MAX_WALL_SECONDS = 300

ERROR_KEYLESS = (
    f"Without a model key, the request limit is at most {KEYLESS_MAX_REQUESTS} and the time for the whole "
    f"scan at most {KEYLESS_MAX_WALL_SECONDS} seconds."
)

ERROR_OVER_BUDGET = (
    "These probes and limits need up to {planned} requests, more than the request limit of {limit}. "
    "Choose fewer probes or prompts, or raise the request limit."
)


@dataclass(frozen=True)
class ScanLimits:
    """The checked limits of one scan. Build it with ``ScanLimits.build``."""

    generations: int = GENERATIONS.default
    prompts_per_probe: int = PROMPTS_PER_PROBE.default
    total_requests: int = TOTAL_REQUESTS.default
    request_timeout_seconds: int = REQUEST_TIMEOUT_SECONDS.default
    wall_clock_seconds: int = WALL_CLOCK_SECONDS.default

    @classmethod
    def build(
        cls,
        *,
        generations: object = GENERATIONS.default,
        prompts_per_probe: object = PROMPTS_PER_PROBE.default,
        total_requests: object = TOTAL_REQUESTS.default,
        request_timeout_seconds: object = REQUEST_TIMEOUT_SECONDS.default,
        wall_clock_seconds: object = WALL_CLOCK_SECONDS.default,
    ) -> ScanLimits:
        """Check each value against its range. Raises ``ValidationError``."""
        return cls(
            generations=GENERATIONS.check(generations),
            prompts_per_probe=PROMPTS_PER_PROBE.check(prompts_per_probe),
            total_requests=TOTAL_REQUESTS.check(total_requests),
            request_timeout_seconds=REQUEST_TIMEOUT_SECONDS.check(request_timeout_seconds),
            wall_clock_seconds=WALL_CLOCK_SECONDS.check(wall_clock_seconds),
        )

    def to_dict(self) -> dict[str, int]:
        """The limits as plain JSON values, for the scan record."""
        return {
            "generations": self.generations,
            "prompts_per_probe": self.prompts_per_probe,
            "total_requests": self.total_requests,
            "request_timeout_seconds": self.request_timeout_seconds,
            "wall_clock_seconds": self.wall_clock_seconds,
        }


def keyless(limit: Limit) -> Limit:
    """``limit`` as it applies to a scan that needs no key: the request and
    whole-scan limits get their lower maximums (and a default within them)."""
    lower = {TOTAL_REQUESTS.label: KEYLESS_MAX_REQUESTS, WALL_CLOCK_SECONDS.label: KEYLESS_MAX_WALL_SECONDS}
    maximum = lower.get(limit.label)
    if maximum is None:
        return limit
    return Limit(limit.label, min(limit.default, maximum), limit.minimum, maximum)


def check_keyless(limits: ScanLimits) -> ScanLimits:
    """``limits``, or ``ValidationError`` when they pass the keyless maximums."""
    if limits.total_requests > KEYLESS_MAX_REQUESTS or limits.wall_clock_seconds > KEYLESS_MAX_WALL_SECONDS:
        raise ValidationError(ERROR_KEYLESS)
    return limits


def planned_requests(probe_ids: Iterable[str], limits: ScanLimits) -> int:
    """The most requests these probes can send under ``limits``."""
    prompts = sum(probe(pid).prompts(limits.prompts_per_probe) for pid in probe_ids)
    return prompts * limits.generations


def check_budget(probe_ids: Iterable[str], limits: ScanLimits) -> int:
    """``planned_requests``, or ``ValidationError`` when it exceeds the request limit."""
    planned = planned_requests(probe_ids, limits)
    if planned > limits.total_requests:
        raise ValidationError(ERROR_OVER_BUDGET.format(planned=planned, limit=limits.total_requests))
    return planned


def check_seed(value: object) -> int | None:
    """None for no seed, else a whole number in ``SEED``'s range."""
    return None if value is None else SEED.check(value)
