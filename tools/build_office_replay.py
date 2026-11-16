"""Record tests/fixtures/office_replay.json from a live agentic run.

Usage (one step, no network, no key):

    python tools/build_office_replay.py [--call-seconds 6] [--every 1]

Runs this repo's agentic threat model pipeline on the mock client through a
``JobRunner`` and samples ``snapshot()`` on a fixed cadence, as the page's
poll would. Every sample is kept, changed or not, so the replay has the same
rhythm a once-a-second poll sees.

The agentic sections call the model without streaming, so the mock's
``mock_chunk_delay_seconds`` does not slow them. Each model call is paced
instead (``PacedLLM``): it sleeps ``--call-seconds`` before answering, which
keeps every specialist visibly at work for a few seconds, about what a real
model call takes. The text in the records is the pipeline's own (the mock
answers about an online retail checkout service).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegisshield.config import get_settings  # noqa: E402
from aegisshield.jobs.runner import JobRunner  # noqa: E402
from aegisshield.llm.factory import get_llm  # noqa: E402
from aegisshield.pipeline.run import run_threat_model  # noqa: E402
from aegisshield.pipeline.schemas import ThreatModelRequest  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "office_replay.json"

PROFILE: dict[str, Any] = {
    "app_type": "Web application",
    "industry_sector": "Retail",
    "sensitive_data": "Payment card data",
    "internet_facing": "Yes",
    "authentication": ["OAuth2"],
}
DESCRIPTION = (
    "An online checkout service for a retail store. Shoppers sign in, keep saved cards, apply "
    "coupons, and place orders; the service calls a payment provider and a shipping API."
)


class PacedLLM:
    """An LLMClient that waits before each answer, so a mock run takes real time."""

    def __init__(self, inner: Any, seconds: float) -> None:
        self._inner = inner
        self._seconds = seconds
        self.calls = 0

    def _wait(self) -> None:
        self.calls += 1
        time.sleep(self._seconds)

    def chat_text(self, **kwargs: Any) -> Any:
        self._wait()
        return self._inner.chat_text(**kwargs)

    def chat_json(self, **kwargs: Any) -> Any:
        self._wait()
        return self._inner.chat_json(**kwargs)

    def describe_image(self, **kwargs: Any) -> Any:
        self._wait()
        return self._inner.describe_image(**kwargs)


def record(call_seconds: float, every: float) -> dict[str, Any]:
    """Run one agentic job and return the sampled poll bodies."""
    settings = get_settings({"AEGIS_MOCK_LLM": "1", "AEGIS_OFFLINE": "1", "AEGIS_AGENTIC": "1"})
    llm = PacedLLM(get_llm(settings, None, mock_chunk_delay_seconds=0.05), call_seconds)
    request = ThreatModelRequest(app_profile=dict(PROFILE), app_description=DESCRIPTION)
    runner = JobRunner(max_concurrent_jobs=1, job_timeout_seconds=900)
    job_id = runner.submit(
        lambda progress: run_threat_model(request, llm=llm, settings=settings, progress=progress),
        kind="threat_model",
    )
    frames: list[dict[str, Any]] = []
    t0 = time.monotonic()
    tick = 0
    while True:
        snap = runner.snapshot(job_id)
        if snap is None:
            raise RuntimeError("job vanished")
        frames.append(
            {
                "seen": round(time.monotonic() - t0, 2),
                "status": snap.status.value,
                "error": snap.error,
                "progress": snap.progress,
            }
        )
        if snap.done:
            break
        tick += 1
        time.sleep(max(0.0, t0 + tick * every - time.monotonic()))
    return {
        "about": (
            "Poll bodies from one agentic threat model run on the mock client, sampled every "
            f"{every:g} s; each model call paced to {call_seconds:g} s. "
            "Regenerate with tools/build_office_replay.py."
        ),
        "model_calls": llm.calls,
        "frames": frames,
    }


def _normalize_times(data: dict[str, Any]) -> None:
    """Make the recorded epoch times relative to the first sample, so the file is stable."""
    base = None
    for frame in data["frames"]:
        for agent in (frame.get("progress") or {}).get("agents", []):
            for k in ("started_at", "finished_at"):
                if isinstance(agent.get(k), (int, float)):
                    base = agent[k] if base is None else min(base, agent[k])
    if base is None:
        return
    for frame in data["frames"]:
        for agent in (frame.get("progress") or {}).get("agents", []):
            for k in ("started_at", "finished_at"):
                if isinstance(agent.get(k), (int, float)):
                    agent[k] = round(agent[k] - base, 2)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--call-seconds", type=float, default=6.0)
    ap.add_argument("--every", type=float, default=1.0)
    args = ap.parse_args()
    data = record(args.call_seconds, args.every)
    _normalize_times(data)
    OUT.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    statuses = [f["status"] for f in data["frames"]]
    sys.stdout.write(
        f"{OUT.relative_to(ROOT)}: {len(statuses)} frames, {data['model_calls']} model calls, "
        f"final {statuses[-1]}\n"
    )


if __name__ == "__main__":
    main()
