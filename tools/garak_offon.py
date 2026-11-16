"""Real garak scans of each workflow surface with the safeguards off and on.

Runs garak (the interpreter named by ``AEGIS_GARAK_PYTHON``) through the
app's own scan service against the simulated stand-in model, once per
surface with the safeguards off and once with them on, at small limits, plus
a positive control: a surface that does whatever injected text says, which
must make the detectors fire, so a detector that never fires cannot pass as
a clean result. Writes each scan's stored record (as the app stores it:
redacted, capped, with its settings) under ``<out>/garak/`` and the per-probe
counts side by side in ``<out>/garak.md``.

The stand-in follows only some phrasings, so a zero on a probe it does not
follow says nothing about the safeguards. Nothing here contacts anything but
the loopback shim the scan service starts.

Run from the repository root:
    AEGIS_GARAK_PYTHON=/path/to/garak-env/bin/python python tools/garak_offon.py --out build/garak_offon
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegisshield.aiscan import ScanLimits, ScanRequest, run_scan, scan_availability, surfaces  # noqa: E402
from aegisshield.aiscan.probes import DEFAULT_PROBE_IDS  # noqa: E402
from aegisshield.config import get_settings  # noqa: E402
from aegisshield.safeguards.engine import nemo_version  # noqa: E402

NOTE = (
    "Model: the simulated stand-in (SusceptibleLLM), not a real model. These counts describe the "
    "checks and the plumbing, not any real model's behavior. A clean count is not evidence that "
    "the workflow resists an attack; the stand-in follows only some phrasings."
)
PROMPTS_PER_PROBE = 3
TOTAL_REQUESTS = 30
SEED = 7
# Scans without a key may run at most 300 seconds.
WALL_CLOCK_SECONDS = 300
_QUOTED = re.compile(r'"([^"\n]{1,200})"')


def obey(prompt: str) -> str:
    """The positive control: repeats every quoted string in the prompt, then the prompt."""
    return "\n".join(_QUOTED.findall(prompt)) + "\n" + prompt


def _hits(probe: Mapping[str, Any]) -> str:
    evaluations = probe.get("evaluations") or []
    fails = sum(int(e.get("fails") or 0) for e in evaluations)
    total = sum(int(e.get("total_evaluated") or 0) for e in evaluations)
    return f"{fails} of {total}"


def scan(name: str, surface: Any, *, settings: Any, availability: Any, on: bool, guards: Any,
         model_name: str = "simulated stand-in") -> dict[str, Any]:
    """One scan through the app's scan service; its stored record."""
    request = ScanRequest.build(surface_id=name, surface_title=name, probe_ids=list(DEFAULT_PROBE_IDS),
                                limits=ScanLimits.build(prompts_per_probe=PROMPTS_PER_PROBE,
                                                        total_requests=TOTAL_REQUESTS,
                                                        wall_clock_seconds=WALL_CLOCK_SECONDS),
                                seed=SEED, safeguards_on=on, model_kind="simulated",
                                model_name=model_name, developer=True)
    summary = (lambda: surfaces.safeguards_summary(guards)) if guards is not None else None
    return run_scan(request, surface=surface, availability=availability, job_timeout_seconds=1800,
                    safeguards_report=summary)["record"]


def run_all() -> list[tuple[str, str, dict[str, Any]]]:
    """The positive control, then every surface off and on: ``(surface, mode, record)``."""
    settings = get_settings({"AEGIS_AI_SCAN": "1", "AEGIS_GARAK_PYTHON": os.environ["AEGIS_GARAK_PYTHON"]})
    availability = scan_availability(settings)
    if not availability.available:
        raise SystemExit("AEGIS_GARAK_PYTHON does not name a garak environment.")
    runs = [("positive_control", "off", scan("positive_control", obey, settings=settings,
                                             availability=availability, on=False, guards=None,
                                             model_name="control surface (repeats any quoted string)"))]
    for spec in surfaces.SURFACES:
        for on in (False, True):
            guards = surfaces.make_safeguards(settings, on)
            surface = spec.build(surfaces.simulated_llm(), settings, guards)
            runs.append((spec.id, "on" if on else "off",
                         scan(spec.id, surface, settings=settings, availability=availability, on=on,
                              guards=guards)))
    return runs


def render(runs: Sequence[tuple[str, str, Mapping[str, Any]]], header: Mapping[str, Any]) -> str:
    """The per-probe counts with the safeguards off and on, side by side."""
    lines = ["# garak scans: safeguards off and on", "", f"> {NOTE}", "",
             f"Date {header['date']}, {header['commit']}, Python {header['python']}, NeMo Guardrails "
             f"{header['nemo_guardrails']}, garak {header['garak']}. Probes: {', '.join(DEFAULT_PROBE_IDS)}; "
             f"{PROMPTS_PER_PROBE} prompts per probe, request limit {TOTAL_REQUESTS}, seed {SEED}.", "",
             "Cells read \"the detector found the attack in X of Y answers\", summed over a probe's "
             "detectors; garak calls an answer where it found nothing \"passed\".", "",
             "## Scans", "", "| Surface | Safeguards | Status | Requests | Refused | Safeguards record |",
             "|---|---|---|---|---|---|"]
    for name, mode, record in runs:
        sg = record.get("safeguards") or {}
        sg_words = (f"{sg.get('checks', 0)} checks, {sg.get('inputs_changed', 0)} inputs changed, "
                    f"{sg.get('answers_withheld', 0)} answers withheld, {sg.get('not_checked', 0)} not checked"
                    if sg else "none (positive control)")
        reasons = "; ".join(record.get("reasons") or [])
        lines.append(f"| {name} | {mode} | {record['status']}{': ' + reasons if reasons else ''} | "
                     f"{record['shim'].get('requests', 0)} | {record['shim'].get('refusals', 0)} | {sg_words} |")
    by = {(n, m): {p["probe"]: p for p in r["probes"]} for n, m, r in runs}
    lines += ["", "## Per probe", "", "| Surface | Probe | Off | On |", "|---|---|---|---|"]
    for name in dict.fromkeys(n for n, _, _ in runs):
        off, on = by.get((name, "off"), {}), by.get((name, "on"), {})
        for probe in DEFAULT_PROBE_IDS:
            cells = []
            for side in (off, on):
                row = side.get(probe)
                cells.append("" if row is None else f"{_hits(row)} ({row['state']})")
            lines.append(f"| {name} | {probe} | {cells[0]} | {cells[1] or 'not run'} |")
    return "\n".join(lines) + "\n"


def stamp() -> dict[str, Any]:
    """Date, versions, and the commit, named as the one that adds the files:
    the branch is squashed before it is published, so an id would point at nothing."""
    from aegisshield.aiscan.availability import garak_version

    return {"date": time.strftime("%Y-%m-%d"), "commit": "the commit that added these files", "python": platform.python_version(),
            "nemo_guardrails": nemo_version(), "garak": garak_version(os.environ["AEGIS_GARAK_PYTHON"])}


def main(argv: Sequence[str] | None = None, *, stdout: TextIO | None = None) -> int:
    """Run the scans and write the records and the table; 1 when a scan did not complete."""
    out_stream = stdout or sys.stdout
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    if not os.environ.get("AEGIS_GARAK_PYTHON"):
        raise SystemExit("Set AEGIS_GARAK_PYTHON to the Python of a garak environment.")
    runs = run_all()
    header = stamp()
    records = args.out / "garak"
    records.mkdir(parents=True, exist_ok=True)
    for name, mode, record in runs:
        model = "control surface (repeats any quoted string)" if name == "positive_control" else "simulated stand-in"
        wrapped = {"note": NOTE, "stamp": {**header, "surface": name, "safeguards": mode, "model": model},
                   "record": record}
        (records / f"{name}-{mode}.json").write_text(json.dumps(wrapped, indent=1) + "\n", encoding="utf-8")
    (args.out / "garak.md").write_text(render(runs, header), encoding="utf-8")
    incomplete = [f"{n}-{m}" for n, m, r in runs if r["status"] != "complete"]
    out_stream.write(f"{NOTE}\nWrote {len(runs)} scan records and garak.md under {args.out}\n")
    if incomplete:
        out_stream.write(f"Not complete: {', '.join(incomplete)}\n")
    return 1 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
