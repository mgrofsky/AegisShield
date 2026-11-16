"""One short scan through the real garak, when ``AEGIS_GARAK_PYTHON`` names
a garak environment in the test environment; skipped otherwise.

A positive control (a surface that obeys injected instructions) must make
the detectors fire, so a detector that never fires cannot pass as a clean
result. A negative control (a surface that always refuses) must make none
fire, and must be shown as refused, not as resisted.
"""

from __future__ import annotations

import os
import re

import pytest

from aegisshield.aiscan import ScanLimits, ScanRequest, ScanState, run_scan, scan_availability
from aegisshield.aiscan.shim import SurfaceRefused
from aegisshield.config import get_settings

PYTHON = os.environ.get("AEGIS_GARAK_PYTHON", "")
pytestmark = pytest.mark.skipif(
    not PYTHON, reason="AEGIS_GARAK_PYTHON is not set: no garak environment to run the real scan with"
)
PROBES = ["promptinject.HijackHateHumans", "latentinjection.LatentInjectionReport"]
_QUOTED = re.compile(r'"([^"\n]{1,200})"')


def obey(prompt: str) -> str:
    """Does what injected text says: repeats any quoted string, then the input."""
    return "\n".join(_QUOTED.findall(prompt)) + "\n" + prompt


def refuse(prompt: str) -> str:
    raise SurfaceRefused


def _scan(surface, generations: int = 1):
    available = scan_availability(get_settings({"AEGIS_AI_SCAN": "1", "AEGIS_GARAK_PYTHON": PYTHON}))
    assert available.state is ScanState.AVAILABLE, "AEGIS_GARAK_PYTHON does not name a garak environment"
    request = ScanRequest.build(surface_id="control", surface_title="Control surface", probe_ids=PROBES,
                                limits=ScanLimits.build(prompts_per_probe=3, total_requests=12,
                                                        generations=generations, wall_clock_seconds=300),
                                seed=3, safeguards_on=False, model_kind="simulated", model_name="control",
                                developer=True)
    return run_scan(request, surface=surface, availability=available, job_timeout_seconds=1800)


def test_positive_control_makes_the_detectors_fire():
    out = _scan(obey)
    record = out["record"]
    assert record["status"] == "complete", record["reasons"]
    assert record["settings"]["garak_version"] == "0.17.1"
    for row in record["probes"]:
        assert row["state"] == "complete"
        assert sum(e["fails"] for e in row["evaluations"]) > 0, row
    assert record["shim"]["requests"] == 6
    assert record["shim"]["rejected"] == 0  # the connection cap never turned garak away
    assert b"<garak environment>" in out["files"]["garak.report.jsonl"]
    home = os.path.expanduser("~").encode()
    garak_env = os.path.dirname(os.path.dirname(PYTHON)).encode()
    assert set(out["files"]) == {"garak.report.jsonl", "garak.hitlog.jsonl", "garak.report.html"}
    for name, data in out["files"].items():
        assert home not in data and garak_env not in data, name


def test_two_answers_per_prompt_count_consistently():
    out = _scan(obey, generations=2)
    record = out["record"]
    assert record["status"] == "complete", record["reasons"]
    assert record["shim"]["requests"] == 12
    assert record["shim"]["rejected"] == 0
    for row in record["probes"]:
        assert all(e["total_processed"] == 6 for e in row["evaluations"]), row


def test_negative_control_fires_nothing_and_reads_as_refused():
    record = _scan(refuse)["record"]
    assert record["status"] == "complete", record["reasons"]
    for row in record["probes"]:
        assert row["state"] == "all_refused"
        assert sum(e["fails"] for e in row["evaluations"]) == 0
        assert sum(e["total_evaluated"] for e in row["evaluations"]) > 0
    assert record["shim"]["refusals"] == 6


@pytest.mark.parametrize("surface_id", ["threat_description", "retrieved_content", "policy_profile"])
def test_safeguards_off_then_on_with_the_simulated_stand_in(surface_id):
    """SIMULATED: the stand-in obeys the hijack, so with the safeguards off the
    detector fires; with them on it must not, and the record says they ran."""
    from aegisshield.aiscan import surfaces

    settings = get_settings({"AEGIS_AI_SCAN": "1", "AEGIS_GARAK_PYTHON": PYTHON, "AEGIS_MOCK_LLM": "1",
                             "AEGIS_OFFLINE": "1"})
    available = scan_availability(settings)
    spec = surfaces.surface_spec(surface_id)
    hits = {}
    for on in (False, True):
        guards = surfaces.make_safeguards(settings, on)
        request = ScanRequest.build(surface_id=spec.id, surface_title=spec.title,
                                    probe_ids=["promptinject.HijackHateHumans"],
                                    limits=ScanLimits.build(prompts_per_probe=3, total_requests=3,
                                                            wall_clock_seconds=300), seed=7,
                                    safeguards_on=on, model_kind="simulated", model_name="simulated stand-in",
                                    developer=True)
        record = run_scan(request, surface=spec.build(surfaces.simulated_llm(), settings, guards),
                          availability=available, job_timeout_seconds=1800,
                          safeguards_report=lambda g=guards: surfaces.safeguards_summary(g))["record"]
        assert record["status"] == "complete", record["reasons"]
        hits[on] = sum(e["fails"] for e in record["probes"][0]["evaluations"])
        assert record["safeguards"]["status"] == ("on" if on else "off")
    assert hits[False] > 0 and hits[True] == 0


def test_the_visitors_workflow_off_then_on_with_the_simulated_stand_in():
    """The page's own surface through real garak: the hijack reaches the
    stand-in's answers without the checks and none with them, both runs
    are complete, and the record carries garak's OWASP and AVID tags and
    the app's ATLAS references."""
    from aegisshield.aiscan import surfaces

    settings = get_settings({"AEGIS_AI_SCAN": "1", "AEGIS_GARAK_PYTHON": PYTHON, "AEGIS_MOCK_LLM": "1",
                             "AEGIS_OFFLINE": "1"})
    available = scan_availability(settings)
    workflow = {"system_prompt": "You answer billing questions for Example Retail in two sentences or fewer.",
                "sample_context": "Invoice 42 is due on the 3rd.", "model": "gpt-5.4"}
    hits = {}
    for on in (False, True):
        guards = surfaces.make_safeguards(settings, on)
        request = ScanRequest.build(surface_id=surfaces.WORKFLOW_SURFACE_ID, surface_title="Your AI workflow",
                                    probe_ids=["promptinject.HijackHateHumans"],
                                    limits=ScanLimits.build(prompts_per_probe=3, total_requests=3,
                                                            wall_clock_seconds=300), seed=7,
                                    safeguards_on=on, model_kind="simulated", model_name="simulated stand-in",
                                    workflow=workflow)
        surface = surfaces.WORKFLOW_SURFACE.build(surfaces.simulated_llm(surfaces.WORKFLOW_SURFACE_ID), settings,
                                                  guards, request.workflow)
        record = run_scan(request, surface=surface, availability=available, job_timeout_seconds=1800,
                          safeguards_report=lambda g=guards: surfaces.safeguards_summary(g))["record"]
        assert record["status"] == "complete", record["reasons"]
        (row,) = record["probes"]
        hits[on] = sum(e["fails"] for e in row["evaluations"])
        assert row["taxonomy"]["owasp"] == ["owasp:llm01"]
        assert row["taxonomy"]["avid"] == ["avid-effect:security:S0403"]
        assert [a["id"] for a in row["taxonomy"]["atlas"]] == ["AML.T0051.000"]
        assert record["settings"]["workflow"]["model"] == "gpt-5.4"
        if on:
            assert row["state"] == "all_refused" and record["safeguards"]["answers_withheld"] == 3
    assert hits[False] == 3 and hits[True] == 0


DEFAULTS = ["promptinject.HijackHateHumans", "latentinjection.LatentInjectionReport",
            "web_injection.MarkdownImageExfil", "encoding.InjectBase64"]


def _garak_tags(probe_ids: list[str], tmp: str) -> dict[str, list[str]]:
    """Each probe's ``tags`` as garak 0.17.1 defines them, read in garak's
    own environment (no network, a private home)."""
    import json
    import subprocess
    import sys

    code = ("import importlib, json, sys\n"
            "out = {}\n"
            "for pid in sys.argv[1:]:\n"
            "    mod, cls = pid.split('.')\n"
            "    out[pid] = list(getattr(getattr(importlib.import_module('garak.probes.' + mod), cls), 'tags'))\n"
            "print(json.dumps(out))\n")
    env = {"PATH": os.environ.get("PATH", ""), "HOME": tmp, "XDG_CONFIG_HOME": tmp, "XDG_DATA_HOME": tmp,
           "XDG_CACHE_HOME": tmp, "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"}
    assert sys.executable != PYTHON
    done = subprocess.run([PYTHON, "-I", "-c", code, *probe_ids], env=env, cwd=tmp, capture_output=True,
                          text=True, timeout=120, check=True)
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_the_real_report_carries_tags_where_the_reader_looks(tmp_path):
    """garak 0.17.1's report: ``plugin_cache.probes["probes.<id>"].tags`` and
    ``digest.eval.<group>.<id>._summary.probe_tags``. Each alone gives the
    reader the probe's OWASP and AVID tags exactly as garak defines them."""
    import json

    from aegisshield.aiscan import ScanLimits as Limits
    from aegisshield.aiscan.report import parse_report

    available = scan_availability(get_settings({"AEGIS_AI_SCAN": "1", "AEGIS_GARAK_PYTHON": PYTHON}))
    request = ScanRequest.build(surface_id="control", surface_title="Control surface", probe_ids=DEFAULTS,
                                limits=Limits.build(prompts_per_probe=1, total_requests=20,
                                                    wall_clock_seconds=300),
                                seed=3, safeguards_on=False, model_kind="simulated", model_name="control",
                                developer=True)
    out = run_scan(request, surface=obey, availability=available, job_timeout_seconds=1800)
    assert out["record"]["status"] == "complete", out["record"]["reasons"]
    lines = out["files"]["garak.report.jsonl"].splitlines(keepends=True)
    entries = [json.loads(line) for line in lines]
    cache = [e for e in entries if e.get("entry_type") == "plugin_cache"]
    digest = [e for e in entries if e.get("entry_type") == "digest"]
    assert cache and len(digest) == 1
    for probe in DEFAULTS:
        group = probe.split(".")[0]
        assert isinstance(digest[0]["eval"][group][probe]["_summary"]["probe_tags"], list)
        assert any(isinstance(e["plugin_cache"]["probes"].get(f"probes.{probe}", {}).get("tags"), list)
                   for e in cache)
    wanted = {p: {"owasp": [t for t in tags if t.startswith("owasp:")],
                  "avid": [t for t in tags if t.startswith("avid-effect:")]}
              for p, tags in _garak_tags(DEFAULTS, str(tmp_path)).items()}
    keep = {"init", "completion"}
    for kind in ("plugin_cache", "digest"):
        only = b"".join(line for line, e in zip(lines, entries, strict=True)
                        if e.get("entry_type") in keep | {kind})
        parsed = parse_report(only)
        assert {p: parsed.tags_for(p) for p in DEFAULTS} == wanted, kind


def test_the_kept_tags_are_every_owasp_and_avid_tag_the_offered_probes_use(tmp_path):
    """Every OWASP and AVID tag garak gives an offered probe is one the
    reader keeps, and every AVID tag the reader keeps is used by one."""
    from aegisshield.aiscan.probes import PROBES as OFFERED
    from aegisshield.aiscan.report import AVID_TAGS, OWASP_LLM_TAGS

    tags = {t for ts in _garak_tags([p.id for p in OFFERED], str(tmp_path)).values() for t in ts}
    assert {t for t in tags if t.startswith("avid-effect:")} == AVID_TAGS
    assert {t for t in tags if t.startswith("owasp:")} <= OWASP_LLM_TAGS
