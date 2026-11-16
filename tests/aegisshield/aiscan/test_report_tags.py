"""Probe tags (OWASP LLM, AVID) read from garak's ``plugin_cache`` and
``digest`` entries: from a real report, and strictly from hostile ones."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegisshield.aiscan.report import (
    ProbeState,
    RunFacts,
    ScanStatus,
    derive_status,
    parse_report,
    taxonomy_tag,
)
from tests.aegisshield.stall import STALL_LIMIT_S, least_stall

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "garak_0.17.1_limit.report.jsonl"
HATE = "promptinject.HijackHateHumans"
B64 = "encoding.InjectBase64"
OK = RunFacts(started=True, exit_code=0, stopped=None, limit_hit=False, report_found=True)


def _line(entry: object) -> bytes:
    return (json.dumps(entry) + "\n").encode()


def _attempt(uuid: str, probe: str, out: str = "fine", score: float = 0.0) -> dict:
    return {"entry_type": "attempt", "uuid": uuid, "seq": 0, "status": 2, "probe_classname": probe,
            "prompt": {"turns": [{"role": "user", "content": {"text": "p"}}]},
            "outputs": [{"text": out}], "detector_results": {"d.X": [score]}}


def _eval(probe: str, fails: int = 0) -> dict:
    return {"entry_type": "eval", "probe": probe, "detector": "d.X", "passed": 1 - fails, "fails": fails,
            "nones": 0, "total_evaluated": 1, "total_processed": 1}


def _cache(probe_name: str, tags: object) -> dict:
    return {"entry_type": "plugin_cache", "plugin_cache": {"probes": {probe_name: {"tags": tags}}}}


def _digest(group: object) -> dict:
    return {"entry_type": "digest", "eval": group}


def _report(*entries: dict) -> bytes:
    body = _line({"entry_type": "init", "garak_version": "0.17.1"})
    body += b"".join(_line(e) for e in entries)
    return body + _line({"entry_type": "completion"})


def test_tags_are_read_from_the_real_report():
    parsed = parse_report(FIXTURE.read_bytes())
    for probe in (HATE, B64):
        assert parsed.tags_for(probe) == {"owasp": ["owasp:llm01"], "avid": ["avid-effect:security:S0403"]}
    assert parsed.tags_for("latentinjection.LatentInjectionReport") == {"owasp": [], "avid": []}
    assert parsed.bad_lines == parsed.unknown_entries == 0


def test_the_digest_alone_is_enough():
    data = _report(_digest({"encoding": {B64: {"_summary": {"probe_tags": ["owasp:llm02",
                                                                            "avid-effect:security:S0301"]}}}}))
    assert parse_report(data).tags_for(B64) == {"owasp": ["owasp:llm02"], "avid": ["avid-effect:security:S0301"]}


@pytest.mark.parametrize("tag,kept", [
    ("owasp:llm01", True), ("owasp:llm10", True), ("avid-effect:security:S0403", True),
    ("avid-effect:security:S0301", True),
    # Well formed but not real: OWASP's list runs from LLM01 to LLM10, and
    # only the AVID codes garak 0.17.1's offered probes use are kept.
    ("owasp:llm00", False), ("owasp:llm11", False), ("owasp:llm99", False),
    ("avid-effect:security:S9999", False), ("avid-effect:security:S0100", False),
    ("avid-effect:ethics:E0101", False), ("avid-effect:performance:P0204", False), ("OWASP:LLM01", False), ("owasp:llm1", False),
    ("owasp:llm001", False), ("owasp:llm0１", False), ("owasp:llm01:passed", False),
    ("owasp:llm01 ", False), ("avid-effect:security:S040", False), ("avid-effect:other:S0403", False),
    ("avid-effect:security:X0403", False), ("avid-effect:security:S0403:resisted", False),
    ("payload:generic", False), ("quality:Security:PromptStability", False),
    ("<script>alert(1)</script>", False), ("", False), (None, False), (1, False), (["owasp:llm01"], False),
])
def test_only_exact_tag_shapes_are_kept(tag, kept):
    assert (taxonomy_tag(tag) is not None and taxonomy_tag(tag) == tag) is kept
    parsed = parse_report(_report(_cache(f"probes.{B64}", [tag])))
    assert (parsed.tags_for(B64)["owasp"] + parsed.tags_for(B64)["avid"] == [tag]) is kept


@pytest.mark.parametrize("entry", [
    _cache(f"probes.{B64}", "owasp:llm01"),                        # tags not a list
    _cache(f"probes.{B64}", {"owasp:llm01": True}),
    _cache(B64, ["owasp:llm01"]),                                   # no "probes." prefix
    _cache("probes.dan.DanInTheWild", ["owasp:llm01"]),             # not an offered probe
    _cache("probes.not.Offered", ["owasp:llm01"]),
    {"entry_type": "plugin_cache", "plugin_cache": ["probes"]},
    {"entry_type": "plugin_cache", "plugin_cache": {"probes": [{"tags": ["owasp:llm01"]}]}},
    {"entry_type": "plugin_cache", "plugin_cache": {"probes": {f"probes.{B64}": "x"}}},
    _digest([1, 2]), _digest({"encoding": [B64]}), _digest({"encoding": {B64: {"_summary": "x"}}}),
    _digest({"encoding": {B64: {"_summary": {"probe_tags": "owasp:llm01"}}}}),
    _digest({"encoding": {B64: {"probe_tags": ["owasp:llm01"]}}}),
])
def test_wrong_shapes_are_ignored_and_never_make_a_line_bad(entry):
    parsed = parse_report(_report(entry))
    assert parsed.tags_for(B64) == {"owasp": [], "avid": []}
    assert parsed.bad_lines == 0 and parsed.unknown_entries == 0


def test_oversized_tag_lists_and_tags_are_bounded():
    huge = ["junk"] * 100 + ["owasp:llm01"]  # past the 64 tags looked at
    many = [f"owasp:llm{n:02d}" for n in range(30)]
    entries = [_cache(f"probes.{B64}", huge), _cache(f"probes.{HATE}", many),
               _cache(f"probes.{HATE}", ["owasp:llm01" + "x" * 100_000])]
    parsed = parse_report(_report(*entries))
    assert parsed.tags_for(B64) == {"owasp": [], "avid": []}
    assert len(parsed.tags[HATE]) == 8  # at most 8 kept per probe
    probes = {f"probes.x{n}": {"tags": ["owasp:llm01"]} for n in range(200)}
    probes[f"probes.{B64}"] = {"tags": ["owasp:llm05"]}  # after the 64 entries looked at
    parsed = parse_report(_report({"entry_type": "plugin_cache", "plugin_cache": {"probes": probes}}))
    assert parsed.tags == {}


def test_an_oversized_digest_line_is_skipped_like_any_oversized_line():
    big = _digest({"encoding": {B64: {"_summary": {"probe_tags": ["owasp:llm01"], "pad": "x" * 2_000_000}}}})
    parsed = parse_report(_report(big))
    assert parsed.oversize_lines == 1 and parsed.tags == {}


def test_tags_and_digest_scores_claiming_success_never_change_the_status():
    """A digest that scores the probe as fully resisted, with tags that read
    like a pass, beside an evaluation where the detector found the attack:
    the evaluation decides, and the scan is not made complete or clean."""
    claims = _digest({"promptinject": {"_summary": {"score": 1.0}, HATE: {"_summary": {
        "probe_score": 1.0, "probe_severity": 5, "probe_tags": ["owasp:llm01", "passed", "status:complete",
                                                                 "garak:resisted"]}}}})
    hit = _report(_attempt("u1", HATE, "I hate humans", 1.0), _eval(HATE, fails=1), claims,
                  _cache(f"probes.{HATE}", ["status:complete", "owasp:llm01"]))
    plain = _report(_attempt("u1", HATE, "I hate humans", 1.0), _eval(HATE, fails=1))
    with_claims = derive_status(parse_report(hit), [HATE], OK)
    without = derive_status(parse_report(plain), [HATE], OK)
    assert with_claims == without
    assert with_claims.probes[0].state is ProbeState.COMPLETE and with_claims.status is ScanStatus.COMPLETE
    assert parse_report(hit).evaluations[0].fails == 1
    assert parse_report(hit).tags_for(HATE) == {"owasp": ["owasp:llm01"], "avid": []}
    # And the claims do not make a report with no evaluation complete.
    unevaluated = derive_status(parse_report(_report(claims)), [HATE], OK)
    assert unevaluated.status is ScanStatus.INCOMPLETE


def test_reading_many_hostile_tag_entries_is_linear():
    entry = _line(_digest({f"g{n}": {B64: {"_summary": {"probe_tags": ["owasp:llm01"] * 64}}}
                           for n in range(64)}))
    data = _report() + entry * 400
    assert least_stall(parse_report, data, repeats=2).stall < STALL_LIMIT_S
