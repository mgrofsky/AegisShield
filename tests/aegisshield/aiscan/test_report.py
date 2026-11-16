"""The report parser reads garak's file strictly, and the status comes from
the evidence in it, never from the exit code."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from aegisshield.aiscan.report import (
    ProbeState,
    RunFacts,
    ScanStatus,
    derive_status,
    parse_report,
    probe_outcome,
)
from aegisshield.aiscan.shim import FixedAnswers
from tests.aegisshield.stall import STALL_LIMIT_S, least_stall

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "garak_0.17.1_limit.report.jsonl"
PROBES = ("promptinject.HijackHateHumans", "encoding.InjectBase64")
OK = RunFacts(started=True, exit_code=0, stopped=None, limit_hit=False, report_found=True)


def _line(entry: dict) -> bytes:
    return (json.dumps(entry) + "\n").encode()


def _attempt(uuid="u1", probe="p.A", seq=0, status=2, outputs=("out",), scores=(1.0,)) -> dict:
    return {"entry_type": "attempt", "uuid": uuid, "seq": seq, "status": status, "probe_classname": probe,
            "prompt": {"turns": [{"role": "user", "content": {"text": "the prompt"}}]},
            "outputs": [None if o is None else {"text": o} for o in outputs],
            "detector_results": {"d.X": list(scores)}}


def _eval(probe="p.A", passed=0, fails=1, nones=0, evaluated=1, processed=1) -> dict:
    return {"entry_type": "eval", "probe": probe, "detector": "d.X", "passed": passed, "fails": fails,
            "nones": nones, "total_evaluated": evaluated, "total_processed": processed}


def _report(*entries: dict, completion: bool = True) -> bytes:
    body = _line({"entry_type": "init", "garak_version": "0.17.1", "start_time": "t0"})
    body += b"".join(_line(e) for e in entries)
    if completion:
        body += _line({"entry_type": "completion", "end_time": "t1"})
    return body


def test_fixture_holds_no_token_path_or_user_name():
    text = FIXTURE.read_text()
    for needle in ("/Users/", "/home/", "/private/", "Bearer ", "REST_API_KEY"):
        assert needle not in text


def test_real_report_is_read():
    parsed = parse_report(FIXTURE.read_bytes())
    assert parsed.has_init and parsed.has_completion and parsed.garak_version == "0.17.1"
    assert parsed.bad_lines == parsed.oversize_lines == parsed.unknown_entries == 0
    assert not parsed.ends_mid_line  # garak's last line has no newline, and that is fine
    # Each attempt was written twice; the evaluated copy was kept.
    assert len(parsed.attempts) == 4 and all(a.status == 2 for a in parsed.attempts.values())
    hate = parsed.attempts_for("promptinject.HijackHateHumans")
    assert [a.outputs for a in hate] == [("I hate humans\nNoted.",), (None,)]
    assert hate[0].detector_results == {"promptinject.AttackRogueString": (1.0,)}
    assert "I hate humans" in hate[0].prompt
    evals = {(e.probe, e.detector): e for e in parsed.evaluations}
    assert evals[("promptinject.HijackHateHumans", "promptinject.AttackRogueString")].nones == 1


def test_real_report_status():
    parsed = parse_report(FIXTURE.read_bytes())
    facts = RunFacts(started=True, exit_code=0, stopped=None, limit_hit=True, report_found=True)
    verdict = derive_status(parsed, PROBES, facts)
    assert verdict.status is ScanStatus.INCOMPLETE
    states = {o.probe: o.state for o in verdict.probes}
    assert states == {"promptinject.HijackHateHumans": ProbeState.INCOMPLETE,
                      "encoding.InjectBase64": ProbeState.COMPLETE}
    assert any("request limit" in r for r in verdict.reasons)


def test_truncated_real_report_is_never_complete():
    data = FIXTURE.read_bytes()
    for cut in (len(data) // 3, len(data) // 2, len(data) - 40, data.rindex(b'{"entry_type": "completion"')):
        verdict = derive_status(parse_report(data[:cut]), PROBES, OK)
        assert verdict.status is not ScanStatus.COMPLETE


def test_exit_code_zero_with_nothing_evaluated_is_not_complete():
    verdict = derive_status(parse_report(_report()), ["p.A"], OK)
    assert verdict.status is ScanStatus.INCOMPLETE
    assert verdict.probes[0].state is ProbeState.NOT_RUN


def test_complete_needs_consistent_counts():
    good = _report(_attempt(), _eval())
    assert derive_status(parse_report(good), ["p.A"], OK).status is ScanStatus.COMPLETE
    for bad in (_eval(processed=2), _eval(passed=1), _eval(evaluated=0, fails=0, processed=1, nones=1)):
        verdict = derive_status(parse_report(_report(_attempt(), bad)), ["p.A"], OK)
        assert verdict.status is ScanStatus.INCOMPLETE, bad
        assert verdict.probes[0].state is ProbeState.INCOMPLETE


def test_attempt_never_evaluated_is_incomplete():
    data = _report(_attempt(status=1), _eval())
    assert probe_outcome(parse_report(data), "p.A").state is ProbeState.INCOMPLETE


def test_no_report_unreadable_and_not_started():
    assert derive_status(parse_report(None), ["p.A"], RunFacts(True, 0, None, False, False)).status \
        is ScanStatus.FAILED
    assert derive_status(parse_report(b"garbage\n"), ["p.A"], OK).status is ScanStatus.FAILED
    assert derive_status(parse_report(b""), ["p.A"], RunFacts(False, None, None, False, False)).reasons == (
        "garak could not be started.",)
    stopped = derive_status(parse_report(None), ["p.A"], RunFacts(True, -9, "time_limit", False, False))
    assert stopped.status is ScanStatus.INCOMPLETE


def test_unrequested_probe_in_report_is_flagged():
    data = _report(_attempt(), _eval(), _attempt(uuid="u2", probe="p.B"))
    verdict = derive_status(parse_report(data), ["p.A"], OK)
    assert verdict.status is ScanStatus.INCOMPLETE


def test_malformed_values_are_dropped_not_trusted():
    entries = [
        {**_attempt(), "seq": "0"},
        {**_attempt(uuid="u3"), "outputs": "nope"},
        {**_eval(), "fails": True},
        {**_eval(), "passed": -1},
        {**_eval(), "fails": 1.5},
        {"entry_type": "attempt"},
        [1, 2],
        {"entry_type": "mystery"},
    ]
    parsed = parse_report(_report(*entries))
    assert parsed.attempts == {} and parsed.evaluations == []
    assert parsed.bad_lines == 7 and parsed.unknown_entries == 1


def test_odd_scores_and_prompts_are_tolerated():
    attempt = _attempt(scores=("x", float("inf"), True, 0.5), outputs=("a", None, "b", "c"))
    attempt["prompt"] = {"turns": []}
    attempt["detector_results"]["d.Y"] = "not a list"
    parsed = parse_report(_report(attempt))
    (only,) = parsed.attempts.values()
    assert only.detector_results == {"d.X": (None, None, None, 0.5)} and only.prompt == ""
    for prompt in (None, {"turns": ["x"]}, {"turns": [{"content": "x"}]}):
        attempt["prompt"] = prompt
        assert next(iter(parse_report(_report(attempt)).attempts.values())).prompt == ""


def test_oversize_lines_are_skipped_without_reading_them_whole():
    big = b'{"entry_type": "attempt", "pad": "' + b"x" * 5000 + b'"}\n'
    parsed = parse_report(_report(_attempt()) + big + _line(_eval()), max_line_bytes=1000)
    assert parsed.oversize_lines == 1 and len(parsed.evaluations) == 1
    tail = parse_report(_report(_attempt(), completion=False) + b"x" * 5000, max_line_bytes=1000)
    assert tail.oversize_lines == 1 and tail.ends_mid_line


def test_line_and_byte_limits(monkeypatch):
    from aegisshield.aiscan import report

    data = _report(_attempt(), _eval())
    assert parse_report(data, max_lines=2).over_line_limit
    monkeypatch.setattr(report, "MAX_REPORT_BYTES", 50)
    assert parse_report(data).over_byte_limit
    monkeypatch.setattr(report, "MAX_REPORT_BYTES", 10_000)
    monkeypatch.setattr(report, "MAX_ATTEMPTS", 1)
    parsed = parse_report(_report(_attempt(), _attempt(uuid="u2")))
    assert len(parsed.attempts) == 1 and parsed.unknown_entries == 1


def test_bad_utf8_and_blank_lines():
    parsed = parse_report(b"\n\xff\xfe\n" + _report())
    assert parsed.bad_lines == 1 and parsed.has_init


FIXED = FixedAnswers.for_scan()


def test_all_refused_and_all_failed_probes():
    refused = parse_report(_report(_attempt(outputs=(FIXED.refused,), scores=(0.0,)), _eval(passed=1, fails=0)))
    assert probe_outcome(refused, "p.A", FIXED).state is ProbeState.ALL_REFUSED
    failed = parse_report(_report(_attempt(outputs=(FIXED.failed,)), _attempt(uuid="u2", seq=1,
                                                                              outputs=(FIXED.timeout,))))
    assert probe_outcome(failed, "p.A", FIXED).state is ProbeState.NOT_EVALUATED
    failed = parse_report(_report(_attempt(outputs=(FIXED.failed,)), _eval()))
    assert probe_outcome(failed, "p.A", FIXED).state is ProbeState.ALL_FAILED
    some = parse_report(_report(_attempt(), _attempt(uuid="u2", seq=1, outputs=(FIXED.failed,)),
                                _eval(fails=2, evaluated=2, processed=2)))
    assert probe_outcome(some, "p.A", FIXED).state is ProbeState.INCOMPLETE


def test_an_answer_that_copies_a_fixed_answer_without_this_scans_mark_is_not_a_refusal():
    # The model can write any text, including a refusal's words or another
    # scan's whole fixed answer; it cannot know this scan's mark.
    other = FixedAnswers.for_scan()
    assert other.mark != FIXED.mark
    for text in (other.refused, "[AegisShield scan: the workflow step refused this input and gave no answer.]"):
        data = _report(_attempt(outputs=(text,), scores=(1.0,)), _eval(passed=0, fails=1))
        outcome = probe_outcome(parse_report(data), "p.A", FIXED)
        assert outcome.state is ProbeState.COMPLETE and outcome.refusals == 0
        verdict = derive_status(parse_report(data), ["p.A"], replace(OK, fixed=FIXED))
        assert verdict.status is ScanStatus.COMPLETE and verdict.probes[0].state is ProbeState.COMPLETE
    # Without the scan's fixed answers, nothing is read as a refusal.
    data = _report(_attempt(outputs=(FIXED.refused,), scores=(0.0,)), _eval(passed=1, fails=0))
    assert probe_outcome(parse_report(data), "p.A").state is ProbeState.COMPLETE


def test_a_probe_with_a_detector_hit_is_never_all_refused():
    # Every answer is this scan's own refusal, yet a detector reports a hit:
    # the hit is shown, never hidden behind "all refused".
    by_eval = _report(_attempt(outputs=(FIXED.refused,), scores=(0.0,)), _eval(passed=0, fails=1))
    by_score = _report(_attempt(outputs=(FIXED.refused,), scores=(0.9,)), _eval(passed=1, fails=0))
    for data in (by_eval, by_score):
        outcome = probe_outcome(parse_report(data), "p.A", FIXED)
        assert outcome.state is ProbeState.INCOMPLETE and outcome.refusals == 1
        assert "yet a detector reported the attack found" in outcome.reason
        verdict = derive_status(parse_report(data), ["p.A"], replace(OK, fixed=FIXED))
        assert verdict.status is ScanStatus.INCOMPLETE


def test_an_integer_longer_than_the_digit_limit_is_an_unreadable_line():
    huge = "9" * 5000
    lines = (b'{"entry_type": "eval", "probe": "p.A", "detector": "d.X", "fails": ' + huge.encode() + b"}\n",
             b'{"entry_type": "attempt", "seq": ' + huge.encode() + b"}\n")
    parsed = parse_report(_report() + b"".join(lines))
    assert parsed.bad_lines == 2 and parsed.has_init and parsed.has_completion
    assert derive_status(parsed, ["p.A"], OK).status is not ScanStatus.COMPLETE
    # The same line last, without a newline, is a report cut off mid-write.
    assert parse_report(_report() + lines[0].rstrip()).ends_mid_line


def test_parsing_a_large_hostile_report_does_not_stall_other_threads():
    line = _line(_attempt(outputs=("[" * 50_000,)))
    data = _report() + line * 200
    assert least_stall(parse_report, data, repeats=2).stall < STALL_LIMIT_S
