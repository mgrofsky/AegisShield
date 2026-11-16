import gc
import logging
import threading
import time
import weakref

import pytest

from aegisshield.config import Settings
from aegisshield.core.errors import (
    IntelLookupError,
    JobError,
    LLMError,
    LLMResponseError,
    ValidationError,
)
from aegisshield.jobs import runner as runner_mod
from aegisshield.jobs.runner import (
    ERROR_CAP,
    ERROR_GENERIC,
    ERROR_INPUT,
    ERROR_LOOKUP,
    ERROR_UNREADABLE,
    ERROR_UPSTREAM,
    JobRunner,
    JobStatus,
    plain_error,
)

KEY = "sk-test-abcdefghij0123456789"


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


def make(max_jobs=2, timeout=60.0, ttl=900.0, clock=None):
    return JobRunner(
        max_concurrent_jobs=max_jobs,
        job_timeout_seconds=timeout,
        ttl_seconds=ttl,
        clock=clock or Clock(),
    )


def wait_for(predicate, limit=5.0):
    deadline = time.monotonic() + limit
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        time.sleep(0.002)


def wait_done(runner, job_id):
    wait_for(lambda: runner.snapshot(job_id).done)
    return runner.snapshot(job_id)


def wait_idle(runner):
    wait_for(lambda: runner._alive == 0)


def test_complete_job_and_snapshot_fields():
    clock = Clock()
    r = make(clock=clock)
    job_id = r.submit(lambda progress: {"answer": 42}, kind="threat_model")
    snap = wait_done(r, job_id)
    assert snap.status is JobStatus.COMPLETE
    assert snap.result == {"answer": 42}
    assert snap.error is None
    assert snap.kind == "threat_model"
    assert snap.created_at == snap.started_at == snap.finished_at == 1000.0


def test_seconds_since_end_uses_the_runner_clock():
    clock = Clock()
    r = make(clock=clock)
    gate = threading.Event()
    running = r.submit(lambda progress: gate.wait(5) and {}, kind="lookup")
    wait_for(lambda: r.snapshot(running).status is JobStatus.RUNNING)
    assert r.seconds_since_end(r.snapshot(running)) == 0.0
    gate.set()
    snap = wait_done(r, running)
    clock.now += 12.5
    assert r.seconds_since_end(snap) == 12.5


def test_ids_are_long_and_unique():
    r = make(max_jobs=50)
    ids = {r.submit(lambda p: {}, kind="k") for _ in range(20)}
    assert len(ids) == 20
    assert all(len(i) >= 43 for i in ids)
    assert not hasattr(r, "list") and not hasattr(r, "jobs")
    wait_idle(r)


def test_unknown_id():
    r = make()
    assert r.snapshot("nope") is None
    assert r.cancel("nope") is False
    r.discard("nope")


def test_progress_visible_while_running_and_deep_copied():
    r = make()
    step = threading.Event()
    release = threading.Event()
    record = {"stage": "stride", "items": [1]}

    def fn(progress):
        progress.set(record)
        record["items"].append(2)  # the job keeps changing its own dict
        step.set()
        release.wait(5)
        return {"done": True}

    job_id = r.submit(fn, kind="k")
    step.wait(5)
    snap = r.snapshot(job_id)
    assert snap.status is JobStatus.RUNNING
    assert snap.progress == {"stage": "stride", "items": [1]}
    snap.progress["items"].append(99)  # the page changes its copy
    assert r.snapshot(job_id).progress == {"stage": "stride", "items": [1]}
    release.set()
    done = wait_done(r, job_id)
    done.result["done"] = False
    assert r.snapshot(job_id).result == {"done": True}


def test_progress_must_be_dict():
    r = make()
    job_id = r.submit(lambda p: p.set(["not", "a", "dict"]), kind="k")
    snap = wait_done(r, job_id)
    assert snap.status is JobStatus.FAILED
    assert snap.error == ERROR_GENERIC


def test_non_dict_result_fails():
    r = make()
    snap = wait_done(r, r.submit(lambda p: "text", kind="k"))
    assert snap.status is JobStatus.FAILED


def test_cap_counts_running_threads():
    r = make(max_jobs=2)
    release = threading.Event()
    ids = [r.submit(lambda p: (release.wait(5), {})[1], kind="k") for _ in range(2)]
    with pytest.raises(JobError) as info:
        r.submit(lambda p: {}, kind="k")
    assert str(info.value) == ERROR_CAP
    # A cancelled job whose thread is still running still counts.
    r.cancel(ids[0])
    with pytest.raises(JobError):
        r.submit(lambda p: {}, kind="k")
    release.set()
    wait_idle(r)
    wait_done(r, r.submit(lambda p: {}, kind="k"))


def test_thread_start_failure_releases_slot(monkeypatch):
    r = make(max_jobs=1)

    def refuse(self):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", refuse)
    with pytest.raises(JobError):
        r.submit(lambda p: {}, kind="k")
    assert r._alive == 0 and r._jobs == {}


def test_timeout_marks_failed_and_signals_cancel():
    clock = Clock()
    r = make(timeout=1800, clock=clock)
    started = threading.Event()
    release = threading.Event()
    seen_cancel = []

    def fn(progress):
        started.set()
        release.wait(5)
        seen_cancel.append(progress.cancelled())
        progress.set({"late": True})
        return {"late": True}

    job_id = r.submit(fn, kind="k")
    started.wait(5)
    clock.now += 1799
    assert r.snapshot(job_id).status is JobStatus.RUNNING
    clock.now += 1
    snap = r.snapshot(job_id)
    assert snap.status is JobStatus.FAILED
    assert snap.error == "The task took longer than 30 minutes and was stopped."
    assert snap.finished_at == clock.now
    release.set()
    wait_idle(r)
    after = r.snapshot(job_id)
    assert seen_cancel == [True]
    assert after.status is JobStatus.FAILED  # the late finish does not overwrite it
    assert after.result is None and after.progress == {}


def test_timeout_sentence_singular():
    assert runner_mod._timeout_sentence(30) == (
        "The task took longer than 1 minute and was stopped."
    )


def test_finished_jobs_evicted_after_ttl():
    clock = Clock()
    r = make(ttl=900, clock=clock)
    job_id = r.submit(lambda p: {}, kind="k")
    wait_done(r, job_id)
    clock.now += 899
    assert r.snapshot(job_id) is not None
    clock.now += 1
    assert r.snapshot(job_id) is None


def test_discard_forgets_and_cancels():
    r = make()
    started = threading.Event()
    flags = []

    def fn(progress):
        started.set()
        wait_for(progress.cancelled)
        flags.append(True)
        return {}

    job_id = r.submit(fn, kind="k")
    started.wait(5)
    r.discard(job_id)
    assert r.snapshot(job_id) is None
    wait_idle(r)
    assert flags == [True]


def test_cancel_running_job():
    r = make()
    started = threading.Event()

    def fn(progress):
        started.set()
        wait_for(progress.cancelled)
        return {"ignored": True}

    job_id = r.submit(fn, kind="k")
    started.wait(5)
    assert r.cancel(job_id) is True
    assert r.snapshot(job_id).status is JobStatus.CANCELLED
    wait_idle(r)
    snap = r.snapshot(job_id)
    assert snap.status is JobStatus.CANCELLED and snap.result is None
    assert r.cancel(job_id) is False


def test_cancel_before_start(monkeypatch):
    r = make()
    held = []
    monkeypatch.setattr(threading.Thread, "start", lambda self: held.append(self))
    ran = []
    job_id = r.submit(lambda p: ran.append(1) or {}, kind="k")
    assert r.snapshot(job_id).status is JobStatus.QUEUED
    assert r.cancel(job_id)
    held[0].run()
    assert ran == []
    assert r.snapshot(job_id).status is JobStatus.CANCELLED
    assert r._alive == 0


def test_cooperative_cancel_flag_set_after_job_marks_cancelled():
    r = make()
    started = threading.Event()
    go = threading.Event()

    def fn(progress):
        started.set()
        go.wait(5)
        return {}

    job_id = r.submit(fn, kind="k")
    started.wait(5)
    with r._lock:
        r._jobs[job_id].cancel_event.set()
    go.set()
    assert wait_done(r, job_id).status is JobStatus.CANCELLED


def test_the_jobs_own_secrets_are_redacted_from_its_log_line(caplog):
    r = make()
    nvd_key = "0b5c3a3e-" + "7c1d-4f7e-9a51-2f6c9d8e1a77"

    def fn(progress):
        raise RuntimeError(f"lookup refused key {nvd_key} for nginx")

    with caplog.at_level(logging.WARNING, logger="aegisshield.jobs.runner"):
        wait_done(r, r.submit(fn, kind="lookup", secrets=(nvd_key, "")))
        wait_idle(r)
    assert nvd_key not in caplog.text
    assert "lookup refused key [redacted] for nginx" in caplog.text


def test_a_job_drops_its_secrets_once_it_starts():
    r = make()
    gate = threading.Event()
    job_id = r.submit(lambda progress: gate.wait(5) and {}, kind="lookup", secrets=("s3cret-value",))
    wait_for(lambda: r.snapshot(job_id).status is JobStatus.RUNNING)
    assert r._jobs[job_id].secrets == ()
    gate.set()
    wait_done(r, job_id)


def test_exception_gives_plain_sentence_and_redacted_log(caplog):
    r = make()

    def fn(progress):
        raise RuntimeError(f"provider said: Incorrect API key provided: {KEY}")

    with caplog.at_level(logging.WARNING, logger="aegisshield.jobs.runner"):
        snap = wait_done(r, r.submit(fn, kind="k"))
        wait_idle(r)
    assert snap.status is JobStatus.FAILED
    assert snap.error == ERROR_GENERIC
    assert KEY not in caplog.text
    assert "RuntimeError" in caplog.text and "[redacted]" in caplog.text


@pytest.mark.parametrize(
    ("exc", "sentence"),
    [
        (LLMResponseError("x"), ERROR_UNREADABLE),
        (LLMError("x"), ERROR_UPSTREAM),
        (IntelLookupError("x"), ERROR_LOOKUP),
        (ValidationError("x"), ERROR_INPUT),
        (ValueError("x"), ERROR_GENERIC),
    ],
)
def test_plain_error(exc, sentence):
    assert plain_error(exc) == sentence


def test_plain_error_looks_at_cause():
    import json

    try:
        try:
            json.loads("{")
        except json.JSONDecodeError as inner:
            raise LLMError("wrapped") from inner
    except LLMError as outer:
        assert plain_error(outer) == ERROR_UNREADABLE


def test_closure_released_after_success_and_failure():
    class Secret:
        pass

    for should_fail in (False, True):
        r = make()
        secret = Secret()
        ref = weakref.ref(secret)

        def fn(progress, held=secret, fail=should_fail):
            if fail:
                raise RuntimeError("bad")
            return {"ok": bool(held)}

        job_id = r.submit(fn, kind="k")
        del fn, secret
        wait_done(r, job_id)
        wait_idle(r)
        gc.collect()
        assert ref() is None, f"closure kept alive (fail={should_fail})"
        assert r.snapshot(job_id) is not None


def test_from_settings_and_get_runner(monkeypatch):
    r = JobRunner.from_settings(Settings(max_concurrent_jobs=3, job_timeout_seconds=10))
    assert r._max == 3 and r._timeout == 10
    monkeypatch.setattr(runner_mod, "_runner", None)
    first = runner_mod.get_runner()
    assert runner_mod.get_runner() is first


def test_rejects_bad_cap():
    with pytest.raises(ValueError):
        JobRunner(max_concurrent_jobs=0, job_timeout_seconds=1)


# The SystemExit is raised again on the job thread, as it should be.
@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_base_exception_marks_failed_not_complete():
    r = make()

    def fn(progress):
        raise SystemExit("stop")

    snap = wait_done(r, r.submit(fn, kind="exit"))
    assert snap.status is JobStatus.FAILED
    assert snap.error == ERROR_GENERIC and snap.result is None
    # Let the thread finish raising inside this test so the warning stays here.
    wait_for(lambda: not any(t.name == "aegis-job-exit" for t in threading.enumerate()))


def test_kind_limit_leaves_slots_for_other_kinds():
    clock = Clock()
    r = JobRunner(max_concurrent_jobs=4, job_timeout_seconds=60, clock=clock,
                  kind_limits=(("lookup", 2), ("pcap", 1)))
    release = threading.Event()

    def hold(progress):
        release.wait(5)
        return {}

    first = r.submit(hold, kind="lookup")
    r.submit(hold, kind="lookup")
    with pytest.raises(JobError) as info:
        r.submit(hold, kind="lookup")
    assert str(info.value) == ERROR_CAP
    # Other kinds still get the slots that are left.
    r.submit(hold, kind="pcap")
    with pytest.raises(JobError):
        r.submit(hold, kind="pcap")
    r.submit(hold, kind="unlisted")
    assert r._alive == 4 and r._alive_by_kind == {"lookup": 2, "pcap": 1, "unlisted": 1}
    # A timed-out lookup whose thread is still running keeps counting for its kind.
    clock.now += 61
    assert r.snapshot(first).status is JobStatus.FAILED
    with pytest.raises(JobError):
        r.submit(hold, kind="lookup")
    release.set()
    wait_idle(r)
    assert r._alive_by_kind == {}
    wait_done(r, r.submit(lambda p: {}, kind="lookup"))


def test_thread_start_failure_releases_the_kind_slot(monkeypatch):
    r = JobRunner(max_concurrent_jobs=4, job_timeout_seconds=60, kind_limits=(("pcap", 1),))

    def refuse(self):
        raise RuntimeError("can't start new thread")

    with monkeypatch.context() as m:
        m.setattr(threading.Thread, "start", refuse)
        with pytest.raises(JobError):
            r.submit(lambda p: {}, kind="pcap")
    assert r._alive_by_kind == {}
    wait_done(r, r.submit(lambda p: {}, kind="pcap"))


def test_rejects_bad_kind_limit():
    with pytest.raises(ValueError):
        JobRunner(max_concurrent_jobs=4, job_timeout_seconds=1, kind_limits=(("pcap", 0),))


def test_from_settings_carries_the_kind_limits():
    r = JobRunner.from_settings(Settings())
    assert r._kind_limits == {"pcap": 1, "lookup": 2, "policy": 2, "threat_model": 3, "ai_scan": 1}
    # No one kind may take every slot of the default total.
    assert max(r._kind_limits.values()) < r._max


class _ServiceError(runner_mod.AegisError):
    pass


SHOWN = frozenset({"Reading the capture took too long. Try a smaller capture."})


@pytest.mark.parametrize(
    ("exc", "sentence"),
    [
        (_ServiceError("Reading the capture took too long. Try a smaller capture."),
         "Reading the capture took too long. Try a smaller capture."),
        (_ServiceError("Reading the capture took too long. Try a smaller capture. /tmp/x"), ERROR_GENERIC),
        (ValidationError("Reading the capture took too long. Try a smaller capture! "), ERROR_INPUT),
        (RuntimeError("Reading the capture took too long. Try a smaller capture."), ERROR_GENERIC),
    ],
)
def test_plain_error_shows_only_listed_sentences_from_aegis_errors(exc, sentence):
    assert plain_error(exc, SHOWN) == sentence
    assert plain_error(exc) in {ERROR_GENERIC, ERROR_INPUT}


def test_a_job_shows_its_listed_sentence():
    r = make()
    sentence = next(iter(SHOWN))

    def fail(_progress):
        raise _ServiceError(sentence)

    shown = wait_done(r, r.submit(fail, kind="k", shown_errors=SHOWN))
    hidden = wait_done(r, r.submit(fail, kind="k"))
    assert (shown.status, shown.error) == (JobStatus.FAILED, sentence)
    assert hidden.error == ERROR_GENERIC
