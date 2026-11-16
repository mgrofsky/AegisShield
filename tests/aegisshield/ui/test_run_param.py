"""``?run=<job id>`` is a bearer link to a running job: every page that sets
it removes it as soon as the job's result has been taken, whether the job
finished, failed, or was cancelled, and a link to a job that ended more than
``ADOPT_AFTER_END_SECONDS`` ago is refused."""

from __future__ import annotations

import shutil

import pytest

from aegisshield.jobs import JobRunner
from aegisshield.ui import state
from aegisshield.ui.pages import pcap_analysis, policies, vulnerability_lookup
from tests.aegisshield.ui import pcap_fakes
from tests.aegisshield.ui.tool_helpers import Gate, fresh_runner, make_app, wait_for_jobs

__all__ = ["fresh_runner"]

PAGES = [
    (vulnerability_lookup.PAGE, vulnerability_lookup.JOB_KIND),
    (policies.PAGE, policies.JOB_KIND),
    (pcap_analysis.PAGE, pcap_analysis.JOB_KIND),
]


@pytest.fixture(autouse=True)
def tshark(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", pcap_fakes.install(tmp_path / "bin"))
    assert shutil.which("tshark")


def _run_param(at) -> str | None:
    value = at.query_params.get(state.RUN_PARAM)
    return value[0] if isinstance(value, list) else value


def _held_job(runner: JobRunner, kind: str, gate: Gate, outcome: str) -> str:
    def fn(progress):
        gate.wait()
        if outcome == "fail":
            raise RuntimeError("the job failed")
        return {}

    return runner.submit(fn, kind=kind)


@pytest.mark.parametrize(("page", "kind"), PAGES)
@pytest.mark.parametrize("outcome", ["fail", "cancel"])
def test_the_run_link_is_removed_when_the_job_ends(fresh_runner, page, kind, outcome) -> None:
    gate = Gate()
    job_id = _held_job(fresh_runner, kind, gate, outcome)
    assert gate.started.wait(5)
    at = make_app(page, aegis_jobs={kind: job_id}).run()
    assert not at.exception
    assert _run_param(at) == job_id
    if outcome == "cancel":
        fresh_runner.cancel(job_id)
    gate.release.set()
    wait_for_jobs(fresh_runner)
    at.run()
    assert not at.exception
    assert state.RUN_PARAM not in at.query_params


@pytest.mark.parametrize(("page", "kind"), PAGES)
def test_a_reloaded_run_link_is_removed_when_the_adopted_job_fails(fresh_runner, page, kind) -> None:
    gate = Gate()
    job_id = _held_job(fresh_runner, kind, gate, "fail")
    assert gate.started.wait(5)
    reloaded = make_app(page)
    reloaded.query_params[state.RUN_PARAM] = job_id
    reloaded.run()
    assert _run_param(reloaded) == job_id
    gate.release.set()
    wait_for_jobs(fresh_runner)
    reloaded.run()
    assert state.RUN_PARAM not in reloaded.query_params


@pytest.mark.parametrize(("page", "kind"), PAGES)
def test_an_evicted_job_in_the_link_is_dropped(fresh_runner, page, kind) -> None:
    job_id = fresh_runner.submit(lambda p: {}, kind=kind)
    wait_for_jobs(fresh_runner)
    fresh_runner.discard(job_id)
    at = make_app(page)
    at.query_params[state.RUN_PARAM] = job_id
    at.run()
    assert state.RUN_PARAM not in at.query_params


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clocked_runner(monkeypatch: pytest.MonkeyPatch) -> tuple[JobRunner, _Clock]:
    from aegisshield.jobs import runner as runner_module

    clock = _Clock()
    runner = JobRunner(max_concurrent_jobs=4, job_timeout_seconds=60, clock=clock)
    monkeypatch.setattr(runner_module, "_runner", runner)
    return runner, clock


@pytest.mark.parametrize(("page", "kind"), PAGES)
def test_a_link_to_a_job_that_ended_a_while_ago_is_refused(clocked_runner, page, kind) -> None:
    runner, clock = clocked_runner
    job_id = runner.submit(lambda p: {"answer": 1}, kind=kind)
    wait_for_jobs(runner)
    clock.now += state.ADOPT_AFTER_END_SECONDS + 1
    at = make_app(page)
    at.query_params[state.RUN_PARAM] = job_id
    at.run()
    assert not at.exception
    assert state.RUN_PARAM not in at.query_params
    # the job is still in the runner: the page did not adopt and take it
    assert runner.snapshot(job_id) is not None


def test_adopt_job_takes_a_running_job_and_a_job_that_just_ended(clocked_runner) -> None:
    runner, clock = clocked_runner
    gate = Gate()
    running = _held_job(runner, "lookup", gate, "ok")
    assert gate.started.wait(5)
    ended = runner.submit(lambda p: {}, kind="policy")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(state.st, "session_state", {})
        assert state.adopt_job("lookup", running) is True
        gate.release.set()
        wait_for_jobs(runner)
        # a reload that lands just after the end still saves the result
        clock.now += state.ADOPT_AFTER_END_SECONDS - 1
        assert state.adopt_job("policy", ended) is True
        clock.now += 2
        assert state.adopt_job("policy", ended) is False
        # a wrong kind or an unknown id is refused as before
        assert state.adopt_job("lookup", ended) is False
        assert state.adopt_job("policy", "x" * 20) is False
