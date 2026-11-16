"""Shared helpers for the tool page tests (lookup, policies, PCAP)."""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Iterator

import pytest
from streamlit.testing.v1 import AppTest

from aegisshield.jobs import runner as runner_module
from aegisshield.jobs.runner import JobRunner


def page_app() -> None:
    """Run the page named in session state inside the real navigation, as
    the frame does, so page links and ``switch_page`` resolve."""
    import streamlit as st

    from aegisshield.ui import routes

    current = st.navigation(routes.build_navigation(with_tshark=True, with_ai_scan=True), position="hidden")
    wanted = st.session_state.get("tool_page")
    if wanted and current.url_path in ("", routes.spec(wanted).url_path, "dashboard"):
        import importlib

        importlib.import_module(f"aegisshield.ui.pages.{wanted}").render()
    else:
        current.run()


def make_app(page: str, **session) -> AppTest:
    at = AppTest.from_function(page_app, default_timeout=30)
    at.session_state["tool_page"] = page
    for key, value in session.items():
        at.session_state[key] = value
    return at


def html_of(at: AppTest) -> str:
    return "\n".join(h.proto.body for h in at.get("html"))


@pytest.fixture
def fresh_runner(monkeypatch: pytest.MonkeyPatch) -> Iterator[JobRunner]:
    """A runner of our own for each test, so jobs never leak between tests."""
    runner = JobRunner(max_concurrent_jobs=4, job_timeout_seconds=60)
    monkeypatch.setattr(runner_module, "_runner", runner)
    yield runner


def wait_for_jobs(runner: JobRunner, timeout: float = 10.0) -> None:
    """Wait until every job the runner holds has reached a final state."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        with runner._lock:
            jobs = list(runner._jobs.values())
            alive = runner._alive
        if all(j.status in ("complete", "failed", "cancelled") for j in jobs) and alive == 0:
            return
        time.sleep(0.02)
    raise AssertionError("jobs did not finish in time")


@contextlib.contextmanager
def jobs_held(runner: JobRunner) -> Iterator[None]:
    """Hold every job submitted inside the block until the block ends.

    A mock job can otherwise finish inside the run of the click that started
    it, on a slow machine or under coverage, and the page then saves it and
    clears its job id a run earlier than the test reads them.
    """
    release = threading.Event()
    real = runner.submit

    def submit(fn, *, kind, shown_errors=frozenset(), secrets=()):  # noqa: ANN001, ANN202 - the runner's own signature
        def held(progress):  # noqa: ANN001, ANN202
            assert release.wait(30), "the block that started the job never ended"
            return fn(progress)

        return real(held, kind=kind, shown_errors=shown_errors, secrets=secrets)

    runner.submit = submit  # type: ignore[method-assign]
    try:
        yield
    finally:
        del runner.submit
        release.set()


def click_and_finish(at: AppTest, key: str, runner: JobRunner) -> AppTest:
    """Click a button that starts a job, let the job finish, and run the page.

    The job is held until the click's own run has returned (see ``jobs_held``).
    """
    with jobs_held(runner):
        at.button(key=key).click().run()
    wait_for_jobs(runner)
    return at.run()


class Gate:
    """A latch a fake job waits on, so a test can hold a job in 'running'."""

    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()

    def wait(self) -> None:
        self.started.set()
        assert self.release.wait(10), "the test never released the job"


def openai_session(key: str = "sk-test-0123456789abcdef", models: tuple[str, ...] | None = None) -> dict:
    """Session entries for a visitor who gave an OpenAI key and whose
    model list was already fetched (the Settings page does that): the
    configured default model is listed, so it is preselected."""
    from aegisshield.config import DEFAULT_MODEL_NAME
    from aegisshield.llm.base import ModelInfo

    listed = tuple(ModelInfo(m) for m in (models or (DEFAULT_MODEL_NAME,)))
    return {"aegis_key_openai": key,
            "aegis_model_lists": {"openai": {"at": time.time(), "models": listed, "failed": False}}}
