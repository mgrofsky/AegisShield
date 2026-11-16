"""In-process background jobs with progress the page can poll.

A Streamlit app is one process shared by every visitor, so a job is a thread
rather than a queue entry for a worker process, and isolation between visitors
is built into the runner:

- Job ids are unguessable (``secrets.token_urlsafe(32)``) and there is no way
  to list jobs. A page sees only the jobs whose ids it holds.
- Finished jobs are dropped after a short time to live, or at once on
  ``discard``.
- The runner lets go of the job function as soon as the job ends, because its
  closure holds the visitor's API key.
- A failed job's ``error`` is a fixed sentence chosen by exception class; the
  real exception is logged with anything key-shaped redacted.
"""

from __future__ import annotations

import copy
import json
import logging
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from secrets import token_urlsafe
from typing import Any

from aegisshield.config import Settings, get_settings
from aegisshield.core.errors import (
    AegisError,
    IntelLookupError,
    JobError,
    LLMError,
    LLMResponseError,
    ValidationError,
)
from aegisshield.core.text import redact_keys

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 15 * 60

ERROR_UNREADABLE = "The AI returned an answer that could not be read. Try again."
ERROR_UPSTREAM = "The AI service did not answer. Try again in a minute."
ERROR_LOOKUP = "A threat intelligence lookup failed. Try again later."
ERROR_INPUT = "Some of the input could not be used. Check it and try again."
# These sentences are shown for every kind of job (threat models, lookups,
# policies, captures), so they name none of them.
ERROR_GENERIC = "The task could not be completed. Try again."
ERROR_CAP = "Too many tasks are running on this server right now. Wait a minute and try again."


class JobStatus(StrEnum):
    """Where a job is in its life. The last three are final."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


_FINAL = frozenset({JobStatus.COMPLETE, JobStatus.FAILED, JobStatus.CANCELLED})


@dataclass(frozen=True)
class JobSnapshot:
    """A copy of a job's state at one moment. Times are epoch seconds."""

    id: str
    kind: str
    status: JobStatus
    progress: dict[str, Any]
    result: dict[str, Any] | None
    error: str | None
    created_at: float
    started_at: float | None
    finished_at: float | None

    @property
    def done(self) -> bool:
        """True when the job has reached a final status."""
        return self.status in _FINAL


@dataclass(eq=False)
class _Job:
    id: str
    kind: str
    created_at: float
    fn: Callable[[ProgressSink], dict[str, Any]] | None
    status: JobStatus = JobStatus.QUEUED
    progress: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: str | None = None
    started_at: float | None = None
    finished_at: float | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)
    shown_errors: frozenset[str] = frozenset()
    # The visitor's credential values, held only until the job starts so a
    # failure's log line can have them removed (see ``_run``).
    secrets: tuple[str, ...] = ()


class ProgressSink:
    """What a job function uses to report progress and check for cancel."""

    def __init__(self, job: _Job, lock: threading.Lock) -> None:
        self._job = job
        self._lock = lock

    def set(self, record: dict[str, Any]) -> None:
        """Replace the job's progress record with a deep copy of ``record``.

        Ignored once the job has a final status (timed out or cancelled).
        """
        if not isinstance(record, dict):
            raise TypeError("progress record must be a dict")
        snapshot = copy.deepcopy(record)
        with self._lock:
            if self._job.status not in _FINAL:
                self._job.progress = snapshot

    def cancelled(self) -> bool:
        """True when the job was cancelled, discarded, or timed out; stop soon."""
        return self._job.cancel_event.is_set()


def plain_error(exc: BaseException, shown: frozenset[str] = frozenset()) -> str:
    """The fixed sentence shown to the visitor for an exception.

    ``shown`` holds sentences a service wrote as constants for visitors to
    read (``pcap_service.JOB_ERRORS``): an ``AegisError`` whose whole message
    is one of them is shown as it is. Every other message is replaced, since
    exception text can quote input, a path, or a provider's reply.
    """
    if isinstance(exc, AegisError) and str(exc) in shown:
        return str(exc)
    unreadable = (LLMResponseError, json.JSONDecodeError)
    if isinstance(exc, unreadable) or isinstance(exc.__cause__, unreadable):
        return ERROR_UNREADABLE
    if isinstance(exc, LLMError):
        return ERROR_UPSTREAM
    if isinstance(exc, IntelLookupError):
        return ERROR_LOOKUP
    if isinstance(exc, ValidationError):
        return ERROR_INPUT
    return ERROR_GENERIC


class JobRunner:
    """Runs job functions on threads, one per job, up to a concurrency cap.

    ``clock`` returns epoch seconds and is injectable so tests can move time.
    """

    def __init__(
        self,
        *,
        max_concurrent_jobs: int,
        job_timeout_seconds: float,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
        kind_limits: Iterable[tuple[str, int]] = (),
    ) -> None:
        if max_concurrent_jobs < 1:
            raise ValueError("max_concurrent_jobs must be at least 1")
        self._kind_limits = dict(kind_limits)
        if any(limit < 1 for limit in self._kind_limits.values()):
            raise ValueError("a job kind limit must be at least 1")
        self._max = max_concurrent_jobs
        self._timeout = job_timeout_seconds
        self._ttl = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._jobs: dict[str, _Job] = {}
        # Threads still running, including ones already timed out, cancelled,
        # or discarded: a thread cannot be killed, so it counts toward the cap
        # until it returns.
        self._alive = 0
        # The same count per job kind, for ``kind_limits``.
        self._alive_by_kind: dict[str, int] = {}

    @classmethod
    def from_settings(cls, settings: Settings) -> JobRunner:
        """A runner using the caps and timeout from ``settings``."""
        return cls(
            max_concurrent_jobs=settings.max_concurrent_jobs,
            job_timeout_seconds=settings.job_timeout_seconds,
            kind_limits=settings.job_kind_limits,
        )

    def submit(
        self,
        fn: Callable[[ProgressSink], dict[str, Any]],
        *,
        kind: str,
        shown_errors: frozenset[str] = frozenset(),
        secrets: Iterable[str] = (),
    ) -> str:
        """Start ``fn(progress)`` on a new thread and return the job id.

        ``fn`` returns the result dict. A failure is shown as its own message
        only when that message is in ``shown_errors`` (see ``plain_error``).
        ``secrets`` are the credential values the job was given; they are
        removed from a failure's log line whatever their shape.
        Raises ``JobError`` when the total cap is reached, or the cap for
        ``kind`` (``kind_limits``).
        """
        with self._lock:
            self._sweep_locked()
            if self._alive >= self._max:
                raise JobError(ERROR_CAP)
            limit = self._kind_limits.get(kind)
            if limit is not None and self._alive_by_kind.get(kind, 0) >= limit:
                raise JobError(ERROR_CAP)
            job = _Job(id=token_urlsafe(32), kind=kind, created_at=self._clock(), fn=fn,
                       shown_errors=frozenset(shown_errors),
                       secrets=tuple(s for s in secrets if s))
            self._jobs[job.id] = job
            self._count_locked(kind, 1)
        thread = threading.Thread(target=self._run, args=(job,), name=f"aegis-job-{kind}", daemon=True)
        try:
            thread.start()
        except RuntimeError:
            with self._lock:
                self._count_locked(kind, -1)
                self._jobs.pop(job.id, None)
            job.fn = None
            raise JobError(ERROR_CAP) from None
        return job.id

    def snapshot(self, job_id: str) -> JobSnapshot | None:
        """A deep copy of the job's state, or None if the id is unknown or evicted."""
        with self._lock:
            self._sweep_locked()
            job = self._jobs.get(job_id)
            if job is None:
                return None
            return JobSnapshot(
                id=job.id,
                kind=job.kind,
                status=job.status,
                progress=copy.deepcopy(job.progress),
                result=copy.deepcopy(job.result),
                error=job.error,
                created_at=job.created_at,
                started_at=job.started_at,
                finished_at=job.finished_at,
            )

    def seconds_since_end(self, snap: JobSnapshot) -> float:
        """How long ago ``snap``'s job ended by this runner's clock; 0 if it
        has not ended."""
        if snap.finished_at is None:
            return 0.0
        return max(0.0, self._clock() - snap.finished_at)

    def cancel(self, job_id: str) -> bool:
        """Ask the job to stop and mark it cancelled. True if it was still going."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status in _FINAL:
                return False
            job.cancel_event.set()
            self._finish_locked(job, JobStatus.CANCELLED)
            return True

    def discard(self, job_id: str) -> None:
        """Cancel the job if it is going and forget it at once."""
        with self._lock:
            job = self._jobs.pop(job_id, None)
        if job is not None:
            job.cancel_event.set()

    # Internals -------------------------------------------------------------

    def _run(self, job: _Job) -> None:
        fn = job.fn
        job.fn = None
        own_secrets = job.secrets
        job.secrets = ()
        with self._lock:
            if job.status is JobStatus.QUEUED:
                job.status = JobStatus.RUNNING
                job.started_at = self._clock()
            go = job.status is JobStatus.RUNNING and fn is not None
        result: dict[str, Any] | None = None
        error: str | None = None
        returned = False
        try:
            if go:
                result = fn(ProgressSink(job, self._lock))  # type: ignore[misc]
                if not isinstance(result, dict):
                    raise TypeError("job function must return a dict")
                returned = True
        # A job function can fail in any way. The visitor gets a fixed
        # sentence; the log gets the class and the redacted message.
        except Exception as exc:
            error = plain_error(exc, job.shown_errors)
            result = None
            logger.warning(
                "job failed kind=%s job=%s error=%s",
                job.kind,
                job.id[:8],
                redact_keys(f"{type(exc).__name__}: {exc}", *own_secrets),
            )
        finally:
            # Drop the closure and the key values before anything else.
            del fn, own_secrets
            with self._lock:
                self._count_locked(job.kind, -1)
                if job.status not in _FINAL:
                    if job.cancel_event.is_set():
                        self._finish_locked(job, JobStatus.CANCELLED)
                    elif returned:
                        job.result = result
                        self._finish_locked(job, JobStatus.COMPLETE)
                    else:
                        # An Exception sets ``error``; anything else that ended
                        # the function early (SystemExit, KeyboardInterrupt)
                        # still must not read as a finished task.
                        job.error = error or ERROR_GENERIC
                        self._finish_locked(job, JobStatus.FAILED)

    def _count_locked(self, kind: str, delta: int) -> None:
        """Change the live-thread counts, in total and for ``kind``."""
        self._alive += delta
        left = self._alive_by_kind.get(kind, 0) + delta
        if left:
            self._alive_by_kind[kind] = left
        else:
            self._alive_by_kind.pop(kind, None)

    def _finish_locked(self, job: _Job, status: JobStatus) -> None:
        job.status = status
        job.finished_at = self._clock()

    def _sweep_locked(self) -> None:
        now = self._clock()
        for job_id, job in list(self._jobs.items()):
            if job.status in _FINAL:
                if job.finished_at is not None and now - job.finished_at >= self._ttl:
                    del self._jobs[job_id]
                continue
            began = job.started_at if job.started_at is not None else job.created_at
            if now - began >= self._timeout:
                job.cancel_event.set()
                job.error = _timeout_sentence(self._timeout)
                self._finish_locked(job, JobStatus.FAILED)
                logger.warning("job timed out kind=%s job=%s", job.kind, job.id[:8])


def _timeout_sentence(seconds: float) -> str:
    minutes = max(1, round(seconds / 60))
    unit = "minute" if minutes == 1 else "minutes"
    return f"The task took longer than {minutes} {unit} and was stopped."


_runner: JobRunner | None = None
_runner_lock = threading.Lock()


def get_runner() -> JobRunner:
    """The process-wide runner, built from ``get_settings()`` on first use."""
    global _runner
    with _runner_lock:
        if _runner is None:
            _runner = JobRunner.from_settings(get_settings())
        return _runner
