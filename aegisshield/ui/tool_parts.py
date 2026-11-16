"""Parts the tool pages share: the running-job panel, finish handling,
plain-text lines, and the delete confirmation.

The vulnerability lookup, policy, and PCAP pages each run one background job
of their own kind per session (``state.start_job``). While it runs, the page
shows a panel that polls the job once a second inside an ``st.fragment``, so
only the panel reruns. When the job ends, the panel asks for a full rerun and
the page takes the finished job with :func:`take_finished`, which forgets it
in the same run. A result is therefore saved exactly once, however many
reruns follow.

Re-attaching needs nothing extra: the job id lives in the session, so leaving
the page and coming back (or any rerun) finds the job still running and shows
the panel again.
"""

from __future__ import annotations

import html
import time
from collections.abc import Callable
from functools import lru_cache
from typing import Any

import streamlit as st

from aegisshield.config import Settings
from aegisshield.jobs import JobSnapshot, JobStatus, ProgressSink
from aegisshield.llm import LLMClient, get_llm
from aegisshield.ui import kit, routes, state
from aegisshield.ui.theme import ASSETS_DIR, Tone

__all__ = [
    "MOCK_STREAM_DELAY", "POLL_SECONDS", "StreamingProgress", "confirm_delete", "session_llm", "elapsed_words", "failure_notice", "follow_job", "line", "muted", "running_panel",
    "show_flash", "take_finished", "tools_css", "upload_too_large",
]

POLL_SECONDS = 1.0
# Mock mode streams its canned text this slowly, so the live view has
# something to show without a key. Tests set it to 0.
MOCK_STREAM_DELAY = 0.03
# The streamed text is pushed to the job record at most this often.
_PUSH_SECONDS = 0.2
_MAX_STREAM_CHARS = 200_000


def session_llm(settings: Settings) -> LLMClient:
    """The model client for this session: the mock in mock mode, else the
    chosen provider's client with the visitor's credential (``LLMError``
    with a fixed sentence when the credential or the model is missing).
    ``settings`` is ``state.get_settings()``, which carries the choice."""
    return get_llm(settings, state.credential(settings.provider),
                   mock_chunk_delay_seconds=MOCK_STREAM_DELAY)


class StreamingProgress:
    """A progress sink that keeps the last step record and the streamed text
    together, because the runner's ``set`` replaces the whole record.

    Pass it as a service's ``progress`` and its ``on_text`` as ``on_text``.
    Every record carries ``base`` (for example the policy key and title).
    """

    def __init__(self, sink: ProgressSink, base: dict[str, Any] | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._sink = sink
        self._record: dict[str, Any] = dict(base or {})
        self._text = ""
        self._clock = clock
        self._pushed = 0.0
        self._push()

    def _push(self) -> None:
        self._pushed = self._clock()
        self._sink.set({**self._record, "text": self._text})

    def set(self, record: dict[str, Any]) -> None:
        """Merge a step record (``step``, ``total``, ``current``) and publish it."""
        self._record.update(record)
        self._push()

    def cancelled(self) -> bool:
        """True once the job was cancelled."""
        return self._sink.cancelled()

    def on_text(self, chunk: str) -> None:
        """Add streamed model text; published at most every 0.2 seconds."""
        if len(self._text) < _MAX_STREAM_CHARS:
            self._text = (self._text + chunk)[:_MAX_STREAM_CHARS]
        if self._clock() - self._pushed >= _PUSH_SECONDS:
            self._push()

    def retract(self) -> None:
        """Drop the streamed text now: its answer was withheld or its call failed."""
        self._text = ""
        self._push()

    def flush(self) -> None:
        """Publish whatever text arrived since the last push."""
        self._push()


@lru_cache(maxsize=1)
def _tools_stylesheet() -> str:
    return (ASSETS_DIR / "tools.css").read_text(encoding="utf-8")


def tools_css() -> None:
    """Add the tool pages' small stylesheet (``assets/tools.css``) to this run."""
    st.html(f"<style>{_tools_stylesheet()}</style>")


def show_flash() -> None:
    """Show the one-time message left by the previous run, if any."""
    message = state.consume_flash()
    if message is None:
        return
    text, tone = message
    try:
        kit.notice(text, tone=Tone(tone))
    except ValueError:
        kit.notice(text, tone=Tone.INFO)


def upload_too_large(upload: Any, max_bytes: int) -> bool:
    """True when an uploaded file is larger than ``max_bytes``.

    Reads the size Streamlit recorded (``upload.size``) so an oversized file
    is refused before ``getvalue()`` copies it into memory. The uploader's
    ``max_upload_size`` is only enforced by the browser, and the server's
    ``maxUploadSize`` is the largest limit of any page, not this one.
    """
    size = getattr(upload, "size", None)
    return isinstance(size, int) and size > max_bytes


def muted(text: str) -> None:
    """One small, muted line of plain text (escaped; never markdown)."""
    st.html(f'<p class="tx-muted">{html.escape(text)}</p>')


def line(text: str) -> None:
    """One line of plain body text (escaped; never markdown)."""
    st.html(f'<p class="tx-line">{html.escape(text)}</p>')


def elapsed_words(snap: JobSnapshot, now: float | None = None) -> str:
    """How long the job has run, as "12 s" or "3 min 4 s"."""
    began = snap.started_at if snap.started_at is not None else snap.created_at
    seconds = max(0, int((now if now is not None else time.time()) - began))
    minutes, rest = divmod(seconds, 60)
    return f"{minutes} min {rest} s" if minutes else f"{rest} s"


def follow_job(kind: str) -> None:
    """Keep this session's job of ``kind`` in the URL (``?run=<job id>``).

    Call at the top of the page, before :func:`take_finished`. After a
    browser reload (a new session) the job named in the URL is adopted
    again, so its progress shows and its result is saved in the new
    session. Once no job is running the parameter is removed.
    """
    if state.active_job_id(kind) is None:
        requested = state.requested_run_id()
        if requested and not state.adopt_job(kind, requested):
            state.set_run_param(None)
    job_id = state.active_job_id(kind)
    snap = state.job_snapshot(kind)
    state.set_run_param(job_id if snap is not None and not snap.done else None)


def take_finished(kind: str) -> JobSnapshot | None:
    """This session's job of ``kind`` if it has ended.

    Returns None while it still runs or when there is none. A completed or
    cancelled job is forgotten as it is taken, so the caller saves it once
    and a later run cannot see it again. A failed job stays until the
    visitor dismisses it (:func:`failure_notice`) or starts another job, so
    its message does not vanish on the next rerun.
    """
    snap = state.job_snapshot(kind)
    if snap is None or not snap.done:
        return None
    if snap.status is not JobStatus.FAILED:
        state.forget_job(kind)
    return snap


def failure_notice(kind: str, text: str, *, key: str) -> None:
    """Show a failed job's message with a Dismiss button that forgets the job."""
    kit.notice(text, tone=Tone.CRIT)
    if st.button("Dismiss", key=f"{key}_dismiss", type="tertiary"):
        state.forget_job(kind)
        st.rerun()


def running_panel(
    kind: str,
    *,
    key: str,
    render_progress: Callable[[JobSnapshot], None],
    cancel_label: str,
    cancelled_message: str,
) -> None:
    """Show the job's live progress, polled every second, with a cancel button.

    ``render_progress`` draws the progress from a snapshot. When the job ends
    the whole page reruns, so the page can save or report the result.
    Cancelling forgets the job, so nothing from it is saved, and leaves
    ``cancelled_message`` for the next run.
    """

    @st.fragment(run_every=POLL_SECONDS)
    def poll() -> None:
        snap = state.job_snapshot(kind)
        if snap is None or snap.done:
            st.rerun()
        render_progress(snap)
        if st.button(cancel_label, key=f"{key}_cancel_danger", icon=":material/close:"):
            state.forget_job(kind)
            state.flash(cancelled_message, "info")
            st.rerun()

    poll()


@st.dialog("Delete this item?")
def confirm_delete(what: str, on_confirm: Callable[[], None], *, key: str,
                   page_name: routes.PageName) -> None:
    """Ask before deleting. ``what`` names the item in plain words.

    The delete runs in ``on_click`` (a click inside a dialog only counts in
    its callback when the dialog body does not run again). Afterwards the
    page opens without a record in its URL.
    """
    line(f"{what} will be removed from this session's workspace. This cannot be undone.")
    cancel, confirm = st.columns(2)
    if cancel.button("Cancel", key=f"{key}_cancel", width="stretch"):
        st.rerun()
    if confirm.button("Delete", key=f"{key}_confirm_danger", type="primary", width="stretch",
                      on_click=on_confirm):
        st.switch_page(routes.page(page_name))
