"""The loopback HTTP endpoint garak talks to during one scan.

garak's REST generator posts each prompt here; the shim calls the scan's
surface (one of the app's own workflow steps) and returns its answer. Only
this process calls the model, so the visitor's key never leaves it.

For each scan the shim:

- binds 127.0.0.1 on a port the system picks, and nothing else;
- makes a random bearer token and compares it in constant time;
- accepts one route (``POST /generate``) with a JSON object ``{"prompt": ...}``
  of bounded size, and returns ``{"text": ...}`` of bounded size;
- answers ``LIMIT_STATUS`` to every request past the request limit, without
  calling the surface, and counts it; the garak configuration lists that
  status as one to skip, so garak records no answer and moves on;
- serves at most ``MAX_CONNECTIONS`` connections at once (garak sends one
  request at a time) and closes any connection over that at once, so no
  local process can make it hold more threads;
- gives each connection one deadline, ``READ_DEADLINE_SECONDS``, for
  reading its whole request (request line, headers, and body), so a client
  that sends a byte now and then is dropped all the same;
- runs one surface call at a time, in a worker thread; the wait for an
  earlier call and the call itself share one deadline, the request timeout;
  a call that raises or runs too long returns a fixed short answer that
  says the step was refused or failed, and is counted; the fixed answers
  carry a random mark made for this scan (``FixedAnswers``), so a model
  answer cannot pass for one;
- shuts down when the scan ends, however it ends (``close`` is idempotent and
  the shim is a context manager): it stops accepting, closes every
  connection still open, and waits for their threads. A surface call
  already in flight is not stopped (a thread cannot be killed); it ends when
  the model call returns, bounded by the model client's own timeout.
"""

from __future__ import annotations

import hmac
import io
import json
import logging
import secrets
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from aegisshield.core.text import redact_keys

logger = logging.getLogger(__name__)

Surface = Callable[[str], str]

ROUTE = "/generate"
LOOPBACK = "127.0.0.1"
LIMIT_STATUS = 429
MAX_PROMPT_CHARS = 20_000
MAX_ANSWER_CHARS = 20_000
# A JSON-escaped character is at most 6 bytes (\\uXXXX), plus the wrapper.
MAX_BODY_BYTES = MAX_PROMPT_CHARS * 6 + 1024
# Seconds a client has to send its whole request (request line, headers, and
# body) before the connection is dropped; also the limit on each write.
READ_DEADLINE_SECONDS = 15
# Connections served at once. garak sends one request at a time
# (``parallel_attempts: 1``); the second slot covers a new request arriving
# while the last one's connection is still closing.
MAX_CONNECTIONS = 2
# Seconds ``close`` waits for each connection's thread.
CLOSE_JOIN_SECONDS = 5
# How often a wait for the model checks whether the shim is closing.
_WAIT_STEP_SECONDS = 0.1


@dataclass(frozen=True)
class FixedAnswers:
    """The shim's fixed answers for one scan, each with a random mark.

    A model answer can say anything, including a fixed answer's words; it
    cannot hold this scan's mark, which the model never sees. The report
    reader counts a refusal or a failure only for an exact match.
    """

    mark: str
    refused: str
    failed: str
    timeout: str

    @classmethod
    def for_scan(cls) -> FixedAnswers:
        """Fixed answers with a new random mark."""
        mark = secrets.token_hex(8)
        return cls(
            mark=mark,
            refused=f"[AegisShield scan {mark}: the workflow step refused this input and gave no answer.]",
            failed=f"[AegisShield scan {mark}: the workflow step failed and gave no answer.]",
            timeout=f"[AegisShield scan {mark}: the workflow step did not answer in time.]",
        )


class SurfaceRefused(Exception):  # noqa: N818 - it is a signal, not an error
    """Raised by a surface when the workflow step refused the input (for
    example, a safeguard blocked it). Counted as a refusal, not a failure."""


class Shim:
    """One scan's loopback endpoint. Use as a context manager."""

    def __init__(
        self,
        surface: Surface,
        *,
        max_requests: int,
        request_timeout: float,
        on_request: Callable[[int], None] | None = None,
        max_prompt_chars: int = MAX_PROMPT_CHARS,
        max_answer_chars: int = MAX_ANSWER_CHARS,
    ) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be at least 1")
        self._surface = surface
        self._max_requests = max_requests
        self._timeout = request_timeout
        self._on_request = on_request
        self._max_prompt = max_prompt_chars
        self._max_answer = max_answer_chars
        self.token = secrets.token_urlsafe(32)
        self.fixed = FixedAnswers.for_scan()
        self._closed = threading.Event()
        self._lock = threading.Lock()
        # One surface call at a time; a call that outlives its timeout keeps
        # this until it returns, so calls never pile up behind a slow model.
        self._busy = threading.Lock()
        self._counts = {
            "requests": 0,
            "answered": 0,
            "refusals": 0,
            "failures": 0,
            "timeouts": 0,
            "limit_hits": 0,
            "rejected": 0,
        }
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None

    # Lifecycle -------------------------------------------------------------

    def start(self) -> Shim:
        """Bind 127.0.0.1 on a free port and serve on a daemon thread."""
        if self._server is not None:
            raise RuntimeError("the shim is already started")
        server = _Server((LOOPBACK, 0), _handler_class(self), on_overflow=self.reject)
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1},
                                        name="aegis-aiscan-shim", daemon=True)
        self._thread.start()
        return self

    @property
    def port(self) -> int:
        """The port the shim is bound to."""
        if self._server is None:
            raise RuntimeError("the shim is not started")
        return int(self._server.server_address[1])

    def close(self) -> None:
        """Stop serving, close every open connection, and release the port.
        Safe to call more than once."""
        server, self._server = self._server, None
        if server is None:
            return
        self._closed.set()
        server.shutdown()
        server.server_close()
        server.close_connections()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> Shim:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.close()

    # State -----------------------------------------------------------------

    def counts(self) -> dict[str, int]:
        """A copy of the shim's counts."""
        with self._lock:
            return dict(self._counts)

    @property
    def limit_hit(self) -> bool:
        """True once a request arrived past the request limit."""
        with self._lock:
            return self._counts["limit_hits"] > 0

    def _count(self, name: str) -> int:
        with self._lock:
            self._counts[name] += 1
            return self._counts[name]

    # Requests --------------------------------------------------------------

    def admit(self) -> bool:
        """Count a request; False when it is past the request limit."""
        with self._lock:
            if self._counts["requests"] >= self._max_requests:
                self._counts["limit_hits"] += 1
                return False
            self._counts["requests"] += 1
            done = self._counts["requests"]
        if self._on_request is not None:
            self._on_request(done)
        return True

    def answer(self, prompt: str) -> str:
        """The surface's answer to ``prompt``, or a fixed answer when it could not give one.

        One deadline covers both waiting for an earlier call to let go of the
        model and this call itself, so an answer never takes longer than the
        request timeout (garak waits a margin longer).
        """
        deadline = time.monotonic() + self._timeout
        if not self._acquire_model(deadline):
            self._count("timeouts")
            return self.fixed.timeout
        box: dict[str, Any] = {}

        def call() -> None:
            try:
                box["answer"] = self._surface(prompt)
            except SurfaceRefused:
                box["refused"] = True
            # A workflow step can fail in any way (the model, a parser, a
            # rail); the scan records it as a failure and goes on.
            except Exception as exc:
                box["failed"] = True
                logger.warning("scan surface failed kind=%s detail=%s", type(exc).__name__,
                               redact_keys(str(exc), self.token)[:200])
            finally:
                self._busy.release()

        worker = threading.Thread(target=call, name="aegis-aiscan-surface", daemon=True)
        worker.start()
        while worker.is_alive() and not self._closed.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            worker.join(min(remaining, _WAIT_STEP_SECONDS))
        if worker.is_alive():
            self._count("timeouts")
            return self.fixed.timeout
        if box.get("refused"):
            self._count("refusals")
            return self.fixed.refused
        answer = box.get("answer")
        if box.get("failed") or not isinstance(answer, str):
            self._count("failures")
            return self.fixed.failed
        self._count("answered")
        return answer[: self._max_answer]

    def _acquire_model(self, deadline: float) -> bool:
        """Wait for the model until ``deadline``; False on timeout or when closing."""
        while not self._closed.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            if self._busy.acquire(timeout=min(remaining, _WAIT_STEP_SECONDS)):
                return True
        return False

    def token_ok(self, header: str | None) -> bool:
        """True when ``header`` is exactly ``Bearer <token>`` (constant time)."""
        expected = f"Bearer {self.token}".encode()
        return hmac.compare_digest((header or "").encode("utf-8", "replace"), expected)

    def read_prompt(self, body: bytes) -> str | None:
        """The prompt from a request body, or None when it is not acceptable."""
        try:
            data = json.loads(body.decode("utf-8"))
        # ValueError covers bad JSON, bad UTF-8, and an integer longer than
        # Python's digit limit.
        except (ValueError, RecursionError):
            return None
        prompt = data.get("prompt") if isinstance(data, dict) else None
        if not isinstance(prompt, str) or len(prompt) > self._max_prompt:
            return None
        return prompt

    def reject(self) -> None:
        """Count a request refused for its route, token, or body, or a
        connection closed because the shim was already serving its limit."""
        self._count("rejected")


class _DeadlineReader(io.RawIOBase):
    """Reads a socket with one deadline for everything read through it.

    The socket's own timeout applies to each read; this sets it to what is
    left before every read, so the whole request shares one deadline.
    """

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        super().__init__()
        self._sock = sock
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("the request was not read in time")
        self._sock.settimeout(remaining)
        return self._sock.recv_into(buffer)


class _Server(ThreadingHTTPServer):
    """A threading HTTP server that serves at most ``MAX_CONNECTIONS`` at
    once, closes any connection over that at once, and tracks the threads
    it starts so ``close_connections`` can end them."""

    daemon_threads = True
    block_on_close = False

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], *,
                 on_overflow: Callable[[], None]) -> None:
        super().__init__(address, handler)
        self._on_overflow = on_overflow
        self._live_lock = threading.Lock()
        self._live: dict[socket.socket, threading.Thread] = {}
        self._closing = False

    def process_request(self, request: Any, client_address: Any) -> None:
        with self._live_lock:
            admit = not self._closing and len(self._live) < MAX_CONNECTIONS
            if admit:
                thread = threading.Thread(target=self.process_request_thread, args=(request, client_address),
                                          name="aegis-aiscan-conn", daemon=True)
                self._live[request] = thread
                thread.start()
        if not admit:
            self._on_overflow()
            self.shutdown_request(request)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._live_lock:
                self._live.pop(request, None)

    def handle_error(self, request: Any, client_address: Any) -> None:
        """A client that resets or drops its connection is not an error worth a traceback."""
        logger.debug("scan shim connection error", exc_info=True)

    def close_connections(self) -> None:
        """Close every connection still open and wait for its thread."""
        with self._live_lock:
            self._closing = True
            live = dict(self._live)
        for sock in live:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # already closed by its own thread
        for thread in live.values():
            thread.join(CLOSE_JOIN_SECONDS)


def _handler_class(shim: Shim) -> type[BaseHTTPRequestHandler]:
    """A request handler bound to ``shim`` (a class per shim, so nothing is shared)."""

    class Handler(BaseHTTPRequestHandler):
        timeout = READ_DEADLINE_SECONDS
        server_version = "aegis-aiscan"
        sys_version = ""

        def setup(self) -> None:
            """Read the whole request under one deadline from now."""
            super().setup()
            self.rfile.close()  # the plain reader; an open one would keep the socket from closing
            self.rfile = io.BufferedReader(
                _DeadlineReader(self.connection, time.monotonic() + READ_DEADLINE_SECONDS))

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib name
            """Silence the default per-request log line (it quotes the path)."""

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            data = json.dumps(payload, ensure_ascii=True).encode("ascii")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802 - stdlib name
            shim.reject()
            self._send(405, {"error": "method not allowed"})

        def do_POST(self) -> None:  # noqa: N802 - stdlib name
            if self.path != ROUTE:
                shim.reject()
                self._send(404, {"error": "not found"})
                return
            if not shim.token_ok(self.headers.get("Authorization")):
                shim.reject()
                self._send(401, {"error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                length = -1
            if not 0 < length <= MAX_BODY_BYTES:
                shim.reject()
                self._send(413, {"error": "body missing or too large"})
                return
            body = self.rfile.read(length)
            # The request is read; writes get their own timeout again.
            self.connection.settimeout(READ_DEADLINE_SECONDS)
            prompt = shim.read_prompt(body)
            if prompt is None:
                shim.reject()
                self._send(400, {"error": "expected a JSON object with a prompt"})
                return
            if not shim.admit():
                self._send(LIMIT_STATUS, {"error": "request limit reached"})
                return
            self._send(200, {"text": shim.answer(prompt)})

    return Handler
