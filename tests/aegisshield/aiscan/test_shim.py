"""The loopback shim: token, route, size bounds, request limit, refusals,
failures, timeouts, and shutdown."""

from __future__ import annotations

import http.client
import json
import socket
import threading
import time

import pytest

from aegisshield.aiscan import shim as shim_mod
from aegisshield.aiscan.shim import LIMIT_STATUS, Shim, SurfaceRefused
from aegisshield.core.errors import LLMError


def _post(shim: Shim, body: object, *, token: str | None = None, path: str = "/generate",
          raw: bytes | None = None, headers: dict | None = None) -> tuple[int, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", shim.port, timeout=10)
    data = raw if raw is not None else json.dumps(body).encode()
    sent = {"Content-Type": "application/json", "Content-Length": str(len(data))}
    if token is not None:
        sent["Authorization"] = f"Bearer {token}"
    sent.update(headers or {})
    conn.request("POST", path, body=data, headers=sent)
    resp = conn.getresponse()
    payload = json.loads(resp.read() or b"{}")
    conn.close()
    return resp.status, payload


def test_binds_loopback_only_and_answers_through_the_surface():
    seen = []
    with Shim(lambda p: seen.append(p) or f"echo:{p}", max_requests=5, request_timeout=5) as shim:
        assert shim._server.server_address[0] == "127.0.0.1"
        status, body = _post(shim, {"prompt": "hello"}, token=shim.token)
        assert (status, body) == (200, {"text": "echo:hello"})
        assert seen == ["hello"]
        assert shim.counts()["answered"] == 1


def test_token_is_random_per_shim_and_required():
    a = Shim(lambda p: p, max_requests=5, request_timeout=5)
    b = Shim(lambda p: p, max_requests=5, request_timeout=5)
    assert a.token != b.token and len(a.token) >= 40
    with a:
        for token in (None, "wrong", b.token, a.token + "x"):
            assert _post(a, {"prompt": "x"}, token=token)[0] == 401
        assert _post(a, {"prompt": "x"}, headers={"Authorization": a.token})[0] == 401
        counts = a.counts()
        assert counts["rejected"] == 5 and counts["requests"] == 0


def test_only_one_route_and_method():
    with Shim(lambda p: p, max_requests=5, request_timeout=5) as shim:
        assert _post(shim, {"prompt": "x"}, token=shim.token, path="/other")[0] == 404
        conn = http.client.HTTPConnection("127.0.0.1", shim.port, timeout=5)
        conn.request("GET", "/generate")
        assert conn.getresponse().status == 405
        conn.close()


@pytest.mark.parametrize("raw", [b"not json", b"[1,2]", b'{"prompt": 5}', b'{"other": "x"}', b"\xff\xfe"])
def test_body_must_be_a_json_object_with_a_string_prompt(raw):
    with Shim(lambda p: p, max_requests=5, request_timeout=5) as shim:
        assert _post(shim, None, token=shim.token, raw=raw)[0] == 400


def test_prompt_and_body_size_are_bounded():
    with Shim(lambda p: p, max_requests=5, request_timeout=5, max_prompt_chars=10) as shim:
        assert _post(shim, {"prompt": "x" * 11}, token=shim.token)[0] == 400
        assert _post(shim, {"prompt": "x" * 10}, token=shim.token)[0] == 200
        big = b'{"prompt": "' + b"x" * (shim_mod.MAX_BODY_BYTES) + b'"}'
        assert _post(shim, None, token=shim.token, raw=big)[0] == 413
        assert _post(shim, None, token=shim.token, raw=b'{"prompt": "x"}',
                     headers={"Content-Length": "nope"})[0] == 413


def test_answer_size_is_bounded():
    with Shim(lambda p: "y" * 50, max_requests=5, request_timeout=5, max_answer_chars=7) as shim:
        assert _post(shim, {"prompt": "x"}, token=shim.token)[1]["text"] == "y" * 7


def test_request_limit_is_enforced_without_calling_the_surface():
    calls = []
    with Shim(lambda p: calls.append(p) or "ok", max_requests=2, request_timeout=5) as shim:
        assert [_post(shim, {"prompt": str(i)}, token=shim.token)[0] for i in range(4)] == [200, 200, LIMIT_STATUS,
                                                                                             LIMIT_STATUS]
        assert calls == ["0", "1"]
        assert shim.limit_hit
        assert shim.counts()["limit_hits"] == 2 and shim.counts()["requests"] == 2
    with pytest.raises(ValueError):
        Shim(lambda p: p, max_requests=0, request_timeout=1)


def test_on_request_sees_each_admitted_request():
    seen = []
    with Shim(lambda p: "ok", max_requests=3, request_timeout=5, on_request=seen.append) as shim:
        for _ in range(4):
            _post(shim, {"prompt": "x"}, token=shim.token)
    assert seen == [1, 2, 3]


def _raise(exc):
    def surface(_prompt):
        raise exc
    return surface


def test_a_refusal_is_a_fixed_answer_and_counted():
    with Shim(_raise(SurfaceRefused()), max_requests=5, request_timeout=5) as shim:
        assert _post(shim, {"prompt": "x"}, token=shim.token)[1]["text"] == shim.fixed.refused
        assert shim.counts()["refusals"] == 1


@pytest.mark.parametrize("exc", [LLMError("upstream sk-abcdefghijklmnop"), RuntimeError("boom"), KeyError("k")])
def test_a_surface_that_raises_is_a_fixed_failure_answer(exc, caplog):
    with Shim(_raise(exc), max_requests=5, request_timeout=5) as shim:
        assert _post(shim, {"prompt": "x"}, token=shim.token)[1]["text"] == shim.fixed.failed
        assert shim.counts()["failures"] == 1
    assert "sk-abcdefghijklmnop" not in caplog.text


def test_a_non_string_answer_is_a_failure():
    with Shim(lambda p: None, max_requests=5, request_timeout=5) as shim:  # type: ignore[arg-type,return-value]
        assert _post(shim, {"prompt": "x"}, token=shim.token)[1]["text"] == shim.fixed.failed


def test_a_slow_surface_times_out_and_blocks_the_next_call_until_it_returns():
    release = threading.Event()

    def slow(prompt):
        release.wait(5)
        return "late"

    with Shim(slow, max_requests=5, request_timeout=0.3) as shim:
        start = time.monotonic()
        assert _post(shim, {"prompt": "x"}, token=shim.token)[1]["text"] == shim.fixed.timeout
        # The first call still holds the model; the second waits its timeout and gives up.
        assert _post(shim, {"prompt": "y"}, token=shim.token)[1]["text"] == shim.fixed.timeout
        assert time.monotonic() - start < 3
        release.set()
        time.sleep(0.1)
        assert _post(shim, {"prompt": "z"}, token=shim.token)[1]["text"] == "late"
        assert shim.counts()["timeouts"] == 2


def test_close_releases_the_port_and_is_idempotent():
    shim = Shim(lambda p: p, max_requests=1, request_timeout=1).start()
    port = shim.port
    with pytest.raises(RuntimeError):
        shim.start()
    shim.close()
    shim.close()
    with pytest.raises(OSError), socket.create_connection(("127.0.0.1", port), timeout=1):
        pass
    with pytest.raises(RuntimeError):
        _ = shim.port


def test_the_shim_closes_when_the_scan_raises():
    with pytest.raises(ZeroDivisionError), Shim(lambda p: p, max_requests=1, request_timeout=1) as shim:
        port = shim.port
        raise ZeroDivisionError
    with pytest.raises(OSError), socket.create_connection(("127.0.0.1", port), timeout=1):
        pass


def test_waiting_for_the_model_and_the_call_share_one_deadline():
    def slow(prompt):
        time.sleep(0.5)
        return "late"

    with Shim(slow, max_requests=5, request_timeout=0.4) as shim:
        assert _post(shim, {"prompt": "a"}, token=shim.token)[1]["text"] == shim.fixed.timeout
        start = time.monotonic()
        # The first call lets go about 0.1 s into this wait; this call then
        # gets only what is left of its 0.4 s, not another 0.4 s.
        assert _post(shim, {"prompt": "b"}, token=shim.token)[1]["text"] == shim.fixed.timeout
        assert time.monotonic() - start < 0.7


def test_fixed_answers_carry_a_random_mark_made_for_each_scan():
    a = Shim(lambda p: p, max_requests=1, request_timeout=1)
    b = Shim(lambda p: p, max_requests=1, request_timeout=1)
    assert a.fixed.mark != b.fixed.mark and len(a.fixed.mark) == 16
    for answer in (a.fixed.refused, a.fixed.failed, a.fixed.timeout):
        assert a.fixed.mark in answer and answer.startswith("[AegisShield scan ")
    assert len({a.fixed.refused, a.fixed.failed, a.fixed.timeout}) == 3


def test_a_huge_integer_in_the_body_is_a_bad_request():
    with Shim(lambda p: p, max_requests=5, request_timeout=5) as shim:
        raw = b'{"prompt": "x", "n": ' + b"9" * 5000 + b"}"
        assert _post(shim, None, token=shim.token, raw=raw)[0] == 400
        assert _post(shim, {"prompt": "x"}, token=shim.token)[0] == 200


# -- Slow and silent local clients ---------------------------------------------------


# The cap the shim must hold to (named here so these tests also run, and
# fail on the thread counts, against a shim without the constant).
CAP = getattr(shim_mod, "MAX_CONNECTIONS", 2)


def _threads_back_to(baseline: int, within: float = 3.0) -> bool:
    """True once no more threads run than ``baseline`` (threads other tests
    left may end meanwhile, so fewer is fine)."""
    end = time.monotonic() + within
    while threading.active_count() > baseline and time.monotonic() < end:
        time.sleep(0.05)
    return threading.active_count() <= baseline


def _connection_threads() -> int:
    # Ours are named; the standard library's are named for their target.
    return sum(1 for t in threading.enumerate()
               if t.name == "aegis-aiscan-conn" or "process_request_thread" in t.name)


def _connect(shim: Shim) -> socket.socket:
    return socket.create_connection(("127.0.0.1", shim.port), timeout=5)


def _closed_by_server(sock: socket.socket, within: float) -> bool:
    """True when the server closes ``sock`` (EOF or reset) within ``within`` seconds."""
    sock.settimeout(within)
    try:
        return sock.recv(1024) == b""
    except ConnectionResetError:
        return True
    except TimeoutError:
        return False


def test_slow_clients_cannot_hold_more_threads_than_the_cap(monkeypatch):
    monkeypatch.setattr(shim_mod, "READ_DEADLINE_SECONDS", 0.6, raising=False)
    baseline = threading.active_count()
    clients: list[socket.socket] = []
    with Shim(lambda p: p, max_requests=5, request_timeout=5) as shim:
        for _ in range(30):
            sock = _connect(shim)
            try:
                sock.sendall(b"POST /generate HTTP/1.1\r\n")
            except OSError:
                pass  # over the cap: already closed
            clients.append(sock)
        # Each client sends one header line now and then, each read well
        # inside a per-read timeout; the shim still holds at most the cap.
        end = time.monotonic() + 1.5
        while time.monotonic() < end:
            for sock in clients:
                try:
                    sock.sendall(b"X-Slow: 1\r\n")
                except OSError:
                    pass
            assert _connection_threads() <= CAP
            time.sleep(0.2)
        # The whole request had one deadline: every slow client is gone.
        end = time.monotonic() + 2
        while _connection_threads() and time.monotonic() < end:
            time.sleep(0.05)
        assert _connection_threads() == 0
        assert all(_closed_by_server(sock, 0.5) for sock in clients)
        # And the shim still answers a real request.
        assert _post(shim, {"prompt": "x"}, token=shim.token) == (200, {"text": "x"})
    for sock in clients:
        sock.close()
    assert _threads_back_to(baseline)


def test_a_connection_over_the_cap_is_closed_at_once_and_counted():
    with Shim(lambda p: p, max_requests=5, request_timeout=5) as shim:
        silent = [_connect(shim) for _ in range(CAP)]
        time.sleep(0.2)
        start = time.monotonic()
        extra = _connect(shim)
        assert _closed_by_server(extra, 2.0) and time.monotonic() - start < 1.0
        assert shim.counts()["rejected"] >= 1
        for sock in (*silent, extra):
            sock.close()


def test_silent_clients_are_dropped_at_the_deadline(monkeypatch):
    monkeypatch.setattr(shim_mod, "READ_DEADLINE_SECONDS", 0.4, raising=False)
    with Shim(lambda p: p, max_requests=5, request_timeout=5) as shim:
        silent = [_connect(shim) for _ in range(CAP)]
        assert all(_closed_by_server(sock, 2.0) for sock in silent)
        assert _post(shim, {"prompt": "x"}, token=shim.token)[0] == 200
        for sock in silent:
            sock.close()


def test_close_ends_every_connection_and_its_thread(monkeypatch):
    monkeypatch.setattr(shim_mod, "READ_DEADLINE_SECONDS", 60, raising=False)
    baseline = threading.active_count()
    shim = Shim(lambda p: p, max_requests=5, request_timeout=5).start()
    # One client part way through its body and one silent: both hold a slot.
    slow = _connect(shim)
    slow.sendall(b"POST /generate HTTP/1.1\r\nAuthorization: Bearer " + shim.token.encode()
                 + b"\r\nContent-Length: 100\r\n\r\n{")
    silent = _connect(shim)
    time.sleep(0.2)
    assert _connection_threads() == CAP
    start = time.monotonic()
    shim.close()
    assert time.monotonic() - start < 2.0
    assert _threads_back_to(baseline)
    assert not [t.name for t in threading.enumerate()
                if t.name in ("aegis-aiscan-conn", "aegis-aiscan-shim") or "process_request_thread" in t.name]
    for sock in (silent, slow):
        sock.close()


def test_close_does_not_wait_out_a_slow_model_call():
    release = threading.Event()
    answers: list[tuple[int, dict] | Exception] = []

    def slow(prompt):
        release.wait(10)
        return "late"

    baseline = threading.active_count()
    shim = Shim(slow, max_requests=5, request_timeout=30).start()

    def client() -> None:
        try:
            answers.append(_post(shim, {"prompt": "x"}, token=shim.token))
        except Exception as exc:  # noqa: BLE001 - the test only records what the client saw
            answers.append(exc)

    caller = threading.Thread(target=client)
    caller.start()
    time.sleep(0.3)
    start = time.monotonic()
    shim.close()
    assert time.monotonic() - start < 2.0
    caller.join(5)
    release.set()  # the model call itself ends on its own, as a real one does
    assert _threads_back_to(baseline)
    assert answers and (isinstance(answers[0], Exception) or answers[0][1]["text"] == shim.fixed.timeout)
