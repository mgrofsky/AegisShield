"""Guards for every test: nothing leaves this machine.

Tests never touch the outside network. This turns that rule into a check:
a connection or a name lookup for anything but the loopback interface
fails at once, so a test that would reach a real provider fails instead of
sending a request. Unix sockets and 127.0.0.1 (the scan shim, local
servers) still work.
"""

from __future__ import annotations

import socket

import pytest

_LOCAL = frozenset({"127.0.0.1", "::1", "localhost", "0.0.0.0", ""})
_REAL_CONNECT = socket.socket.connect
_REAL_CONNECT_EX = socket.socket.connect_ex
_REAL_GETADDRINFO = socket.getaddrinfo


class OutsideNetworkBlocked(OSError):
    """A test tried to reach an address outside this machine."""


def _outside(address: object) -> bool:
    if not isinstance(address, tuple) or not address:
        return False  # a Unix socket path
    host = address[0]
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    return str(host) not in _LOCAL


def _connect(self: socket.socket, address: object) -> None:
    if _outside(address):
        raise OutsideNetworkBlocked("tests may not reach the outside network")
    return _REAL_CONNECT(self, address)


def _connect_ex(self: socket.socket, address: object) -> int:
    if _outside(address):
        raise OutsideNetworkBlocked("tests may not reach the outside network")
    return _REAL_CONNECT_EX(self, address)


def _getaddrinfo(host: object, *args: object, **kwargs: object) -> object:
    name = host.decode("ascii", "replace") if isinstance(host, bytes) else host
    if name is not None and str(name) not in _LOCAL:
        raise OutsideNetworkBlocked("tests may not look up outside names")
    return _REAL_GETADDRINFO(host, *args, **kwargs)


@pytest.fixture(autouse=True)
def no_outside_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Block connections and name lookups outside loopback for each test."""
    monkeypatch.setattr(socket.socket, "connect", _connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo)
