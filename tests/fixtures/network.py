"""The test suite's network boundary.

Lives in ``fixtures`` rather than in a ``conftest`` so a test can import the
exception type and assert the boundary holds — a guard nothing checks is a guard
that quietly stops working.

Two enforcement points, because a request can leave the machine through either
--------------------------------------------------------------------------

**Name resolution.** ``socket.getaddrinfo`` and friends. This is the one the
suite was missing, and its absence was not theoretical: an unmocked async
request spent its entire timeout budget inside a 20-second DNS lookup for
``threatfox-api.abuse.ch`` and died with ``ConnectTimeout`` before ``connect``
was ever reached. The test asserting the boundary therefore failed with a
timeout rather than a refusal — and, worse, every unit run was telling a resolver
which threat-intelligence APIs a developer was working on.

**Connection.** ``socket.socket.connect`` / ``connect_ex``. Blocking resolution
alone is not enough: a literal address needs no DNS.

Blocking resolution is what makes the refusal *immediate*. Blocking connection is
what makes it *complete*. Neither substitutes for the other.

Why not ``pytest-socket`` alone
-------------------------------

``pytest-socket`` is a dependency and does the connection half — see
``pyproject.toml``'s ``addopts``, which runs every test under
``--disable-socket --allow-hosts=127.0.0.1,::1``. It closes the socket before
raising, which avoids a descriptor leak this module would otherwise have to
handle itself.

It cannot do the resolution half here. Its ``disable_socket()`` mode *does* block
``getaddrinfo``, but it works by refusing socket **creation** outright, which
would also break the loopback that asyncio, coverage and this suite's own
listener test legitimately need. The ``--allow-hosts`` mode that preserves
loopback patches ``connect`` and leaves DNS wide open — which is precisely the
gap that produced the timeout above. So the resolution guard is ours, layered on
top, and the two together cover both routes off the machine.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Final

__all__ = [
    "LOOPBACK_HOSTS",
    "NetworkAccessDenied",
    "install_network_guard",
    "is_local_address",
    "is_local_host",
    "network_guard",
]

#: Hosts a test may legitimately reach. asyncio, pytest plugins and coverage all
#: talk to themselves, and one test binds a real loopback listener on purpose.
LOOPBACK_HOSTS: Final[frozenset[str]] = frozenset(
    {"127.0.0.1", "::1", "localhost", "ip6-localhost", "0.0.0.0", ""}
)


class NetworkAccessDenied(RuntimeError):
    """A test tried to resolve or reach something outside this machine.

    Deliberately a ``RuntimeError`` rather than an ``OSError``: an ``OSError``
    would be swallowed by the ``except OSError`` retry and fallback paths that
    every HTTP stack has, and the refusal would come back looking like an
    ordinary connection failure instead of a broken test.
    """


def is_local_host(host: Any) -> bool:
    """Whether a hostname or address string is this machine."""
    return isinstance(host, str) and host.strip().lower() in LOOPBACK_HOSTS


def is_local_address(address: Any) -> bool:
    """Whether ``address`` is loopback or addressed by path.

    A non-tuple address is an ``AF_UNIX`` path or similar: local by
    construction, and never a way off the machine.
    """
    if not isinstance(address, tuple) or not address:
        return True
    return is_local_host(address[0])


def install_network_guard(monkeypatch: Any) -> None:
    """Refuse every non-loopback resolution and connection for one test.

    Applied with ``monkeypatch`` so it is undone at teardown even when a test
    fails, and so a test that genuinely needs the network can override it by
    redefining the fixture rather than by unpicking global state.

    ``getaddrinfo`` is guarded *before* the connection functions on purpose: it
    is what a hostname request reaches first, so the refusal arrives in
    milliseconds instead of after a resolver timeout.
    """
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def _denied(what: str, target: Any) -> NetworkAccessDenied:
        return NetworkAccessDenied(
            f"tests must not reach the network; something tried to {what} {target!r}. "
            f"Mock it, or move the test to tests/live/ and run it with "
            f"--allow-live-network."
        )

    def guarded_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
        if not is_local_host(host):
            raise _denied("resolve", host)
        return _REAL_GETADDRINFO(host, port, *args, **kwargs)

    def guarded_gethostbyname(host: Any, *args: Any) -> Any:
        if not is_local_host(host):
            raise _denied("resolve", host)
        return _REAL_GETHOSTBYNAME(host, *args)

    def guarded_gethostbyname_ex(host: Any, *args: Any) -> Any:
        if not is_local_host(host):
            raise _denied("resolve", host)
        return _REAL_GETHOSTBYNAME_EX(host, *args)

    def guarded_connect(self: socket.socket, address: Any) -> Any:
        if not is_local_address(address):
            self.close()
            raise _denied("connect to", address)
        return real_connect(self, address)

    def guarded_connect_ex(self: socket.socket, address: Any) -> Any:
        if not is_local_address(address):
            self.close()
            raise _denied("connect to", address)
        return real_connect_ex(self, address)

    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", guarded_gethostbyname)
    monkeypatch.setattr(socket, "gethostbyname_ex", guarded_gethostbyname_ex)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)


#: Captured at import, before any guard is installed, so a guard can still let a
#: loopback lookup through without recursing into itself.
_REAL_GETADDRINFO: Final[Any] = socket.getaddrinfo
_REAL_GETHOSTBYNAME: Final[Any] = socket.gethostbyname
_REAL_GETHOSTBYNAME_EX: Final[Any] = socket.gethostbyname_ex


@contextmanager
def network_guard() -> Iterator[None]:
    """The guard as a context manager, for a test that installs it explicitly."""
    import pytest

    patcher = pytest.MonkeyPatch()
    try:
        install_network_guard(patcher)
        yield
    finally:
        patcher.undo()
