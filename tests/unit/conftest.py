"""Unit-suite guard: no test here may reach the network.

Every provider integration in this repository is tested against fake clients or
against ``respx``, both of which intercept above the socket layer. So a real
outbound connection from the unit suite is never intentional — it means a test
slipped past its mock, which is how one of these files once authenticated against
a live API and got a ``401`` back.

Several tests rely on this directly. They assert that a malformed or
disallowed request is refused *without* mocking the endpoint, on the grounds
that anything escaping validation would fail loudly rather than pass silently.
That reasoning needs the network to be genuinely unreachable, not merely
unused.

Loopback and ``AF_UNIX`` stay open — asyncio, pytest plugins and coverage all
legitimately talk to themselves, and breaking that would make the guard the
problem rather than the protection.

``tests/live/`` is a sibling directory and is unaffected: those tests are
supposed to reach a real API, and they stay off unless explicitly enabled.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from typing import Any

import pytest

from fixtures.network import NetworkAccessDenied, is_local_address


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Refuse any non-loopback connect for the duration of one unit test."""
    real_connect = socket.socket.connect

    def guarded(self: socket.socket, address: Any) -> Any:
        if is_local_address(address):
            return real_connect(self, address)
        msg = (
            f"unit tests must not reach the network; something tried to connect "
            f"to {address!r}. Mock it, or move the test to tests/live/."
        )
        raise NetworkAccessDenied(msg)

    monkeypatch.setattr(socket.socket, "connect", guarded)
    yield
