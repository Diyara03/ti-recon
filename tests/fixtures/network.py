"""The unit suite's network boundary.

Lives in ``fixtures`` rather than in a ``conftest`` so a test can import the
exception type and assert the boundary holds — a guard nothing checks is a guard
that quietly stops working.
"""

from __future__ import annotations

from typing import Any, Final

__all__ = ["LOOPBACK_HOSTS", "NetworkAccessDenied", "is_local_address"]

#: Addresses a unit test may legitimately connect to. asyncio, pytest plugins
#: and coverage all talk to themselves.
LOOPBACK_HOSTS: Final[frozenset[str]] = frozenset({"127.0.0.1", "::1", "localhost", "0.0.0.0", ""})


class NetworkAccessDenied(RuntimeError):
    """A unit test tried to open a real outbound connection."""


def is_local_address(address: Any) -> bool:
    """Whether ``address`` is loopback or addressed by path.

    A non-tuple address is an ``AF_UNIX`` path or similar: local by
    construction, and never a way off the machine.
    """
    if not isinstance(address, tuple) or not address:
        return True
    host = address[0]
    return isinstance(host, str) and host in LOOPBACK_HOSTS
