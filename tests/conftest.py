"""Shared pytest configuration, and the suite-wide network boundary.

The boundary is Python-level: it refuses this process's socket and
name-resolution calls, and is not an OS sandbox. See ``tests/fixtures/network.py``
for what that does and does not cover.

Adds ``tests/`` to ``sys.path`` so fixture packages are importable as
``fixtures.*`` without installing the test tree.

No test reaches the network unless it is asked to, twice
--------------------------------------------------------

The guard is installed here rather than under ``tests/unit/`` so it covers
*every* collected test, including the shared adapter-contract suite. A real
outbound connection from an offline test is never intentional: every provider
integration is exercised against a fake client or ``respx``, both of which
intercept above the socket, so an escaping request means a test slipped past its
mock — which is how one of these files once authenticated against a live API and
got a ``401`` back.

Several tests rely on the guard directly. They assert that a malformed or
disallowed request is refused *without* mocking the endpoint, on the grounds that
anything escaping validation would fail loudly rather than pass silently. That
reasoning needs those calls to be genuinely refused, not merely unmade.

Loopback stays open, because asyncio, pytest plugins and coverage legitimately
talk to themselves and one test binds a real listener on purpose.

Live tests need two independent switches
----------------------------------------

``tests/live/`` is supposed to reach real APIs, and until now the only thing
standing between an ordinary ``uv run pytest`` and live provider traffic was an
environment variable. An exported ``RUN_GTI_LIVE_TESTS`` left over from a
debugging session an hour earlier would have been enough — and environment
variables are exactly the kind of state that outlives the intent behind it.

So a live test now needs its provider's ``RUN_*_LIVE_TESTS`` gate **and**
``--allow-live-network`` on the command line. The flag is per-invocation and
cannot be set ahead of time by accident, which is the property the environment
variable does not have. See ``tests/live/conftest.py``.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

_TESTS_ROOT = Path(__file__).resolve().parent
if str(_TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_TESTS_ROOT))

from fixtures.network import install_network_guard  # noqa: E402

#: ``pytester`` runs a throwaway pytest project in a subprocess, which is the
#: only way to observe this conftest's own gating from the outside — an
#: in-process run would still be sitting inside the guard it is trying to
#: describe.
pytest_plugins = ["pytester"]

#: The opt-in that lets ``tests/live/`` talk to real provider APIs.
ALLOW_LIVE_NETWORK_OPTION = "--allow-live-network"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        ALLOW_LIVE_NETWORK_OPTION,
        action="store_true",
        default=False,
        help=(
            "Permit tests under tests/live/ to make real provider requests. "
            "Each live suite still requires its own RUN_*_LIVE_TESTS environment "
            "gate; this flag is the second, non-persistent half."
        ),
    )


@pytest.fixture(autouse=True)
def _network_guard(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Refuse every non-loopback resolution and connection, for one test.

    Overridden by ``tests/live/conftest.py`` for live tests that were explicitly
    permitted. Redefining the fixture is deliberate: a live test lifts the guard
    by being collected somewhere that declares a different one, never by
    reaching into global state that a later test would inherit.
    """
    install_network_guard(monkeypatch)
    yield
