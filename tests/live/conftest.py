"""The live suite's second switch.

Every module here already refuses to run without its provider's
``RUN_*_LIVE_TESTS`` environment variable and a credential. That gate is kept
exactly as it was — it is what stops a live run without a key — but on its own it
is not enough to stand between ``uv run pytest`` and real provider traffic.

An environment variable outlives the intention behind it. Exported for one
debugging session, it is still exported an hour later when somebody runs the
whole suite, and nothing about that run looks different. ``--allow-live-network``
cannot be left behind that way: it is typed per invocation, so an ordinary
``uv run pytest -q`` reaches nothing even with every ``RUN_*_LIVE_TESTS``
variable set.

Both switches are required, and they fail in different directions on purpose: the
environment gate says *which* provider may be contacted and with whose
credential, and the flag says *this run, now, deliberately*.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from conftest import ALLOW_LIVE_NETWORK_OPTION
from fixtures.network import install_network_guard

_SKIP_REASON = (
    f"live provider tests need {ALLOW_LIVE_NETWORK_OPTION} as well as their "
    f"RUN_*_LIVE_TESTS environment gate"
)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip every live test unless this run explicitly asked for the network.

    Applied at collection so the decision is visible in the report — a skipped
    test with a reason, rather than a test that quietly did nothing.

    When the flag *is* given, each item is marked ``enable_socket`` so
    pytest-socket lifts its connection block for that item alone; the resolution
    guard is lifted by the fixture below. Both are per-item, so a live run does
    not open the network for anything else that happens to be collected
    alongside it.
    """
    if config.getoption(ALLOW_LIVE_NETWORK_OPTION):
        for item in items:
            if _is_live(item):
                item.add_marker(pytest.mark.enable_socket)
        return

    skip = pytest.mark.skip(reason=_SKIP_REASON)
    for item in items:
        if _is_live(item):
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _network_guard(request: pytest.FixtureRequest) -> Iterator[None]:
    """Replaces the suite-wide guard for permitted live tests.

    Shadows ``tests/conftest.py``'s fixture of the same name for everything under
    this directory. Without the flag the guard is installed exactly as it is
    everywhere else, so a live module that somehow ran anyway still could not
    reach anything.
    """
    if request.config.getoption(ALLOW_LIVE_NETWORK_OPTION):
        yield
        return

    patcher = pytest.MonkeyPatch()
    try:
        install_network_guard(patcher)
        yield
    finally:
        patcher.undo()


#: This conftest's own directory. Membership is decided by path rather than by a
#: substring of the node id, so the rule is exact and survives the directory
#: being moved, renamed or copied into a throwaway project by a test.
_LIVE_ROOT = Path(__file__).resolve().parent


def _is_live(item: pytest.Item) -> bool:
    path = getattr(item, "path", None)
    if path is None:  # pragma: no cover - every collected item has one
        return False
    return _LIVE_ROOT == path.resolve().parent or _LIVE_ROOT in path.resolve().parents
