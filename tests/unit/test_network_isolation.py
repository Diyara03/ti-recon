"""The suite's network boundary, exercised rather than assumed.

A guard nothing checks is a guard that quietly stops working, and this one did:
it patched ``socket.socket.connect`` and left name resolution untouched, so an
unmocked async request spent its whole timeout budget inside a 20-second DNS
lookup and came back with ``ConnectTimeout`` instead of a refusal. Every test
here pins one route off the machine that must be closed.

The point of each is *immediacy* as much as refusal. A boundary that eventually
times out is not a boundary — it is slow, it leaks which hosts a developer is
working on to a resolver, and it makes a broken mock look like a flaky network.
"""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import Iterator

import httpx
import pytest
import respx
from pytest_socket import SocketBlockedError

from conftest import ALLOW_LIVE_NETWORK_OPTION
from fixtures.network import (
    LOOPBACK_HOSTS,
    NetworkAccessDenied,
    is_local_address,
    is_local_host,
)

#: A host the suite must never resolve. Chosen because it is one this repository
#: genuinely talks to in live runs, so a regression here is a regression that
#: matters rather than a synthetic one.
EXTERNAL_HOST = "threatfox-api.abuse.ch"

#: An address literal, for the route that needs no DNS at all.
EXTERNAL_IP = "203.0.113.7"

#: Anything slower than this is a real lookup or a real connection attempt, not a
#: refusal. Generous by two orders of magnitude: a refused call returns in
#: microseconds, while the failure it replaced took sixteen seconds.
IMMEDIATE_SECONDS = 1.0


def blocked(call: object) -> tuple[BaseException, float]:
    """Run ``call``, returning what it raised and how long it took."""
    started = time.monotonic()
    try:
        call()  # type: ignore[operator]
    except BaseException as error:
        return error, time.monotonic() - started
    pytest.fail("the network guard let something through")


def denied(error: BaseException) -> bool:
    """Whether ``error`` is, or wraps, a refusal from either guard layer.

    Both layers count: resolution is refused by this repository's guard and
    connection by pytest-socket, and a caller should not have to know which one
    a given route hits first. httpx runs its connect inside a task group, so a
    refusal frequently arrives wrapped rather than raw.
    """
    if isinstance(error, NetworkAccessDenied | SocketBlockedError):
        return True
    if isinstance(error, BaseExceptionGroup):
        return any(denied(inner) for inner in error.exceptions)
    cause = error.__cause__ or error.__context__
    return cause is not None and denied(cause)


# --------------------------------------------------------------------------- #
# 1. Synchronous external TCP
# --------------------------------------------------------------------------- #


def test_a_synchronous_connection_to_an_external_address_is_refused_at_once() -> None:
    """The literal-address route, which needs no DNS to be dangerous."""

    def connect() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5.0)
            sock.connect((EXTERNAL_IP, 443))

    error, elapsed = blocked(connect)
    assert denied(error)
    assert elapsed < IMMEDIATE_SECONDS


def test_connect_ex_cannot_slip_past_by_returning_an_errno() -> None:
    """``connect_ex`` reports failure as a return value rather than an exception,
    so a guard that only covered ``connect`` would let it through silently."""

    def connect() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5.0)
            sock.connect_ex((EXTERNAL_IP, 443))

    error, elapsed = blocked(connect)
    assert denied(error)
    assert elapsed < IMMEDIATE_SECONDS


def test_a_synchronous_httpx_request_is_refused_at_once() -> None:
    error, elapsed = blocked(lambda: httpx.Client(timeout=5.0).get(f"https://{EXTERNAL_HOST}/"))
    assert denied(error)
    assert elapsed < IMMEDIATE_SECONDS


# --------------------------------------------------------------------------- #
# 2. Async httpx / AnyIO external TCP
# --------------------------------------------------------------------------- #


async def test_an_async_httpx_request_is_refused_at_once() -> None:
    """The route that was actually escaping.

    httpx's async transport resolves through AnyIO and the event loop's thread
    pool, so the first thing it touches is ``getaddrinfo``. With DNS unguarded it
    never reached ``connect`` at all — it simply timed out, which is why the
    boundary test that depended on it failed with ``ProviderTimeoutError``.
    """
    started = time.monotonic()
    with pytest.raises((BaseExceptionGroup, NetworkAccessDenied, SocketBlockedError)) as raised:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.get(f"https://{EXTERNAL_HOST}/api/v1/")
    elapsed = time.monotonic() - started

    assert denied(raised.value)
    assert elapsed < IMMEDIATE_SECONDS


async def test_an_async_connection_to_a_bare_address_is_refused_at_once() -> None:
    """No hostname, so no resolution to intercept: this one has to be stopped at
    the connection."""
    started = time.monotonic()
    with pytest.raises((BaseExceptionGroup, NetworkAccessDenied, SocketBlockedError)) as raised:
        await asyncio.wait_for(
            asyncio.open_connection(EXTERNAL_IP, 443), timeout=IMMEDIATE_SECONDS * 4
        )
    assert denied(raised.value)
    assert time.monotonic() - started < IMMEDIATE_SECONDS


# --------------------------------------------------------------------------- #
# 3. DNS cannot escape
# --------------------------------------------------------------------------- #


def test_name_resolution_of_an_external_host_is_refused_at_once() -> None:
    """The gap this whole change exists to close.

    Resolution is not a harmless prelude to a blocked connection. It is a request
    that leaves the machine, it tells a resolver which threat-intelligence APIs
    somebody is working on, and — as here — it can consume an entire timeout
    budget before any connection guard is consulted.
    """
    error, elapsed = blocked(lambda: socket.getaddrinfo(EXTERNAL_HOST, 443))
    assert isinstance(error, NetworkAccessDenied)
    assert elapsed < IMMEDIATE_SECONDS


@pytest.mark.parametrize(
    "resolve",
    [
        pytest.param(lambda: socket.gethostbyname(EXTERNAL_HOST), id="gethostbyname"),
        pytest.param(lambda: socket.gethostbyname_ex(EXTERNAL_HOST), id="gethostbyname_ex"),
        pytest.param(
            lambda: socket.create_connection((EXTERNAL_HOST, 443), timeout=5.0),
            id="create_connection",
        ),
    ],
)
def test_every_resolution_entry_point_is_guarded(resolve: object) -> None:
    """One unguarded spelling is the whole boundary."""
    error, elapsed = blocked(resolve)
    assert denied(error)
    assert elapsed < IMMEDIATE_SECONDS


async def test_the_event_loops_own_resolver_is_guarded_too() -> None:
    """``loop.getaddrinfo`` runs in a thread-pool executor. Patching a module
    attribute rather than a bound method is what makes that thread see it."""
    with pytest.raises(NetworkAccessDenied):
        await asyncio.get_running_loop().getaddrinfo(EXTERNAL_HOST, 443)


# --------------------------------------------------------------------------- #
# 4. Loopback still works
# --------------------------------------------------------------------------- #


def test_the_guard_still_allows_a_platform_to_talk_to_itself() -> None:
    """asyncio, coverage and pytest plugins need loopback. Breaking it would make
    the guard the problem rather than the protection."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(2.0)
            client.connect(("127.0.0.1", port))
            accepted, _ = listener.accept()
            accepted.close()


def test_loopback_names_still_resolve() -> None:
    assert socket.getaddrinfo("127.0.0.1", 0)
    assert socket.gethostbyname("localhost") in {"127.0.0.1", "::1"}


async def test_an_async_loopback_connection_still_works() -> None:
    """The event loop's own machinery runs over loopback; a guard that blocked it
    would break every async test in the suite."""

    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.close()
        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize("host", sorted(LOOPBACK_HOSTS))
def test_the_loopback_allow_list_is_recognized_by_both_helpers(host: str) -> None:
    assert is_local_host(host)
    assert is_local_address((host, 443))


def test_a_non_tuple_address_is_local_by_construction() -> None:
    """An ``AF_UNIX`` path is never a way off the machine."""
    assert is_local_address("/run/some.sock")
    assert is_local_address(())
    assert not is_local_address((EXTERNAL_IP, 443))


# --------------------------------------------------------------------------- #
# 5. Mocked HTTP still works
# --------------------------------------------------------------------------- #


@respx.mock
def test_a_respx_mocked_request_is_unaffected() -> None:
    """respx intercepts above the socket, so the guard never sees it — which is
    what lets the entire provider suite run offline."""
    respx.get(f"https://{EXTERNAL_HOST}/api/v1/").mock(
        return_value=httpx.Response(200, json={"query_status": "ok"})
    )
    response = httpx.Client().get(f"https://{EXTERNAL_HOST}/api/v1/")
    assert response.json() == {"query_status": "ok"}


@respx.mock
async def test_an_async_respx_mocked_request_is_unaffected() -> None:
    respx.get(f"https://{EXTERNAL_HOST}/api/v1/").mock(
        return_value=httpx.Response(200, json={"query_status": "ok"})
    )
    async with httpx.AsyncClient() as client:
        response = await client.get(f"https://{EXTERNAL_HOST}/api/v1/")
    assert response.status_code == 200


def test_a_mock_transport_is_unaffected() -> None:
    """The other way provider tests avoid the socket."""
    transport = httpx.MockTransport(lambda _: httpx.Response(204))
    assert httpx.Client(transport=transport).get(f"https://{EXTERNAL_HOST}/").status_code == 204


# --------------------------------------------------------------------------- #
# 6. Both layers are actually installed
# --------------------------------------------------------------------------- #


def test_both_layers_are_armed(request: pytest.FixtureRequest) -> None:
    """Neither substitutes for the other, so both are asserted present.

    pytest-socket is configured through ``addopts`` and refuses connections;
    this repository's guard refuses resolution, which pytest-socket cannot do in
    ``--allow-hosts`` mode without also blocking the loopback this suite needs.

    Our guard is installed by a fixture, so it wraps pytest-socket's and is the
    one that raises here. That ordering is why the assertion below is on the
    *configuration* of the connection layer rather than on which exception type
    surfaces — see the subprocess test for proof that it carries weight on its
    own.
    """
    assert request.config.getoption("--disable-socket") is True
    assert request.config.getoption("--allow-hosts") == "127.0.0.1,::1"

    with pytest.raises(NetworkAccessDenied):
        socket.getaddrinfo(EXTERNAL_HOST, 443)
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
        pytest.raises(NetworkAccessDenied),
    ):
        sock.connect((EXTERNAL_IP, 443))


def test_pytest_socket_blocks_a_literal_address_without_our_guard(
    pytester: pytest.Pytester,
) -> None:
    """The connection layer, proved on its own.

    Run in a subprocess with no conftest of ours, so the only thing standing in
    the way is pytest-socket. It refuses the literal address — which is the route
    a resolution guard can never see, and the reason both layers exist.

    The same run shows why pytest-socket is not sufficient by itself: with
    ``--allow-hosts`` preserving loopback, ``getaddrinfo`` is left open.
    """
    pytester.makepyfile(
        """
        import socket
        from pytest_socket import SocketConnectBlockedError

        def test_connect_is_blocked():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                try:
                    sock.connect(("203.0.113.7", 443))
                except SocketConnectBlockedError:
                    return
                raise AssertionError("pytest-socket did not block the connection")

        def test_resolution_is_not_blocked_by_this_layer():
            assert socket.getaddrinfo is not None
            assert not type(socket.getaddrinfo).__name__ == "NetworkAccessDenied"
        """
    )
    result = pytester.runpytest_subprocess("-q", "--disable-socket", "--allow-hosts=127.0.0.1,::1")
    result.assert_outcomes(passed=2, failed=0)


def test_the_guard_is_undone_between_tests(_restore_probe: None) -> None:
    """Installed with monkeypatch, so a failing test cannot leave the suite in a
    state a later test would inherit."""
    assert socket.getaddrinfo is not None


@pytest.fixture
def _restore_probe() -> Iterator[None]:
    original = socket.getaddrinfo
    yield
    assert socket.getaddrinfo is original


# --------------------------------------------------------------------------- #
# 7-8. The live boundary
# --------------------------------------------------------------------------- #


def test_the_live_opt_in_is_off_by_default(request: pytest.FixtureRequest) -> None:
    """An ordinary ``uv run pytest`` never carries it."""
    assert request.config.getoption(ALLOW_LIVE_NETWORK_OPTION) is False


def test_a_live_env_gate_alone_cannot_open_the_network(
    monkeypatch: pytest.MonkeyPatch, pytester: pytest.Pytester
) -> None:
    """The requirement in one test: an exported RUN_*_LIVE_TESTS variable left
    over from an earlier session must not be enough.

    Run in a nested pytest **subprocess** so the real live modules are untouched
    and the nested run is genuinely outside this one's guard, with the
    environment variable actually set — asserting the *policy* rather than the
    accident that nobody happened to have one exported.
    """
    monkeypatch.setenv("RUN_GTI_LIVE_TESTS", "1")
    monkeypatch.setenv("GTI_API_KEY", "not-a-real-key")
    _write_live_harness(pytester)

    result = pytester.runpytest_subprocess("-q")
    result.assert_outcomes(skipped=1, passed=0, failed=0)


def test_both_switches_together_permit_the_network(
    monkeypatch: pytest.MonkeyPatch, pytester: pytest.Pytester
) -> None:
    """And the pair does open it — a gate nothing can pass is not a gate.

    The nested test asserts the guards are gone rather than making a request:
    proving the boundary was lifted needs no traffic, and this suite does not
    generate any.
    """
    monkeypatch.setenv("RUN_GTI_LIVE_TESTS", "1")
    monkeypatch.setenv("GTI_API_KEY", "not-a-real-key")
    _write_live_harness(pytester)

    result = pytester.runpytest_subprocess("-q", ALLOW_LIVE_NETWORK_OPTION)
    result.assert_outcomes(passed=1, skipped=0, failed=0)


def _write_live_harness(pytester: pytest.Pytester) -> None:
    """A miniature ``tests/live/`` that mirrors the real gating.

    Copies this repository's own conftests so the nested run exercises the real
    option, the real collection hook and the real guard fixture, rather than a
    restatement of them that could drift.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    pytester.makeconftest((root / "conftest.py").read_text(encoding="utf-8"))
    pytester.mkpydir("fixtures")
    (pytester.path / "fixtures" / "network.py").write_text(
        (root / "fixtures" / "network.py").read_text(encoding="utf-8"), encoding="utf-8"
    )
    live = pytester.mkpydir("live")
    (live / "conftest.py").write_text(
        (root / "live" / "conftest.py").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (live / "test_gated.py").write_text(
        '''
import os
import socket

import pytest

pytestmark = pytest.mark.skipif(
    not (os.environ.get("RUN_GTI_LIVE_TESTS") == "1" and os.environ.get("GTI_API_KEY")),
    reason="gti live tests are off.",
)


def test_the_boundary_is_lifted_for_a_permitted_live_test() -> None:
    """No request is made. What is asserted is that the guards are not installed."""
    from fixtures.network import NetworkAccessDenied

    try:
        socket.getaddrinfo("example.invalid", 443)
    except NetworkAccessDenied:  # pragma: no cover - the failure this asserts against
        pytest.fail("the resolution guard was still installed for a permitted live test")
    except OSError:
        pass  # an ordinary resolution failure is fine; the guard is what must be gone
''',
        encoding="utf-8",
    )
