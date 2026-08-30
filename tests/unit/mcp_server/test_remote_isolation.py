"""Tenant isolation and load control over the real HTTP boundary (Task 22).

Phase 1 proved the isolation by calling the runtime directly. These tests prove
the whole chain instead — bearer header, SDK middleware, strict verifier, tenant
derivation, request-scoped context, Task 6 keys, credential resolution — because
each of those is a link that could be wired correctly on its own and still not
join up.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
from collections.abc import Iterator

import httpx
import pytest
from pydantic import SecretStr

from fixtures.investigation.stack import ScriptedProvider, claim_evidence, spec
from fixtures.mcp_server.auth import FAKE_TENANT_SECRET
from fixtures.mcp_server.remote import (
    FAKE_BEARER,
    ISSUER,
    call_tool,
    http_config,
    remote_harness,
    result_of,
)
from ti_recon.application.composition import CREDENTIAL_ENVIRONMENT
from ti_recon.credentials import AuthType, CredentialStatus
from ti_recon.enums import ProviderCapability, ProviderRunStatus
from ti_recon.execution.models import ExecutionScope
from ti_recon.mcp_server.limits import TenantBusyError, TenantInvestigationLimiter
from ti_recon.mcp_server.principal import derive_tenant_id
from ti_recon.planning.models import CallCostClass, ProviderLocality
from ti_recon.reasoning.claims.models import ClaimSemantic

OBSERVABLE = "1.2.3.4"

ALICE_BEARER = "bearer-for-alice"
BOB_BEARER = "bearer-for-bob"
CAROL_BEARER = "bearer-for-carol"

ALICE_KEY = "PROVIDER_KEY_FOR_ALICE_AAA"
BOB_KEY = "PROVIDER_KEY_FOR_BOB_BBB"

SUBJECT_ALICE = "alice.analyst@example.invalid"
SUBJECT_BOB = "bob.analyst@example.invalid"
SUBJECT_CAROL = "carol.analyst@example.invalid"


def tenant(subject: str) -> str:
    return derive_tenant_id(
        issuer=ISSUER, subject=subject, tenant_key=SecretStr(FAKE_TENANT_SECRET)
    )


def _remote(gate: asyncio.Event | None = None) -> ScriptedProvider:
    return ScriptedProvider(
        spec(
            "reputation_remote",
            family="fam_remote",
            capabilities=frozenset({ProviderCapability.REPUTATION}),
        ),
        {OBSERVABLE: claim_evidence(ClaimSemantic.MALICIOUS_REPUTATION)},
        gate=gate,
    )


def _local() -> ScriptedProvider:
    return ScriptedProvider(
        spec(
            "local_context",
            family="fam_local",
            capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
            locality=ProviderLocality.LOCAL,
            cost=CallCostClass.ZERO,
        ),
        {},
    )


async def _seed(harness, *, subject: str, secret: str) -> None:
    await harness.stack.manager.create_connection(
        user_id=tenant(subject),
        provider_id="reputation_remote",
        secret=secret,
        auth_type=AuthType.API_KEY,
        status=CredentialStatus.ACTIVE,
    )


def _register(harness) -> None:
    harness.directory.add(ALICE_BEARER, subject=SUBJECT_ALICE)
    harness.directory.add(BOB_BEARER, subject=SUBJECT_BOB)
    harness.directory.add(CAROL_BEARER, subject=SUBJECT_CAROL)


async def _investigate(harness, bearer: str) -> httpx.Response:
    return await call_tool(
        harness, "investigate_observable", {"observable": OBSERVABLE}, bearer=bearer
    )


# --------------------------------------------------------------------------- #
# Two tenants over the real wire
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_each_bearer_reaches_the_provider_with_its_own_credential() -> None:
    """The full chain, end to end.

    One ASGI app, one executor, one credential repository, two Authorization
    headers. What separates the two investigations is a token, and everything
    downstream of it.
    """
    provider = _remote()
    async with remote_harness([provider]) as harness:
        _register(harness)
        await _seed(harness, subject=SUBJECT_ALICE, secret=ALICE_KEY)
        await _seed(harness, subject=SUBJECT_BOB, secret=BOB_KEY)

        assert (await _investigate(harness, ALICE_BEARER)).status_code == 200
        assert (await _investigate(harness, BOB_BEARER)).status_code == 200

    assert provider.credentials == [ALICE_KEY, BOB_KEY]


@pytest.mark.asyncio
async def test_one_tenants_cache_entry_is_never_served_to_another() -> None:
    """Two real provider requests, because the cache key names the tenant."""
    provider = _remote()
    async with remote_harness([provider]) as harness:
        _register(harness)
        await _seed(harness, subject=SUBJECT_ALICE, secret=ALICE_KEY)
        await _seed(harness, subject=SUBJECT_BOB, secret=BOB_KEY)

        await _investigate(harness, ALICE_BEARER)
        await _investigate(harness, BOB_BEARER)

        assert len(provider.requests) == 2
        assert [item.cache_hit for item in harness.stack.execution_metrics.executions] == [
            False,
            False,
        ]
        assert not any(item.coalesced for item in harness.stack.execution_metrics.executions)


@pytest.mark.asyncio
async def test_the_same_bearer_twice_keeps_the_existing_cache_behaviour() -> None:
    """Remote auth must not mint a fresh tenant per request.

    If it did the isolation would work by accident, at the cost of every repeat
    question spending the quota again and never seeing its own cooldowns.
    """
    provider = _remote()
    async with remote_harness([provider]) as harness:
        _register(harness)
        await _seed(harness, subject=SUBJECT_ALICE, secret=ALICE_KEY)

        await _investigate(harness, ALICE_BEARER)
        await _investigate(harness, ALICE_BEARER)

        assert len(provider.requests) == 1
        assert [item.cache_hit for item in harness.stack.execution_metrics.executions] == [
            False,
            True,
        ]


@pytest.mark.asyncio
async def test_the_tenant_id_from_the_bearer_is_what_keys_task_6() -> None:
    """The cache, cooldown, quota, concurrency and single-flight key spaces.

    All five are the same ``ExecutionScope.identity`` string, so asserting the
    cache key carries the tenant asserts all of them — and asserting the raw
    subject is absent proves the pseudonymisation survived the whole chain.
    """
    async with remote_harness([_remote()]) as harness:
        _register(harness)
        await _seed(harness, subject=SUBJECT_ALICE, secret=ALICE_KEY)
        await _investigate(harness, ALICE_BEARER)

        connection = await harness.stack.connections.find_by_group(
            tenant(SUBJECT_ALICE), "reputation_remote"
        )
        assert connection is not None
        expected = ExecutionScope.for_user(
            provider_id="reputation_remote",
            user_id=tenant(SUBJECT_ALICE),
            provider_connection_id=connection.id,
            credential_group="reputation_remote",
        ).identity

        keys = list(harness.stack.executor._cache._entries)
        assert keys
        for key in keys:
            assert f"|{expected}|" in key
            assert SUBJECT_ALICE not in key
            assert ALICE_BEARER not in key
            assert FAKE_TENANT_SECRET not in key


@pytest.mark.asyncio
async def test_a_cooldown_one_tenant_earned_does_not_block_another() -> None:
    from ti_recon.execution.limits import CooldownEntry
    from ti_recon.execution.models import CooldownReason
    from ti_recon.models.base import utc_now

    provider = _remote()
    async with remote_harness([provider]) as harness:
        _register(harness)
        await _seed(harness, subject=SUBJECT_ALICE, secret=ALICE_KEY)
        await _seed(harness, subject=SUBJECT_BOB, secret=BOB_KEY)

        connection = await harness.stack.connections.find_by_group(
            tenant(SUBJECT_ALICE), "reputation_remote"
        )
        assert connection is not None
        scope = ExecutionScope.for_user(
            provider_id="reputation_remote",
            user_id=tenant(SUBJECT_ALICE),
            provider_connection_id=connection.id,
            credential_group="reputation_remote",
        )
        now = utc_now()
        await harness.stack.executor._cooldown_store.set(
            CooldownEntry(
                provider_id="reputation_remote",
                scope_identity=scope.identity,
                operation=None,
                until=now.replace(year=now.year + 1),
                reason=CooldownReason.QUOTA_EXHAUSTED,
            )
        )

        assert (await _investigate(harness, BOB_BEARER)).status_code == 200

    assert provider.credentials == [BOB_KEY]


# --------------------------------------------------------------------------- #
# provider_status over the real wire
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_provider_status_describes_the_bearer_and_nobody_else() -> None:
    """Three analysts, one catalogue, three different answers to one question."""
    remote, local = _remote(), _local()
    async with remote_harness([remote, local]) as harness:
        _register(harness)
        await _seed(harness, subject=SUBJECT_ALICE, secret=ALICE_KEY)
        await _seed(harness, subject=SUBJECT_BOB, secret=BOB_KEY)

        reports = {}
        for label, bearer in (
            ("alice", ALICE_BEARER),
            ("bob", BOB_BEARER),
            ("carol", CAROL_BEARER),
        ):
            response = await call_tool(harness, "provider_status", bearer=bearer)
            assert response.status_code == 200
            reports[label] = result_of(response)["structuredContent"]

        for label in ("alice", "bob"):
            configured = {
                item["provider_id"]: item["configured"] for item in reports[label]["providers"]
            }
            assert configured == {"reputation_remote": True, "local_context": True}

        carol = {item["provider_id"]: item["configured"] for item in reports["carol"]["providers"]}
        assert carol == {"reputation_remote": False, "local_context": True}

        # The catalogue is a property of the installation, identical for everyone.
        assert (
            [item["provider_id"] for item in reports["alice"]["providers"]]
            == [item["provider_id"] for item in reports["bob"]["providers"]]
            == [item["provider_id"] for item in reports["carol"]["providers"]]
        )
        # Nothing was asked anything.
        assert remote.requests == [] and remote.credentials == []
        assert local.requests == []


@pytest.mark.asyncio
async def test_provider_status_leaks_no_credential_material_over_http() -> None:
    async with remote_harness([_remote()]) as harness:
        _register(harness)
        await _seed(harness, subject=SUBJECT_ALICE, secret=ALICE_KEY)
        connection = await harness.stack.connections.find_by_group(
            tenant(SUBJECT_ALICE), "reputation_remote"
        )
        assert connection is not None
        response = await call_tool(harness, "provider_status", bearer=ALICE_BEARER)

    body = response.text
    for secret in (
        ALICE_KEY,
        BOB_KEY,
        connection.id,
        connection.secret_reference.key,
        SUBJECT_ALICE,
        ALICE_BEARER,
        FAKE_TENANT_SECRET,
        tenant(SUBJECT_ALICE),
    ):
        assert secret not in body
    assert str(len(ALICE_KEY)) not in body


@pytest.mark.asyncio
async def test_the_environment_configures_no_remote_tenant(monkeypatch) -> None:
    """A server's environment is global to the server.

    Even with every documented variable set, an authenticated analyst with no
    stored connection sees nothing configured and the provider reports
    ``NOT_CONFIGURED`` — never the server's own keys under somebody else's name.
    """
    for variable in CREDENTIAL_ENVIRONMENT.values():
        monkeypatch.setenv(variable, f"FAKE-{variable}-NOT-TO-BE-LOADED")

    remote, local = _remote(), _local()
    async with remote_harness([remote, local]) as harness:
        _register(harness)

        status = result_of(await call_tool(harness, "provider_status", bearer=CAROL_BEARER))
        configured = {
            item["provider_id"]: item["configured"]
            for item in status["structuredContent"]["providers"]
        }
        assert configured == {"reputation_remote": False, "local_context": True}

        result = await harness.runtime.application.run(
            __import__(
                "ti_recon.application.models", fromlist=["AnalystInvestigationRequest"]
            ).AnalystInvestigationRequest(observable=OBSERVABLE, observable_type="ipv4"),
            __import__("ti_recon.execution.models", fromlist=["ExecutionContext"]).ExecutionContext(
                authenticated_user_id=tenant(SUBJECT_CAROL)
            ),
        )
        statuses = {item.provider_id: item.status for item in result.enrichment.attempts}
        assert statuses["reputation_remote"] is ProviderRunStatus.NOT_CONFIGURED
        assert remote.credentials == []
        assert await harness.stack.connections.list_for_user(tenant(SUBJECT_CAROL)) == []


@contextlib.contextmanager
def _capturing_logs(sink: io.StringIO) -> Iterator[None]:
    """Capture every logger that could plausibly echo a request, then put it back.

    Restored rather than left reassigned. Logging is global, and a test that
    silently redirects ``httpx`` for the rest of the session makes some *other*
    test fail somewhere far away — which is exactly what happened while this file
    was being written.
    """
    handler = logging.StreamHandler(sink)
    names = ("ti_recon", "mcp", "httpx", "starlette")
    saved = [
        (
            logging.getLogger(name),
            logging.getLogger(name).handlers,
            logging.getLogger(name).propagate,
            logging.getLogger(name).level,
        )
        for name in names
    ]
    for logger, *_ in saved:
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.DEBUG)
    try:
        yield
    finally:
        for logger, handlers, propagate, level in saved:
            logger.handlers = handlers
            logger.propagate = propagate
            logger.setLevel(level)


# --------------------------------------------------------------------------- #
# The bearer stops at the boundary
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_bearer_reaches_the_verifier_and_nothing_else() -> None:
    """The token may exist in the header and in the verifier call. Nowhere else.

    Not in a tool argument, not in the execution context, not in a provider
    request, not in the report, not in the response, not in a log and not on
    stderr.
    """
    provider = _remote()
    captured = io.StringIO()
    stderr = io.StringIO()
    with _capturing_logs(captured):
        await _assert_bearer_stops_here(provider, captured, stderr)


async def _assert_bearer_stops_here(
    provider: ScriptedProvider, captured: io.StringIO, stderr: io.StringIO
) -> None:
    async with remote_harness([provider]) as harness:
        harness.directory.add(FAKE_BEARER, subject=SUBJECT_ALICE)
        await _seed(harness, subject=SUBJECT_ALICE, secret=ALICE_KEY)
        with contextlib.redirect_stderr(stderr):
            response = await _investigate(harness, FAKE_BEARER)

        assert response.status_code == 200
        # The verifier saw it, once. That is the whole permitted footprint.
        assert harness.directory.seen == [FAKE_BEARER]
        # Only the provider's own key reached the wire.
        assert provider.credentials == [ALICE_KEY]

        surfaces = [
            response.text,
            json.dumps(dict(response.headers)),
            captured.getvalue(),
            stderr.getvalue(),
        ]

    for text in surfaces:
        assert FAKE_BEARER not in text
        assert SUBJECT_ALICE not in text
        assert FAKE_TENANT_SECRET not in text
        assert ALICE_KEY not in text
        assert tenant(SUBJECT_ALICE) not in text


@pytest.mark.asyncio
async def test_a_provider_key_is_never_accepted_as_a_bearer() -> None:
    """The reverse direction. A provider key proves nothing about an analyst."""
    async with remote_harness([_remote()]) as harness:
        harness.directory.add(FAKE_BEARER, subject=SUBJECT_ALICE)
        response = await _investigate(harness, ALICE_KEY)

    assert response.status_code == 401


# --------------------------------------------------------------------------- #
# One investigation per tenant
# --------------------------------------------------------------------------- #


def test_the_limiter_refuses_rather_than_queues() -> None:
    limiter = TenantInvestigationLimiter()
    assert limiter.max_concurrent == 1
    with pytest.raises(ValueError):
        TenantInvestigationLimiter(max_concurrent=0)


@pytest.mark.asyncio
async def test_a_slot_is_released_on_completion_error_and_cancellation() -> None:
    """All three paths, because a leaked slot locks an analyst out for good.

    Cancellation is the one that matters most: a client going away mid-request is
    ordinary, not exceptional.
    """
    limiter = TenantInvestigationLimiter()

    async with limiter.hold("t"):
        assert limiter.active_count("t") == 1
    assert limiter.tracked_tenants == 0

    with pytest.raises(RuntimeError):
        async with limiter.hold("t"):
            msg = "provider exploded"
            raise RuntimeError(msg)
    assert limiter.tracked_tenants == 0

    started = asyncio.Event()

    async def blocked() -> None:
        async with limiter.hold("t"):
            started.set()
            await asyncio.Event().wait()

    task = asyncio.ensure_future(blocked())
    await started.wait()
    assert limiter.active_count("t") == 1
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert limiter.tracked_tenants == 0


@pytest.mark.asyncio
async def test_a_second_concurrent_investigation_for_one_tenant_is_refused() -> None:
    """Fast refusal, not an unbounded queue.

    A caller told "try again" still has a working service; a caller behind a
    backlog has a slow one, and the server is holding memory for requests nobody
    is waiting on any more.
    """
    gate = asyncio.Event()
    provider = _remote(gate=gate)
    async with remote_harness([provider]) as harness:
        _register(harness)
        await _seed(harness, subject=SUBJECT_ALICE, secret=ALICE_KEY)
        await _seed(harness, subject=SUBJECT_BOB, secret=BOB_KEY)

        first = asyncio.ensure_future(_investigate(harness, ALICE_BEARER))
        while harness.limiter.active_count(tenant(SUBJECT_ALICE)) == 0:
            await asyncio.sleep(0)

        second = await _investigate(harness, ALICE_BEARER)
        assert second.status_code == 200
        payload = result_of(second)
        assert payload["isError"] is True
        message = " ".join(item.get("text", "") for item in payload["content"])
        assert "Another investigation is already running" in message
        # It says nothing about anybody else's load or identity.
        assert SUBJECT_ALICE not in message
        assert tenant(SUBJECT_ALICE) not in message

        # Tenant B is unaffected while A is still running.
        gate.set()
        assert (await _investigate(harness, BOB_BEARER)).status_code == 200

        assert (await first).status_code == 200
        assert harness.limiter.tracked_tenants == 0


@pytest.mark.asyncio
async def test_provider_status_never_takes_an_investigation_slot() -> None:
    """The diagnostic has to work exactly when somebody is wondering why."""
    gate = asyncio.Event()
    async with remote_harness([_remote(gate=gate)]) as harness:
        _register(harness)
        await _seed(harness, subject=SUBJECT_ALICE, secret=ALICE_KEY)

        running = asyncio.ensure_future(_investigate(harness, ALICE_BEARER))
        while harness.limiter.active_count(tenant(SUBJECT_ALICE)) == 0:
            await asyncio.sleep(0)

        status = await call_tool(harness, "provider_status", bearer=ALICE_BEARER)
        assert status.status_code == 200
        assert result_of(status).get("isError") is not True
        assert harness.limiter.active_count(tenant(SUBJECT_ALICE)) == 1

        gate.set()
        assert (await running).status_code == 200


@pytest.mark.asyncio
async def test_the_local_profile_has_no_limiter_at_all() -> None:
    """One process, one analyst, one conversation: nothing there can collide."""
    from fixtures.mcp_server import scripted_runtime

    runtime, _ = await scripted_runtime([_remote()])
    assert runtime.investigations is None


def test_the_limiter_key_is_the_tenant_and_nothing_else() -> None:
    """No observable, no subject, no bearer, no client id.

    And entries are dropped when a tenant goes idle, so a long-lived server holds
    no record of everyone who ever connected.
    """
    limiter = TenantInvestigationLimiter()
    with pytest.raises(TenantBusyError):
        asyncio.run(_double_hold(limiter))
    assert limiter.tracked_tenants == 0


async def _double_hold(limiter: TenantInvestigationLimiter) -> None:
    async with limiter.hold("tenant-v1:abc"), limiter.hold("tenant-v1:abc"):
        pass


@pytest.mark.asyncio
async def test_two_tenants_hold_two_independent_slots() -> None:
    limiter = TenantInvestigationLimiter()
    async with limiter.hold("tenant-a"), limiter.hold("tenant-b"):
        assert limiter.tracked_tenants == 2
    assert limiter.tracked_tenants == 0


def test_the_limiter_repr_names_no_tenant() -> None:
    limiter = TenantInvestigationLimiter()
    assert "tenant" not in repr(limiter).replace("tenants=", "")


@pytest.mark.asyncio
async def test_a_configured_limit_above_one_is_honoured() -> None:
    """The policy is a number, not a hard-coded one, so Task 24 can tune it."""
    config = http_config(max_investigations_per_tenant=2)
    async with remote_harness([_remote()], config=config) as harness:
        assert harness.limiter.max_concurrent == 2


def test_the_metadata_url_is_derived_from_the_one_canonical_resource() -> None:
    """RFC 9728 §3.1: the well-known prefix goes between authority and path."""
    assert (
        http_config().resource_metadata_url
        == "https://mcp.example.invalid/.well-known/oauth-protected-resource/mcp"
    )


@pytest.mark.asyncio
async def test_a_higher_limit_decrements_rather_than_forgetting_a_tenant() -> None:
    """Two slots held, one released: the tenant is still tracked with one left."""
    limiter = TenantInvestigationLimiter(max_concurrent=2)
    async with limiter.hold("t"):
        async with limiter.hold("t"):
            assert limiter.active_count("t") == 2
        assert limiter.active_count("t") == 1
        assert limiter.tracked_tenants == 1
    assert limiter.tracked_tenants == 0
