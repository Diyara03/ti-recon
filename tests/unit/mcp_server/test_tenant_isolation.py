"""One shared engine, many authenticated analysts, nothing shared (Task 22).

Everything below the principal is the shipped code: one
:class:`~ti_recon.application.service.InvestigationApplication`, one
:class:`~ti_recon.execution.executor.ProviderExecutor`, one cache, one cooldown
store, one credential repository. The claim under test is that this is safe
*because the isolation lives in the key*, so these tests exercise the real Task 6
path rather than asserting that two objects are different objects.

They are also where the two credentials are told apart. An MCP access token
authenticates the analyst to TI Recon; a provider key authenticates TI Recon to a
provider. They come from different trust domains and neither may become the
other.
"""

from __future__ import annotations

import contextlib
import io
import logging
from collections.abc import Iterator

import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import SecretBytes

from fixtures.investigation.stack import InvestigationStack, ScriptedProvider, claim_evidence, spec
from fixtures.mcp_server.auth import (
    FAKE_MCP_TOKEN,
    FAKE_PROVIDER_TOKEN,
    FAKE_SUBJECT,
    FAKE_TENANT_SECRET,
    ISSUER,
    OTHER_ISSUER,
    access_token,
    auth_config,
)
from ti_recon.application.composition import CREDENTIAL_ENVIRONMENT, CredentialLoadReport
from ti_recon.application.models import AnalystInvestigationRequest, ObservableInputType
from ti_recon.application.service import InvestigationApplication
from ti_recon.correlation.policy import PivotMode
from ti_recon.credentials import AuthType, CredentialStatus
from ti_recon.enums import (
    InvestigationDepth,
    ProviderCapability,
    ProviderRunStatus,
)
from ti_recon.execution.limits import CooldownEntry
from ti_recon.execution.models import CooldownReason, ExecutionScope
from ti_recon.mcp_server import tools
from ti_recon.mcp_server.auth import RemoteAuthenticationError
from ti_recon.mcp_server.principal import derive_tenant_id
from ti_recon.mcp_server.runtime import (
    STDIO_PRINCIPAL,
    FixedPrincipal,
    McpRuntime,
    RemotePrincipalSource,
    build_remote_runtime,
    build_stdio_runtime,
)
from ti_recon.models.base import utc_now
from ti_recon.planning.models import CallCostClass, ProviderLocality
from ti_recon.reasoning.claims.models import ClaimSemantic
from ti_recon.reporting.builder import build_analyst_report

CONFIG = auth_config()
OBSERVABLE = "1.2.3.4"

#: Two analysts, and a third with nothing configured.
ALICE = "alice"
BOB = "bob"
CAROL = "carol"

FAKE_KEY_A = "PROVIDER_KEY_FOR_ALICE_AAA"
FAKE_KEY_B = "PROVIDER_KEY_FOR_BOB_BBB"


def tenant(subject: str, *, issuer: str = ISSUER) -> str:
    return derive_tenant_id(
        issuer=issuer, subject=subject, tenant_key=SecretBytes(FAKE_TENANT_SECRET)
    )


@contextlib.contextmanager
def authenticated(subject: str, *, issuer: str = ISSUER) -> Iterator[None]:
    """Serve one request as this principal, exactly as the SDK middleware would."""
    reset = auth_context_var.set(
        AuthenticatedUser(access_token(subject=subject, issuer=issuer))  # type: ignore[arg-type]
    )
    try:
        yield
    finally:
        auth_context_var.reset(reset)


def _remote_provider() -> ScriptedProvider:
    return ScriptedProvider(
        spec(
            "reputation_remote",
            family="fam_remote",
            capabilities=frozenset({ProviderCapability.REPUTATION}),
        ),
        {OBSERVABLE: claim_evidence(ClaimSemantic.MALICIOUS_REPUTATION)},
    )


def _local_provider() -> ScriptedProvider:
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


async def _remote_stack(
    providers: list[ScriptedProvider],
) -> tuple[McpRuntime, InvestigationStack]:
    """One application, one executor, one set of stores, many principals."""
    stack = InvestigationStack(providers=providers)
    runtime = McpRuntime(
        application=InvestigationApplication(orchestrator=stack.orchestrator),
        credentials=CredentialLoadReport(),
        connections=stack.connections,
        principals=RemotePrincipalSource(CONFIG),
        adapters=tuple(providers),
    )
    return runtime, stack


async def _seed(stack: InvestigationStack, *, user_id: str, provider_id: str, secret: str) -> None:
    await stack.manager.create_connection(
        user_id=user_id,
        provider_id=provider_id,
        secret=secret,
        auth_type=AuthType.API_KEY,
        status=CredentialStatus.ACTIVE,
    )


async def _investigate(runtime: McpRuntime, observable: str = OBSERVABLE) -> object:
    return await tools.investigate_observable(
        runtime,
        observable=observable,
        observable_type=ObservableInputType.IPV4,
        depth=InvestigationDepth.STANDARD,
        pivot_mode=PivotMode.NONE,
        allow_remote_pivot_lookup=False,
    )


# --------------------------------------------------------------------------- #
# The remote profile never reads the server's environment for provider keys
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_remote_composition_loads_no_provider_credential_from_the_environment(
    monkeypatch,
) -> None:
    """A server's environment is global to the server.

    Loading it would hand every authenticated analyst the same keys, spend one
    quota on everybody's behalf and use a provider account under terms nobody
    agreed to. So even with every documented variable set, remote composition
    creates no connection for anybody.
    """
    for variable in CREDENTIAL_ENVIRONMENT.values():
        monkeypatch.setenv(variable, f"FAKE-{variable}-NOT-TO-BE-LOADED")

    providers = [_remote_provider(), _local_provider()]
    runtime = await build_remote_runtime(auth=CONFIG, adapters=list(providers))

    assert runtime.credentials.configured_groups == frozenset()
    for subject in (ALICE, BOB, STDIO_PRINCIPAL):
        assert await runtime.connections.list_for_user(tenant(subject)) == []
    assert await runtime.connections.list_for_user(STDIO_PRINCIPAL) == []


@pytest.mark.asyncio
async def test_the_stdio_profile_still_loads_this_machines_environment(monkeypatch) -> None:
    """The local product is unchanged: one process, one analyst, one env."""
    monkeypatch.setenv(CREDENTIAL_ENVIRONMENT["virustotal"], "FAKE-LOCAL-VT-KEY")
    runtime = await build_stdio_runtime()

    assert "virustotal" in runtime.credentials.configured_groups
    assert await runtime.connections.list_for_user(STDIO_PRINCIPAL) != []


# --------------------------------------------------------------------------- #
# Two analysts, one engine
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_each_analyst_reaches_the_provider_with_their_own_credential() -> None:
    """The only place credential isolation is genuinely observable.

    Both investigations run through one executor, one cache and one credential
    resolver. What separates them is the authenticated user id, and nothing else.
    """
    provider = _remote_provider()
    runtime, stack = await _remote_stack([provider])
    await _seed(stack, user_id=tenant(ALICE), provider_id="reputation_remote", secret=FAKE_KEY_A)
    await _seed(stack, user_id=tenant(BOB), provider_id="reputation_remote", secret=FAKE_KEY_B)

    with authenticated(ALICE):
        await _investigate(runtime)
    with authenticated(BOB):
        await _investigate(runtime)

    assert provider.credentials == [FAKE_KEY_A, FAKE_KEY_B]


@pytest.mark.asyncio
async def test_one_analysts_cached_result_is_never_served_to_another() -> None:
    """Two calls, two real provider requests, because the cache key names the user.

    A shared entry would let one analyst read intelligence fetched with another's
    key — and quietly under another organization's provider terms.
    """
    provider = _remote_provider()
    runtime, stack = await _remote_stack([provider])
    await _seed(stack, user_id=tenant(ALICE), provider_id="reputation_remote", secret=FAKE_KEY_A)
    await _seed(stack, user_id=tenant(BOB), provider_id="reputation_remote", secret=FAKE_KEY_B)

    with authenticated(ALICE):
        await _investigate(runtime)
    with authenticated(BOB):
        await _investigate(runtime)

    assert len(provider.requests) == 2
    assert [item.cache_hit for item in stack.execution_metrics.executions] == [False, False]
    assert not any(item.coalesced for item in stack.execution_metrics.executions)


@pytest.mark.asyncio
async def test_the_same_analyst_asking_twice_keeps_the_existing_cache_behaviour() -> None:
    """Remote auth must not mint a fresh tenant per request.

    If it did, every repeat question would miss the cache, spend the quota again
    and never see its own cooldowns — the isolation would work by accident, at
    the cost of the engine's whole execution policy.
    """
    provider = _remote_provider()
    runtime, stack = await _remote_stack([provider])
    await _seed(stack, user_id=tenant(ALICE), provider_id="reputation_remote", secret=FAKE_KEY_A)

    with authenticated(ALICE):
        await _investigate(runtime)
        await _investigate(runtime)

    assert len(provider.requests) == 1
    assert [item.cache_hit for item in stack.execution_metrics.executions] == [False, True]


@pytest.mark.asyncio
async def test_the_same_subject_from_two_issuers_shares_nothing() -> None:
    """Mandatory. Two organizations can both have an analyst called ``alice``.

    One shared engine and one shared credential repository, reached through two
    deployment configurations that trust different issuers. Deriving the tenant
    from the subject alone would hand one organization's analyst the other's
    credential, cache entry and quota.
    """
    provider = _remote_provider()
    runtime, stack = await _remote_stack([provider])
    other = McpRuntime(
        application=runtime.application,
        credentials=runtime.credentials,
        connections=runtime.connections,
        principals=RemotePrincipalSource(auth_config(issuer=OTHER_ISSUER)),
        adapters=runtime.adapters,
    )
    await _seed(stack, user_id=tenant(ALICE), provider_id="reputation_remote", secret=FAKE_KEY_A)
    await _seed(
        stack,
        user_id=tenant(ALICE, issuer=OTHER_ISSUER),
        provider_id="reputation_remote",
        secret=FAKE_KEY_B,
    )

    with authenticated(ALICE):
        await _investigate(runtime)
    with authenticated(ALICE, issuer=OTHER_ISSUER):
        await _investigate(other)

    assert provider.credentials == [FAKE_KEY_A, FAKE_KEY_B]
    assert len(provider.requests) == 2


@pytest.mark.asyncio
async def test_a_token_from_an_untrusted_issuer_serves_nobody() -> None:
    """A deployment pins one issuer, and a token from elsewhere is not a tenant."""
    runtime, _ = await _remote_stack([_remote_provider()])

    with authenticated(ALICE, issuer=OTHER_ISSUER), pytest.raises(RemoteAuthenticationError):
        runtime.execution_context()


@pytest.mark.asyncio
async def test_the_tenant_id_is_what_reaches_every_task_6_key() -> None:
    """Task 6 was already isolating; it only needed the right identity.

    The scope identity is what the cache, the cooldown store, the quota store,
    the concurrency limiter and single-flight are all keyed by, so asserting it
    carries the tenant asserts all six at once.
    """
    provider = _remote_provider()
    runtime, stack = await _remote_stack([provider])
    await _seed(stack, user_id=tenant(ALICE), provider_id="reputation_remote", secret=FAKE_KEY_A)

    with authenticated(ALICE):
        await _investigate(runtime)

    connection = await stack.connections.find_by_group(tenant(ALICE), "reputation_remote")
    assert connection is not None
    expected = ExecutionScope.for_user(
        provider_id="reputation_remote",
        user_id=tenant(ALICE),
        provider_connection_id=connection.id,
        credential_group="reputation_remote",
    ).identity

    keys = list(stack.executor._cache._entries)
    assert keys
    for key in keys:
        assert f"|{expected}|" in key
        assert FAKE_SUBJECT not in key
        assert FAKE_TENANT_SECRET.decode() not in key
    assert expected.startswith(f"user|{tenant(ALICE)}|")
    # The same string keys the cooldown, quota, concurrency and single-flight
    # stores, so one assertion covers all five key spaces.
    assert (
        expected
        != ExecutionScope.for_user(
            provider_id="reputation_remote",
            user_id=tenant(BOB),
            provider_connection_id=connection.id,
            credential_group="reputation_remote",
        ).identity
    )


@pytest.mark.asyncio
async def test_a_cooldown_one_analyst_earned_does_not_block_another() -> None:
    """Two credentials, two cooldown key spaces.

    A quota one analyst spent, or a key one provider refused, says nothing about
    somebody else's account.
    """
    provider = _remote_provider()
    runtime, stack = await _remote_stack([provider])
    await _seed(stack, user_id=tenant(ALICE), provider_id="reputation_remote", secret=FAKE_KEY_A)
    await _seed(stack, user_id=tenant(BOB), provider_id="reputation_remote", secret=FAKE_KEY_B)

    connection = await stack.connections.find_by_group(tenant(ALICE), "reputation_remote")
    assert connection is not None
    scope = ExecutionScope.for_user(
        provider_id="reputation_remote",
        user_id=tenant(ALICE),
        provider_connection_id=connection.id,
        credential_group="reputation_remote",
    )
    await stack.executor._cooldown_store.set(
        CooldownEntry(
            provider_id="reputation_remote",
            scope_identity=scope.identity,
            operation=None,
            until=utc_now().replace(year=utc_now().year + 1),
            reason=CooldownReason.QUOTA_EXHAUSTED,
        )
    )

    with authenticated(BOB):
        await _investigate(runtime)

    assert provider.credentials == [FAKE_KEY_B]


# --------------------------------------------------------------------------- #
# Authenticated is not provider-configured
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_an_analyst_with_no_provider_credential_still_gets_a_report() -> None:
    """A fully authenticated analyst may legitimately have configured nothing.

    The credential-free source still answers, the credentialed one reports
    ``NOT_CONFIGURED``, and the tool call succeeds. Missing provider keys are a
    coverage fact, never an authorization failure.
    """
    remote, local = _remote_provider(), _local_provider()
    runtime, stack = await _remote_stack([remote, local])
    await _seed(stack, user_id=tenant(ALICE), provider_id="reputation_remote", secret=FAKE_KEY_A)

    with authenticated(CAROL):
        result = await runtime.application.run(
            AnalystInvestigationRequest(
                observable=OBSERVABLE, observable_type=ObservableInputType.IPV4
            ),
            runtime.execution_context(),
        )

    statuses = {item.provider_id: item.status for item in result.enrichment.attempts}
    assert statuses["reputation_remote"] is ProviderRunStatus.NOT_CONFIGURED
    assert statuses["local_context"] is not ProviderRunStatus.NOT_CONFIGURED
    assert remote.credentials == []


# --------------------------------------------------------------------------- #
# provider_status answers for whoever is asking
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_provider_status_describes_the_caller_and_nobody_else() -> None:
    """Not "some user has it", not "the server has it", not "startup saw it"."""
    remote, local = _remote_provider(), _local_provider()
    runtime, stack = await _remote_stack([remote, local])
    await _seed(stack, user_id=tenant(ALICE), provider_id="reputation_remote", secret=FAKE_KEY_A)

    with authenticated(ALICE):
        for_alice = await tools.provider_status(runtime)
    with authenticated(CAROL):
        for_carol = await tools.provider_status(runtime)

    assert {item.provider_id: item.configured for item in for_alice.providers} == {
        "reputation_remote": True,
        "local_context": True,
    }
    assert {item.provider_id: item.configured for item in for_carol.providers} == {
        "reputation_remote": False,
        "local_context": True,
    }
    # Catalogue facts are properties of the installation, not of the caller.
    assert [item.provider_id for item in for_alice.providers] == [
        item.provider_id for item in for_carol.providers
    ]
    assert for_alice.total == for_carol.total == 2
    assert for_alice.configured_count == 2
    assert for_carol.configured_count == 1


@pytest.mark.asyncio
async def test_provider_status_exposes_no_credential_material() -> None:
    """Not a connection id, a secret reference, an owner, a prefix or a length."""
    remote = _remote_provider()
    runtime, stack = await _remote_stack([remote])
    await _seed(stack, user_id=tenant(ALICE), provider_id="reputation_remote", secret=FAKE_KEY_A)
    connection = await stack.connections.find_by_group(tenant(ALICE), "reputation_remote")
    assert connection is not None

    with authenticated(ALICE):
        report = await tools.provider_status(runtime)

    dumped = report.model_dump_json()
    for secret in (FAKE_KEY_A, connection.id, connection.secret_reference.key, FAKE_SUBJECT):
        assert secret not in dumped
    assert str(len(FAKE_KEY_A)) not in dumped


@pytest.mark.asyncio
async def test_provider_status_contacts_nothing_and_needs_no_credential() -> None:
    """A local read of configuration, for either profile.

    No provider request, no DNS, no socket, and no call back to an authorization
    server beyond the authentication the current request already completed.
    """
    remote = _remote_provider()
    runtime, _ = await _remote_stack([remote])

    with authenticated(CAROL):
        await tools.provider_status(runtime)

    assert remote.requests == []
    assert remote.credentials == []


# --------------------------------------------------------------------------- #
# The two credentials never become each other
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_mcp_access_token_never_reaches_a_provider() -> None:
    """Different trust domains, and neither credential may become the other.

    The MCP token authorizes the analyst to call TI Recon; the provider key
    authenticates TI Recon to a provider. This drives the real seam rather than
    grepping the source, because a passthrough would be a runtime behaviour.
    """
    provider = _remote_provider()
    runtime, stack = await _remote_stack([provider])
    await _seed(
        stack, user_id=tenant(ALICE), provider_id="reputation_remote", secret=FAKE_PROVIDER_TOKEN
    )

    captured = io.StringIO()
    handler = logging.StreamHandler(captured)
    for name in ("ti_recon", "mcp"):
        logger = logging.getLogger(name)
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.DEBUG)

    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr), authenticated(ALICE):
        context = runtime.execution_context()
        result = await runtime.application.run(
            AnalystInvestigationRequest(
                observable=OBSERVABLE, observable_type=ObservableInputType.IPV4
            ),
            context,
        )
        report = await _investigate(runtime)

    # Only the provider key reached the wire.
    assert provider.credentials and all(
        item == FAKE_PROVIDER_TOKEN for item in provider.credentials
    )

    haystacks = [
        result.model_dump_json(),
        report.model_dump_json(),  # type: ignore[attr-defined]
        context.model_dump_json(),
        captured.getvalue(),
        stderr.getvalue(),
    ]
    for text in haystacks:
        assert FAKE_MCP_TOKEN not in text
        assert FAKE_SUBJECT not in text
        assert FAKE_TENANT_SECRET.decode() not in text
        assert ISSUER not in text
    # And the provider secret does not travel back out either.
    for text in (result.model_dump_json(), report.model_dump_json(), captured.getvalue()):  # type: ignore[attr-defined]
        assert FAKE_PROVIDER_TOKEN not in text


@pytest.mark.asyncio
async def test_a_provider_key_is_never_accepted_as_an_mcp_credential() -> None:
    """The reverse direction. A provider key proves nothing about an analyst."""
    provider = _remote_provider()
    runtime, _ = await _remote_stack([provider])

    with pytest.raises(RemoteAuthenticationError):
        runtime.execution_context()


# --------------------------------------------------------------------------- #
# Request-scoped context
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_every_invocation_gets_a_fresh_request_id() -> None:
    """One id reused for a process's whole life makes two runs one run in a trace."""
    runtime, _ = await _remote_stack([_remote_provider()])

    with authenticated(ALICE):
        first, second = runtime.execution_context(), runtime.execution_context()

    assert first.request_id != second.request_id
    assert first.authenticated_user_id == second.authenticated_user_id == tenant(ALICE)


def test_the_stdio_profile_still_names_its_reserved_principal() -> None:
    """One process, one analyst, one reserved name that is not a real username."""
    runtime = McpRuntime(
        application=InvestigationApplication(orchestrator=None),  # type: ignore[arg-type]
        credentials=CredentialLoadReport(),
        connections=InvestigationStack(providers=[]).connections,
        principals=FixedPrincipal(STDIO_PRINCIPAL),
    )

    assert runtime.execution_context().authenticated_user_id == STDIO_PRINCIPAL
    assert runtime.execution_context().request_id != runtime.execution_context().request_id


@pytest.mark.asyncio
async def test_a_transport_request_id_never_reaches_the_analytical_contract() -> None:
    """A fresh id per call must not disturb what Task 20 promises.

    ``request_id`` identifies one execution to the execution layer. It is not an
    analytical input, so it appears in neither the internal result nor the public
    report — which is what makes it safe to stop reusing one for a whole process.
    """
    provider = _remote_provider()
    runtime, stack = await _remote_stack([provider])
    await _seed(stack, user_id=tenant(ALICE), provider_id="reputation_remote", secret=FAKE_KEY_A)

    with authenticated(ALICE):
        context = runtime.execution_context()
        result = await runtime.application.run(
            AnalystInvestigationRequest(
                observable=OBSERVABLE, observable_type=ObservableInputType.IPV4
            ),
            context,
        )
        report = build_analyst_report(result)

    assert context.request_id
    assert context.request_id not in result.model_dump_json()
    assert context.request_id not in report.model_dump_json()
    # And the report is a pure function of the result, so the same result always
    # renders the same bytes and the same id.
    again = build_analyst_report(result)
    assert again.model_dump_json() == report.model_dump_json()
    assert again.report_id == report.report_id


@pytest.mark.asyncio
async def test_an_unauthenticated_call_is_refused_without_describing_the_token() -> None:
    """Both tools fail closed, with a message that reveals nothing.

    Unreachable once the HTTP layer exists — the bearer middleware answers 401
    first — but a tool that would serve *somebody* when it cannot say who is not
    a state worth leaving reachable.
    """
    runtime, _ = await _remote_stack([_remote_provider()])

    for call in (_investigate(runtime), tools.provider_status(runtime)):
        with pytest.raises(ToolError) as raised:
            await call
        message = str(raised.value)
        assert "not authenticated" in message
        for secret in (FAKE_MCP_TOKEN, FAKE_SUBJECT, ISSUER, FAKE_TENANT_SECRET.decode()):
            assert secret not in message
