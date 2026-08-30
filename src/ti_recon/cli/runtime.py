"""Composing a runnable engine for a local invocation (Task 20).

Deployment configuration, kept out of the application service on purpose: the
service takes an orchestrator and does not care where it came from, which is why
a test can hand it a fully faked stack and get the identical report.

What a local CLI can compose
----------------------------

Adapters that need neither a credential nor a network client. In the shipped
catalogue that is the local dataset provider, which answers from a pinned
snapshot inside the package — so ``ti-recon investigate`` does something honest
on a machine with no keys configured at all, and discloses nothing to anybody
while doing it.

Remote providers are deliberately *not* constructed here. Each needs an HTTP
client, a base URL and a resolved per-user credential, and choosing those is a
deployment decision — the kind that belongs in whatever configures a service,
not in an argument parser. A deployment that has them builds its own registry
and executor and injects the orchestrator; nothing in the application layer
changes.

The consequence is stated rather than hidden: with no remote provider
registered, coverage says so. Task 18 reports the capabilities nobody could
serve, and the report shows an investigation that consulted what it had.
"""

from __future__ import annotations

from ti_recon.credentials import (
    CredentialResolver,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.execution import (
    ConcurrencyLimiter,
    ExecutionContext,
    InMemoryCooldownStore,
    InMemoryProviderCache,
    InMemoryQuotaStore,
    ProviderExecutor,
    ProviderPolicyRegistry,
    SystemClock,
)
from ti_recon.investigation.composition import build_default_investigation_orchestrator
from ti_recon.investigation.engine import InvestigationOrchestrator
from ti_recon.providers.adapter import ProviderAdapter
from ti_recon.providers.misp_warninglists import MispWarningListsAdapter
from ti_recon.providers.registry import ProviderRegistry

__all__ = ["LOCAL_CLI_USER", "build_local_adapters", "build_local_context", "build_local_runtime"]

#: The identity a local invocation runs under.
#:
#: Every execution store below is keyed by this, so it has to be *something*.
#: A fixed local name rather than an operating-system user: it is a cache and
#: quota partition, and putting a real account name into a key that is also a
#: metrics dimension would make a person identifiable in operational data for no
#: analytical gain. A deployment serving several analysts supplies its own.
LOCAL_CLI_USER: str = "local-cli"


def build_local_adapters() -> list[ProviderAdapter]:
    """Every shipped adapter a local invocation can construct safely.

    Credential-free and network-free. An adapter that would need a key or an
    endpoint is absent rather than registered-and-broken: a provider that cannot
    answer should be a coverage fact, not a failed call in every investigation.
    """
    return [MispWarningListsAdapter()]


def build_local_context(*, user_id: str = LOCAL_CLI_USER) -> ExecutionContext:
    """The isolation boundary for one local run."""
    return ExecutionContext(authenticated_user_id=user_id)


def build_local_runtime(
    adapters: list[ProviderAdapter] | None = None,
) -> InvestigationOrchestrator:
    """One orchestrator, wired to the shipped catalogues and in-memory stores.

    In-memory throughout, because a CLI invocation is one process with no next
    time: a cache that outlived it would be persistence, which this task does
    not implement and which would need its own isolation story.
    """
    registry = ProviderRegistry(build_local_adapters() if adapters is None else adapters)
    clock = SystemClock()
    secrets = InMemorySecretStore()
    connections = InMemoryConnectionRepository()
    executor = ProviderExecutor(
        credential_resolver=CredentialResolver(secrets, connections),
        cache=InMemoryProviderCache(clock=clock),
        quota_store=InMemoryQuotaStore(clock=clock),
        cooldown_store=InMemoryCooldownStore(clock=clock),
        limiter=ConcurrencyLimiter(max_concurrency=4),
        policies=ProviderPolicyRegistry(policies=[]),
        clock=clock,
    )
    return build_default_investigation_orchestrator(registry=registry, executor=executor)
