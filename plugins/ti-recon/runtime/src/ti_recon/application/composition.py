"""Building a runnable application from the shipped catalogues (Task 20).

The one place an interface gets a working engine. A CLI calls it now; a future
MCP server calls the same function and receives the same thing, so neither
becomes the place where the provider stack is assembled and the two cannot end
up investigating differently.

What this assembles
-------------------

Every adapter the repository ships, from :mod:`ti_recon.providers.catalog`, with
the Task 6 execution stores around it and the Task 13/19 catalogues above it.
Nothing here chooses a provider or knows what any of them do — the list comes
from the catalogue, the ranking is Task 13's, and this module could not express
a preference if it wanted to.

Credentials
-----------

Resolved through the existing per-user credential store. For a local invocation
the secrets are read from the environment variable names ``.env.example``
already documents, and written into that store — the bootstrap the repository
describes, not a second credential mechanism. A deployment serving several
analysts passes its own store and skips this entirely.

A missing credential removes nothing. The provider stays registered and Task 6
reports ``NOT_CONFIGURED`` when it is selected, because "the analyst has not set
this up" and "no such source exists" are different answers and Task 18 decides
materiality from the difference.

Zero network
------------

Building an application contacts nothing. Adapters create their clients lazily,
the executor's stores are in-memory, and no credential is validated here — so
``ti-recon providers`` and ``ti-recon schema`` stay offline commands, and the
first packet leaves only when Task 13 selects a provider and Task 6 runs it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from ti_recon.application.service import InvestigationApplication
from ti_recon.credentials import (
    ABUSE_CH_GROUP,
    VIRUSTOTAL_GROUP,
    AuthType,
    ConnectionRepository,
    CredentialManager,
    CredentialResolver,
    CredentialStatus,
    InMemoryConnectionRepository,
    InMemorySecretStore,
    SecretStore,
)
from ti_recon.execution import (
    ConcurrencyLimiter,
    InMemoryCooldownStore,
    InMemoryProviderCache,
    InMemoryQuotaStore,
    ProviderExecutor,
    ProviderPolicyRegistry,
    SystemClock,
)
from ti_recon.execution.clock import Clock
from ti_recon.investigation.composition import build_default_investigation_orchestrator
from ti_recon.providers.adapter import ProviderAdapter
from ti_recon.providers.catalog import build_default_adapters
from ti_recon.providers.registry import ProviderRegistry

__all__ = [
    "CREDENTIAL_ENVIRONMENT",
    "CredentialLoadReport",
    "build_default_application",
    "load_environment_credentials",
]

#: Credential group -> the environment variable ``.env.example`` documents.
#:
#: Keyed by *group* rather than by provider, which is what keeps one abuse.ch
#: key serving ThreatFox, URLhaus and MalwareBazaar and one VirusTotal key
#: serving GTI. Storing a secret per provider would ask an analyst for the same
#: value three times and create three copies of it.
CREDENTIAL_ENVIRONMENT: dict[str, str] = {
    VIRUSTOTAL_GROUP: "VIRUSTOTAL_API_KEY",
    ABUSE_CH_GROUP: "ABUSECH_AUTH_KEY",
    "urlscan": "URLSCAN_API_KEY",
    "greynoise": "GREYNOISE_API_KEY",
    "censys": "CENSYS_PAT",
    "hybrid_analysis": "HYBRID_ANALYSIS_API_KEY",
}

#: Non-secret per-connection configuration, read the same way.
#:
#: A Censys organization id selects the organization credit endpoint instead of
#: the user one. It is configuration rather than a credential, and it lives in
#: connection metadata exactly as it does in a deployment.
_CENSYS_ORGANIZATION_ENV: str = "CENSYS_ORGANIZATION_ID"


@dataclass(frozen=True)
class CredentialLoadReport:
    """Which groups were configured, named without their values.

    Group names only, and never a secret, a prefix, a length or a digest. The
    point of reporting anything is so an analyst can see why a provider was not
    consulted; a length is enough to help somebody guessing.
    """

    configured_groups: frozenset[str] = frozenset()

    def configured(self, credential_group: str) -> bool:
        return credential_group in self.configured_groups


async def load_environment_credentials(
    manager: CredentialManager,
    *,
    user_id: str,
    adapters: list[ProviderAdapter],
    environment: dict[str, str] | None = None,
) -> CredentialLoadReport:
    """Store whatever credentials this machine has, for one analyst.

    **One connection per credential group**, which is the repository's own
    model: the resolver looks a credential up by group, and the connection
    repository refuses a second connection for a group a user already has. That
    is what makes one abuse.ch key serve ThreatFox, URLhaus and MalwareBazaar
    and one VirusTotal key serve GTI — the analyst stores a secret once, and it
    is stored once.

    Groups are visited in a fixed order so the provider recorded against a
    shared connection is deterministic; it is only a label, since resolution
    keys on the group.

    Connections are created ``UNKNOWN`` rather than ``ACTIVE``. Nothing has
    validated them — doing so would mean a network call during startup — and
    claiming otherwise would make a typo look like a working integration.
    """
    source = os.environ if environment is None else environment
    representatives: dict[str, str] = {}
    for adapter in sorted(adapters, key=lambda item: item.descriptor.provider_id):
        descriptor = adapter.descriptor
        if descriptor.requires_credentials:
            representatives.setdefault(descriptor.credential_group, descriptor.provider_id)

    configured: set[str] = set()
    for group, provider_id in sorted(representatives.items()):
        variable = CREDENTIAL_ENVIRONMENT.get(group)
        secret = "" if variable is None else source.get(variable, "").strip()
        if not secret:
            continue
        await manager.create_connection(
            user_id=user_id,
            provider_id=provider_id,
            secret=secret,
            auth_type=AuthType.API_KEY,
            credential_group=group,
            metadata=_metadata_for(group, source),
            status=CredentialStatus.UNKNOWN,
        )
        configured.add(group)

    return CredentialLoadReport(configured_groups=frozenset(configured))


def _metadata_for(group: str, source: dict[str, str] | os._Environ[str]) -> dict[str, str]:
    """Non-secret per-connection configuration, where a group needs one."""
    if group != "censys":
        return {}
    organization = source.get(_CENSYS_ORGANIZATION_ENV, "").strip()
    return {"organization_id": organization} if organization else {}


@dataclass(frozen=True)
class _Stores:
    """The Task 6 execution state one application owns."""

    secrets: SecretStore = field(default_factory=InMemorySecretStore)
    connections: ConnectionRepository = field(default_factory=InMemoryConnectionRepository)


async def build_default_application(
    *,
    user_id: str | None = None,
    adapters: list[ProviderAdapter] | None = None,
    secrets: SecretStore | None = None,
    connections: ConnectionRepository | None = None,
    environment: dict[str, str] | None = None,
    clock: Clock | None = None,
    load_credentials: bool = True,
    max_concurrency: int = 4,
) -> tuple[InvestigationApplication, CredentialLoadReport]:
    """One application, wired to every provider the repository ships.

    Returns the credential report alongside it so a diagnostic can say which
    groups are configured without asking the store for anything it should not
    hand out.

    Everything is injectable because a deployment has its own answers: a durable
    secret store, a shared cache, a different concurrency limit. The defaults
    are what a single local invocation needs and nothing more.

    ``user_id`` names whose environment credentials are being bootstrapped, so it
    is required exactly when that bootstrap runs. A deployment serving several
    authenticated analysts passes ``load_credentials=False`` and its own stores;
    it has no single user to name, and inventing a placeholder would put a
    meaningless owner on real credential records.
    """
    if load_credentials and user_id is None:
        msg = "user_id is required when load_credentials is True"
        raise ValueError(msg)
    catalogue = build_default_adapters() if adapters is None else adapters
    stores = _Stores(
        secrets=InMemorySecretStore() if secrets is None else secrets,
        connections=InMemoryConnectionRepository() if connections is None else connections,
    )
    report = CredentialLoadReport()
    if load_credentials:
        assert user_id is not None
        report = await load_environment_credentials(
            CredentialManager(stores.secrets, stores.connections),
            user_id=user_id,
            adapters=catalogue,
            environment=environment,
        )

    resolved_clock = SystemClock() if clock is None else clock
    executor = ProviderExecutor(
        credential_resolver=CredentialResolver(stores.secrets, stores.connections),
        cache=InMemoryProviderCache(clock=resolved_clock),
        quota_store=InMemoryQuotaStore(clock=resolved_clock),
        cooldown_store=InMemoryCooldownStore(clock=resolved_clock),
        limiter=ConcurrencyLimiter(max_concurrency=max_concurrency),
        policies=ProviderPolicyRegistry(policies=[]),
        clock=resolved_clock,
    )
    orchestrator = build_default_investigation_orchestrator(
        registry=ProviderRegistry(catalogue), executor=executor, clock=resolved_clock
    )
    return InvestigationApplication(orchestrator=orchestrator), report
