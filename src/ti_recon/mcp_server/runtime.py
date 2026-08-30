"""What one MCP server process holds (Tasks 21, 22).

Built once, when the process starts. Rebuilding the Task 20 application per tool
call would re-read credentials, re-register nine adapters and throw away the
execution caches on every question — and would make two calls in one
conversation behave differently for no reason a user could see.

Identity is per request, not per process
----------------------------------------

Task 20 keys every cache, quota bucket, cooldown and credential lookup by an
authenticated user id, so this layer has to supply one. Where it comes from is
the difference between the two deployment profiles, and it is the *only*
difference: one shared application, one shared executor, one set of execution
stores, and a fresh :class:`~ti_recon.execution.models.ExecutionContext` built
for every tool invocation.

That is safe precisely because the isolation is in the key rather than in the
object. Task 6 derives its cache, quota, cooldown, concurrency and single-flight
keys from ``authenticated_user_id``, and the credential layer refuses a lookup
that does not name whose secret is wanted — so two analysts sharing one
executor share nothing at all. An application *per* user would discard the cache
for no gain; a server-wide ``current_user`` field would be a race.

* **stdio** — one process serves one analyst, so the principal is a fixed
  reserved name. It is never taken from tool input: a model-supplied identity
  would let one conversation read another's cached results and spend their
  quota, which is the whole reason the scope exists.
* **remote** — the principal is derived from the validated access token of the
  request being served, and resolution fails closed if there is none.

A reserved name rather than the operating-system account, because that identity
reaches metrics and cache keys and putting a real username there would make a
person identifiable in operational data for no analytical gain. The remote
profile goes further: what reaches those keys is a pseudonymous tenant id, never
the subject the identity provider stated.

Run-specific state stays where Task 19 already puts it: per investigation,
discarded with it. This object holds only what a process legitimately shares.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ti_recon.application.composition import CredentialLoadReport, build_default_application
from ti_recon.application.service import InvestigationApplication
from ti_recon.credentials import (
    ConnectionRepository,
    InMemoryConnectionRepository,
    InMemorySecretStore,
    SecretStore,
)
from ti_recon.execution.models import ExecutionContext
from ti_recon.mcp_server.auth import RemoteAuthConfig, resolve_remote_principal
from ti_recon.mcp_server.models import ProviderStatusItem, ProviderStatusReport
from ti_recon.planning.catalog import build_default_planning_registry
from ti_recon.providers.adapter import ProviderAdapter
from ti_recon.providers.catalog import build_default_adapters

__all__ = [
    "STDIO_PRINCIPAL",
    "FixedPrincipal",
    "McpRuntime",
    "PrincipalSource",
    "RemotePrincipalSource",
    "build_remote_runtime",
    "build_stdio_runtime",
]

#: The identity a local stdio server runs everything under.
#:
#: Reserved and process-local. One MCP server process serves one analyst, and
#: this names that principal without naming the person.
STDIO_PRINCIPAL: str = "mcp-stdio-local"


@runtime_checkable
class PrincipalSource(Protocol):
    """Where the identity for the call being served comes from.

    The one seam between the two deployment profiles. Everything downstream sees
    a string and cannot tell which profile produced it, which is what keeps the
    engine free of any notion of transport.
    """

    def user_id(self) -> str:
        """The authenticated user id for the current call, or fail closed."""
        ...


@dataclass(frozen=True)
class FixedPrincipal:
    """One process, one analyst. The stdio profile."""

    principal: str

    def user_id(self) -> str:
        return self.principal


@dataclass(frozen=True)
class RemotePrincipalSource:
    """The authenticated principal of the HTTP request being served.

    Holds no identity of its own: it reads the request-scoped access token every
    time it is asked, so two concurrent requests never observe each other's
    principal and a cached answer from a previous request cannot be reused.
    """

    config: RemoteAuthConfig

    def user_id(self) -> str:
        return resolve_remote_principal(self.config).tenant_id


@dataclass(frozen=True)
class McpRuntime:
    """The engine and the stores a server process shares between requests."""

    application: InvestigationApplication
    #: Which credential groups the *startup* environment load configured, if it
    #: ran. Group names only — never a secret, a prefix, a length or a digest.
    #: Informational: the connection repository below is what actually answers
    #: whether a given principal is configured.
    credentials: CredentialLoadReport
    #: The shared, user-keyed credential connections. Principal-scoped
    #: ``provider_status`` reads this rather than a startup snapshot, so one
    #: analyst is never told about another's configuration — or about the
    #: server's.
    connections: ConnectionRepository
    #: How to identify whoever this call belongs to.
    principals: PrincipalSource
    #: The adapters actually registered, so the diagnostic describes the
    #: catalogue that will really answer rather than a second list of its own.
    adapters: tuple[ProviderAdapter, ...] = ()

    def execution_context(self) -> ExecutionContext:
        """A fresh isolation boundary for one tool invocation.

        Fresh on every call, for two reasons. The identity has to be the one
        authenticated for *this* request — a context captured at startup would
        pin a remote server to whoever happened to connect first. And the
        request id has to be new, because it is what distinguishes one execution
        from another in outcomes and metrics; reusing one for a process's whole
        life makes two investigations indistinguishable in a trace.

        The id comes from the repository's own generator. It is never derived
        from the observable and never accepted from a caller.
        """
        return ExecutionContext(authenticated_user_id=self.principals.user_id())

    async def provider_status(self, *, user_id: str) -> ProviderStatusReport:
        """Describe this installation for one principal, contacting nothing.

        Reads descriptors, the planning profiles and *this principal's* stored
        connections. No provider is asked anything and no authorization server is
        called, so it is safe before anybody has decided to investigate.

        Catalogue facts — provider id, family, locality, capabilities, object
        types, credential group, dataset version — are properties of the
        installation and are the same for everyone. Only ``configured`` is
        personal, and it is a boolean: never a value, a prefix, a length, a
        digest, a connection id or a secret reference.
        """
        profiles = build_default_planning_registry()
        items: list[ProviderStatusItem] = []
        for adapter in sorted(self.adapters, key=lambda item: item.descriptor.provider_id):
            descriptor = adapter.descriptor
            profile = profiles.get(descriptor.provider_id)
            items.append(
                ProviderStatusItem(
                    provider_id=descriptor.provider_id,
                    source_family=descriptor.source_family,
                    locality="unknown" if profile is None else profile.locality.value,
                    capabilities=tuple(sorted(item.value for item in descriptor.capabilities)),
                    supported_object_types=tuple(
                        sorted(item.value for item in descriptor.supported_object_types)
                    ),
                    requires_credentials=descriptor.requires_credentials,
                    credential_group=descriptor.credential_group,
                    configured=await self._configured(adapter, user_id),
                    dataset_version=descriptor.dataset_version,
                )
            )
        return ProviderStatusReport(
            providers=tuple(items),
            total=len(items),
            configured_count=sum(1 for item in items if item.configured),
            local_count=sum(1 for item in items if item.locality == "local"),
            remote_count=sum(1 for item in items if item.locality == "remote"),
        )

    async def _configured(self, adapter: ProviderAdapter, user_id: str) -> bool:
        """Whether *this* principal could authenticate if this provider were selected.

        A credential-free source is always configured — there is nothing to
        configure — which is the honest answer rather than a false negative.

        Everything else is a lookup in the shared connection repository, scoped
        by user and credential group. One authoritative path: a startup snapshot
        would answer "the server has a key", and on a multi-tenant deployment
        that is a different question from the one being asked.
        """
        descriptor = adapter.descriptor
        if not descriptor.requires_credentials:
            return True
        connection = await self.connections.find_by_group(user_id, descriptor.credential_group)
        return connection is not None and connection.is_usable


async def build_stdio_runtime(*, user_id: str = STDIO_PRINCIPAL) -> McpRuntime:
    """Compose the default application once, for one local analyst.

    Every shipped provider is registered whether or not it has a credential:
    one without stays visible and reports ``NOT_CONFIGURED`` if the planner
    selects it, which is what lets Task 18 tell "the analyst has not set this
    up" from "no such source exists".

    Credentials come from this machine's environment, read once at startup, so
    changing one still means restarting the server.

    Contacts nothing. Adapters create their clients lazily and no credential is
    validated here, so starting a server is offline even though investigating
    with it is not.
    """
    adapters = build_default_adapters()
    connections = InMemoryConnectionRepository()
    application, credentials = await build_default_application(
        user_id=user_id,
        adapters=adapters,
        secrets=InMemorySecretStore(),
        connections=connections,
    )
    return McpRuntime(
        application=application,
        credentials=credentials,
        connections=connections,
        principals=FixedPrincipal(user_id),
        adapters=tuple(adapters),
    )


async def build_remote_runtime(
    *,
    auth: RemoteAuthConfig,
    secrets: SecretStore | None = None,
    connections: ConnectionRepository | None = None,
    adapters: list[ProviderAdapter] | None = None,
    max_concurrency: int = 4,
) -> McpRuntime:
    """Compose one application for many authenticated analysts.

    **The process environment is never read for provider credentials here**, and
    that is the point of the profile rather than an oversight. A server's
    environment is global to the server: loading it would hand every
    authenticated analyst the same keys, spend one quota on everybody's behalf,
    share one abuse.ch fair-use block between strangers, and use a provider
    account under terms nobody agreed to. Each analyst's provider credentials
    belong to that analyst, and reach the shared stores through the credential
    layer — an organization-wide shared credential would be a deliberate
    deployment mode, never a default nobody chose.

    Durable, encrypted credential storage and the authenticated path that fills
    it are Task 23. The stores are injectable precisely so this function does not
    have to know which one a deployment uses.

    Contacts nothing, and authenticates nobody: identity is resolved per request.
    """
    catalogue = build_default_adapters() if adapters is None else adapters
    repository = InMemoryConnectionRepository() if connections is None else connections
    application, credentials = await build_default_application(
        adapters=catalogue,
        secrets=InMemorySecretStore() if secrets is None else secrets,
        connections=repository,
        load_credentials=False,
        max_concurrency=max_concurrency,
    )
    return McpRuntime(
        application=application,
        credentials=credentials,
        connections=repository,
        principals=RemotePrincipalSource(auth),
        adapters=tuple(catalogue),
    )
