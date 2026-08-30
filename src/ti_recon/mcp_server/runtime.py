"""What one MCP server process holds (Task 21).

Built once, when the process starts. Rebuilding the Task 20 application per tool
call would re-read credentials, re-register nine adapters and throw away the
execution caches on every question — and would make two calls in one
conversation behave differently for no reason a user could see.

One principal per process
-------------------------

Task 20 keys every cache, quota bucket, cooldown and credential lookup by an
authenticated user id, so this layer has to supply one. Over local stdio there
is exactly one: the person who started the server. A fixed reserved name is used
rather than the operating-system account, because that identity reaches metrics
and cache keys, and putting a real username there would make a person
identifiable in operational data for no analytical gain.

**It is never taken from tool input.** A model-supplied identity would let one
conversation read another's cached results and spend their quota, which is the
whole reason the scope exists. Authenticated multi-principal deployment is a
later task with a real identity to map.

Run-specific state stays where Task 19 already puts it: per investigation,
discarded with it. This object holds only what a process legitimately shares.
"""

from __future__ import annotations

from dataclasses import dataclass

from ti_recon.application.composition import CredentialLoadReport, build_default_application
from ti_recon.application.service import InvestigationApplication
from ti_recon.execution.models import ExecutionContext
from ti_recon.mcp_server.models import ProviderStatusItem, ProviderStatusReport
from ti_recon.planning.catalog import build_default_planning_registry
from ti_recon.providers.adapter import ProviderAdapter
from ti_recon.providers.catalog import build_default_adapters

__all__ = ["STDIO_PRINCIPAL", "McpRuntime", "build_stdio_runtime"]

#: The identity a local stdio server runs everything under.
#:
#: Reserved and process-local. One MCP server process serves one analyst, and
#: this names that principal without naming the person.
STDIO_PRINCIPAL: str = "mcp-stdio-local"


@dataclass(frozen=True)
class McpRuntime:
    """The engine and the configuration snapshot a server process shares."""

    application: InvestigationApplication
    #: Which credential groups were configured when this process started.
    #: Group names only — never a secret, a prefix, a length or a digest.
    credentials: CredentialLoadReport
    #: The isolation boundary every investigation in this process runs under.
    context: ExecutionContext
    #: The adapters actually registered, so the diagnostic describes the
    #: catalogue that will really answer rather than a second list of its own.
    adapters: tuple[ProviderAdapter, ...] = ()

    def provider_status(self) -> ProviderStatusReport:
        """Describe this installation, contacting nothing.

        Reads descriptors, the planning profiles and the startup credential
        snapshot. No provider is asked anything, so this is safe to call before
        anybody has decided to investigate.
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
                    configured=self._configured(adapter),
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

    def _configured(self, adapter: ProviderAdapter) -> bool:
        """Whether this provider could authenticate if it were selected.

        A credential-free source is always configured — there is nothing to
        configure — which is the honest answer rather than a false negative.
        """
        descriptor = adapter.descriptor
        if not descriptor.requires_credentials:
            return True
        return self.credentials.configured(descriptor.credential_group)


async def build_stdio_runtime(*, user_id: str = STDIO_PRINCIPAL) -> McpRuntime:
    """Compose the default application once, for one server process.

    Every shipped provider is registered whether or not it has a credential:
    one without stays visible and reports ``NOT_CONFIGURED`` if the planner
    selects it, which is what lets Task 18 tell "the analyst has not set this
    up" from "no such source exists".

    Contacts nothing. Adapters create their clients lazily and no credential is
    validated here, so starting a server is offline even though investigating
    with it is not.
    """
    adapters = build_default_adapters()
    application, credentials = await build_default_application(user_id=user_id, adapters=adapters)
    return McpRuntime(
        application=application,
        credentials=credentials,
        context=ExecutionContext(authenticated_user_id=user_id),
        adapters=tuple(adapters),
    )
