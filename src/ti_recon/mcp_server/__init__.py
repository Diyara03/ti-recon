"""The MCP server over the Task 20 boundary (Tasks 21, 22).

Exposes capability, and adds no threat-intelligence reasoning of its own.

Task 22 adds the authenticated remote surface: a strict OAuth resource-server
token check, a pseudonymous tenant identity derived from the validated issuer and
subject, request-scoped identity so one shared application can serve many
analysts in isolation, and an ASGI Streamable HTTP application over the same
Task 20 stack.

The remote surface is a *factory*, not a process. Running it needs a real token
verifier, and that means an identity platform; a console entry point could only
be built today around a verifier that must never exist. The deployment injects
its own delegate.
"""

from ti_recon.mcp_server.auth import (
    RemoteAuthConfig,
    RemoteAuthenticationError,
    StrictTokenVerifier,
    resolve_remote_principal,
)
from ti_recon.mcp_server.http import (
    HEALTH_PATH,
    MCP_PATH,
    REMOTE_SCOPE,
    REMOTE_SCOPES,
    RemoteHttpApp,
    RemoteHttpConfig,
    build_remote_http_app,
)
from ti_recon.mcp_server.limits import TenantBusyError, TenantInvestigationLimiter
from ti_recon.mcp_server.models import ProviderStatusItem, ProviderStatusReport
from ti_recon.mcp_server.principal import TENANT_ID_PREFIX, RemotePrincipal, derive_tenant_id
from ti_recon.mcp_server.runtime import (
    STDIO_PRINCIPAL,
    FixedPrincipal,
    McpRuntime,
    PrincipalSource,
    RemotePrincipalSource,
    build_remote_runtime,
    build_stdio_runtime,
)
from ti_recon.mcp_server.server import (
    REPORT_SCHEMA_URI,
    REQUEST_SCHEMA_URI,
    SERVER_INSTRUCTIONS,
    SERVER_NAME,
    build_mcp_server,
    build_remote_server,
    build_stdio_server,
)

__all__ = [
    "HEALTH_PATH",
    "MCP_PATH",
    "REMOTE_SCOPE",
    "REMOTE_SCOPES",
    "REPORT_SCHEMA_URI",
    "REQUEST_SCHEMA_URI",
    "SERVER_INSTRUCTIONS",
    "SERVER_NAME",
    "STDIO_PRINCIPAL",
    "TENANT_ID_PREFIX",
    "FixedPrincipal",
    "McpRuntime",
    "PrincipalSource",
    "ProviderStatusItem",
    "ProviderStatusReport",
    "RemoteAuthConfig",
    "RemoteAuthenticationError",
    "RemoteHttpApp",
    "RemoteHttpConfig",
    "RemotePrincipal",
    "RemotePrincipalSource",
    "StrictTokenVerifier",
    "TenantBusyError",
    "TenantInvestigationLimiter",
    "build_mcp_server",
    "build_remote_http_app",
    "build_remote_runtime",
    "build_remote_server",
    "build_stdio_runtime",
    "build_stdio_server",
    "derive_tenant_id",
    "resolve_remote_principal",
]
