"""The MCP server over the Task 20 boundary (Tasks 21, 22).

Exposes capability, and adds no threat-intelligence reasoning of its own.

Task 22 adds the remote authentication primitives: a strict OAuth
resource-server token check, a pseudonymous tenant identity derived from the
validated issuer and subject, and request-scoped identity so one shared
application can serve many authenticated analysts in isolation. There is no HTTP
entry point yet — the transport is built on this boundary, not before it.
"""

from ti_recon.mcp_server.auth import (
    RemoteAuthConfig,
    RemoteAuthenticationError,
    StrictTokenVerifier,
    resolve_remote_principal,
)
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
)

__all__ = [
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
    "RemotePrincipal",
    "RemotePrincipalSource",
    "StrictTokenVerifier",
    "build_mcp_server",
    "build_remote_runtime",
    "build_stdio_runtime",
    "derive_tenant_id",
    "resolve_remote_principal",
]
