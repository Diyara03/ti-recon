"""The local MCP server over the Task 20 boundary (Task 21).

Exposes capability, and adds no threat-intelligence reasoning of its own.
"""

from ti_recon.mcp_server.models import ProviderStatusItem, ProviderStatusReport
from ti_recon.mcp_server.runtime import STDIO_PRINCIPAL, McpRuntime, build_stdio_runtime
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
    "McpRuntime",
    "ProviderStatusItem",
    "ProviderStatusReport",
    "build_mcp_server",
    "build_stdio_runtime",
]
