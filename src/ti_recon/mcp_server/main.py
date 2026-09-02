"""The ``ti-recon-mcp`` process (Task 21).

A server, not a command. It speaks MCP over stdin and stdout and is started by a
host rather than by a person, which is why it has no options: no host, no port,
no provider flags, and no credential arguments. Credentials are resolved per
user by the credential layer, exactly as they are for the CLI.

**stdout belongs to the protocol.** Nothing here prints. A banner, a progress
line or a stray debug message on stdout corrupts the JSON-RPC stream and the
host simply fails to connect — so diagnostics go to stderr, and the logging
configuration happens here, in the thing that owns a process, rather than in the
reusable factory where it would silently replace an embedding application's
handlers.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

from ti_recon.mcp_server.runtime import build_stdio_runtime
from ti_recon.mcp_server.server import build_stdio_server

__all__ = ["main"]

#: Quiet by default. A server whose stderr is full of INFO lines makes a host's
#: log unreadable, and the useful failures are warnings and above.
_DEFAULT_LEVEL = "WARNING"

#: The variable the repository already documents for log level.
_LEVEL_ENV = "TI_RECON_LOG_LEVEL"


def _configure_logging() -> None:
    """Send diagnostics to stderr, and never to stdout.

    Explicit rather than relying on the root logger's default, which writes to
    stderr only because ``basicConfig`` has not been called: a library that
    called it first could attach a stdout handler and break the transport.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    for name in ("ti_recon", "mcp"):
        logger = logging.getLogger(name)
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(os.environ.get(_LEVEL_ENV, _DEFAULT_LEVEL).upper())


def main() -> None:
    """Compose the default runtime and serve MCP over stdio.

    The runtime is built once, before the transport starts: every shipped
    provider is registered and whatever credentials this machine has are loaded.
    Building contacts nothing — adapters create their clients lazily — so a
    server starts cleanly on a machine with no keys and reports what is missing
    through ``provider_status`` and through coverage.

    Built through :func:`build_stdio_server` rather than the generic factory, so
    the process serves the *local* profile: all three tools, and instructions
    that describe how a credential is configured on this machine. The generic
    factory defaults to the deployment-neutral core, which is the honest default
    for a caller that has not said which profile it is — and the wrong thing for
    a process that knows.
    """
    _configure_logging()
    runtime = asyncio.run(build_stdio_runtime())
    build_stdio_server(runtime).run()
