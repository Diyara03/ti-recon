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
from ti_recon.mcp_server.server import LocalCredentialSetup, build_stdio_server

__all__ = ["CREDENTIAL_SETUP_ENV", "main"]

#: Quiet by default. A server whose stderr is full of INFO lines makes a host's
#: log unreadable, and the useful failures are warnings and above.
_DEFAULT_LEVEL = "WARNING"

#: The variable the repository already documents for log level.
_LEVEL_ENV = "TI_RECON_LOG_LEVEL"

#: How the credentials in this process's environment got there.
#:
#: Set by whatever started the process — the TI Recon Claude Code plugin sets it
#: to ``claude-plugin`` in its ``.mcp.json`` — and absent for an analyst who
#: started the server from their own environment. It selects which true
#: description of the credential step a client is given, and nothing else: the
#: engine, the tool surface and credential resolution never read it.
CREDENTIAL_SETUP_ENV = "TI_RECON_CREDENTIAL_SETUP"


class _StartupError(SystemExit):
    """A configuration the process refuses to start under.

    Refused before the transport opens, with one line on stderr: a server that
    described its credential step wrongly would send an analyst to a setting
    the plugin overwrites, so an unrecognised value is not defaulted.
    """

    def __init__(self, message: str) -> None:
        sys.stderr.write(f"ti-recon-mcp: {message}\n")
        super().__init__(2)


def _credential_setup() -> LocalCredentialSetup:
    """Read the credential-setup profile, defaulting to the environment case.

    An unrecognised value fails closed. The message names the variable and the
    accepted values and never echoes what was set — a misconfiguration is not a
    secret, but the habit of never printing environment contents is.
    """
    raw = os.environ.get(CREDENTIAL_SETUP_ENV, "").strip()
    if not raw:
        return LocalCredentialSetup.ENVIRONMENT
    try:
        return LocalCredentialSetup(raw)
    except ValueError:
        accepted = ", ".join(item.value for item in LocalCredentialSetup)
        raise _StartupError(
            f"{CREDENTIAL_SETUP_ENV} must be one of: {accepted}; refusing to start"
        ) from None


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
    credential_setup = _credential_setup()
    runtime = asyncio.run(build_stdio_runtime())
    build_stdio_server(runtime, credential_setup=credential_setup).run()
