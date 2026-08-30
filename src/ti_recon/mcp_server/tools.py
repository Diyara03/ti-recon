"""What the three tools actually do (Task 21).

Each one builds a Task 20 request, calls the Task 20 application and returns the
Task 20 report. There is no analysis here and no room for any: the verdict is
Task 17's, the readiness is Task 18's, the provider choice is Task 13's, and
this module could not express an opinion about any of them if it wanted to.

Errors
------

Two kinds, and the distinction matters to a model trying to recover.

*Anticipated* failures — an observable nobody can parse, a path that is not a
regular file, a flag combination that cannot mean anything — become
:class:`ToolError` carrying a plain message. The SDK returns it as
``is_error=True`` with that text for the model to read, and logs it at INFO
without a traceback.

*Unexpected* failures are converted here, deliberately, into a generic message.
Left to escape, the SDK logs the full traceback at ERROR — and a badly behaved
dependency can put a credential or a provider payload in an exception string.
The type name is safe to log; the message is not, so it is not logged.

``asyncio.CancelledError`` is a ``BaseException`` and is therefore untouched by
both handlers. Cancellation propagates rather than becoming an analytical
result.

Identity
--------

Every tool resolves the principal itself, per call, and every investigation gets
a fresh execution context. Nothing here accepts an identity as an argument: a
model sets its own arguments, so a ``user_id`` field would be an identity from
nobody. A call with no establishable principal is refused with a fixed message
that describes nothing about the token — and once the HTTP layer exists it never
reaches here, because the bearer middleware has already answered 401.
"""

from __future__ import annotations

import logging
from pathlib import Path

from mcp.server.mcpserver.exceptions import ToolError
from pydantic import ValidationError

from ti_recon.application.models import AnalystInvestigationRequest, ObservableInputType
from ti_recon.application.service import InvalidObservableError, hash_local_file
from ti_recon.correlation.policy import PivotMode
from ti_recon.enums import InvestigationDepth
from ti_recon.execution.models import ExecutionContext
from ti_recon.investigation.engine import InvestigationError
from ti_recon.mcp_server.auth import RemoteAuthenticationError
from ti_recon.mcp_server.limits import TenantBusyError
from ti_recon.mcp_server.models import ProviderStatusReport
from ti_recon.mcp_server.runtime import McpRuntime
from ti_recon.reporting.models import AnalystInvestigationReport

__all__ = ["investigate_file", "investigate_observable", "provider_status"]

_LOGGER = logging.getLogger("ti_recon.mcp_server")

#: What a model is told when something failed that it cannot fix.
#:
#: Deliberately says nothing about the failure. The alternative is forwarding an
#: exception string this process did not write and cannot vouch for.
_INTERNAL_FAILURE = (
    "The investigation could not be completed because of an internal application error."
)

#: What a caller is told when they already have one running.
#:
#: Says nothing about anybody else's load, how long the other call has been
#: going, or how many the server is handling. Only remote deployments have a
#: limiter at all — over stdio there is one conversation and nothing to collide.
_ALREADY_RUNNING = (
    "Another investigation is already running for this account. Try again after it completes."
)


async def investigate_observable(
    runtime: McpRuntime,
    *,
    observable: str,
    observable_type: ObservableInputType,
    depth: InvestigationDepth,
    pivot_mode: PivotMode,
    allow_remote_pivot_lookup: bool,
) -> AnalystInvestigationReport:
    """One investigation, through the public application boundary."""
    request = _request(
        observable=observable,
        observable_type=observable_type,
        depth=depth,
        pivot_mode=pivot_mode,
        allow_remote_pivot_lookup=allow_remote_pivot_lookup,
    )
    return await _investigate(runtime, request)


async def investigate_file(
    runtime: McpRuntime,
    *,
    path: str,
    depth: InvestigationDepth,
    pivot_mode: PivotMode,
    allow_remote_pivot_lookup: bool,
) -> AnalystInvestigationReport:
    """Hash a local file and investigate the digest.

    The hashing, the regular-file check and the streaming are all Task 20's.
    Nothing here reads bytes, and nothing here reimplements a path validator —
    a second one would be a second set of rules to get subtly wrong.
    """
    try:
        digest = hash_local_file(Path(path))
    except InvalidObservableError as error:
        raise ToolError(str(error)) from error

    request = _request(
        observable=digest,
        observable_type=ObservableInputType.FILE_HASH,
        depth=depth,
        pivot_mode=pivot_mode,
        allow_remote_pivot_lookup=allow_remote_pivot_lookup,
    )
    return await _investigate(runtime, request)


async def provider_status(runtime: McpRuntime) -> ProviderStatusReport:
    """What this installation is set up to consult, for whoever is asking.

    Contacts nothing — no provider, no DNS, no authorization server. The
    catalogue is shared; ``configured`` is answered from the caller's own stored
    connections, so one analyst is never told about another's setup or about the
    server's.
    """
    return await runtime.provider_status(user_id=_principal(runtime))


def _principal(runtime: McpRuntime) -> str:
    """Who this call belongs to, or a plain refusal.

    Fails closed. There is no fallback to the stdio principal, to the OAuth
    client id or to an anonymous tenant: serving one identity's work under
    another's is exactly what the scope exists to prevent.

    The message is fixed and describes nothing about the token — and once the
    HTTP layer exists this is unreachable, because the bearer middleware has
    already answered 401.
    """
    try:
        return runtime.principals.user_id()
    except RemoteAuthenticationError as error:
        raise ToolError(str(error)) from None


def _context(runtime: McpRuntime) -> ExecutionContext:
    """A fresh isolation boundary for one invocation, or a plain refusal."""
    try:
        return runtime.execution_context()
    except RemoteAuthenticationError as error:
        raise ToolError(str(error)) from None


def _request(**fields: object) -> AnalystInvestigationRequest:
    """Build the public request, letting Task 20 do the validating.

    The remote-pivot rule lives on the request model and is not restated here:
    two copies of a validation rule is one copy too many, and the second is
    always the one that goes stale.
    """
    try:
        return AnalystInvestigationRequest(**fields)  # type: ignore[arg-type]
    except ValidationError as error:
        raise ToolError(_readable(error)) from error
    except ValueError as error:
        raise ToolError(str(error)) from error


def _readable(error: ValidationError) -> str:
    """A pydantic failure as one line a model can act on.

    The default rendering is multi-line with a docs URL and an input echo. The
    echo is the part worth removing: it repeats whatever was submitted back into
    a message that gets logged.
    """
    messages = [item["msg"].removeprefix("Value error, ") for item in error.errors()]
    return "; ".join(messages)[:300] or "the request was not valid"


async def _investigate(
    runtime: McpRuntime, request: AnalystInvestigationRequest
) -> AnalystInvestigationReport:
    """Run it, and convert only the failures a model could not have foreseen.

    A provider that was unconfigured, throttled, out of quota or simply broken
    is **not** a failure here: Task 19 still returns a report, Task 18 records
    what that cost the coverage, and the tool call succeeds. Turning a provider
    problem into a tool error would hide a real assessment behind an
    infrastructure complaint.
    """
    # Built before the guard, and per call: the identity has to be the one
    # authenticated for *this* request, and a failure to establish one is an
    # authentication problem rather than an investigation that went wrong.
    context = _context(runtime)
    limiter = runtime.investigations
    if limiter is None:
        return await _run(runtime, request, context)
    try:
        async with limiter.hold(context.authenticated_user_id):
            return await _run(runtime, request, context)
    except TenantBusyError:
        # A refusal the caller can act on, so a plain message rather than the
        # generic internal one. It names nothing about them or about anybody
        # else's load.
        raise ToolError(_ALREADY_RUNNING) from None


async def _run(
    runtime: McpRuntime,
    request: AnalystInvestigationRequest,
    context: ExecutionContext,
) -> AnalystInvestigationReport:
    """The investigation itself, with only the failures a model could not foresee
    converted."""
    try:
        return await runtime.application.investigate(request, context)
    except InvalidObservableError as error:
        # Reachable for input that parses as a string but is not an observable.
        raise ToolError(str(error)) from error
    except InvestigationError as error:
        # A structural fault in the workflow. Reported as a failure rather than
        # dressed up as an inconclusive assessment somebody might act on — and
        # with our own message, because the engine's may name internals.
        _LOGGER.error("investigation failed structurally: %s", type(error).__name__)
        raise ToolError(_INTERNAL_FAILURE) from error
    except Exception as error:
        # The type is safe to log. The message is not: a dependency can put a
        # credential or a raw provider payload in it, and the SDK would log the
        # whole traceback at ERROR if this escaped.
        _LOGGER.error("investigation raised %s", type(error).__name__)
        raise ToolError(_INTERNAL_FAILURE) from None
