"""The process, and the two error paths a unit suite can reach (Task 21).

``main`` starts a server and blocks, so the unit suite cannot call it — the
installed stdio smoke exercises that. What it can and should check is everything
around it: that the module imports, that logging lands on stderr and not on the
stream the protocol owns, and that the tool errors an unusual input produces are
the ones a model can act on.
"""

from __future__ import annotations

import logging
import sys

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from ti_recon.application.composition import CredentialLoadReport
from ti_recon.execution.models import ExecutionContext
from ti_recon.mcp_server import main as entry_point
from ti_recon.mcp_server import tools
from ti_recon.mcp_server.models import ProviderStatusReport
from ti_recon.mcp_server.runtime import STDIO_PRINCIPAL, McpRuntime


@pytest.fixture
def restored_logging():
    """Save and restore the loggers the entry point owns.

    ``main`` legitimately reconfigures them because it owns a process. A test is
    not a process, and leaving them reconfigured would detach logging for
    everything that ran afterwards — the leak Task 20 already learned about
    once.
    """
    saved = {
        name: (
            list(logging.getLogger(name).handlers),
            logging.getLogger(name).propagate,
            logging.getLogger(name).level,
        )
        for name in ("ti_recon", "mcp")
    }
    yield
    for name, (handlers, propagate, level) in saved.items():
        logger = logging.getLogger(name)
        logger.handlers, logger.propagate, logger.level = handlers, propagate, level


def test_logging_is_attached_to_stderr_and_never_to_stdout(restored_logging) -> None:
    """stdout belongs to the protocol.

    A handler on stdout would interleave log lines with JSON-RPC frames, and the
    host would fail to connect with no indication why.
    """
    entry_point._configure_logging()

    for name in ("ti_recon", "mcp"):
        logger = logging.getLogger(name)
        assert logger.handlers
        for handler in logger.handlers:
            assert isinstance(handler, logging.StreamHandler)
            assert handler.stream is sys.stderr
            assert handler.stream is not sys.stdout
        # Detached from the root logger, whose handlers this process does not own.
        assert logger.propagate is False


def test_the_log_level_is_quiet_by_default_and_configurable(restored_logging, monkeypatch) -> None:
    """A server whose stderr is full of INFO makes a host's log unreadable."""
    monkeypatch.delenv("TI_RECON_LOG_LEVEL", raising=False)
    entry_point._configure_logging()
    assert logging.getLogger("ti_recon").level == logging.WARNING

    monkeypatch.setenv("TI_RECON_LOG_LEVEL", "debug")
    entry_point._configure_logging()
    assert logging.getLogger("ti_recon").level == logging.DEBUG


def test_the_console_entry_point_is_importable_and_callable() -> None:
    """The name pyproject wires to must exist and be a function.

    A typo here fails only when a host tries to start the server, which is the
    worst place to discover it.
    """
    assert callable(entry_point.main)


# --------------------------------------------------------------------------- #
# The remaining tool error paths
# --------------------------------------------------------------------------- #


def _runtime(application: object) -> McpRuntime:
    return McpRuntime(
        application=application,  # type: ignore[arg-type]
        credentials=CredentialLoadReport(),
        context=ExecutionContext(authenticated_user_id=STDIO_PRINCIPAL),
    )


def test_a_field_level_validation_failure_becomes_one_readable_line() -> None:
    """Pydantic's default rendering is multi-line and echoes the input.

    The echo is the part worth removing: it repeats whatever was submitted into
    a message that then gets logged.
    """
    with pytest.raises(ToolError) as raised:
        tools._request(observable="")

    message = str(raised.value)
    assert "\n" not in message
    assert len(message) <= 300
    assert "For further information" not in message


@pytest.mark.asyncio
async def test_a_structural_workflow_failure_is_reported_as_a_failure() -> None:
    """Not dressed up as an inconclusive assessment somebody might act on.

    The engine's own message may name internals, so the client gets ours.
    """
    from ti_recon.investigation.engine import InvestigationError

    class _Broken:
        async def investigate(self, request: object, context: object) -> object:
            msg = "stages describe different observables: internal/detail"
            raise InvestigationError(msg)

    with pytest.raises(ToolError) as raised:
        await tools._investigate(_runtime(_Broken()), tools._request(observable="8.8.8.8"))

    message = str(raised.value)
    assert "internal application error" in message
    assert "internal/detail" not in message


def test_provider_status_is_empty_and_honest_with_no_adapters() -> None:
    """A runtime holding nothing reports nothing, rather than guessing."""
    report = tools.provider_status(_runtime(object()))

    assert isinstance(report, ProviderStatusReport)
    assert report.providers == ()
    assert report.total == 0
    assert report.configured_count == 0
