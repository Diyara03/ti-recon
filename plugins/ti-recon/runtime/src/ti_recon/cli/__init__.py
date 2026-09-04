"""The analyst command line (Task 20).

A thin shell over the application service. Every command here is reachable
programmatically without a terminal, which is what lets a future MCP server
consume the same contract instead of parsing this output.
"""

from ti_recon.cli.main import (
    EXIT_INTERRUPTED,
    EXIT_OK,
    EXIT_OPERATIONAL_ERROR,
    EXIT_USAGE_ERROR,
    main,
    run,
)
from ti_recon.cli.parser import build_parser

__all__ = [
    "EXIT_INTERRUPTED",
    "EXIT_OK",
    "EXIT_OPERATIONAL_ERROR",
    "EXIT_USAGE_ERROR",
    "build_parser",
    "main",
    "run",
]
