"""Argument parsing for the analyst CLI (Task 20).

Stdlib ``argparse``: the repository has no CLI dependency and this needs
subcommands and choices, which argparse already does. Adding a framework for
two commands would be a dependency every consumer inherits.

What is deliberately not an option
----------------------------------

**No credential flags.** Not ``--api-key``, not ``--token``, not anything that
would put a secret in a process listing, a shell history file or a CI log.
Credentials are resolved per user by the credential layer, and that stays the
only route.

**No provider flags.** Not ``--use-x``, not ``--skip-y``. Which sources answer a
capability is Task 13's ranked decision; letting an interface override it would
make results depend on who typed the command.
"""

from __future__ import annotations

import argparse

from ti_recon import __version__
from ti_recon.application.models import ObservableInputType
from ti_recon.correlation.policy import PivotMode
from ti_recon.enums import InvestigationDepth

__all__ = ["OUTPUT_FORMATS", "SCHEMA_TARGETS", "build_parser"]

#: Machine output first in the help text, because it is the integration contract.
OUTPUT_FORMATS: tuple[str, ...] = ("text", "json")

SCHEMA_TARGETS: tuple[str, ...] = ("report", "request")

_DESCRIPTION = """\
External threat-intelligence enrichment and analysis for analyst triage.

Produces an assessment, the confidence that assessment is correct, and whether
the collection behind it was adequate. It does not decide what to do about the
result: blocking, alert closure and incident declaration need organisational
context this engine does not have.
"""


def build_parser() -> argparse.ArgumentParser:
    """The whole command surface.

    Two commands that do something and one that describes the contract. A larger
    surface would mostly be aliases, and every one of them is an interface
    somebody later has to keep working.
    """
    parser = argparse.ArgumentParser(
        prog="ti-recon",
        description=_DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"ti-recon {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    _add_investigate(commands)
    _add_schema(commands)
    _add_providers(commands)
    return parser


def _add_investigate(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    command = commands.add_parser(
        "investigate",
        help="investigate one observable",
        description=(
            "Investigate one observable and report what external threat intelligence "
            "says about it. Exit status reports whether the command ran, never what "
            "the verdict was."
        ),
    )
    source = command.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "observable",
        nargs="?",
        help="an address, domain, URL or file hash",
    )
    source.add_argument(
        "--file",
        metavar="PATH",
        help=(
            "hash a local file and investigate the digest. The file is read and "
            "hashed locally; its contents are never sent anywhere."
        ),
    )
    command.add_argument(
        "--type",
        dest="observable_type",
        choices=[item.value for item in ObservableInputType],
        default=ObservableInputType.AUTO.value,
        help="how to read the input (default: auto-detect, refusing what it cannot place)",
    )
    command.add_argument(
        "--depth",
        choices=[item.value for item in InvestigationDepth],
        default=InvestigationDepth.STANDARD.value,
        help="how much enrichment to buy (default: %(default)s)",
    )
    command.add_argument(
        "--pivot",
        dest="pivot_mode",
        choices=[item.value for item in PivotMode],
        default=PivotMode.RECOMMEND.value,
        help=(
            "what to do with related objects (default: %(default)s, which records "
            "them without querying third parties about them)"
        ),
    )
    command.add_argument(
        "--format",
        dest="output_format",
        choices=OUTPUT_FORMATS,
        default="text",
        help="%(default)s for an analyst, json for an application",
    )


def _add_schema(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    command = commands.add_parser(
        "schema",
        help="print the JSON Schema for the public contract",
        description=(
            "Print a JSON Schema document describing the analyst report or the "
            "request that produces one. Local only: no provider is contacted and "
            "no credential is read."
        ),
    )
    command.add_argument("target", choices=SCHEMA_TARGETS, help="which contract to describe")


def _add_providers(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    commands.add_parser(
        "providers",
        help="list locally registered providers and whether they are configured",
        description=(
            "A local diagnostic. Contacts nothing, and never prints a credential, "
            "its length or any part of its value."
        ),
    )
