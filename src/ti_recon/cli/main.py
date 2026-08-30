"""The command entry point (Task 20).

A thin shell over :class:`~ti_recon.application.service.InvestigationApplication`.
Everything analytical happens below it, and everything below it is reachable
without a terminal — which is the point: a future MCP server calls the same
service and receives the same report, rather than parsing text this module
printed.

Two contracts this module owns
------------------------------

**Streams.** In JSON mode stdout carries exactly one JSON document and nothing
else. Every log line, warning and error goes to stderr. A single stray print
onto stdout would make the output unparseable for the automation the format
exists to serve.

**Exit status.** It reports whether the *command* ran, never what the verdict
was. A completed investigation exits 0 whether it found malware or nothing at
all: encoding maliciousness in the status would make ``&&`` in a shell script
mean something nobody intended, and would make a finding indistinguishable from
a crash.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final, TextIO

from ti_recon.application.models import AnalystInvestigationRequest, ObservableInputType
from ti_recon.application.service import (
    InvalidObservableError,
    InvestigationApplication,
    hash_local_file,
)
from ti_recon.cli.parser import build_parser
from ti_recon.cli.runtime import build_local_context, build_local_runtime
from ti_recon.correlation.policy import PivotMode
from ti_recon.enums import InvestigationDepth
from ti_recon.investigation.engine import InvestigationError
from ti_recon.reporting.schema import report_json_schema, request_json_schema
from ti_recon.reporting.text import render_text, safe_text

__all__ = [
    "EXIT_INTERRUPTED",
    "EXIT_OK",
    "EXIT_OPERATIONAL_ERROR",
    "EXIT_USAGE_ERROR",
    "main",
    "run",
]

#: The command completed. Says nothing about the verdict.
#:
#: A finished investigation reporting MALICIOUS, SUSPICIOUS, INCONCLUSIVE or
#: LIKELY_BENIGN all exit here, and so does an UNRESOLVED readiness: each is an
#: answer the engine produced successfully.
EXIT_OK: Final[int] = 0

#: Something went wrong that is not the caller's syntax: a broken configuration,
#: a structural fault in the workflow, an unexpected failure.
EXIT_OPERATIONAL_ERROR: Final[int] = 1

#: The command line itself was wrong — an unknown flag, a missing argument, an
#: observable the engine cannot parse. Conventionally 2, and argparse already
#: uses it for the flags it rejects itself.
EXIT_USAGE_ERROR: Final[int] = 2

#: Interrupted. The conventional shell encoding of SIGINT.
EXIT_INTERRUPTED: Final[int] = 130

_LOGGER = logging.getLogger("ti_recon.cli")


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the console script."""
    return run(argv, stdout=sys.stdout, stderr=sys.stderr)


def run(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO,
    stderr: TextIO,
    application: InvestigationApplication | None = None,
) -> int:
    """The whole command, with its streams injected.

    Injected so a test can prove what landed on which stream — the JSON contract
    is a claim about stdout specifically, and a test that captured both together
    could not tell the difference.
    """
    _configure_logging(stderr)
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(stderr)
        return EXIT_USAGE_ERROR

    try:
        return _dispatch(args, stdout=stdout, stderr=stderr, application=application)
    except KeyboardInterrupt:
        # No traceback and no report: the caller went away, and printing a
        # partial result would present an investigation that never finished.
        print("interrupted", file=stderr)
        return EXIT_INTERRUPTED


def _dispatch(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
    application: InvestigationApplication | None,
) -> int:
    match args.command:
        case "schema":
            return _schema(args, stdout=stdout)
        case "providers":
            return _providers(stdout=stdout)
        case _:
            return _investigate(args, stdout=stdout, stderr=stderr, application=application)


def _configure_logging(stderr: TextIO) -> None:
    """Send diagnostics to stderr, and never to stdout.

    Configured here rather than left to the root logger's default, which writes
    to stderr only by accident of ``basicConfig`` not having been called; a
    library elsewhere calling it first could redirect records onto stdout and
    corrupt the JSON document.
    """
    handler = logging.StreamHandler(stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger("ti_recon")
    root.handlers = [handler]
    root.propagate = False
    if root.level == logging.NOTSET:
        root.setLevel(logging.WARNING)


def _schema(args: argparse.Namespace, *, stdout: TextIO) -> int:
    """One schema document, and nothing else."""
    schema = report_json_schema() if args.target == "report" else request_json_schema()
    _write_json(schema, stdout)
    return EXIT_OK


def _providers(*, stdout: TextIO) -> int:
    """What is registered locally, as a diagnostic.

    Contacts nothing. Reports whether a provider *requires* a credential, which
    is a property of the descriptor — never whether one is present, how long it
    is, or any part of its value.
    """
    from ti_recon.cli.runtime import build_local_adapters

    rows = [
        {
            "provider_id": adapter.descriptor.provider_id,
            "source_family": adapter.descriptor.source_family,
            "requires_credentials": adapter.descriptor.requires_credentials,
            "capabilities": sorted(item.value for item in adapter.descriptor.capabilities),
            "object_types": sorted(
                item.value for item in adapter.descriptor.supported_object_types
            ),
            "dataset_version": adapter.descriptor.dataset_version,
        }
        for adapter in sorted(build_local_adapters(), key=lambda item: item.descriptor.provider_id)
    ]
    _write_json({"providers": rows}, stdout)
    return EXIT_OK


def _investigate(
    args: argparse.Namespace,
    *,
    stdout: TextIO,
    stderr: TextIO,
    application: InvestigationApplication | None,
) -> int:
    """Run one investigation and render it.

    Input problems fail here, before anything is asked of anybody: an
    unparseable observable has not been investigated, and reporting it as an
    inconclusive result would invent an answer.
    """
    try:
        request = _request_from(args)
    except (InvalidObservableError, ValueError, OSError) as error:
        print(f"error: {safe_text(str(error), limit=300)}", file=stderr)
        return EXIT_USAGE_ERROR

    service = (
        InvestigationApplication(orchestrator=build_local_runtime())
        if application is None
        else application
    )
    try:
        report = asyncio.run(service.investigate(request, build_local_context()))
    except InvalidObservableError as error:
        print(f"error: {safe_text(str(error), limit=300)}", file=stderr)
        return EXIT_USAGE_ERROR
    except InvestigationError as error:
        # A structural fault in the workflow. Reported as a failure rather than
        # dressed up as an inconclusive assessment somebody might act on.
        print(f"investigation failed: {safe_text(str(error), limit=300)}", file=stderr)
        return EXIT_OPERATIONAL_ERROR
    except Exception as error:
        _LOGGER.debug("unexpected failure", exc_info=True)
        print(f"error: {safe_text(type(error).__name__, limit=120)}", file=stderr)
        return EXIT_OPERATIONAL_ERROR

    if args.output_format == "json":
        stdout.write(report.model_dump_json())
        stdout.write("\n")
    else:
        stdout.write(render_text(report))
    return EXIT_OK


def _request_from(args: argparse.Namespace) -> AnalystInvestigationRequest:
    """The public request, from parsed arguments.

    A local file becomes its SHA-256 and nothing else. The bytes are hashed on
    this machine and discarded; what reaches a provider is a digest, which is
    the same thing anybody could compute from a copy they already had.
    """
    if args.file is not None:
        path = Path(args.file)
        observable = hash_local_file(path)
        observable_type = ObservableInputType.FILE_HASH
    else:
        observable = args.observable
        observable_type = ObservableInputType(args.observable_type)

    return AnalystInvestigationRequest(
        observable=observable,
        observable_type=observable_type,
        depth=InvestigationDepth(args.depth),
        pivot_mode=PivotMode(args.pivot_mode),
    )


def _write_json(document: object, stdout: TextIO) -> None:
    """One complete JSON document, deterministically.

    ``sort_keys`` because a schema dictionary is assembled from several sources
    and its iteration order is not a contract; ``allow_nan=False`` because
    ``NaN`` and ``Infinity`` are not JSON and a consumer's parser is entitled to
    reject them.
    """
    json.dump(document, stdout, indent=2, sort_keys=True, allow_nan=False)
    stdout.write("\n")


def _entrypoint() -> None:  # pragma: no cover - exercised as a subprocess
    with contextlib.suppress(BrokenPipeError):
        sys.exit(main())
