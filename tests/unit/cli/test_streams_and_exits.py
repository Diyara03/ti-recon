"""What a script calling the CLI can rely on (Task 20).

Two promises, and both are the kind that fail silently. Stdout in JSON mode is
exactly one JSON document — a single stray line makes it unparseable for the
automation the format exists to serve. And the exit status describes whether the
*command* ran, never what it found: a MALICIOUS verdict returning nonzero would
make a finding indistinguishable from a crash to every shell that checks ``&&``.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import sys

import pytest

from fixtures.investigation import claim_evidence, spec
from fixtures.investigation.stack import ScriptedProvider
from fixtures.reporting import DIGEST, application_for, scripted_application
from ti_recon.application.service import InvestigationApplication
from ti_recon.cli import EXIT_OK, EXIT_OPERATIONAL_ERROR, EXIT_USAGE_ERROR, run
from ti_recon.cli.runtime import LOCAL_CLI_USER
from ti_recon.enums import EvidenceEffect, ProviderCapability
from ti_recon.investigation.engine import InvestigationError
from ti_recon.reasoning.claims.models import ClaimSemantic

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE


def _app(semantic: ClaimSemantic | None, **kwargs: object) -> InvestigationApplication:
    script = (
        {} if semantic is None else {DIGEST: claim_evidence(semantic, **kwargs)}  # type: ignore[arg-type]
    )
    provider = ScriptedProvider(
        spec("repo", family="fam_repo", capabilities=frozenset({INTELLIGENCE, REPUTATION})),
        script,
    )
    stack = scripted_application([provider])
    # Registered for the identity the CLI actually runs under. Credential
    # resolution is per user, so a connection belonging to somebody else is
    # correctly invisible here — which is why this is explicit rather than
    # inherited from the fixture's default analyst.
    asyncio.run(stack.add_credentials(user_id=LOCAL_CLI_USER))
    return application_for(stack)


def _invoke(argv: list[str], application: InvestigationApplication | None = None):
    out, err = io.StringIO(), io.StringIO()
    code = run(argv, stdout=out, stderr=err, application=application)
    return code, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------- #
# Exit status is about the command
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("semantic", "effect", "expected_verdict"),
    [
        (ClaimSemantic.MALWARE_SAMPLE_IDENTITY, EvidenceEffect.SUPPORTS_MALICIOUS, "malicious"),
        (ClaimSemantic.MALICIOUS_REPUTATION, EvidenceEffect.SUPPORTS_MALICIOUS, "suspicious"),
        (ClaimSemantic.BENIGN_REPUTATION, EvidenceEffect.SUPPORTS_BENIGN, "likely_benign"),
    ],
)
def test_every_completed_verdict_exits_successfully(semantic, effect, expected_verdict) -> None:
    """Mandatory: maliciousness is not a CLI failure.

    A shell running ``ti-recon investigate x && something`` is asking whether
    the command worked. Encoding the verdict here would break that for everyone.
    """
    code, stdout, _ = _invoke(
        ["investigate", DIGEST, "--type", "file_hash", "--format", "json"],
        _app(semantic, effect=effect),
    )

    assert code == EXIT_OK
    assert json.loads(stdout)["assessment"]["verdict"] == expected_verdict


def test_an_inconclusive_investigation_exits_successfully() -> None:
    """Nobody knew anything, and finding that out is a successful command."""
    code, stdout, _ = _invoke(
        ["investigate", DIGEST, "--type", "file_hash", "--format", "json"], _app(None)
    )

    assert code == EXIT_OK
    assert json.loads(stdout)["assessment"]["verdict"] == "inconclusive"


def test_an_unresolved_readiness_exits_successfully() -> None:
    """An unresolved *analysis* is not a failed *process*.

    Task 18 saying the search finished with the question open is a real answer
    about the external intelligence available, produced successfully.
    """
    code, stdout, _ = _invoke(
        ["investigate", DIGEST, "--type", "file_hash", "--format", "json"], _app(None)
    )

    assert code == EXIT_OK
    assert json.loads(stdout)["readiness"]["status"] == "unresolved"


# --------------------------------------------------------------------------- #
# Failures are failures
# --------------------------------------------------------------------------- #


def test_an_unparseable_observable_never_reaches_a_provider() -> None:
    """Rejected at the boundary, before anything is asked of anybody.

    An input nobody could parse has not been investigated, so there is nothing
    to report — and stdout stays empty rather than carrying a fabricated
    inconclusive result a script would treat as an answer.
    """
    application = _app(None)
    code, stdout, stderr = _invoke(
        ["investigate", "not a valid observable!!", "--format", "json"], application
    )

    assert code == EXIT_USAGE_ERROR
    assert stdout == ""
    assert stderr.startswith("error:")


def test_a_structural_failure_is_not_dressed_up_as_a_verdict() -> None:
    """A software fault must not become an analytical conclusion.

    Returning INCONCLUSIVE here would hand an analyst a result they might act
    on, produced by a bug.
    """

    class _Broken(InvestigationApplication):
        async def investigate(self, request, context):  # type: ignore[override]
            msg = "stages describe different observables"
            raise InvestigationError(msg)

    broken = _Broken(orchestrator=_app(None).orchestrator)
    code, stdout, stderr = _invoke(["investigate", DIGEST, "--type", "file_hash"], broken)

    assert code == EXIT_OPERATIONAL_ERROR
    assert stdout == ""
    assert "investigation failed" in stderr


def test_an_unexpected_failure_reports_a_bounded_error() -> None:
    """No traceback, no internal detail, nonzero status."""

    class _Exploding(InvestigationApplication):
        async def investigate(self, request, context):  # type: ignore[override]
            raise RuntimeError("internal detail that should not be printed verbatim")

    exploding = _Exploding(orchestrator=_app(None).orchestrator)
    code, stdout, stderr = _invoke(["investigate", DIGEST, "--type", "file_hash"], exploding)

    assert code == EXIT_OPERATIONAL_ERROR
    assert stdout == ""
    assert "Traceback" not in stderr
    assert "internal detail" not in stderr


def test_no_command_prints_help_to_stderr() -> None:
    """Usage goes to stderr, so stdout stays a data channel."""
    code, stdout, stderr = _invoke([])

    assert code == EXIT_USAGE_ERROR
    assert stdout == ""
    assert "usage:" in stderr


# --------------------------------------------------------------------------- #
# Stream discipline
# --------------------------------------------------------------------------- #


def test_json_stdout_is_exactly_one_document_even_while_logging() -> None:
    """The promise automation depends on.

    Logging is emitted deliberately during the run: if a handler were attached
    to stdout, the document would be corrupted and this is the only place that
    would notice.
    """
    application = _app(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)
    out, err = io.StringIO(), io.StringIO()

    logger = logging.getLogger("ti_recon.test")
    code = run(
        ["investigate", DIGEST, "--type", "file_hash", "--format", "json"],
        stdout=out,
        stderr=err,
        application=application,
    )
    logger.warning("a diagnostic that must not reach stdout")

    document = out.getvalue()
    assert code == EXIT_OK
    assert json.loads(document)
    # One document: nothing before it, nothing after it, one trailing newline.
    assert document.endswith("\n")
    assert document.count("\n") == 1
    assert "\x1b" not in document
    assert "WARNING" not in document


def test_the_schema_command_prints_only_a_schema() -> None:
    """Local, and a single valid document."""
    code, stdout, stderr = _invoke(["schema", "report"])

    schema = json.loads(stdout)
    assert code == EXIT_OK
    assert stderr == ""
    assert schema["$schema"].startswith("https://json-schema.org/draft/")
    assert schema["title"] == "AnalystInvestigationReport"


def test_the_request_schema_is_published_too() -> None:
    """Task 21 needs to build a request as much as read a report."""
    code, stdout, _ = _invoke(["schema", "request"])

    schema = json.loads(stdout)
    assert code == EXIT_OK
    assert schema["title"] == "AnalystInvestigationRequest"
    assert "observable" in schema["properties"]


def test_the_providers_command_names_no_credential() -> None:
    """A diagnostic that contacts nothing and reveals nothing.

    It may say a provider *requires* a credential, which is a descriptor fact.
    It may never say whether one is present, how long it is, or any part of it.
    """
    code, stdout, stderr = _invoke(["providers"])

    document = json.loads(stdout)
    assert code == EXIT_OK
    assert stderr == ""
    for row in document["providers"]:
        assert set(row) == {
            "provider_id",
            "source_family",
            "requires_credentials",
            "capabilities",
            "object_types",
            "dataset_version",
        }


def test_a_closed_pipe_is_not_a_traceback() -> None:
    """``ti-recon schema report | head`` is an ordinary thing to type.

    Without handling, Python raises again while flushing at interpreter
    shutdown and the analyst gets a traceback for having piped into something
    that stopped reading.
    """

    class _ClosedPipe(io.StringIO):
        def write(self, _: str) -> int:
            raise BrokenPipeError

    from ti_recon.cli.main import main

    # ``main`` owns a process, so it configures the package logger. Restored
    # here because this test is not a process: leaving it configured would
    # detach the logger for every test that ran afterwards, which is exactly
    # the leak that moved this call out of ``run`` in the first place.
    logger = logging.getLogger("ti_recon")
    saved = (list(logger.handlers), logger.propagate, logger.level)
    original = (sys.stdout, sys.stderr)
    sys.stdout, sys.stderr = _ClosedPipe(), io.StringIO()
    try:
        code = main(["schema", "report"])
    finally:
        sys.stdout, sys.stderr = original
        logger.handlers, logger.propagate, logger.level = saved

    assert code == EXIT_OK
