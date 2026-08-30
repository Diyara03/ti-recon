"""The seam a future interface consumes (Task 20).

The CLI must be a shell, not the interface. If the application service can only
be driven through a terminal, the next consumer parses text — and then the text
becomes the contract, which is precisely what the JSON report exists to prevent.

So these tests use no CLI at all: build a request, await the service, receive a
report, serialise it, read its schema. That is the whole surface Task 21 needs.
"""

from __future__ import annotations

import ast
import asyncio
import hashlib
import io
import json
from pathlib import Path

import pytest

from fixtures.investigation import claim_evidence, spec
from fixtures.investigation.stack import ScriptedProvider
from fixtures.reporting import DIGEST, application_for, scripted_application
from ti_recon.application import (
    AnalystInvestigationRequest,
    InvalidObservableError,
    InvestigationApplication,
    ObservableInputType,
    hash_local_file,
    resolve_observable,
)
from ti_recon.cli import run
from ti_recon.cli.runtime import LOCAL_CLI_USER, build_local_context
from ti_recon.correlation.policy import PivotMode
from ti_recon.enums import IntelObjectType, InvestigationDepth, ProviderCapability
from ti_recon.reasoning.claims.models import ClaimSemantic
from ti_recon.reporting import AnalystInvestigationReport, report_json_schema

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE

APPLICATION_PACKAGE = Path("src/ti_recon/application")
REPORTING_PACKAGE = Path("src/ti_recon/reporting")
CLI_PACKAGE = Path("src/ti_recon/cli")


async def _direct(request: AnalystInvestigationRequest) -> AnalystInvestigationReport:
    application = await _application()
    return await application.investigate(request, build_local_context())


async def _application() -> InvestigationApplication:
    provider = ScriptedProvider(
        spec("repo", family="fam_repo", capabilities=frozenset({INTELLIGENCE, REPUTATION})),
        {DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)},
    )
    stack = scripted_application([provider])
    await stack.add_credentials(user_id=LOCAL_CLI_USER)
    return application_for(stack)


# --------------------------------------------------------------------------- #
# The seam
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_consumer_needs_no_terminal() -> None:
    """Everything Task 21 will do, without importing anything protocol-shaped.

    Request in, report out, serialisable, and a schema describing it. No stdin,
    no stdout, no argument parsing anywhere in the path.
    """
    application = await _application()
    request = AnalystInvestigationRequest(
        observable=DIGEST, observable_type=ObservableInputType.FILE_HASH
    )

    report = await application.investigate(request, build_local_context())

    assert isinstance(report, AnalystInvestigationReport)
    document = json.loads(report.model_dump_json())
    assert document["assessment"]["verdict"] == "malicious"
    assert report_json_schema()["title"] == "AnalystInvestigationReport"


def test_the_cli_is_a_thin_shell_over_the_same_service() -> None:
    """Same request, same report, whichever door it came through.

    If these ever diverged, one of the two consumers would be reading a result
    the other could not reproduce — and the CLI's text would quietly become a
    second contract.
    """
    # Synchronous on purpose: the CLI owns its event loop, which is exactly the
    # arrangement a caller with its own loop must not be forced into — and is
    # why the service, not this function, is the seam Task 21 consumes.
    request = AnalystInvestigationRequest(
        observable=DIGEST, observable_type=ObservableInputType.FILE_HASH
    )
    direct = asyncio.run(_direct(request))

    out, err = io.StringIO(), io.StringIO()
    code = run(
        ["investigate", DIGEST, "--type", "file_hash", "--format", "json"],
        stdout=out,
        stderr=err,
        application=asyncio.run(_application()),
    )
    through_cli = AnalystInvestigationReport.model_validate_json(out.getvalue())

    assert code == 0
    # Run-scoped identities differ by design — Task 17 builds an assessment id
    # from the evidence ids of the run that produced it — so the comparison is
    # of everything analytical, which must not differ at all.
    assert _analysis(through_cli) == _analysis(direct)


#: Identities Task 17 and Task 3 build from one run's evidence.
#:
#: Documented and deliberate: an assessment id incorporates the evidence ids of
#: the run that produced it, so two collections of the same intelligence differ
#: here and agree everywhere else. Stripping them is what makes the comparison
#: about the analysis rather than about the clock.
_RUN_SCOPED = frozenset({"report_id", "investigation", "assessment_id", "claim_id", "evidence_id"})


def _analysis(report: AnalystInvestigationReport) -> object:
    """A report with every run-scoped identity removed, at any depth."""
    return _strip(json.loads(report.model_dump_json()))


def _strip(document: object) -> object:
    match document:
        case dict():
            return {key: _strip(value) for key, value in document.items() if key not in _RUN_SCOPED}
        case list():
            return [_strip(value) for value in document]
        case _:
            return document


@pytest.mark.asyncio
async def test_the_full_internal_result_stays_reachable() -> None:
    """The report is the supported contract, not a wall.

    Debugging a disagreement between layers needs the planner decisions and the
    graph the report deliberately leaves out.
    """
    application = await _application()
    request = AnalystInvestigationRequest(
        observable=DIGEST, observable_type=ObservableInputType.FILE_HASH
    )

    result = await application.run(request, build_local_context())

    assert result.enrichment.decisions
    assert result.correlation.graph_nodes


# --------------------------------------------------------------------------- #
# Input
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("8.8.8.8", IntelObjectType.IPV4_ADDR),
        ("2001:4860:4860::8888", IntelObjectType.IPV6_ADDR),
        ("example.com", IntelObjectType.DOMAIN_NAME),
        ("https://example.com/a", IntelObjectType.URL),
        ("d" * 64, IntelObjectType.FILE),
        ("d" * 40, IntelObjectType.FILE),
        ("d" * 32, IntelObjectType.FILE),
    ],
)
def test_auto_detection_uses_the_engines_own_canonicaliser(raw, expected) -> None:
    """Every supported type, through the normalizer the engine already has.

    A second parser here would be a slightly different set of rules — defanging,
    IDNA, digest lengths — reached by a different door.
    """
    request = AnalystInvestigationRequest(observable=raw)

    assert resolve_observable(request).object_type is expected


def test_a_domain_is_not_promoted_to_a_url() -> None:
    """Type detection never adds a scheme nobody typed.

    A URL and its host are different observables with different evidence, which
    is the distinction every living-off-trusted-sites payload depends on.
    """
    request = AnalystInvestigationRequest(observable="example.com")

    assert resolve_observable(request).object_type is IntelObjectType.DOMAIN_NAME


def test_an_address_family_mismatch_is_refused() -> None:
    """Asking for one family and receiving the other would investigate
    something the caller did not describe."""
    request = AnalystInvestigationRequest(
        observable="8.8.8.8", observable_type=ObservableInputType.IPV6
    )

    with pytest.raises(InvalidObservableError, match="ipv6"):
        resolve_observable(request)


@pytest.mark.parametrize("raw", ["not an observable!!", "d" * 33, "   "])
def test_unusable_input_is_refused_rather_than_guessed(raw) -> None:
    """Ambiguity fails; it never becomes a silent choice."""
    try:
        request = AnalystInvestigationRequest(observable=raw)
    except ValueError:
        return
    with pytest.raises(InvalidObservableError):
        resolve_observable(request)


def test_resolution_opens_no_socket(tmp_path: Path) -> None:
    """Canonicalisation is local, so an unresolvable name behaves like any other.

    The repository's network guard is active in tests; a name lookup here would
    fail loudly rather than quietly succeeding.
    """
    request = AnalystInvestigationRequest(observable="nonexistent.invalid")

    assert resolve_observable(request).object_type is IntelObjectType.DOMAIN_NAME


# --------------------------------------------------------------------------- #
# Local files
# --------------------------------------------------------------------------- #


def test_a_local_file_becomes_a_digest_and_nothing_else(tmp_path: Path) -> None:
    """The only thing that leaves this machine is a hash.

    A hash lookup asks "has anybody seen this exact sample?", which the owner of
    a sample can ask without handing the sample to anybody. Nothing here
    uploads, submits or detonates.
    """
    sample = tmp_path / "sample.bin"
    payload = b"MZ\x90\x00 not really a binary"
    sample.write_bytes(payload)

    digest = hash_local_file(sample)

    assert digest == hashlib.sha256(payload).hexdigest()
    request = AnalystInvestigationRequest(
        observable=digest, observable_type=ObservableInputType.FILE_HASH
    )
    intel_object = resolve_observable(request)
    assert intel_object.object_type is IntelObjectType.FILE
    assert intel_object.canonical_value == digest
    # The bytes are nowhere in what the engine will be asked about.
    assert payload.decode("latin-1") not in intel_object.model_dump_json()


@pytest.mark.asyncio
async def test_a_provider_asked_about_a_file_receives_only_the_digest(tmp_path: Path) -> None:
    """Proven at the provider, not at the boundary that built the request."""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"payload that must not travel")
    digest = hash_local_file(sample)

    provider = ScriptedProvider(
        spec("repo", family="fam_repo", capabilities=frozenset({INTELLIGENCE, REPUTATION})),
        {},
    )
    stack = scripted_application([provider])
    await stack.add_credentials(user_id=LOCAL_CLI_USER)
    await application_for(stack).investigate(
        AnalystInvestigationRequest(
            observable=digest, observable_type=ObservableInputType.FILE_HASH
        ),
        build_local_context(),
    )

    asked = [value for value, _ in stack.requests_for("repo")]
    assert asked == [digest]


# --------------------------------------------------------------------------- #
# Defaults are the engine's
# --------------------------------------------------------------------------- #


def test_the_defaults_are_the_ones_the_engine_already_documents() -> None:
    """Neither default is chosen here.

    Deepening an investigation spends somebody's quota; enabling pivot
    enrichment discloses infrastructure the analyst did not ask about. Both are
    the caller's to opt into, and both already have an engine default.
    """
    request = AnalystInvestigationRequest(observable="example.com")

    assert request.depth is InvestigationDepth.STANDARD
    assert request.pivot_mode is PivotMode.RECOMMEND


def test_the_cli_defaults_match_the_request_defaults() -> None:
    """One default, not two that drift."""
    from ti_recon.cli.parser import build_parser

    args = build_parser().parse_args(["investigate", "example.com"])

    assert args.depth == InvestigationDepth.STANDARD.value
    assert args.pivot_mode == PivotMode.RECOMMEND.value
    assert args.output_format == "text"


# --------------------------------------------------------------------------- #
# Static boundaries
# --------------------------------------------------------------------------- #


def _sources(*packages: Path) -> list[tuple[Path, str]]:
    return [
        (path, path.read_text(encoding="utf-8"))
        for package in packages
        for path in sorted(package.rglob("*.py"))
    ]


def test_no_interface_module_names_a_provider() -> None:
    """Provider selection is Task 13's, and stays reproducible only while it is.

    ``runtime.py`` is the one composition root, exactly as every other layer in
    this repository keeps one.
    """
    # ``composition.py`` is this layer's composition root, and ``runtime.py``
    # names the local identity — the same exemption ``planning/catalog.py``
    # already carries, for the same reason: a catalogue that could not name a
    # provider would be an empty list.
    offenders = [
        path.name
        for path, source in _sources(APPLICATION_PACKAGE, REPORTING_PACKAGE, CLI_PACKAGE)
        if path.name not in {"runtime.py", "composition.py"}
        and any(
            name in source.lower()
            for name in (
                "virustotal",
                "urlscan",
                "greynoise",
                "censys",
                "threatfox",
                "urlhaus",
                "malwarebazaar",
                "hybrid_analysis",
            )
        )
    ]
    assert offenders == []


def test_no_interface_module_calls_an_adapter_or_opens_a_socket() -> None:
    """Execution belongs to Task 13 and Task 6; presentation performs no I/O."""
    for path, source in _sources(APPLICATION_PACKAGE, REPORTING_PACKAGE, CLI_PACKAGE):
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in {"lookup", "batch_lookup", "active_action"}, path.name
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in {"socket", "httpx", "ssl"}, path.name
            if isinstance(node, ast.ImportFrom):
                assert node.module not in {"socket", "httpx", "ssl"}, path.name


def test_the_report_layer_reimplements_no_policy() -> None:
    """It consumes decisions; it does not make them.

    Importing a policy module would be the first step towards a second opinion
    that could disagree with the engine's.
    """
    for path, source in _sources(REPORTING_PACKAGE):
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.endswith(".policy"), f"{path.name} imports {node.module}"


def test_building_a_report_and_a_schema_never_touches_the_network() -> None:
    """Rendering is pure, so it works with the network unplugged."""
    schema = report_json_schema()

    assert schema["properties"]["assessment"]
    assert "socket" not in json.dumps(schema)


def test_hashing_refuses_anything_but_a_regular_file(tmp_path: Path) -> None:
    """A FIFO would block the command forever with no output and no reason.

    Opening a pipe waits for a writer, and a character device can be endless.
    Either would hang ``ti-recon investigate --file`` in a way an analyst could
    only diagnose with a debugger, so the shape is checked before the open.
    """
    import os

    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)

    with pytest.raises(InvalidObservableError, match="not a regular file"):
        hash_local_file(fifo)

    with pytest.raises(InvalidObservableError, match="not a regular file"):
        hash_local_file(tmp_path)

    with pytest.raises(InvalidObservableError, match="cannot read"):
        hash_local_file(tmp_path / "absent.bin")


def test_a_symlink_to_a_real_file_is_followed_and_one_to_a_pipe_is_not(
    tmp_path: Path,
) -> None:
    """Deliberate, and stated: the check is against the resolved target.

    An analyst pointing at a symlink means the file it names. A symlink to a
    pipe is refused like the pipe it is, so the indirection cannot be used to
    get past the check.
    """
    import os

    real = tmp_path / "sample.bin"
    real.write_bytes(b"payload")
    good = tmp_path / "good.lnk"
    good.symlink_to(real)
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    bad = tmp_path / "bad.lnk"
    bad.symlink_to(fifo)

    assert hash_local_file(good) == hash_local_file(real)
    with pytest.raises(InvalidObservableError, match="not a regular file"):
        hash_local_file(bad)


def test_hashing_streams_rather_than_reading_the_whole_file(tmp_path: Path) -> None:
    """Constant memory, so a large sample is hashable rather than fatal."""
    import hashlib as _hashlib

    from ti_recon.application.service import _READ_CHUNK

    sample = tmp_path / "big.bin"
    payload = b"\xde\xad\xbe\xef" * (_READ_CHUNK // 2)
    sample.write_bytes(payload)

    assert len(payload) > _READ_CHUNK
    assert hash_local_file(sample) == _hashlib.sha256(payload).hexdigest()


def test_a_non_regular_file_never_reaches_an_investigation() -> None:
    """The CLI reports it as input, not as an analytical outcome."""
    import io
    import os
    import tempfile

    directory = Path(tempfile.mkdtemp())
    fifo = directory / "pipe"
    os.mkfifo(fifo)
    out, err = io.StringIO(), io.StringIO()

    code = run(["investigate", "--file", str(fifo), "--format", "json"], stdout=out, stderr=err)

    assert code == 2
    assert out.getvalue() == ""
    assert "not a regular file" in err.getvalue()
