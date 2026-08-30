"""What the tools return, through the real protocol (Task 21).

The claim these tests defend is that MCP adds nothing: the same request through
the application directly and through a tool call produces the same report, and
every distinction Tasks 13-19 drew survives the trip. A transport that quietly
reinterpreted a verdict, flattened a coverage state or relabelled a related
observable would be the most damaging possible bug here, because it would look
like the engine's own answer.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest
from mcp import Client

from fixtures.investigation import claim_evidence, file_root, spec
from fixtures.investigation.stack import ScriptedProvider
from fixtures.mcp_server import scripted_runtime, scripted_server
from ti_recon.application.models import AnalystInvestigationRequest, ObservableInputType
from ti_recon.enums import (
    EvidenceEffect,
    IntelObjectType,
    ProviderCapability,
    RelationshipType,
)
from ti_recon.mcp_server.server import build_mcp_server
from ti_recon.reasoning.claims.models import ClaimSemantic
from ti_recon.reporting.models import AnalystInvestigationReport

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
DIGEST = "a" * 64
CONTACTED = "contacted.example"


def _provider(script: dict[str, object], **kwargs: object) -> ScriptedProvider:
    return ScriptedProvider(
        spec(
            "repo",
            family="fam_repo",
            capabilities=frozenset({INTELLIGENCE, REPUTATION}),
            **kwargs,  # type: ignore[arg-type]
        ),
        script,  # type: ignore[arg-type]
    )


async def _call(server, name: str, arguments: dict[str, object]):
    async with Client(server) as client:
        return await client.call_tool(name, arguments)


# --------------------------------------------------------------------------- #
# MCP adds no interpretation
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_tool_returns_exactly_what_the_application_returns() -> None:
    """The same request, two doors, one report.

    If these diverged, the protocol would have become a second opinion — and a
    consumer would have no way to tell which of the two the engine meant.
    """
    # Two independent runtimes, so both runs are cold. Sharing one would let
    # the second be served from Task 6's cache — correct behaviour, and it would
    # make the execution record differ for a reason that has nothing to do with
    # the transport.
    script = {DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)}
    direct_runtime, _ = await scripted_runtime([_provider(dict(script))])
    mcp_runtime, _ = await scripted_runtime([_provider(dict(script))])
    request = AnalystInvestigationRequest(
        observable=DIGEST, observable_type=ObservableInputType.FILE_HASH
    )
    direct = await direct_runtime.application.investigate(
        request, direct_runtime.execution_context()
    )

    result = await _call(
        build_mcp_server(mcp_runtime),
        "investigate_observable",
        {"observable": DIGEST, "observable_type": "file_hash"},
    )
    through_mcp = AnalystInvestigationReport.model_validate(result.structured_content)

    assert result.is_error is False
    # Run-scoped identities differ between two collections by design; every
    # analytical section must not.
    assert _analysis(through_mcp) == _analysis(direct)
    assert through_mcp.schema_version == direct.schema_version


#: Identities Task 17 and Task 3 build from one run's evidence.
_RUN_SCOPED = frozenset({"report_id", "investigation", "assessment_id", "claim_id", "evidence_id"})


def _analysis(report: AnalystInvestigationReport) -> object:
    return _strip(json.loads(report.model_dump_json()))


def _strip(document: object) -> object:
    match document:
        case dict():
            return {k: _strip(v) for k, v in document.items() if k not in _RUN_SCOPED}
        case list():
            return [_strip(v) for v in document]
        case _:
            return document


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("semantic", "effect", "verdict"),
    [
        (ClaimSemantic.MALWARE_SAMPLE_IDENTITY, EvidenceEffect.SUPPORTS_MALICIOUS, "malicious"),
        (ClaimSemantic.MALICIOUS_REPUTATION, EvidenceEffect.SUPPORTS_MALICIOUS, "suspicious"),
        (ClaimSemantic.BENIGN_REPUTATION, EvidenceEffect.SUPPORTS_BENIGN, "likely_benign"),
    ],
)
async def test_every_verdict_is_a_successful_tool_call(semantic, effect, verdict) -> None:
    """Mandatory: a finding is not a failure.

    ``is_error`` says whether the *tool* worked. A MALICIOUS assessment is the
    tool working perfectly, and reporting it as an error would make a real
    finding indistinguishable from a crash.
    """
    provider = _provider({DIGEST: claim_evidence(semantic, effect=effect)})
    server, _ = await scripted_server([provider])

    result = await _call(
        server, "investigate_observable", {"observable": DIGEST, "observable_type": "file_hash"}
    )

    assert result.is_error is False
    assert result.structured_content["assessment"]["verdict"] == verdict


@pytest.mark.asyncio
async def test_an_inconclusive_unresolved_investigation_still_succeeds() -> None:
    """Nobody knew anything, and finding that out is a successful call.

    Task 18 saying the search finished with the question open is a real answer,
    not a protocol problem.
    """
    server, _ = await scripted_server([_provider({})])

    result = await _call(
        server, "investigate_observable", {"observable": DIGEST, "observable_type": "file_hash"}
    )

    assert result.is_error is False
    assert result.structured_content["assessment"]["verdict"] == "inconclusive"
    assert result.structured_content["readiness"]["status"] == "unresolved"


@pytest.mark.asyncio
async def test_a_provider_failure_is_not_a_tool_failure() -> None:
    """An unconfigured source is coverage, not an error.

    Task 19 still returns a report and Task 18 records what the failure cost.
    Converting that into a tool error would hide a real assessment behind an
    infrastructure complaint.
    """
    from ti_recon.enums import ProviderRunStatus

    broken = ScriptedProvider(
        spec("broken", family="fam_broken", capabilities=frozenset({REPUTATION})),
        {
            DIGEST: claim_evidence(
                ClaimSemantic.MALICIOUS_REPUTATION, status=ProviderRunStatus.NOT_CONFIGURED
            )
        },
    )
    server, _ = await scripted_server([broken])

    result = await _call(
        server, "investigate_observable", {"observable": DIGEST, "observable_type": "file_hash"}
    )

    assert result.is_error is False
    statuses = {
        item["provider_id"]: item["status"]
        for item in result.structured_content["source_checks"]["items"]
    }
    assert statuses["broken"] == "not_configured"


@pytest.mark.asyncio
async def test_coverage_vocabulary_survives_the_transport() -> None:
    """``NO_DATA`` and ``UNATTRIBUTED`` reach a client as themselves.

    Remapping either would be the transport making a claim: that a source held
    nothing when it was never asked, or that an unattributable answer was an
    empty one.
    """
    server, _ = await scripted_server([_provider({})])

    result = await _call(
        server, "investigate_observable", {"observable": DIGEST, "observable_type": "file_hash"}
    )

    yields = {item["information_yield"] for item in result.structured_content["coverage"]["items"]}
    assert yields <= {"directional", "context_only", "no_data", "none", "unattributed"}
    # Whatever came back, it is one of the engine's own words.
    assert "benign" not in json.dumps(result.structured_content["coverage"])


@pytest.mark.asyncio
async def test_a_related_observable_arrives_as_a_relationship() -> None:
    """No MCP-only accusation is added.

    A contacted host is something a source connected to the root. The transport
    must not introduce ``malicious_ioc`` or a truthy ``malicious`` that Task 17
    never asserted.
    """
    provider = _provider(
        {
            DIGEST: claim_evidence(
                ClaimSemantic.MALWARE_SAMPLE_IDENTITY,
                relations=((RelationshipType.CONTACTS, CONTACTED, "contacted"),),
            )
        },
        object_types=frozenset({IntelObjectType.FILE, IntelObjectType.DOMAIN_NAME}),
    )
    server, _ = await scripted_server([provider])

    result = await _call(
        server, "investigate_observable", {"observable": DIGEST, "observable_type": "file_hash"}
    )

    related = result.structured_content["related_observables"]["items"]
    assert related
    entry = next(item for item in related if item["canonical_value"] == CONTACTED)
    assert entry["relationship_type"] == "contacts"
    assert entry["assessed"] is False
    assert "malicious" not in json.dumps(related).lower()


@pytest.mark.asyncio
async def test_report_bounds_are_task_20s_and_unchanged() -> None:
    """The transport does not truncate, and does not hide truncation.

    The counts a client sees are the counts Task 20 computed, so a client can
    trust that ``omitted`` means what it says.
    """
    from ti_recon.reporting.models import MAX_RELATED_OBSERVABLES

    relations = tuple(
        (RelationshipType.CONTACTS, f"host{index:03d}.example", "contacted")
        for index in range(MAX_RELATED_OBSERVABLES + 5)
    )
    provider = _provider(
        {DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY, relations=relations)},
        object_types=frozenset({IntelObjectType.FILE, IntelObjectType.DOMAIN_NAME}),
    )
    runtime, _ = await scripted_runtime([provider])
    direct = await runtime.application.investigate(
        AnalystInvestigationRequest(
            observable=DIGEST, observable_type=ObservableInputType.FILE_HASH
        ),
        runtime.execution_context(),
    )

    result = await _call(
        build_mcp_server(runtime),
        "investigate_observable",
        {"observable": DIGEST, "observable_type": "file_hash"},
    )
    section = result.structured_content["related_observables"]

    assert section["total"] == direct.related_observables.total
    assert section["omitted"] == direct.related_observables.omitted
    assert len(section["items"]) == len(direct.related_observables.items)
    assert section["omitted"] > 0


# --------------------------------------------------------------------------- #
# Local files
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_local_file_is_hashed_and_its_bytes_stay_here(tmp_path: Path) -> None:
    """The only thing that leaves is a digest.

    Proven at the provider, not at the boundary that built the request: the
    scripted source records exactly what it was asked.
    """
    payload = b"MZ\x90 not really a binary, but distinctive"
    sample = tmp_path / "sample.bin"
    sample.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()

    server, stack = await scripted_server(
        [_provider({digest: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)})]
    )

    result = await _call(server, "investigate_file", {"path": str(sample)})

    assert result.is_error is False
    assert result.structured_content["target"]["canonical_value"] == digest
    assert [value for value, _ in stack.requests_for("repo")] == [digest]
    # The bytes appear nowhere a client or a provider could see them.
    assert payload.decode("latin-1") not in json.dumps(result.structured_content)


@pytest.mark.asyncio
async def test_a_special_file_is_refused_without_blocking(tmp_path: Path) -> None:
    """Task 20's guard, unweakened.

    Opening a FIFO waits for a writer. Reaching one here would hang the tool
    call with no result and no way to diagnose it.
    """
    import os

    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    server, stack = await scripted_server([_provider({})])

    result = await asyncio.wait_for(
        _call(server, "investigate_file", {"path": str(fifo)}), timeout=10
    )

    assert result.is_error is True
    assert "not a regular file" in " ".join(item.text for item in result.content)
    assert stack.requests_for("repo") == []


# --------------------------------------------------------------------------- #
# The pivot gate, through MCP input
# --------------------------------------------------------------------------- #


def _pivot_provider() -> ScriptedProvider:
    return _provider(
        {
            DIGEST: claim_evidence(
                ClaimSemantic.MALWARE_SAMPLE_IDENTITY,
                relations=((RelationshipType.CONTACTS, CONTACTED, "contacted"),),
            ),
            CONTACTED: claim_evidence(ClaimSemantic.MALICIOUS_REPUTATION),
        },
        object_types=frozenset({IntelObjectType.FILE, IntelObjectType.DOMAIN_NAME}),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("arguments", "expect_pivot_query"),
    [
        ({"pivot_mode": "recommend"}, False),
        ({"pivot_mode": "enrich"}, False),
        ({"pivot_mode": "enrich", "allow_remote_pivot_lookup": True}, True),
    ],
)
async def test_the_remote_pivot_gate_holds_through_the_tool(arguments, expect_pivot_query) -> None:
    """Both switches, exactly as Task 14 requires.

    ``enrich`` alone authorises following a lead; it does not authorise telling
    a third party about it. The transport adds no special case — the request
    model and Task 14 decide.
    """
    server, stack = await scripted_server([_pivot_provider()])

    result = await _call(
        server,
        "investigate_observable",
        {"observable": DIGEST, "observable_type": "file_hash", **arguments},
    )

    asked = {value for value, _ in stack.requests_for("repo")}
    assert result.is_error is False
    assert (CONTACTED in asked) is expect_pivot_query
    assert result.structured_content["request"]["allow_remote_pivot_lookup"] is (
        arguments.get("allow_remote_pivot_lookup", False)
    )


@pytest.mark.asyncio
async def test_the_invalid_pivot_combination_is_a_tool_error() -> None:
    """Refused by Task 20's own validation, surfaced as a correctable failure.

    No MCP special case: the rule lives on the request model, and a second copy
    here is the one that would go stale.
    """
    server, stack = await scripted_server([_pivot_provider()])

    result = await _call(
        server,
        "investigate_observable",
        {
            "observable": DIGEST,
            "observable_type": "file_hash",
            "pivot_mode": "recommend",
            "allow_remote_pivot_lookup": True,
        },
    )

    assert result.is_error is True
    message = " ".join(item.text for item in result.content)
    assert "enrich" in message
    assert stack.requests_for("repo") == []


@pytest.mark.asyncio
async def test_an_unparseable_observable_is_correctable_not_a_crash() -> None:
    """The model gets something it can act on, and no provider is asked."""
    server, stack = await scripted_server([_provider({})])

    result = await _call(server, "investigate_observable", {"observable": "not an observable!!"})

    assert result.is_error is True
    assert stack.requests_for("repo") == []
    assert "Traceback" not in " ".join(item.text for item in result.content)


@pytest.mark.asyncio
async def test_the_file_root_helper_is_the_expected_shape() -> None:
    """Guard for the fixture import this module relies on."""
    assert file_root(DIGEST).canonical_value == DIGEST
