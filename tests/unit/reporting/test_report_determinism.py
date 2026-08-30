"""One report, one set of bytes (Task 20).

JSON is the integration contract, so a consumer must be able to diff two reports
and have the difference mean something. That requires the same result to
serialise identically — across collection order, across processes, and across
whatever the terminal happens to be.

Bounds are the other half. A section that quietly dropped items would tell an
analyst the investigation found less than it did, which is a worse failure than
a long report.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from fixtures.investigation import claim_evidence, file_root, spec
from fixtures.investigation.stack import InvestigationStack, ScriptedProvider
from fixtures.reporting import malicious_report
from ti_recon.correlation import PivotMode
from ti_recon.correlation.policy import PivotPolicy
from ti_recon.enums import IntelObjectType, ProviderCapability, RelationshipType
from ti_recon.investigation import InvestigationRequest
from ti_recon.reasoning.claims.models import ClaimSemantic
from ti_recon.reporting import build_analyst_report, render_text
from ti_recon.reporting.models import MAX_RELATED_OBSERVABLES

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
DIGEST = "a" * 64


@pytest.mark.asyncio
async def test_report_bytes_do_not_depend_on_collection_order() -> None:
    """Task 19 made set serialisation stable; this keeps the report inside it.

    A renderer that rebuilt an unordered collection of its own would reintroduce
    the problem one layer higher, where nothing else is watching for it.
    """
    result, report = await malicious_report()

    rebuilt = build_analyst_report(result)

    assert rebuilt.model_dump_json() == report.model_dump_json()
    assert render_text(rebuilt) == render_text(report)


def test_report_bytes_do_not_depend_on_the_hash_seed() -> None:
    """The cross-process half a single-process test cannot see.

    Two runs in two interpreters must produce the same document, or a stored
    report cannot be compared with a fresh one.
    """
    script = (
        "import asyncio, sys;"
        "sys.path.insert(0, 'tests');"
        "from fixtures.reporting import malicious_report;"
        "print(asyncio.run(malicious_report())[1].model_dump_json())"
    )
    outputs = {
        subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=True,
            env={"PYTHONHASHSEED": str(seed), "PATH": "/usr/bin:/bin", "PYTHONPATH": "src:tests"},
        ).stdout
        for seed in (1, 2, 3, 4)
    }

    # Run-scoped ids differ between processes by design; the structure must not.
    shapes = {json.dumps(_shape(json.loads(item)), sort_keys=True) for item in outputs}
    assert len(shapes) == 1


def _shape(document: object) -> object:
    """Field names and value kinds, with run-scoped identities removed."""
    match document:
        case dict():
            return {
                key: _shape(value)
                for key, value in sorted(document.items())
                if key
                not in {"report_id", "investigation", "assessment_id", "claim_id", "evidence_id"}
            }
        case list():
            return [_shape(value) for value in document]
        case _:
            return document


@pytest.mark.asyncio
async def test_a_bounded_section_says_what_it_left_out() -> None:
    """More related objects than the bound, and the report admits it.

    Silent truncation is the failure mode worth testing: an analyst who cannot
    see that a list was cut has been told something false about the graph.
    """
    contacted = tuple(
        (RelationshipType.CONTACTS, f"host{index:03d}.example", "contacted")
        for index in range(MAX_RELATED_OBSERVABLES + 7)
    )
    provider = ScriptedProvider(
        spec(
            "repo",
            family="fam_repo",
            capabilities=frozenset({INTELLIGENCE, REPUTATION}),
            object_types=frozenset({IntelObjectType.FILE, IntelObjectType.DOMAIN_NAME}),
        ),
        {DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY, relations=contacted)},
    )
    stack = InvestigationStack(providers=[provider])
    await stack.add_credentials()
    result = await stack.orchestrator.investigate(
        InvestigationRequest(root=file_root(DIGEST)),
        stack.context(),
        pivot_policy=PivotPolicy(mode=PivotMode.RECOMMEND),
    )

    report = build_analyst_report(result)
    section = report.related_observables

    assert len(section.items) == MAX_RELATED_OBSERVABLES
    assert section.total > MAX_RELATED_OBSERVABLES
    assert section.omitted == section.total - MAX_RELATED_OBSERVABLES
    # And an analyst reading the text is told, not left to count.
    assert f"{section.omitted} more of {section.total} not shown" in render_text(report)


@pytest.mark.asyncio
async def test_truncation_keeps_a_stable_prefix() -> None:
    """Which items survive is deterministic, not whichever arrived first."""
    contacted = tuple(
        (RelationshipType.CONTACTS, f"host{index:03d}.example", "contacted")
        for index in range(MAX_RELATED_OBSERVABLES + 3)
    )
    provider = ScriptedProvider(
        spec(
            "repo",
            family="fam_repo",
            capabilities=frozenset({INTELLIGENCE, REPUTATION}),
            object_types=frozenset({IntelObjectType.FILE, IntelObjectType.DOMAIN_NAME}),
        ),
        {DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY, relations=contacted)},
    )
    stack = InvestigationStack(providers=[provider])
    await stack.add_credentials()
    result = await stack.orchestrator.investigate(
        InvestigationRequest(root=file_root(DIGEST)),
        stack.context(),
        pivot_policy=PivotPolicy(mode=PivotMode.RECOMMEND),
    )

    first = build_analyst_report(result).related_observables.items
    second = build_analyst_report(result).related_observables.items

    assert first == second
    keys = [item.canonical_key for item in first]
    assert keys == sorted(keys)
