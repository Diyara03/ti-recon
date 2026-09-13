"""Material correlation issues reach the analyst report (Task 24 Phase 3).

A related object refused for a bound, two samples kept apart because their
stronger digests disagree, or a ceiling that dropped the rest all change what
the analyst sees in related_observables. They are projected under
layer="correlation", bounded, deduplicated and rendered; diagnostics about a
provider's payload shape stay internal.
"""

from __future__ import annotations

import pytest

from fixtures.investigation import InvestigationStack, file_root, spec
from fixtures.investigation.stack import ScriptedProvider, claim_evidence
from ti_recon.enums import InvestigationDepth, ProviderCapability, RelationshipType
from ti_recon.investigation import InvestigationRequest
from ti_recon.reasoning.claims.models import ClaimSemantic
from ti_recon.reporting.builder import MATERIAL_CORRELATION_ISSUES, build_analyst_report
from ti_recon.reporting.text import render_text

DIGEST = "e" * 64
LONG_URL = "https://example.test/" + "a" * 340


async def _report():
    providers = [
        ScriptedProvider(
            spec(
                "sandbox", family="fam_a", capabilities=frozenset({ProviderCapability.REPUTATION})
            ),
            {
                DIGEST: claim_evidence(
                    ClaimSemantic.MALWARE_SAMPLE_IDENTITY,
                    relations=(
                        (RelationshipType.CONTACTS, LONG_URL, "http_conversations"),
                        (
                            RelationshipType.CONTACTS,
                            "https://example.test/ok",
                            "http_conversations",
                        ),
                    ),
                )
            },
        )
    ]
    stack = InvestigationStack(providers=providers)
    await stack.add_credentials()
    result = await stack.investigate(
        InvestigationRequest(root=file_root(DIGEST), depth=InvestigationDepth.STANDARD)
    )
    return result, build_analyst_report(result)


@pytest.mark.asyncio
async def test_a_refused_related_object_is_visible_in_the_report() -> None:
    result, report = await _report()
    assert any(
        issue.issue_type.value == "invalid_related_object"
        for issue in result.correlation.correlation_issues
    )
    items = [item for item in report.issues.items if item.layer == "correlation"]
    assert [item.issue_type for item in items] == ["invalid_related_object"]
    assert items[0].provider_id == "sandbox"
    assert LONG_URL not in items[0].detail
    rendered = render_text(report)
    assert "Issues (recorded by the engine" in rendered
    assert "correlation/invalid_related_object [sandbox]" in rendered
    # The related observable that survived is still there.
    assert any(
        "example.test/ok" in item.canonical_value for item in report.related_observables.items
    )


def test_the_material_set_is_a_fixed_list_and_excludes_payload_diagnostics() -> None:
    from ti_recon.correlation.models import CorrelationIssueType

    assert MATERIAL_CORRELATION_ISSUES == frozenset(
        {
            CorrelationIssueType.INVALID_RELATED_OBJECT,
            CorrelationIssueType.FILE_HASH_CONFLICT,
            CorrelationIssueType.GRAPH_LIMIT_REACHED,
        }
    )
    assert CorrelationIssueType.DANGLING_RELATIONSHIP not in MATERIAL_CORRELATION_ISSUES


@pytest.mark.asyncio
async def test_no_issues_renders_no_issues_section() -> None:
    providers = [
        ScriptedProvider(
            spec("plain", family="fam_a", capabilities=frozenset({ProviderCapability.REPUTATION})),
            {DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)},
        )
    ]
    stack = InvestigationStack(providers=providers)
    await stack.add_credentials()
    result = await stack.investigate(
        InvestigationRequest(root=file_root(DIGEST), depth=InvestigationDepth.STANDARD)
    )
    report = build_analyst_report(result)
    assert report.issues.items == ()
    assert "Issues (" not in render_text(report)
