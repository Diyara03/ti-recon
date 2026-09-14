"""A capability nobody serves ends the run honestly (Task 24, US-06).

Live shape, installed plugin, ``example.com`` at STANDARD: no shipped provider
observes a domain's current infrastructure. The planner dropped the template
goal and every record of it; readiness, rebuilding the requirement from the
template, saw no attempt and no coverage item and said ``not_attempted`` with
more data available; the workflow asked for a continuation, found nothing
admissible to request, and stopped ``no_actionable_continuation`` with an
issue on the record. Contradictory: a catalogue blind spot reported as an
unfinished search.

Now the planner records the blind spot, readiness reads it as
``capability_unavailable`` with no remaining path, and the workflow stops as
``readiness_exhausted`` in one round, with nothing asked for that nobody could
serve. The assessment itself is untouched: INCONCLUSIVE stays INCONCLUSIVE.
"""

from __future__ import annotations

import pytest

from fixtures.investigation import InvestigationStack, observable_root, spec
from fixtures.investigation.stack import ScriptedProvider
from ti_recon.application import AnalystInvestigationRequest
from ti_recon.application.composition import build_default_application
from ti_recon.cli.runtime import LOCAL_CLI_USER, build_local_context
from ti_recon.enums import (
    CoverageStatus,
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    Verdict,
)
from ti_recon.investigation import InvestigationRequest, WorkflowStopReason
from ti_recon.investigation.models import WorkflowIssueType
from ti_recon.planning.models import ProviderLocality
from ti_recon.reasoning.readiness import ContinuationState, GapOutlook, GapType, ReadinessStatus

DOMAIN = "example.com"
INFRA = ProviderCapability.CURRENT_INFRASTRUCTURE
REPUTATION = ProviderCapability.REPUTATION
CONTEXT = ProviderCapability.FALSE_POSITIVE_CONTEXT
DOMAIN_TYPES = frozenset({IntelObjectType.DOMAIN_NAME})


def _stack() -> InvestigationStack:
    """Two reputation families and a local context source, and nobody who
    serves a domain's current infrastructure -- the live catalogue's shape."""
    return InvestigationStack(
        providers=[
            ScriptedProvider(
                spec(
                    "context",
                    family="context",
                    capabilities=frozenset({CONTEXT}),
                    locality=ProviderLocality.LOCAL,
                    object_types=DOMAIN_TYPES,
                    priority=90,
                ),
                {},
            ),
            ScriptedProvider(
                spec(
                    "rep_a",
                    family="fam_a",
                    capabilities=frozenset({REPUTATION}),
                    object_types=DOMAIN_TYPES,
                ),
                {},
            ),
            ScriptedProvider(
                spec(
                    "rep_b",
                    family="fam_b",
                    capabilities=frozenset({REPUTATION}),
                    object_types=DOMAIN_TYPES,
                    priority=40,
                ),
                {},
            ),
        ]
    )


@pytest.mark.asyncio
async def test_a_domain_whose_infrastructure_nobody_observes_ends_exhausted_not_unactionable() -> (
    None
):
    stack = _stack()
    await stack.add_credentials()

    result = await stack.investigate(
        InvestigationRequest(root=observable_root(DOMAIN), depth=InvestigationDepth.STANDARD)
    )

    # The planner recorded the blind spot rather than forgetting it.
    item = next(c for c in result.enrichment.coverage if c.capability is INFRA)
    assert item.status is CoverageStatus.NOT_COVERED
    assert item.providers_considered == ()
    assert item.catalogue_unavailable

    # Readiness read it as a catalogue fact with no remaining path.
    gap = next(g for g in result.readiness.gaps if g.capability is INFRA)
    assert gap.gap_type is GapType.CAPABILITY_UNAVAILABLE
    assert gap.outlook is GapOutlook.NO_REMAINING_PATH
    assert result.readiness.continuation_state is ContinuationState.EXHAUSTED
    assert result.readiness.readiness_status is ReadinessStatus.UNRESOLVED

    # The workflow stopped on that, in one round, without asking for the
    # impossible and without an issue about its own request.
    assert result.stop_reason is WorkflowStopReason.READINESS_EXHAUSTED
    assert len(result.rounds) == 1
    assert not [
        issue
        for issue in result.issues
        if issue.issue_type is WorkflowIssueType.UNACTIONABLE_INFORMATION_NEED
    ]
    assert not any(d.capability is INFRA for r in result.rounds for d in r.directives)
    # Nobody was asked about it, because nobody could be.
    assert all(a.capability is not INFRA for a in result.enrichment.attempts)

    # And the assessment is what the evidence justifies, unchanged by the fix.
    assert result.assessment.assessment.verdict is Verdict.INCONCLUSIVE


@pytest.mark.asyncio
async def test_the_shipped_catalogue_reports_the_domain_blind_spot_in_the_analyst_report() -> None:
    """The live case, offline: the real catalogue with no credential configured.

    Every remote source is unconfigured, so nothing leaves the machine and the
    reputation requirement is *blocked* -- but the infrastructure requirement is
    typed by the catalogue, not by the missing keys: unavailable, with no path,
    and the report says so instead of promising more data.
    """
    application, _ = await build_default_application(user_id=LOCAL_CLI_USER, environment={})
    report = await application.investigate(
        AnalystInvestigationRequest(observable=DOMAIN, depth=InvestigationDepth.STANDARD),
        build_local_context(),
    )

    coverage = {item.capability: item for item in report.coverage.items}
    assert coverage[INFRA.value].gap_type == GapType.CAPABILITY_UNAVAILABLE.value
    assert coverage[INFRA.value].completion == "not_attempted"
    needs = [item for item in report.information_needs.items if item.capability == INFRA.value]
    assert all(item.outlook == GapOutlook.NO_REMAINING_PATH.value for item in needs)
    assert report.readiness.continuation_state != ContinuationState.MORE_DATA_AVAILABLE.value
    assert report.investigation.stop_reason != WorkflowStopReason.NO_ACTIONABLE_CONTINUATION.value
    assert not [
        item
        for item in report.issues.items
        if item.issue_type == WorkflowIssueType.UNACTIONABLE_INFORMATION_NEED.value
    ]
    assert report.assessment.verdict == Verdict.INCONCLUSIVE.value
