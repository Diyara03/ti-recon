"""Gap-aware continuation: an eligible unattempted source is asked first (Task 24 Phase 2).

Reconstructed from a live address investigation. Reputation's two-family target
was met by one family's data plus a sibling dataset's ``NO_DATA``, so the second
dataset in that family -- eligible, configured, unattempted, and built for a
different question -- was never a candidate; the only continuation directive
named a capability nobody configured could serve, and the run ended
"without progress" with an unasked source in the catalogue.

The rule is generic: a family whose only answer was ``NO_DATA`` stays *open*
while a sibling dataset serving the capability is still eligible, so the goal
stays unsatisfied and the sibling is considered. A family that answered with
data is closed exactly as before, so this is gap closure, not
query-everything.
"""

from __future__ import annotations

import pytest

from fixtures.investigation import InvestigationStack, observable_root, spec
from fixtures.investigation.stack import ScriptedProvider, claim_evidence
from ti_recon.credentials import AuthType, CredentialStatus
from ti_recon.enums import (
    EvidenceClass,
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    ProviderRunStatus,
)
from ti_recon.investigation import InvestigationRequest, RoundTrigger, WorkflowStopReason
from ti_recon.planning.models import CallCostClass, NoveltyClass, ProviderLocality, SkipReason
from ti_recon.reasoning.claims.models import ClaimSemantic
from ti_recon.reasoning.readiness.models import ContinuationState, ReadinessStatus

ADDRESS = "203.0.113.77"
REPUTATION = ProviderCapability.REPUTATION
THREAT = ProviderCapability.THREAT_ASSOCIATIONS
SCANNER = ProviderCapability.SCANNER_CONTEXT
OWNERSHIP = ProviderCapability.NETWORK_OWNERSHIP
CONTEXT = ProviderCapability.FALSE_POSITIVE_CONTEXT
IPV4 = frozenset({IntelObjectType.IPV4_ADDR})

USER = "analyst-gap"


def _weak_aggregate() -> object:
    return claim_evidence(
        ClaimSemantic.AGGREGATED_REPUTATION, evidence_class=EvidenceClass.AGGREGATED_REPUTATION
    )


def _stack(
    *,
    urls_status: ProviderRunStatus = ProviderRunStatus.NO_DATA,
    urls_answers: bool = False,
    ioc_capabilities: frozenset[ProviderCapability] = frozenset({REPUTATION, THREAT}),
    urls_capabilities: frozenset[ProviderCapability] = frozenset({REPUTATION, THREAT}),
    configure_scanner: bool = False,
    first_family_decisive: bool = False,
    max_remote: int | None = None,
) -> tuple[InvestigationStack, InvestigationRequest]:
    """The live shape, in generic terms.

    ``fam_a`` answers reputation with data. ``fam_b`` has two datasets: a
    URL-shaped one ranked first, and an IOC-shaped one that knows the address.
    ``scanner`` is the only scanner-context source and is unconfigured unless
    asked for. ``local_ctx`` is a free local context source.
    """
    urls_script = (
        {ADDRESS: claim_evidence(ClaimSemantic.MALICIOUS_REPUTATION)} if urls_answers else {}
    )
    if urls_status is not ProviderRunStatus.NO_DATA and not urls_answers:
        urls_script = {
            ADDRESS: claim_evidence(ClaimSemantic.MALICIOUS_REPUTATION, status=urls_status)
        }
    providers = [
        ScriptedProvider(
            spec(
                "rep_a",
                family="fam_a",
                capabilities=frozenset({REPUTATION, OWNERSHIP}),
                priority=70,
                object_types=IPV4,
            ),
            {
                ADDRESS: (
                    claim_evidence(ClaimSemantic.MALWARE_DISTRIBUTION)
                    if first_family_decisive
                    else _weak_aggregate()
                )
            },
        ),
        ScriptedProvider(
            spec(
                "fam_b_urls",
                family="fam_b",
                capabilities=urls_capabilities,
                priority=55,
                object_types=IPV4,
                invariant=True,
            ),
            urls_script,
        ),
        ScriptedProvider(
            spec(
                "fam_b_iocs",
                family="fam_b",
                capabilities=ioc_capabilities,
                priority=50,
                object_types=IPV4,
                invariant=True,
            ),
            {ADDRESS: claim_evidence(ClaimSemantic.C2_ASSOCIATION)},
        ),
        ScriptedProvider(
            spec(
                "scanner",
                family="fam_scan",
                capabilities=frozenset({SCANNER, REPUTATION, OWNERSHIP}),
                priority=60,
                object_types=IPV4,
            ),
            {},
        ),
        ScriptedProvider(
            spec(
                "local_ctx",
                family="fam_local",
                capabilities=frozenset({CONTEXT}),
                locality=ProviderLocality.LOCAL,
                cost=CallCostClass.ZERO,
                priority=90,
                object_types=IPV4,
            ),
            {},
        ),
    ]
    stack = InvestigationStack(providers=providers)
    stack._configure_scanner = configure_scanner  # type: ignore[attr-defined]
    request = InvestigationRequest(
        root=observable_root(ADDRESS),
        depth=InvestigationDepth.STANDARD,
        max_remote_provider_runs=max_remote,
    )
    return stack, request


async def _credentials(stack: InvestigationStack) -> None:
    """One key per remote fake, keyed by its own id, except the scanner unless asked."""
    for provider in stack.providers:
        descriptor = provider.descriptor
        if not descriptor.requires_credentials:
            continue
        if descriptor.provider_id == "scanner" and not stack._configure_scanner:  # type: ignore[attr-defined]
            continue
        await stack.manager.create_connection(
            user_id=USER,
            provider_id=descriptor.provider_id,
            secret=f"{descriptor.provider_id}-key",
            auth_type=AuthType.API_KEY,
            status=CredentialStatus.ACTIVE,
            credential_group=descriptor.provider_id,
        )


def _attempts_for(result, provider_id: str):
    return [item for item in result.enrichment.attempts if item.provider_id == provider_id]


def _eligible_unattempted_for(
    result, stack: InvestigationStack, capability: ProviderCapability
) -> set[str]:
    """Providers that support ``capability`` for the root and were never attempted,
    never skipped for an ineligibility reason, and not blocked -- the set the
    gap-closure invariant requires to be empty at a no-progress stop."""
    attempted = {item.provider_id for item in result.enrichment.attempts}
    ineligible = {
        item.provider_id
        for decision in result.enrichment.decisions
        for item in decision.skipped
        if item.capability is capability
        and item.reason
        not in {SkipReason.ALREADY_ATTEMPTED, SkipReason.GOAL_NOT_ACTIVE, SkipReason.REDUNDANT}
    }
    object_type = result.root.object_type
    return {
        provider.descriptor.provider_id
        for provider in stack.providers
        if provider.descriptor.supports(object_type, capability)
        and provider.descriptor.provider_id not in attempted
        and provider.descriptor.provider_id not in ineligible
    }


# --------------------------------------------------------------------------- #
# A. The live defect: the sibling dataset is asked before the run gives up
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_sibling_dataset_is_asked_before_a_no_progress_stop() -> None:
    stack, request = _stack()
    await _credentials(stack)

    result = await stack.investigate(request, user_id=USER)

    iocs = _attempts_for(result, "fam_b_iocs")
    assert [item.status for item in iocs] == [ProviderRunStatus.SUCCESS]
    assert iocs[0].novelty is NoveltyClass.NEW_DATASET_SAME_FAMILY
    urls = _attempts_for(result, "fam_b_urls")
    assert [item.status for item in urls] == [ProviderRunStatus.NO_DATA]
    # The sibling was reached inside the round that learned the first dataset
    # was empty, so no continuation was needed to find it.
    assert iocs[0].sequence > urls[0].sequence


@pytest.mark.asyncio
async def test_no_eligible_unattempted_source_remains_for_any_directive_at_a_no_progress_stop() -> (
    None
):
    """The gap-closure invariant, checked from the record rather than trusted."""
    stack, request = _stack()
    await _credentials(stack)

    result = await stack.investigate(request, user_id=USER)

    if result.stop_reason in {
        WorkflowStopReason.NO_PROGRESS,
        WorkflowStopReason.CURRENT_BUDGET_EXHAUSTED,
    }:
        for round_ in result.rounds:
            for directive in round_.directives:
                assert _eligible_unattempted_for(result, stack, directive.capability) == set()
        # And the reputation question itself left nothing eligible unasked.
        assert _eligible_unattempted_for(result, stack, REPUTATION) == set()


# --------------------------------------------------------------------------- #
# B. Nothing left covers the gap: the run may stop
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_gap_nothing_eligible_can_cover_lets_the_run_stop_once() -> None:
    """The scanner gap's only source answered NOT_CONFIGURED inside a bundled
    call, so readiness now sees it as blocked (Task 24 Phase 3) rather than
    never attempted, and the run stops without a fruitless continuation."""
    stack, request = _stack()
    await _credentials(stack)

    result = await stack.investigate(request, user_id=USER)

    assert result.readiness.readiness_status in {
        ReadinessStatus.UNRESOLVED,
        ReadinessStatus.NEEDS_MORE_DATA,
    }
    assert result.readiness.continuation_state in {
        ContinuationState.BLOCKED,
        ContinuationState.MORE_DATA_AVAILABLE,
    }
    assert result.stop_reason in {
        WorkflowStopReason.READINESS_BLOCKED,
        WorkflowStopReason.NO_PROGRESS,
        WorkflowStopReason.CURRENT_BUDGET_EXHAUSTED,
    }
    continuations = [r for r in result.rounds if r.trigger is RoundTrigger.READINESS_CONTINUATION]
    assert len(continuations) <= 1
    # The scanner gap really is unreachable: its only source is unconfigured.
    assert [item.status for item in _attempts_for(result, "scanner")] == [
        ProviderRunStatus.NOT_CONFIGURED
    ]


# --------------------------------------------------------------------------- #
# C. Adequate readiness stops early; no query-everything
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_adequate_readiness_stops_early_and_leaves_the_sibling_unasked() -> None:
    """A family that answered with data is closed: the sibling is redundant."""
    stack, request = _stack(urls_answers=True, first_family_decisive=True)
    await _credentials(stack)

    result = await stack.investigate(request, user_id=USER)

    assert result.readiness.readiness_status in {
        ReadinessStatus.READY,
        ReadinessStatus.READY_WITH_LIMITATIONS,
    }
    assert result.rounds[-1].trigger is RoundTrigger.INITIAL
    assert _attempts_for(result, "fam_b_iocs") == []
    assert [item.status for item in _attempts_for(result, "fam_b_urls")] == [
        ProviderRunStatus.SUCCESS
    ]


@pytest.mark.asyncio
async def test_a_family_that_answered_with_data_is_not_reopened_by_the_sibling() -> None:
    """Even below adequate readiness, one answer with content closes the family."""
    stack, request = _stack(urls_answers=True)
    await _credentials(stack)

    result = await stack.investigate(request, user_id=USER)

    assert _attempts_for(result, "fam_b_iocs") == []


# --------------------------------------------------------------------------- #
# E. Same family, distinct capabilities
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_family_sameness_does_not_suppress_a_materially_different_dataset() -> None:
    stack, request = _stack(urls_capabilities=frozenset({REPUTATION}))
    await _credentials(stack)

    result = await stack.investigate(request, user_id=USER)

    iocs = _attempts_for(result, "fam_b_iocs")
    assert [item.status for item in iocs] == [ProviderRunStatus.SUCCESS]
    assert iocs[0].source_family == "fam_b"
    # Still one family in the coverage record: two datasets, one origin.
    reputation = next(item for item in result.enrichment.coverage if item.capability is REPUTATION)
    assert reputation.status.value == "covered"


# --------------------------------------------------------------------------- #
# F. NO_DATA is never repeated
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_no_data_source_is_never_asked_the_same_question_again() -> None:
    stack, request = _stack()
    await _credentials(stack)

    result = await stack.investigate(request, user_id=USER)

    assert len(stack.requests_for("fam_b_urls")) == 1
    assert len(stack.requests_for("fam_b_iocs")) == 1
    assert len(_attempts_for(result, "fam_b_urls")) == 1


# --------------------------------------------------------------------------- #
# G. Transient failure stays bounded
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_transient_failure_is_bounded_and_the_sibling_is_still_asked() -> None:
    stack, request = _stack(urls_status=ProviderRunStatus.TEMPORARILY_UNAVAILABLE)
    await _credentials(stack)

    result = await stack.investigate(request, user_id=USER)

    assert len(result.rounds) <= 2
    assert len(stack.requests_for("fam_b_urls")) == 1
    assert [item.status for item in _attempts_for(result, "fam_b_urls")] == [
        ProviderRunStatus.TEMPORARILY_UNAVAILABLE
    ]
    # A failed sibling gives the family no answer at all, so the other dataset
    # is asked exactly as before this change.
    assert [item.status for item in _attempts_for(result, "fam_b_iocs")] == [
        ProviderRunStatus.SUCCESS
    ]


# --------------------------------------------------------------------------- #
# The budget still binds
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_an_open_family_does_not_buy_past_the_remote_allowance() -> None:
    stack, request = _stack(max_remote=2)
    await _credentials(stack)

    result = await stack.investigate(request, user_id=USER)

    charged = [
        item
        for item in result.enrichment.attempts
        if item.called_provider and item.locality is ProviderLocality.REMOTE
    ]
    assert len(charged) <= 2
    assert result.enrichment.budget.remote_remaining == 0
