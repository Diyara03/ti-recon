"""Unavailable, unconfigured, unattempted, blocked, empty, out of scope (Task 24, US-06).

Six different reasons a requirement can be unmet, and readiness must keep all
six apart because each asks the analyst for something different: nothing
(unavailable), a credential (unconfigured), another round (unattempted), a
larger allowance or patience (blocked), nothing again but for a different
reason (a source answered and held nothing), and nothing because the question
was never in scope. The live defect collapsed the first into the third.

The planner states availability, as a ``NOT_COVERED`` coverage item with nobody
considered; readiness reads that structure and nothing else -- it walks no
catalogue of its own. Case E proves the handoff end to end through the real
planner.
"""

from __future__ import annotations

from fixtures.planning import FakeProviderSpec, build_registry
from fixtures.readiness import assess, attempt, coverage_item, file_object, scenario, skipped
from ti_recon.enums import (
    CoverageStatus,
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    ProviderRunStatus,
    Verdict,
)
from ti_recon.investigation.continuation import directives_for, wants_continuation
from ti_recon.normalization import normalize_observable
from ti_recon.planning import (
    CAPABILITY_UNAVAILABLE_REASON,
    AdaptiveEnrichmentPlanner,
    EnrichmentPlanningRequest,
    SkipReason,
)
from ti_recon.reasoning.readiness import (
    CheckCompletion,
    ContinuationState,
    GapOutlook,
    GapType,
    InformationYield,
    ReadinessStatus,
    RequirementStatus,
)

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
BEHAVIOUR = ProviderCapability.FILE_BEHAVIOR
INFRA = ProviderCapability.CURRENT_INFRASTRUCTURE
ROOT = file_object(sha256="d" * 64)


def _evaluation(result, capability):
    return next(
        item for item in result.requirement_evaluations if item.requirement.capability is capability
    )


def _gap(result, capability):
    return next((gap for gap in result.gaps if gap.capability is capability), None)


def _base():
    """A file at STANDARD whose intelligence check ran and found nothing, so the
    only thing that varies between cases is what happened to reputation."""
    return scenario(ROOT).with_attempt(
        attempt(INTELLIGENCE, provider="intel", status=ProviderRunStatus.NO_DATA)
    )


# --------------------------------------------------------------------------- #
# A -- zero compatible providers
# --------------------------------------------------------------------------- #


def test_a_a_capability_nobody_serves_is_unavailable_with_no_remaining_path() -> None:
    scene = _base().with_coverage(
        coverage_item(
            REPUTATION,
            status=CoverageStatus.NOT_COVERED,
            providers_considered=(),
            reason=CAPABILITY_UNAVAILABLE_REASON,
        )
    )
    result = assess(scene)
    evaluation = _evaluation(result, REPUTATION)
    gap = _gap(result, REPUTATION)

    assert evaluation.status is RequirementStatus.UNSATISFIED
    assert gap is not None
    assert gap.gap_type is GapType.CAPABILITY_UNAVAILABLE
    assert gap.outlook is GapOutlook.NO_REMAINING_PATH
    assert result.continuation_state is ContinuationState.EXHAUSTED
    assert result.readiness_status is ReadinessStatus.UNRESOLVED
    assert result.verdict is Verdict.INCONCLUSIVE
    # And the workflow is told the truth: nothing further can be asked.
    assert not wants_continuation(result)
    assert directives_for(result, scene.fusion(), admissible=frozenset({INTELLIGENCE})) == ()


def test_a_the_reason_text_is_not_what_readiness_reads() -> None:
    """Structure, never prose: reworded, the item still means unavailable."""
    result = assess(
        _base().with_coverage(
            coverage_item(
                REPUTATION,
                status=CoverageStatus.NOT_COVERED,
                providers_considered=(),
                reason="some other wording",
            )
        )
    )
    assert _gap(result, REPUTATION).gap_type is GapType.CAPABILITY_UNAVAILABLE


# --------------------------------------------------------------------------- #
# B -- a compatible, configured provider exists and was not called
# --------------------------------------------------------------------------- #


def test_b_a_served_capability_nobody_asked_is_unattempted_and_actionable() -> None:
    scene = _base().with_coverage(
        coverage_item(
            REPUTATION, status=CoverageStatus.NOT_COVERED, providers_considered=("alpha",)
        )
    )
    result = assess(scene)
    gap = _gap(result, REPUTATION)

    assert gap.gap_type is GapType.NOT_ATTEMPTED
    assert gap.outlook is GapOutlook.MAY_ADDRESS_MATERIAL_GAP
    assert result.continuation_state is ContinuationState.MORE_DATA_AVAILABLE
    assert result.readiness_status is ReadinessStatus.NEEDS_MORE_DATA
    assert wants_continuation(result)
    directives = directives_for(result, scene.fusion(), admissible=frozenset({REPUTATION}))
    assert [item.capability for item in directives] == [REPUTATION]


# --------------------------------------------------------------------------- #
# C -- a compatible provider exists but is not configured
# --------------------------------------------------------------------------- #


def test_c_an_unconfigured_provider_is_blocked_never_unavailable() -> None:
    result = assess(
        _base()
        .with_attempt(
            attempt(
                REPUTATION,
                provider="alpha",
                status=ProviderRunStatus.NOT_CONFIGURED,
                called_provider=False,
            )
        )
        .with_coverage(
            coverage_item(
                REPUTATION, status=CoverageStatus.NOT_COVERED, providers_considered=("alpha",)
            )
        )
    )
    gap = _gap(result, REPUTATION)

    assert _evaluation(result, REPUTATION).completion is CheckCompletion.BLOCKED
    assert gap.gap_type is GapType.NOT_CONFIGURED
    assert gap.gap_type is not GapType.CAPABILITY_UNAVAILABLE
    # A credential can be supplied, so the door is not closed.
    assert gap.outlook is GapOutlook.MAY_ADDRESS_MATERIAL_GAP
    assert result.continuation_state is ContinuationState.BLOCKED


# --------------------------------------------------------------------------- #
# D -- served only at a deeper investigation
# --------------------------------------------------------------------------- #


def test_d_a_depth_gated_capability_is_out_of_depth_never_unavailable() -> None:
    result = assess(
        _base()
        .with_skip(skipped(REPUTATION, SkipReason.DEPTH_TOO_SHALLOW, provider="alpha"))
        .with_coverage(
            coverage_item(
                REPUTATION, status=CoverageStatus.NOT_COVERED, providers_considered=("alpha",)
            )
        )
    )
    evaluation = _evaluation(result, REPUTATION)

    assert evaluation.status is RequirementStatus.NOT_APPLICABLE
    assert evaluation.completion is CheckCompletion.OUT_OF_SCOPE
    assert _gap(result, REPUTATION) is None


# --------------------------------------------------------------------------- #
# E -- compatibility is capability and observable type, through the planner
# --------------------------------------------------------------------------- #


def _planner_with_address_only_infrastructure() -> AdaptiveEnrichmentPlanner:
    both = frozenset({IntelObjectType.DOMAIN_NAME, IntelObjectType.IPV4_ADDR})
    registry, profiles = build_registry(
        (
            FakeProviderSpec(
                provider_id="local_context",
                source_family="local",
                capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
                object_types=both,
            ),
            FakeProviderSpec(
                provider_id="reputation_a",
                source_family="fam_a",
                capabilities=frozenset({REPUTATION}),
                object_types=both,
            ),
            FakeProviderSpec(
                provider_id="infra",
                source_family="infra",
                capabilities=frozenset({INFRA}),
                object_types=frozenset({IntelObjectType.IPV4_ADDR}),
            ),
        )
    )
    return AdaptiveEnrichmentPlanner(registry=registry, profiles=profiles)


def _planner_coverage(plan: AdaptiveEnrichmentPlanner, value: str):
    root = normalize_observable(value).intel_object
    request = EnrichmentPlanningRequest(
        intel_object=root,
        depth=InvestigationDepth.STANDARD,
        requested_capabilities=frozenset({INFRA}),
    )
    state = plan.initial_state(request)
    return root, state.coverage_items(
        plan.depth_targets(request, state), plan.providers_considered(request)
    )


def test_e_the_same_provider_leaves_a_domain_unserved_and_an_address_served() -> None:
    plan = _planner_with_address_only_infrastructure()

    domain, domain_coverage = _planner_coverage(plan, "example.com")
    scene = scenario(domain, requested_capabilities=frozenset({INFRA}))
    for item in domain_coverage:
        scene = scene.with_coverage(item)
    assert _gap(assess(scene), INFRA).gap_type is GapType.CAPABILITY_UNAVAILABLE

    address, address_coverage = _planner_coverage(plan, "203.0.113.9")
    scene = scenario(address, requested_capabilities=frozenset({INFRA}))
    for item in address_coverage:
        scene = scene.with_coverage(item)
    assert _gap(assess(scene), INFRA).gap_type is GapType.NOT_ATTEMPTED


# --------------------------------------------------------------------------- #
# F -- a compatible provider answered and held nothing
# --------------------------------------------------------------------------- #


def test_f_a_no_data_answer_is_a_completed_check_never_unavailable() -> None:
    result = assess(
        _base()
        .with_attempt(attempt(REPUTATION, provider="alpha", status=ProviderRunStatus.NO_DATA))
        .with_coverage(coverage_item(REPUTATION, providers_considered=("alpha",)))
    )
    evaluation = _evaluation(result, REPUTATION)

    assert evaluation.status is RequirementStatus.SATISFIED
    assert evaluation.completion is CheckCompletion.COMPLETE
    assert evaluation.information_yield is InformationYield.NO_DATA
    assert _gap(result, REPUTATION) is None


# --------------------------------------------------------------------------- #
# G -- a compatible provider was blocked by allowance, quota or cooldown
# --------------------------------------------------------------------------- #


def test_g_a_budget_skip_is_budget_limited_never_unavailable() -> None:
    result = assess(
        _base()
        .with_skip(skipped(REPUTATION, SkipReason.BUDGET_EXHAUSTED, provider="alpha"))
        .with_coverage(
            coverage_item(
                REPUTATION, status=CoverageStatus.NOT_COVERED, providers_considered=("alpha",)
            )
        )
    )
    assert _gap(result, REPUTATION).gap_type is GapType.BUDGET_LIMITED
    assert result.continuation_state is ContinuationState.MORE_DATA_AVAILABLE


def test_g_execution_history_still_outranks_an_empty_candidate_list() -> None:
    """A recorded budget skip proves a candidate existed, whatever the item says."""
    result = assess(
        _base()
        .with_skip(skipped(REPUTATION, SkipReason.BUDGET_EXHAUSTED, provider="alpha"))
        .with_coverage(
            coverage_item(REPUTATION, status=CoverageStatus.NOT_COVERED, providers_considered=())
        )
    )
    assert _gap(result, REPUTATION).gap_type is GapType.BUDGET_LIMITED


def test_g_a_quota_refusal_is_blocked_never_unavailable() -> None:
    result = assess(
        _base()
        .with_attempt(
            attempt(REPUTATION, provider="alpha", status=ProviderRunStatus.QUOTA_EXCEEDED)
        )
        .with_coverage(
            coverage_item(
                REPUTATION, status=CoverageStatus.NOT_COVERED, providers_considered=("alpha",)
            )
        )
    )
    gap = _gap(result, REPUTATION)
    assert gap.gap_type is GapType.QUOTA_EXCEEDED
    assert result.continuation_state is ContinuationState.BLOCKED


# --------------------------------------------------------------------------- #
# H -- the goal was never in play
# --------------------------------------------------------------------------- #


def test_h_a_goal_that_never_activated_is_not_applicable_never_unavailable() -> None:
    result = assess(
        scenario(ROOT, depth=InvestigationDepth.DEEP)
        .with_attempt(attempt(INTELLIGENCE, provider="intel", status=ProviderRunStatus.NO_DATA))
        .with_attempt(attempt(REPUTATION, provider="alpha", status=ProviderRunStatus.NO_DATA))
        .with_skip(skipped(BEHAVIOUR, SkipReason.GOAL_NOT_ACTIVE, provider="sandbox"))
        .with_coverage(
            coverage_item(BEHAVIOUR, status=CoverageStatus.NOT_COVERED, providers_considered=())
        )
    )
    evaluation = _evaluation(result, BEHAVIOUR)
    assert evaluation.status is RequirementStatus.NOT_APPLICABLE
    assert evaluation.completion is CheckCompletion.OUT_OF_SCOPE
    assert _gap(result, BEHAVIOUR) is None


def test_h_a_capability_outside_the_depth_template_is_no_requirement_at_all() -> None:
    result = assess(
        scenario(ROOT, depth=InvestigationDepth.QUICK).with_attempt(
            attempt(REPUTATION, provider="alpha", status=ProviderRunStatus.NO_DATA)
        )
    )
    assert all(
        item.requirement.capability is not BEHAVIOUR for item in result.requirement_evaluations
    )


# --------------------------------------------------------------------------- #
# Blocked outranks exhausted, and continuable outranks both
# --------------------------------------------------------------------------- #


def test_an_unavailable_capability_beside_a_blocked_one_reports_blocked() -> None:
    """A credential can be supplied; a capability nobody implements cannot.
    The cheapest honest next step is the one named."""
    result = assess(
        scenario(ROOT)
        .with_attempt(
            attempt(
                INTELLIGENCE,
                provider="intel",
                status=ProviderRunStatus.NOT_CONFIGURED,
                called_provider=False,
            )
        )
        .with_coverage(
            coverage_item(REPUTATION, status=CoverageStatus.NOT_COVERED, providers_considered=())
        )
        .with_coverage(
            coverage_item(
                INTELLIGENCE, status=CoverageStatus.NOT_COVERED, providers_considered=("intel",)
            )
        )
    )
    assert _gap(result, REPUTATION).gap_type is GapType.CAPABILITY_UNAVAILABLE
    assert _gap(result, INTELLIGENCE).gap_type is GapType.NOT_CONFIGURED
    assert result.continuation_state is ContinuationState.BLOCKED
