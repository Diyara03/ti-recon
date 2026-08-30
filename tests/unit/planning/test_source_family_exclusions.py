"""Barring a source family from one question (Task 13 seam).

Readiness can ask for a search *independent* of whatever produced an
assessment. Family is the only provenance knowable before a call, so a family
already known to share that origin cannot supply the answer however well it
ranks — and letting it win would spend the remaining allowance on a source that
could not satisfy the requirement it was released for, leaving the genuinely
independent candidate unreachable behind an empty budget.

The constraint is per capability throughout. A family barred from challenging a
benign assessment is not barred from anything else, because independence was
never what those other questions were about.
"""

from __future__ import annotations

from fixtures.planning import FakeProviderSpec, build_registry, file_object
from ti_recon.enums import IntelObjectType, InvestigationDepth, ProviderCapability
from ti_recon.planning import (
    AdaptiveEnrichmentPlanner,
    CallCostClass,
    EnrichmentPlanningRequest,
    PlanningConstraints,
    ProviderLocality,
    SkipReason,
)

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
FILE_TYPES = frozenset({IntelObjectType.FILE})


def _spec(
    provider_id: str,
    *,
    family: str,
    capabilities: frozenset[ProviderCapability],
    priority: int = 50,
) -> FakeProviderSpec:
    return FakeProviderSpec(
        provider_id=provider_id,
        source_family=family,
        capabilities=capabilities,
        locality=ProviderLocality.REMOTE,
        cost_class=CallCostClass.LOW,
        object_types=FILE_TYPES,
        priority=priority,
        minimum_depth=InvestigationDepth.QUICK,
    )


def _planner(*specs: FakeProviderSpec) -> AdaptiveEnrichmentPlanner:
    registry, profiles = build_registry(specs)
    return AdaptiveEnrichmentPlanner(registry=registry, profiles=profiles)


def _request() -> EnrichmentPlanningRequest:
    return EnrichmentPlanningRequest(intel_object=file_object(), depth=InvestigationDepth.STANDARD)


def test_an_excluded_family_is_not_a_candidate_however_well_it_ranks() -> None:
    """The higher-ranked source is the one that cannot answer this question.

    ``dependent`` wins on priority and would be chosen every other time. For a
    question that has to come from somewhere else, it is not a candidate at all
    — and the skip says which family, so the trace explains itself.
    """
    plan = _planner(
        _spec("dependent", family="fam_a", capabilities=frozenset({REPUTATION}), priority=99),
        _spec("other", family="fam_b", capabilities=frozenset({REPUTATION}), priority=1),
    )
    request = _request()
    state = plan.initial_state(
        request,
        carry_over=plan.initial_state(request),
        focus=frozenset({REPUTATION}),
        excluded_families={REPUTATION: frozenset({"fam_a"})},
    )

    decision = plan.next(request, state)

    assert decision.call is not None
    assert decision.call.provider_id == "other"
    excluded = [
        item for item in decision.skipped if item.reason is SkipReason.SOURCE_FAMILY_EXCLUDED
    ]
    assert [item.provider_id for item in excluded] == ["dependent"]
    assert excluded[0].detail == "fam_a"


def test_a_different_provider_in_the_same_family_is_still_excluded() -> None:
    """A different provider id is not independent information.

    Three datasets run by one organisation are one source, which is the whole
    reason the exclusion is keyed on family rather than on who was asked.
    """
    plan = _planner(
        _spec("a_one", family="fam_a", capabilities=frozenset({REPUTATION}), priority=99),
        _spec("a_two", family="fam_a", capabilities=frozenset({REPUTATION}), priority=98),
    )
    request = _request()
    state = plan.initial_state(
        request,
        carry_over=plan.initial_state(request),
        focus=frozenset({REPUTATION}),
        excluded_families={REPUTATION: frozenset({"fam_a"})},
    )

    decision = plan.next(request, state)

    assert decision.call is None
    assert {
        item.provider_id
        for item in decision.skipped
        if item.reason is SkipReason.SOURCE_FAMILY_EXCLUDED
    } == {"a_one", "a_two"}


def test_an_exclusion_binds_one_capability_and_not_the_round() -> None:
    """Mandatory: the family answers every other question exactly as before.

    Independence matters to the challenge and to nothing else. One set for the
    whole round would silently withdraw a source from work where its answer was
    worth exactly what it always was.
    """
    plan = _planner(
        _spec("shared", family="fam_a", capabilities=frozenset({REPUTATION, INTELLIGENCE})),
    )
    request = _request()
    state = plan.initial_state(
        request,
        carry_over=plan.initial_state(request),
        focus=frozenset({REPUTATION, INTELLIGENCE}),
        excluded_families={REPUTATION: frozenset({"fam_a"})},
    )

    decision = plan.next(request, state)

    # Still chosen, for the capability the exclusion says nothing about.
    assert decision.call is not None
    assert decision.call.provider_id == "shared"
    assert decision.call.capability is INTELLIGENCE
    assert REPUTATION not in decision.call.capabilities
    assert any(
        item.reason is SkipReason.SOURCE_FAMILY_EXCLUDED and item.capability is REPUTATION
        for item in decision.skipped
    )


def test_a_dependent_source_cannot_spend_the_last_call() -> None:
    """The point of doing this before execution rather than after.

    One remote call left. Without the constraint the higher-ranked dependent
    source takes it, the requirement stays unmet, and the source that could have
    met it is unaffordable — so the investigation ends further from an answer
    than it started the round.
    """
    specs = (
        _spec("dependent", family="fam_a", capabilities=frozenset({REPUTATION}), priority=99),
        _spec("independent", family="fam_b", capabilities=frozenset({REPUTATION}), priority=1),
    )
    request = EnrichmentPlanningRequest(
        intel_object=file_object(),
        depth=InvestigationDepth.STANDARD,
        constraints=PlanningConstraints(max_remote_provider_runs=1),
    )
    plan = _planner(*specs)
    state = plan.initial_state(
        request,
        carry_over=plan.initial_state(request),
        focus=frozenset({REPUTATION}),
        excluded_families={REPUTATION: frozenset({"fam_a"})},
    )

    decision = plan.next(request, state)

    assert state.budget.remote_remaining == 1
    assert decision.call is not None
    assert decision.call.provider_id == "independent"


def test_no_exclusion_leaves_every_family_eligible() -> None:
    """The default, and every first round: nothing is barred from anything."""
    plan = _planner(
        _spec("dependent", family="fam_a", capabilities=frozenset({REPUTATION}), priority=99),
        _spec("other", family="fam_b", capabilities=frozenset({REPUTATION}), priority=1),
    )
    request = _request()
    state = plan.initial_state(request)

    decision = plan.next(request, state)

    assert decision.call is not None
    assert decision.call.provider_id == "dependent"
    assert not any(item.reason is SkipReason.SOURCE_FAMILY_EXCLUDED for item in decision.skipped)
