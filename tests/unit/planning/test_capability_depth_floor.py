"""A capability served only from a deeper investigation is not selected below it.

A provider can answer reputation at QUICK and detonation data only at DEEP.
Before Task 24 Phase 3 the planner selected the shallow-depth behaviour call,
the adapter refused it as NOT_SUPPORTED, and the refusal was charged as a
remote run: a budget unit and a decision spent on an answer the catalogue could
have declined for free. The floor is declared by the provider's planning
profile, per capability, and enforced before cost and budget.
"""

from __future__ import annotations

from fixtures.planning import FAMILY_A, FakeProviderSpec, build_registry, fake_outcome, file_object
from ti_recon.enums import EvidenceEffect, InvestigationDepth, ProviderCapability
from ti_recon.planning import AdaptiveEnrichmentPlanner, EnrichmentPlanningRequest, SkipReason
from ti_recon.planning.models import ProviderPlanningProfile
from ti_recon.providers.gti.descriptor import build_gti_planning_profile

REPUTATION = ProviderCapability.REPUTATION
BEHAVIOR = ProviderCapability.FILE_BEHAVIOR


def _planner() -> AdaptiveEnrichmentPlanner:
    registry, profiles = build_registry(
        (
            FakeProviderSpec(
                provider_id="deep_only_behaviour",
                source_family=FAMILY_A,
                capabilities=frozenset({REPUTATION, BEHAVIOR}),
                priority=60,
            ),
        )
    )
    # Re-declare the profile with the per-capability floor the fake spec
    # cannot express: reputation at any depth, behaviour only at DEEP.
    base = profiles.require("deep_only_behaviour")
    profiles = type(profiles)(
        (base.model_copy(update={"capability_minimum_depth": {BEHAVIOR: InvestigationDepth.DEEP}}),)
    )
    return AdaptiveEnrichmentPlanner(registry=registry, profiles=profiles)


def _run(depth: InvestigationDepth) -> tuple[list[str], list[tuple[str, str]]]:
    plan = _planner()
    request = EnrichmentPlanningRequest(
        intel_object=file_object(),
        depth=depth,
        requested_capabilities=frozenset({BEHAVIOR}),
    )
    state = plan.initial_state(request)
    chosen: list[str] = []
    skipped: list[tuple[str, str]] = []
    for _ in range(6):
        decision = plan.next(request, state)
        skipped.extend((item.capability.value, item.reason.value) for item in decision.skipped)
        if decision.stop is not None:
            break
        call = decision.call
        assert call is not None
        chosen.append(f"{call.provider_id}:{call.capability.value}")
        state.observe(
            call,
            fake_outcome(
                call.provider_id,
                source_family=call.source_family,
                effect=EvidenceEffect.SUPPORTS_MALICIOUS,
            ),
        )
    return chosen, skipped


def test_the_capability_is_skipped_below_its_floor_and_never_charged() -> None:
    chosen, skipped = _run(InvestigationDepth.STANDARD)
    assert "deep_only_behaviour:file_behavior" not in chosen
    assert ("file_behavior", SkipReason.DEPTH_TOO_SHALLOW.value) in skipped
    # Reputation from the same provider is unaffected by the behaviour floor.
    assert "deep_only_behaviour:reputation" in chosen


def test_the_capability_is_selected_at_its_floor() -> None:
    chosen, _ = _run(InvestigationDepth.DEEP)
    assert any(item.endswith(":file_behavior") for item in chosen)


def test_the_floor_never_lowers_the_provider_minimum() -> None:
    profile = ProviderPlanningProfile(
        provider_id="p",
        source_family="f",
        locality="remote",  # type: ignore[arg-type]
        cost_class="low",  # type: ignore[arg-type]
        planning_capabilities=frozenset({REPUTATION}),
        minimum_depth=InvestigationDepth.STANDARD,
        capability_minimum_depth={REPUTATION: InvestigationDepth.QUICK},
    )
    assert profile.minimum_depth_for(REPUTATION) is InvestigationDepth.STANDARD
    assert profile.minimum_depth_for(BEHAVIOR) is InvestigationDepth.STANDARD


def test_gti_declares_behaviour_as_deep_only() -> None:
    """The planner is told the same thing the adapter enforces."""
    profile = build_gti_planning_profile()
    assert profile.minimum_depth_for(BEHAVIOR) is InvestigationDepth.DEEP
    assert profile.minimum_depth_for(REPUTATION) is InvestigationDepth.QUICK
