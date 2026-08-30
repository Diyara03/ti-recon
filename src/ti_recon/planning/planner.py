"""The adaptive planner: what should TI Recon ask next? (Task 13)

One method matters — :meth:`AdaptiveEnrichmentPlanner.next` — and it returns
either a provider to ask or a reason to stop. Nothing here executes anything;
nothing here resolves a credential; nothing here decides what any answer means.

Deterministic
-------------

Same observable, depth, requested capabilities, policy, registry and state
produce the same decision. Candidate generation iterates sorted collections and
ranking is a total order, so there is no dependence on dictionary insertion or
adapter registration order.

Adaptive
--------

"Adaptive" here means *the next decision uses the previous answers*, not that
anything learns. A provider that returned nothing is not asked again; a family
that has covered a capability makes a sibling dataset less valuable than an
independent source; directional evidence can make a specialized follow-up worth
buying that would otherwise not have been. That is the whole mechanism, and it is
why remote execution is sequential — a fan-out cannot use the first answer to
avoid the other three calls.
"""

from __future__ import annotations

from dataclasses import dataclass

from ti_recon.enums import (
    ActivityMode,
    IntelObjectType,
    ProviderCapability,
)
from ti_recon.planning.goals import CapabilityGoal, GoalActivation, depth_at_least
from ti_recon.planning.models import (
    EnrichmentPlanningRequest,
    NoveltyClass,
    PlannedProviderCall,
    PlanningDecision,
    ProviderPlanningProfile,
    SkippedCandidate,
    SkipReason,
    StopReason,
)
from ti_recon.planning.policy import EnrichmentPolicy, ProviderPlanningRegistry
from ti_recon.planning.ranking import candidate_key, selection_reason_for
from ti_recon.planning.state import PlanningState
from ti_recon.providers.adapter import ProviderAdapter
from ti_recon.providers.registry import ProviderRegistry

__all__ = ["AdaptiveEnrichmentPlanner", "Candidate"]


@dataclass(frozen=True, slots=True)
class Candidate:
    """One provider/capability pair the planner could choose."""

    adapter: ProviderAdapter
    profile: ProviderPlanningProfile
    capability: ProviderCapability
    goal: CapabilityGoal
    novelty: NoveltyClass
    explicitly_requested: bool
    goal_required_and_unsatisfied: bool
    specialized: bool


class AdaptiveEnrichmentPlanner:
    """Chooses the next provider to ask, or says why to stop."""

    def __init__(
        self,
        *,
        registry: ProviderRegistry,
        profiles: ProviderPlanningRegistry,
        policy: EnrichmentPolicy | None = None,
    ) -> None:
        self._registry = registry
        self._profiles = profiles
        self._policy = policy if policy is not None else EnrichmentPolicy()

    @property
    def policy(self) -> EnrichmentPolicy:
        return self._policy

    @property
    def profiles(self) -> ProviderPlanningRegistry:
        return self._profiles

    # ------------------------------------------------------------------ #
    # Setting up a run
    # ------------------------------------------------------------------ #

    def initial_state(
        self,
        request: EnrichmentPlanningRequest,
        *,
        carry_over: PlanningState | None = None,
        focus: frozenset[ProviderCapability] = frozenset(),
    ) -> PlanningState:
        """Build the starting state, with goals the registry can actually serve.

        A goal nothing can satisfy is dropped rather than carried: it would
        produce a permanently unsatisfiable plan and report a coverage gap as
        though a provider had failed, when in fact nobody offers the capability
        for this observable type. That distinction is preserved in coverage as a
        different reason.
        """
        self._validate_constraints(request)
        servable = self._servable_capabilities(request)
        goals = tuple(
            goal
            for goal in self._policy.goals_for(
                request.intel_object.object_type,
                request.depth,
                requested=request.requested_capabilities,
            )
            if goal.capability in servable
        )
        if carry_over is not None:
            # A later round of the same investigation: everything already spent,
            # attempted and covered comes with it, so the allowance is
            # investigation-wide rather than per round. Goals are recomputed
            # because a continuation may name a capability the first round's
            # template never included.
            return carry_over.continuation(
                goals=goals,
                requested=request.requested_capabilities,
                focus=focus,
            )
        return PlanningState(
            budget=self._policy.budget_for(
                request.depth,
                override_remote=request.constraints.max_remote_provider_runs,
            ),
            goals=goals,
            requested_capabilities=request.requested_capabilities,
        )

    def _validate_constraints(self, request: EnrichmentPlanningRequest) -> None:
        """Refuse a policy naming providers nobody registered.

        Loudly, because a misspelled denylist entry silently permits the provider
        it was written to exclude.
        """
        named = request.constraints.provider_allowlist | request.constraints.provider_denylist
        if named:
            self._profiles.validate_names(named)

    def _servable_capabilities(
        self, request: EnrichmentPlanningRequest
    ) -> frozenset[ProviderCapability]:
        """Capabilities some registered, plannable provider offers for this object."""
        object_type = request.intel_object.object_type
        found: set[ProviderCapability] = set()
        for adapter in self._registry.list_all():
            profile = self._profiles.get(adapter.descriptor.provider_id)
            if profile is None:
                continue
            for capability in profile.planning_capabilities:
                if adapter.descriptor.supports(object_type, capability):
                    found.add(capability)
        return frozenset(found)

    def providers_considered(
        self, request: EnrichmentPlanningRequest
    ) -> dict[ProviderCapability, tuple[str, ...]]:
        """Which providers could have served each capability, for coverage.

        Records candidacy, not success or configuration — an analyst reading a
        gap needs to know whether anybody could have answered.
        """
        object_type = request.intel_object.object_type
        found: dict[ProviderCapability, set[str]] = {}
        for adapter in self._registry.list_all():
            descriptor = adapter.descriptor
            profile = self._profiles.get(descriptor.provider_id)
            if profile is None:
                continue
            for capability in profile.planning_capabilities:
                if descriptor.supports(object_type, capability):
                    found.setdefault(capability, set()).add(descriptor.provider_id)
        return {key: tuple(sorted(value)) for key, value in found.items()}

    def depth_targets(
        self, request: EnrichmentPlanningRequest, state: PlanningState
    ) -> dict[ProviderCapability, int]:
        """Family target per goal at this depth."""
        return {goal.capability: goal.families_for_depth(request.depth) for goal in state.goals}

    # ------------------------------------------------------------------ #
    # The decision
    # ------------------------------------------------------------------ #

    def next(self, request: EnrichmentPlanningRequest, state: PlanningState) -> PlanningDecision:
        """The next provider to ask, or why to stop."""
        candidates, skipped = self._candidates(request, state)
        if candidates:
            best = min(
                candidates,
                key=lambda item: candidate_key(
                    profile=item.profile,
                    capability=item.capability,
                    novelty=item.novelty,
                    explicitly_requested=item.explicitly_requested,
                    goal_required_and_unsatisfied=item.goal_required_and_unsatisfied,
                    specialized=item.specialized,
                ),
            )
            return PlanningDecision(
                sequence=state.sequence,
                call=self._call_for(request, best, candidates),
                skipped=tuple(skipped),
            )
        return PlanningDecision(
            sequence=state.sequence,
            stop=self._stop_reason(request, state, skipped),
            skipped=tuple(skipped),
        )

    def _call_for(
        self,
        request: EnrichmentPlanningRequest,
        candidate: Candidate,
        candidates: list[Candidate],
    ) -> PlannedProviderCall:
        """Turn the winning candidate into one appropriately shaped call.

        The other capabilities this same provider is *currently* an eligible
        candidate for ride along, because one provider answering four active
        goals is one question with four answers, not four questions. Asking it
        once per capability would spend a budget unit and a real API call per
        goal for the same document.

        Only current candidates are bundled, which keeps three rules intact
        without a single provider-specific condition: a goal that does not exist
        at this depth is not a candidate, so depth can never be widened by a
        bundle; a goal still waiting for its activation is not a candidate
        either; and an elevated-cost capability is excluded outright, so a bundle
        cannot spend the high-cost budget nobody decided to spend.
        """
        profile = candidate.profile
        bundled = frozenset(
            {candidate.capability}
            | {
                other.capability
                for other in candidates
                if other.profile.provider_id == profile.provider_id
                and profile.bundleable(other.capability)
            }
        )
        answered = profile.answered_by_one_response(
            bundled,
            supported=self._supported_capabilities(candidate.adapter, request),
        )
        detail = f"{candidate.capability.value} via {profile.source_family}"
        if len(bundled) > 1:
            detail = f"{detail} (+{len(bundled) - 1} more in one request)"
        return PlannedProviderCall(
            provider_id=profile.provider_id,
            capability=candidate.capability,
            capabilities=bundled,
            answered_capabilities=answered,
            source_family=profile.source_family,
            locality=profile.locality,
            cost_class=profile.cost_for(candidate.capability),
            depth=request.depth,
            reason=selection_reason_for(
                profile=profile,
                novelty=candidate.novelty,
                explicitly_requested=candidate.explicitly_requested,
                specialized=candidate.specialized,
            ),
            novelty=candidate.novelty,
            detail=detail,
        )

    def _supported_capabilities(
        self, adapter: ProviderAdapter, request: EnrichmentPlanningRequest
    ) -> frozenset[ProviderCapability]:
        """What this adapter declares for this observable type.

        Read from the descriptor, so a capability-invariant provider is credited
        only for questions it can actually answer about *this* kind of
        observable.
        """
        object_type = request.intel_object.object_type
        return frozenset(
            capability
            for capability in adapter.descriptor.capabilities
            if adapter.descriptor.supports(object_type, capability)
        )

    # ------------------------------------------------------------------ #
    # Candidate generation
    # ------------------------------------------------------------------ #

    def _candidates(
        self, request: EnrichmentPlanningRequest, state: PlanningState
    ) -> tuple[list[Candidate], list[SkippedCandidate]]:
        """Every eligible provider/capability pair, plus why the rest were not.

        Iterated in sorted order so candidate generation itself is deterministic,
        independent of how adapters were registered.
        """
        object_type = request.intel_object.object_type
        candidates: list[Candidate] = []
        skipped: list[SkippedCandidate] = []
        baseline_done = state.baseline_attempted()

        adapters = sorted(self._registry.list_all(), key=lambda item: item.descriptor.provider_id)
        for goal in state.goals:
            target = goal.families_for_depth(request.depth)
            if state.satisfied(goal, target):
                continue
            if not state.in_focus(goal.capability):
                # A later round asked for specific missing information. The goal
                # is still active and still reported in coverage -- it is simply
                # not what the remaining allowance was released for. No skip is
                # recorded: "out of this round's focus" is not a planning
                # judgement about the goal, and reusing GOAL_NOT_ACTIVE would
                # tell Task 18 the goal had never activated at all.
                continue
            explicit = goal.capability in state.requested_capabilities
            if not self._goal_active(goal, state, request, baseline_done, explicit):
                skipped.append(
                    SkippedCandidate(
                        capability=goal.capability,
                        provider_id="-",
                        reason=SkipReason.GOAL_NOT_ACTIVE,
                        detail=f"{goal.activation.value} goal not yet eligible",
                    )
                )
                continue
            required_unsatisfied = goal.is_required and not state.satisfied(goal, target)

            for adapter in adapters:
                skip = self._ineligible(
                    adapter=adapter,
                    goal=goal,
                    object_type=object_type,
                    request=request,
                    state=state,
                )
                if skip is not None:
                    skipped.append(skip)
                    continue
                profile = self._profiles.require(adapter.descriptor.provider_id)
                novelty = state.novelty_for(goal.capability, profile.source_family)
                if novelty is NoveltyClass.REDUNDANT:  # pragma: no cover - defensive
                    skipped.append(
                        SkippedCandidate(
                            provider_id=profile.provider_id,
                            capability=goal.capability,
                            reason=SkipReason.REDUNDANT,
                        )
                    )
                    continue
                candidates.append(
                    Candidate(
                        adapter=adapter,
                        profile=profile,
                        capability=goal.capability,
                        goal=goal,
                        novelty=novelty,
                        explicitly_requested=explicit,
                        goal_required_and_unsatisfied=required_unsatisfied,
                        specialized=goal.activation is not GoalActivation.IMMEDIATE,
                    )
                )
        return candidates, skipped

    def _goal_active(
        self,
        goal: CapabilityGoal,
        state: PlanningState,
        request: EnrichmentPlanningRequest,
        baseline_done: bool,
        explicit: bool,
    ) -> bool:
        """Whether this goal may spend budget yet.

        An explicit request activates a goal immediately: a caller who named the
        capability has already made the judgement the activation rule exists to
        make on their behalf.
        """
        if explicit:
            return True
        match goal.activation:
            case GoalActivation.IMMEDIATE:
                return True
            case GoalActivation.EXPLICIT_ONLY:
                return False
            case GoalActivation.AFTER_BASELINE:
                if not baseline_done:
                    return False
                if not goal.requires_trigger:
                    return True
                # A conditional follow-up needs a reason: something directional
                # to explain, or a baseline that came back empty.
                return state.has_directional_evidence or state.baseline_uncovered()

    def _ineligible(
        self,
        *,
        adapter: ProviderAdapter,
        goal: CapabilityGoal,
        object_type: IntelObjectType,
        request: EnrichmentPlanningRequest,
        state: PlanningState,
    ) -> SkippedCandidate | None:
        """Why this adapter cannot serve this goal now, or ``None``."""
        descriptor = adapter.descriptor
        provider_id = descriptor.provider_id
        capability = goal.capability
        constraints = request.constraints

        def skip(reason: SkipReason, detail: str | None = None) -> SkippedCandidate:
            return SkippedCandidate(
                provider_id=provider_id, capability=capability, reason=reason, detail=detail
            )

        profile = self._profiles.get(provider_id)
        if profile is None:
            # Registered as an adapter but not as plannable. Deliberate: a
            # provider can be integrated before anybody decides it should be
            # chosen on an analyst's behalf.
            return skip(SkipReason.AUTO_ENRICHMENT_DISABLED, "no planning profile")
        if not profile.auto_enrichment_allowed:
            return skip(SkipReason.AUTO_ENRICHMENT_DISABLED)
        if provider_id in constraints.provider_denylist:
            # Denylist is checked before allowlist so a provider named in both is
            # excluded; the constraint model refuses that combination anyway.
            return skip(SkipReason.DENIED)
        if constraints.provider_allowlist and provider_id not in constraints.provider_allowlist:
            return skip(SkipReason.NOT_ALLOWLISTED)
        if not descriptor.supports_passive:
            return skip(SkipReason.ACTIVE_FORBIDDEN, "provider is not passive")
        if request.activity_mode is not ActivityMode.PASSIVE:  # pragma: no cover - model refuses
            return skip(SkipReason.ACTIVE_FORBIDDEN)
        if not profile.serves(capability):
            return skip(SkipReason.UNSUPPORTED_CAPABILITY, "not offered for planning")
        if capability not in descriptor.capabilities:
            return skip(SkipReason.UNSUPPORTED_CAPABILITY, capability.value)
        if not descriptor.supports(object_type, capability):
            # The provider offers the capability but not for this observable
            # type — an IPv6 address against an IPv4-only provider, say. No
            # provider-specific condition is needed anywhere in the planner.
            return skip(SkipReason.UNSUPPORTED_OBSERVABLE, object_type.value)
        if not depth_at_least(request.depth, profile.minimum_depth):
            return skip(SkipReason.DEPTH_TOO_SHALLOW, f"needs {profile.minimum_depth.value}")
        if (provider_id, capability) in state.attempted:
            return skip(SkipReason.ALREADY_ATTEMPTED)
        if provider_id in state.blocked:
            return skip(SkipReason.BLOCKED)
        if not profile.is_local and not constraints.allow_remote_lookup:
            return skip(SkipReason.REMOTE_FORBIDDEN)
        cost = profile.cost_for(capability)
        if not state.budget.can_afford(locality=profile.locality, cost=cost):
            return skip(
                SkipReason.HIGH_COST_BUDGET_EXHAUSTED
                if state.budget.remote_remaining > 0
                else SkipReason.BUDGET_EXHAUSTED
            )
        return None

    # ------------------------------------------------------------------ #
    # Stopping
    # ------------------------------------------------------------------ #

    def _stop_reason(
        self,
        request: EnrichmentPlanningRequest,
        state: PlanningState,
        skipped: list[SkippedCandidate],
    ) -> StopReason:
        """Why there is nothing left worth asking.

        Ordered most-specific first, so the reported reason is the one an analyst
        can act on: "your budget ran out" is more useful than "nothing was
        eligible", and both are more useful than a bare stop.

        Every reason is operational. None of them means the answer is known.
        """
        # Only goals that were *eligible* count towards satisfaction. A goal
        # deliberately withheld — web forensics nobody asked for, a follow-up
        # whose trigger never fired — is not an unmet objective, and reporting
        # "no eligible provider" for it would describe a design decision as a
        # failure.
        baseline_done = state.baseline_attempted()
        active = [
            goal
            for goal in state.goals
            if self._goal_active(
                goal,
                state,
                request,
                baseline_done,
                goal.capability in state.requested_capabilities,
            )
        ]
        if all(state.satisfied(goal, goal.families_for_depth(request.depth)) for goal in active):
            return StopReason.GOALS_SATISFIED

        reasons = {item.reason for item in skipped}
        if not request.constraints.allow_remote_lookup and SkipReason.REMOTE_FORBIDDEN in reasons:
            return StopReason.REMOTE_LOOKUPS_DISABLED
        if SkipReason.BUDGET_EXHAUSTED in reasons:
            return StopReason.REMOTE_BUDGET_EXHAUSTED
        if SkipReason.HIGH_COST_BUDGET_EXHAUSTED in reasons:
            return StopReason.HIGH_COST_BUDGET_EXHAUSTED
        if SkipReason.BLOCKED in reasons:
            return StopReason.ALL_REMAINING_BLOCKED
        if SkipReason.REDUNDANT in reasons or SkipReason.ALREADY_ATTEMPTED in reasons:
            return StopReason.ALL_REMAINING_REDUNDANT
        return StopReason.NO_ELIGIBLE_PROVIDER
