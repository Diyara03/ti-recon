"""What the planner remembers between decisions (Task 13).

Deliberately a summary, not a copy of the investigation. Planning needs to know
*which questions have been answered by whom*; it does not need provider payloads,
and holding them would make the state unbounded and put provider text somewhere
nobody was looking for it.

Coverage from outcomes
----------------------

``ProviderRunStatus`` is read carefully, because the difference between "asked and
told nothing" and "could not ask" is the whole point of having a planner:

* ``SUCCESS`` / ``NO_DATA`` — **covered**. The source was consulted and answered.
  A ``NO_DATA`` provider must not be asked again; the right move is a different
  source, and there is nothing to learn by repeating the question.
* ``PARTIAL`` — partial. Counts as *a* family for the capability but does not
  satisfy a multi-family target on its own.
* everything else — no coverage. Unsupported, unconfigured, refused, throttled or
  broken are five different problems and none of them is an answer.

``NO_DATA`` is coverage of a *source*, never evidence about the observable. A
planner that treated it as reassurance would stop early on exactly the samples
nobody has seen yet.

Evidence is a trigger, never a tally
------------------------------------

Directional presence is tracked per **source family**, so one provider emitting
several records cannot look like several sources, and so a sandbox's many reports
stay one family. Nothing here counts evidence objects or AV vendors, and nothing
here has a score.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ti_recon.enums import (
    CoverageRelevance,
    CoverageStatus,
    EvidenceEffect,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderRunStatus,
)
from ti_recon.execution.models import ProviderExecutionOutcome
from ti_recon.models.coverage import CoverageItem
from ti_recon.planning.goals import CapabilityGoal
from ti_recon.planning.models import (
    EnrichmentBudget,
    NoveltyClass,
    PlannedProviderCall,
    ProviderAttempt,
)

__all__ = [
    "BLOCKING_ERROR_CATEGORIES",
    "COVERING_STATUSES",
    "PARTIAL_STATUSES",
    "PlanningState",
]

#: Statuses that mean a source was successfully consulted.
COVERING_STATUSES: frozenset[ProviderRunStatus] = frozenset(
    {ProviderRunStatus.SUCCESS, ProviderRunStatus.NO_DATA}
)

#: Statuses that contribute something short of full coverage.
PARTIAL_STATUSES: frozenset[ProviderRunStatus] = frozenset({ProviderRunStatus.PARTIAL})

#: Error categories that make a provider unusable for the rest of this run.
#:
#: Not a retry policy — Task 6 owns retry, and the planner must never retry
#: independently of it. This only stops the planner picking the same blocked
#: source again a moment later, which would waste the decision and, for a
#: throttled provider, make the throttling worse.
BLOCKING_ERROR_CATEGORIES: frozenset[ProviderErrorCategory] = frozenset(
    {
        ProviderErrorCategory.AUTHENTICATION_ERROR,
        ProviderErrorCategory.PERMISSION_ERROR,
        ProviderErrorCategory.PLAN_LIMITED,
        ProviderErrorCategory.QUOTA_EXCEEDED,
        ProviderErrorCategory.RATE_LIMITED,
        ProviderErrorCategory.PROVIDER_UNAVAILABLE,
        ProviderErrorCategory.TRANSIENT_ERROR,
    }
)


@dataclass
class PlanningState:
    """Mutable planning memory for one enrichment run."""

    budget: EnrichmentBudget
    goals: tuple[CapabilityGoal, ...] = ()
    requested_capabilities: frozenset[ProviderCapability] = frozenset()

    #: ``(provider_id, capability)`` pairs already tried. A provider may be asked
    #: for a *different* capability later — one dataset can hold several kinds of
    #: answer — but never the same question twice.
    attempted: set[tuple[str, ProviderCapability]] = field(default_factory=set)
    #: Providers unusable for the remainder of this run.
    blocked: set[str] = field(default_factory=set)

    #: capability -> source families that covered it.
    covered_families: dict[ProviderCapability, set[str]] = field(default_factory=dict)
    #: capability -> source families that partially covered it.
    partial_families: dict[ProviderCapability, set[str]] = field(default_factory=dict)

    #: Source families that produced directional evidence, by direction. Kept as
    #: families rather than counts: this exists to decide whether a follow-up is
    #: worth buying, not to weigh anything.
    malicious_families: set[str] = field(default_factory=set)
    benign_families: set[str] = field(default_factory=set)
    context_families: set[str] = field(default_factory=set)
    false_positive_context_families: set[str] = field(default_factory=set)

    attempts: list[ProviderAttempt] = field(default_factory=list)
    sequence: int = 0

    #: Capabilities this round may spend budget pursuing, or empty for all.
    #:
    #: The seam a later planning round needs (Task 19). A continuation asks for
    #: specific missing information, and without this the planner would happily
    #: spend the remaining allowance on whatever else was still uncovered —
    #: which is not what was asked for and not what the budget is left for.
    #:
    #: Goals themselves are *not* filtered: the full set stays so coverage still
    #: reports every goal's accumulated status. Only what may be newly pursued
    #: narrows. Empty means no restriction, which is what every first round uses,
    #: so default planning behaviour is unchanged.
    focus_capabilities: frozenset[ProviderCapability] = frozenset()

    #: capability -> source families that may not answer *that* capability.
    #:
    #: The second seam a later planning round needs (Task 19). Readiness can ask
    #: for a search independent of the origin behind an assessment, and a family
    #: already known to share that origin cannot supply one however well it
    #: ranks. Without this the planner would spend the remaining allowance on a
    #: source that could not satisfy the requirement it was released for, and the
    #: genuinely independent candidate would be unreachable behind an empty
    #: budget.
    #:
    #: Keyed per capability on purpose. One set for the whole round would block a
    #: family from every other question too, where independence was never what
    #: was being asked and the family's answer is worth exactly what it always
    #: was.
    #:
    #: Conservative, never a proof: a family nobody has linked to the origin is
    #: *potentially* independent, and only the returned provenance settles it.
    excluded_source_families: dict[ProviderCapability, frozenset[str]] = field(default_factory=dict)

    #: Capabilities whose *base* family target is not enough this round.
    #:
    #: The third seam a later planning round needs (Task 19). Task 13's goal
    #: says how much coverage is worth buying by default; a higher layer can
    #: have a requirement the default satisfies numerically and not in
    #: substance — readiness wanting an adverse search from an origin
    #: independent of the one that already answered. The base goal is met, so
    #: the goal would be skipped before any other rule was consulted, and the
    #: eligible unattempted source that could meet the requirement would never
    #: be considered.
    #:
    #: This raises the *target* for one capability, reusing the family-breadth
    #: concept the goal already has, rather than adding a parallel notion of
    #: sufficiency. It never adds a capability, never activates a goal, never
    #: clears coverage and never names a provider: Task 13 still ranks, still
    #: refuses an attempted call, still honours a blocked provider and an
    #: excluded family, and still has to afford it.
    #:
    #: Fresh each round, like the focus and the exclusions.
    additional_coverage_capabilities: frozenset[ProviderCapability] = frozenset()

    def effective_target(self, capability: ProviderCapability, base: int) -> int:
        """The family target for ``capability`` this round.

        ``base`` unless a higher layer asked for more breadth, in which case it
        is one family beyond what is already covered — "somebody else as well",
        expressed in the units the goal already uses. Never a reset: what has
        been covered stays covered, and stays true.
        """
        if capability not in self.additional_coverage_capabilities:
            return base
        return max(base, len(self.covered_families.get(capability, set())) + 1)

    def in_focus(self, capability: ProviderCapability) -> bool:
        """Whether this round may pursue ``capability``."""
        return not self.focus_capabilities or capability in self.focus_capabilities

    def family_excluded(self, capability: ProviderCapability, source_family: str) -> bool:
        """Whether ``source_family`` is barred from answering ``capability`` here."""
        return source_family in self.excluded_source_families.get(capability, frozenset())

    def continuation(
        self,
        *,
        goals: tuple[CapabilityGoal, ...] | None = None,
        requested: frozenset[ProviderCapability] | None = None,
        focus: frozenset[ProviderCapability] = frozenset(),
        excluded_families: dict[ProviderCapability, frozenset[str]] | None = None,
        additional_coverage: frozenset[ProviderCapability] = frozenset(),
    ) -> PlanningState:
        """A state for a later round of the same investigation.

        Everything accumulated carries: the budget with what it has already
        spent, the calls already made, the providers found unusable, the coverage
        reached and the attempt sequence. A fresh state would hand a continuation
        a new allowance and let it repeat calls it has already made, which is
        exactly what an investigation-wide budget exists to prevent.

        Attempts are deliberately *not* carried into the new state's list: each
        round reports what it did, and the caller composes the rounds. Carrying
        them would make every round's result contain the previous one's work.

        ``goals`` is recomputed by the caller rather than carried, because a
        continuation may ask for a capability the first round's goal set never
        contained -- readiness can require a check the depth template does not
        include. Carrying the old goals would silently drop that request, and the
        round would plan nothing while appearing to have tried.
        """
        return PlanningState(
            budget=self.budget,
            goals=self.goals if goals is None else goals,
            requested_capabilities=(
                self.requested_capabilities if requested is None else requested
            ),
            attempted=set(self.attempted),
            blocked=set(self.blocked),
            covered_families={key: set(value) for key, value in self.covered_families.items()},
            partial_families={key: set(value) for key, value in self.partial_families.items()},
            malicious_families=set(self.malicious_families),
            benign_families=set(self.benign_families),
            context_families=set(self.context_families),
            false_positive_context_families=set(self.false_positive_context_families),
            sequence=self.sequence,
            focus_capabilities=focus,
            # Fresh each round, like the focus: an exclusion belongs to the
            # requirement that asked for it, and carrying it forward would keep
            # barring a family long after the question that needed independence
            # had been answered.
            excluded_source_families=dict(excluded_families or {}),
            additional_coverage_capabilities=additional_coverage,
        )

    # ------------------------------------------------------------------ #
    # Questions the planner asks
    # ------------------------------------------------------------------ #

    def families_for(self, capability: ProviderCapability) -> frozenset[str]:
        """Families that covered ``capability``, fully or partially."""
        return frozenset(
            self.covered_families.get(capability, set())
            | self.partial_families.get(capability, set())
        )

    def is_covered(self, capability: ProviderCapability) -> bool:
        return bool(self.covered_families.get(capability))

    def satisfied(self, goal: CapabilityGoal, target_families: int) -> bool:
        """Whether ``goal`` has the independent coverage it asked for.

        Only *full* coverage counts towards a family target. A partial answer is
        real information and is recorded, but letting it satisfy a multi-family
        requirement would report a coverage level nobody achieved.
        """
        return len(self.covered_families.get(goal.capability, set())) >= target_families

    @property
    def has_directional_evidence(self) -> bool:
        """Whether anything pointed anywhere. A trigger, not a conclusion."""
        return bool(self.malicious_families or self.benign_families)

    def baseline_attempted(self) -> bool:
        """Whether every required goal has been tried at least once.

        Gates specialized follow-up: asking what a file *did* before knowing
        whether anyone has ever seen it is the wrong order and spends the
        expensive request first.
        """
        required = [goal for goal in self.goals if goal.is_required]
        if not required:
            return True
        return all(
            self.families_for(goal.capability) or self._attempted_capability(goal.capability)
            for goal in required
        )

    def baseline_uncovered(self) -> bool:
        """Whether a required goal was tried and produced no coverage.

        One of the two reasons a conditional follow-up is worth buying: if the
        baseline came back empty, a different *kind* of question may still
        answer something.
        """
        return any(goal.is_required and not self.is_covered(goal.capability) for goal in self.goals)

    def _attempted_capability(self, capability: ProviderCapability) -> bool:
        return any(item[1] is capability for item in self.attempted)

    def novelty_for(self, capability: ProviderCapability, source_family: str) -> NoveltyClass:
        """What asking ``source_family`` about ``capability`` would add."""
        families = self.families_for(capability)
        if not families:
            return NoveltyClass.NEW_CAPABILITY
        if source_family not in families:
            return NoveltyClass.NEW_SOURCE_FAMILY
        return NoveltyClass.NEW_DATASET_SAME_FAMILY

    # ------------------------------------------------------------------ #
    # Recording what happened
    # ------------------------------------------------------------------ #

    def observe(
        self, call: PlannedProviderCall, outcome: ProviderExecutionOutcome
    ) -> ProviderAttempt:
        """Fold one executed decision into the state.

        The budget is charged on ``called_provider`` rather than on the status,
        so a cache hit, a cooldown short-circuit, an unconfigured credential and
        an unsupported observable all cost nothing — which is what makes
        cache-first ranking safe: the planner can pick the best source and let
        the execution layer answer for free if it already knows.

        One call can answer several questions. Everything the request carried is
        marked attempted, and coverage is credited for everything this one
        response *answers* — which is more than was asked only where the provider
        itself declared that one read returns its whole document. Crediting it is
        what stops the planner buying that document again, at full price, the
        moment a later goal activates.
        """
        self.attempted.update((call.provider_id, capability) for capability in call.capabilities)

        covered = outcome.status in COVERING_STATUSES
        partial = outcome.status in PARTIAL_STATUSES
        if covered:
            for capability in call.answered_capabilities:
                self.covered_families.setdefault(capability, set()).add(call.source_family)
        elif partial:
            for capability in call.answered_capabilities:
                self.partial_families.setdefault(capability, set()).add(call.source_family)
        elif (
            outcome.error_category is not None
            and outcome.error_category in BLOCKING_ERROR_CATEGORIES
        ) or outcome.status is ProviderRunStatus.NOT_CONFIGURED:
            self.blocked.add(call.provider_id)

        produced = self._record_evidence(outcome)
        if produced and ProviderCapability.FALSE_POSITIVE_CONTEXT in call.answered_capabilities:
            # Recorded from the capability the planner *asked for*, not from any
            # provider-specific field. A claim-name heuristic would be provider
            # knowledge in the wrong layer, and would misread a coverage record
            # that is emitted whether or not anything matched.
            self.false_positive_context_families.add(call.source_family)
        self.budget = self.budget.charge(
            locality=call.locality,
            cost=call.cost_class,
            called_provider=outcome.called_provider,
        )

        attempt = ProviderAttempt(
            sequence=self.sequence,
            provider_id=call.provider_id,
            capability=call.capability,
            source_family=call.source_family,
            locality=call.locality,
            cost_class=call.cost_class,
            reason=call.reason,
            novelty=call.novelty,
            status=outcome.status,
            error_category=outcome.error_category,
            called_provider=outcome.called_provider,
            cache_hit=outcome.cache_hit,
            coalesced=outcome.coalesced,
            attempts=outcome.attempts,
            duration_ms=outcome.duration_ms,
            coverage_gained=covered or partial,
            produced_evidence=produced,
        )
        self.attempts.append(attempt)
        self.sequence += 1
        return attempt

    def _record_evidence(self, outcome: ProviderExecutionOutcome) -> bool:
        """Note directional presence per family. Never a count, never a score.

        Reads only each record's ``effect`` and ``source_family``. Deduplicating
        by family is what keeps one provider's several records — and one
        sandbox's several reports — from looking like several sources.
        """
        if outcome.result is None:
            return False
        produced = False
        for evidence in outcome.result.evidence:
            produced = True
            family = evidence.source_family
            if evidence.effect is EvidenceEffect.SUPPORTS_MALICIOUS:
                self.malicious_families.add(family)
            elif evidence.effect is EvidenceEffect.SUPPORTS_BENIGN:
                self.benign_families.add(family)
            else:
                self.context_families.add(family)
        return produced

    def block(self, provider_id: str) -> None:
        self.blocked.add(provider_id)

    # ------------------------------------------------------------------ #
    # Reporting
    # ------------------------------------------------------------------ #

    def coverage_items(
        self,
        depth_targets: dict[ProviderCapability, int],
        considered: dict[ProviderCapability, tuple[str, ...]],
    ) -> tuple[CoverageItem, ...]:
        """Coverage per goal, using the existing Task 3 model.

        ``PARTIAL`` when something was learned but the family target was not met,
        and ``NOT_COVERED`` when nothing was — including when no provider could
        have served it, which is a blind spot rather than a failure and is said
        so in the reason.
        """
        items: list[CoverageItem] = []
        for goal in self.goals:
            capability = goal.capability
            target = depth_targets.get(capability, 1)
            full = self.covered_families.get(capability, set())
            partial = self.partial_families.get(capability, set())
            providers = considered.get(capability, ())
            if len(full) >= target:
                status = CoverageStatus.COVERED
                reason = None
            elif full or partial:
                status = CoverageStatus.PARTIAL
                reason = (
                    f"{len(full)} of {target} independent source families covered"
                    f"{f', {len(partial)} partial' if partial else ''}"
                )
            elif not providers:
                status = CoverageStatus.NOT_COVERED
                reason = "no registered provider offers this capability for this observable"
            else:
                status = CoverageStatus.NOT_COVERED
                reason = "no eligible provider produced coverage"
            items.append(
                CoverageItem(
                    capability=capability,
                    relevance=goal.relevance
                    if goal.relevance is not CoverageRelevance.NOT_APPLICABLE
                    else CoverageRelevance.OPTIONAL,
                    status=status,
                    providers_considered=providers,
                    reason=reason,
                )
            )
        return tuple(items)
