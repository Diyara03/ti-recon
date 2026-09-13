"""Vocabulary for deciding what to ask next (Task 13).

Provider-neutral by construction: nothing in this package names a vendor, and a
test reads the AST to keep it that way. Provider knowledge lives in each
provider's own planning profile.

What this layer decides, and what it refuses to
-----------------------------------------------

The planner answers **"what information is still worth acquiring?"** — which
provider to ask, in what order, at what depth, and when to stop. It does not
answer "is this malicious?". Nothing here produces a verdict, a confidence, a
risk score or a vote tally, and :class:`StopReason` deliberately has no member
meaning "confident enough".

The distinction matters because the two questions have different failure modes. A
planner that got this wrong would stop enriching because a warninglist matched,
or call four reputation providers to make a number look better. A fusion layer
that got it wrong would draw the wrong conclusion from good evidence. Keeping
them apart means neither mistake can cause the other.

Deterministic on purpose
------------------------

Same observable, depth, requested capabilities, policy, registry and previous
outcomes produce the same next decision. No LLM, no ranking service, no
randomness. AI clients will eventually *call* TI Recon; AI must not choose which
intelligence sources TI Recon queries — that is a data-disclosure decision and an
auditability requirement, not a preference.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from pydantic import Field, model_validator

from ti_recon.enums import (
    ActivityMode,
    CoverageRelevance,
    CoverageStatus,
    InvestigationDepth,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.models.base import FrozenTiReconModel, UtcDatetime, utc_now
from ti_recon.models.coverage import CoverageItem
from ti_recon.models.intel_object import IntelObject

__all__ = [
    "COST_ORDER",
    "NOVELTY_ORDER",
    "AdaptiveEnrichmentResult",
    "CallCostClass",
    "EnrichmentBudget",
    "EnrichmentPlanningRequest",
    "NoveltyClass",
    "PlannedProviderCall",
    "PlanningConstraints",
    "PlanningDecision",
    "ProviderAttempt",
    "ProviderLocality",
    "ProviderPlanningProfile",
    "SelectionReason",
    "SkipReason",
    "SkippedCandidate",
    "StopReason",
]


class ProviderLocality(StrEnum):
    """Whether asking this provider discloses the observable to anyone else.

    The distinction is **disclosure**, not authentication. A credential-free HTTP
    provider still sends the observable to a third party, so
    ``requires_credentials == False`` must never be read as ``LOCAL`` — a rule
    worth stating because the two happen to coincide for today's only local
    provider and would silently diverge for the next one.
    """

    LOCAL = "local"
    REMOTE = "remote"


class CallCostClass(StrEnum):
    """How much planning pressure one call to a provider applies.

    A *pressure* class, not a price. It expresses expected physical request
    count, scarcity of the provider's allowance, and latency together — a
    provider that spends three requests of a five-per-minute budget is ``HIGH``
    whether or not anybody is billed for it. No monetary claim is made or
    implied.
    """

    ZERO = "zero"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


#: Ranking order for cost, cheapest first.
COST_ORDER: Final[dict[CallCostClass, int]] = {
    CallCostClass.ZERO: 0,
    CallCostClass.LOW: 1,
    CallCostClass.MEDIUM: 2,
    CallCostClass.HIGH: 3,
}


class NoveltyClass(StrEnum):
    """What a candidate would add that the run does not already have.

    The core planning judgement, and the reason the planner reasons about
    *source families* rather than providers. Three abuse.ch datasets agreeing is
    one ecosystem agreeing with itself; a second genuinely independent family
    saying the same thing is corroboration. Ranking them differently is how the
    planner avoids buying votes.
    """

    #: A capability nothing has covered yet. The most valuable thing to buy.
    NEW_CAPABILITY = "new_capability"
    #: A capability already covered, but by a different, independent source.
    NEW_SOURCE_FAMILY = "new_source_family"
    #: A different dataset inside a family already consulted for this
    #: capability. Sometimes genuinely useful — different datasets hold
    #: different things — but never independent confirmation.
    NEW_DATASET_SAME_FAMILY = "new_dataset_same_family"
    #: Nothing new. Never selected.
    REDUNDANT = "redundant"


#: Ranking order for novelty, most valuable first.
NOVELTY_ORDER: Final[dict[NoveltyClass, int]] = {
    NoveltyClass.NEW_CAPABILITY: 0,
    NoveltyClass.NEW_SOURCE_FAMILY: 1,
    NoveltyClass.NEW_DATASET_SAME_FAMILY: 2,
    NoveltyClass.REDUNDANT: 3,
}


class SelectionReason(StrEnum):
    """Why a provider was chosen. A stable code, not prose.

    Codes rather than sentences because this is what an analyst-facing
    explanation, a metric label and a regression test all read. Free text may
    accompany a code; nothing depends on the text.
    """

    EXPLICIT_CAPABILITY = "explicit_capability"
    MISSING_CAPABILITY = "missing_capability"
    NEW_SOURCE_FAMILY = "new_source_family"
    NEW_DATASET = "new_dataset"
    LOCAL_CONTEXT = "local_context"
    SPECIALIZED_FOLLOWUP = "specialized_followup"


class SkipReason(StrEnum):
    """Why an otherwise-registered provider was not chosen."""

    UNSUPPORTED_OBSERVABLE = "unsupported_observable"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    DENIED = "denied"
    NOT_ALLOWLISTED = "not_allowlisted"
    ACTIVE_FORBIDDEN = "active_forbidden"
    REMOTE_FORBIDDEN = "remote_forbidden"
    AUTO_ENRICHMENT_DISABLED = "auto_enrichment_disabled"
    DEPTH_TOO_SHALLOW = "depth_too_shallow"
    REDUNDANT = "redundant"
    BUDGET_EXHAUSTED = "budget_exhausted"
    HIGH_COST_BUDGET_EXHAUSTED = "high_cost_budget_exhausted"
    ALREADY_ATTEMPTED = "already_attempted"
    BLOCKED = "blocked"
    GOAL_NOT_ACTIVE = "goal_not_active"
    #: This source family cannot answer *this* question independently enough.
    #:
    #: Set only where a caller asked for a capability from outside a named set of
    #: families -- readiness wanting an adverse search independent of whatever
    #: called the object benign. It is per capability, never per run: the same
    #: family stays eligible for every other question, where independence was
    #: never what was being asked.
    SOURCE_FAMILY_EXCLUDED = "source_family_excluded"


class StopReason(StrEnum):
    """Why enrichment stopped.

    Every member is **operational**. There is deliberately no
    ``CONFIDENCE_HIGH_ENOUGH``, ``VERDICT_CONFIRMED`` or ``DEFINITELY_BENIGN``:
    those are conclusions, they need the future fusion layer, and a planner that
    could express them would be making them.
    """

    GOALS_SATISFIED = "goals_satisfied"
    NO_ELIGIBLE_PROVIDER = "no_eligible_provider"
    REMOTE_BUDGET_EXHAUSTED = "remote_budget_exhausted"
    HIGH_COST_BUDGET_EXHAUSTED = "high_cost_budget_exhausted"
    ALL_REMAINING_REDUNDANT = "all_remaining_redundant"
    ALL_REMAINING_BLOCKED = "all_remaining_blocked"
    REMOTE_LOOKUPS_DISABLED = "remote_lookups_disabled"


#: Depth ordering for the per-capability floor; mirrors ``goals.DEPTH_ORDER``
#: without importing it, because ``goals`` imports this module.
_DEPTH_RANK: dict[InvestigationDepth, int] = {
    InvestigationDepth.QUICK: 0,
    InvestigationDepth.STANDARD: 1,
    InvestigationDepth.DEEP: 2,
}


class ProviderPlanningProfile(FrozenTiReconModel):
    """What the planner needs to know about a provider, beyond its descriptor.

    Deliberately small, and deliberately not a second copy of
    :class:`~ti_recon.providers.descriptor.ProviderDescriptor`. Which observables
    and capabilities a provider supports is already declared there and is read
    from there; this adds only what planning needs and the descriptor has no
    business knowing: whether asking discloses the observable, how much pressure
    a call applies, and whether it may be chosen automatically.
    """

    provider_id: str = Field(min_length=1, max_length=64)
    source_family: str = Field(min_length=1, max_length=64)
    locality: ProviderLocality
    cost_class: CallCostClass

    #: Capabilities the planner may *ask this provider for*. Usually every
    #: capability its descriptor declares, but a provider may withhold one from
    #: automatic planning — a capability that is real but too expensive or too
    #: situational to be chosen without being asked for by name.
    planning_capabilities: frozenset[ProviderCapability] = frozenset()

    #: Capabilities whose selection is charged against the high-cost budget
    #: regardless of :attr:`cost_class`. One provider can be cheap for a summary
    #: read and expensive when asked to retrieve and analyse stored content, and
    #: a single per-provider class cannot express that.
    #:
    #: These are also the capabilities that are never *bundled* into a call
    #: selected for something else: an expensive capability has to be chosen on
    #: its own merits, or an implicit bundle becomes a way to spend the high-cost
    #: budget without a decision — and, for retrieved page content, a way around
    #: the rule that forensics needs an explicit request.
    elevated_cost_capabilities: frozenset[ProviderCapability] = frozenset()

    #: Capabilities this provider serves only from a deeper investigation than
    #: :attr:`minimum_depth`, declared per capability (Task 24 Phase 3).
    #:
    #: A provider can answer reputation at QUICK and detonation data only at
    #: DEEP. Without this the planner selected the shallow-depth call, the
    #: adapter refused it as ``NOT_SUPPORTED``, and the refusal was charged as
    #: a remote run -- a budget unit and a decision spent on an answer the
    #: catalogue could have declined for free. Declared by the provider, like
    #: every other planning fact, and enforced before cost and budget.
    capability_minimum_depth: dict[ProviderCapability, InvestigationDepth] = Field(
        default_factory=dict
    )

    def minimum_depth_for(self, capability: ProviderCapability) -> InvestigationDepth:
        """The shallowest depth at which this provider serves ``capability``."""
        declared = self.capability_minimum_depth.get(capability)
        if declared is None:
            return self.minimum_depth
        return max(declared, self.minimum_depth, key=lambda item: _DEPTH_RANK[item])

    #: ``True`` when one read returns everything this provider knows about an
    #: observable, whatever capabilities the request named.
    #:
    #: Most integrations are like this: one deterministic lookup, one document,
    #: normalized into whatever it happens to contain. Asking such a provider a
    #: second time for a different capability re-fetches an identical response —
    #: a real API call, a real budget unit and no new information. Declaring it
    #: lets the planner credit every capability that one response answered.
    #:
    #: ``False`` means the response is *shaped* by the request, so a capability
    #: nobody asked for was not answered and a later call for it is genuinely
    #: incremental work. This is provider-owned knowledge and belongs in the
    #: provider's own profile, never in a planner branch.
    capability_invariant_response: bool = False

    #: Shallowest depth at which this provider may be chosen automatically. An
    #: explicit capability request still respects it — depth is the caller's
    #: statement about how much work this investigation warrants.
    minimum_depth: InvestigationDepth = InvestigationDepth.QUICK

    #: Tie-break preference among otherwise-equal candidates. Higher first.
    #: Never a quality score: it breaks ties, it does not create them.
    priority: int = Field(default=0, ge=-100, le=100)

    #: ``False`` keeps a provider out of automatic plans entirely while leaving
    #: it callable directly. For a provider that must never be chosen on an
    #: analyst's behalf.
    auto_enrichment_allowed: bool = True

    @model_validator(mode="after")
    def _validate_profile(self) -> ProviderPlanningProfile:
        if not self.elevated_cost_capabilities <= self.planning_capabilities:
            msg = "elevated_cost_capabilities must be capabilities this profile plans"
            raise ValueError(msg)
        return self

    def bundleable(self, capability: ProviderCapability) -> bool:
        """Whether ``capability`` may ride along on a call chosen for another.

        Only capabilities that change neither the cost class nor the shape of the
        request qualify, so a bundle can never spend more than the decision that
        created it.
        """
        return self.serves(capability) and capability not in self.elevated_cost_capabilities

    def answered_by_one_response(
        self, requested: frozenset[ProviderCapability], *, supported: frozenset[ProviderCapability]
    ) -> frozenset[ProviderCapability]:
        """Which capabilities one response actually answers.

        For a capability-invariant provider that is everything it plans and the
        observable supports — the document came back whole. Otherwise it is
        exactly what was asked for: crediting more would claim coverage of a
        question the request never carried.
        """
        if not self.capability_invariant_response:
            return requested
        return requested | (self.planning_capabilities & supported)

    def cost_for(self, capability: ProviderCapability) -> CallCostClass:
        """The cost class of asking this provider for ``capability``."""
        if capability in self.elevated_cost_capabilities:
            return CallCostClass.HIGH
        return self.cost_class

    def serves(self, capability: ProviderCapability) -> bool:
        """Whether the planner may ask this provider for ``capability``."""
        return capability in self.planning_capabilities

    @property
    def is_local(self) -> bool:
        return self.locality is ProviderLocality.LOCAL


class PlanningConstraints(FrozenTiReconModel):
    """Caller limits on what the planner may do.

    ``allow_remote_lookup`` is the important one. A passive API lookup is still
    disclosure: it tells a third party that somebody is investigating this
    observable, which for a live incident can itself be sensitive. Setting it
    ``False`` restricts the run to providers that disclose nothing, which is the
    hook a future organizational data-handling policy maps onto rather than a
    policy framework of its own.
    """

    provider_allowlist: frozenset[str] = frozenset()
    provider_denylist: frozenset[str] = frozenset()

    #: ``False`` permits local providers only.
    allow_remote_lookup: bool = True

    #: Override the policy's remote-run budget downwards. ``None`` uses the
    #: policy default. Only ever a *reduction*: a caller may spend less than
    #: policy allows, never more.
    max_remote_provider_runs: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _validate_constraints(self) -> PlanningConstraints:
        overlap = self.provider_allowlist & self.provider_denylist
        if overlap:
            # Denylist would win, so the allowlist entry is dead configuration.
            # Reported rather than silently resolved: a caller who wrote both
            # meant something, and it is not this.
            msg = f"providers cannot be both allowed and denied: {sorted(overlap)}"
            raise ValueError(msg)
        return self


class EnrichmentPlanningRequest(FrozenTiReconModel):
    """What to enrich, how deeply, and under what limits.

    ``requested_capabilities`` is an explicit ask, not a filter. A caller naming
    ``FILE_BEHAVIOR`` is saying "I specifically want that", and the planner ranks
    it first rather than spending the whole budget on baseline reputation before
    reaching it. It still cannot override observable support, the passive-only
    rule, provider policy or the hard budget.
    """

    intel_object: IntelObject
    depth: InvestigationDepth = InvestigationDepth.STANDARD
    requested_capabilities: frozenset[ProviderCapability] = frozenset()
    constraints: PlanningConstraints = PlanningConstraints()

    #: Always ``LOOKUP``. Present so the field is visibly pinned rather than
    #: implicit — see :meth:`_validate_request`.
    operation: ProviderOperation = ProviderOperation.LOOKUP
    activity_mode: ActivityMode = ActivityMode.PASSIVE

    @model_validator(mode="after")
    def _validate_request(self) -> EnrichmentPlanningRequest:
        if self.activity_mode is not ActivityMode.PASSIVE:
            # Automatic planning never submits, detonates or rescans anything.
            # Refused at construction so no plan can exist that would.
            msg = "automatic enrichment planning is passive only"
            raise ValueError(msg)
        if self.operation is not ProviderOperation.LOOKUP:
            msg = "automatic enrichment planning performs lookups only"
            raise ValueError(msg)
        return self


class EnrichmentBudget(FrozenTiReconModel):
    """How many provider runs one enrichment may spend.

    Counts **logical provider runs**, not HTTP requests. A provider that makes
    three internal calls for one lookup is one run here — its own internal bound
    is its own business (Tasks 7-12 each enforce theirs), and duplicating that
    accounting would put provider knowledge in this layer.

    These are TI Recon *enrichment-policy* defaults. They are not provider
    limits and make no claim to be.
    """

    max_remote_provider_runs: int = Field(ge=0)
    max_high_cost_runs: int = Field(ge=0)
    remote_runs_used: int = Field(default=0, ge=0)
    high_cost_runs_used: int = Field(default=0, ge=0)

    @property
    def remote_remaining(self) -> int:
        return max(0, self.max_remote_provider_runs - self.remote_runs_used)

    @property
    def high_cost_remaining(self) -> int:
        return max(0, self.max_high_cost_runs - self.high_cost_runs_used)

    def can_afford(self, *, locality: ProviderLocality, cost: CallCostClass) -> bool:
        """Whether a candidate fits what is left.

        Local providers are always affordable: they disclose nothing and spend no
        allowance, so budgeting them would only stop TI Recon collecting free
        context.
        """
        if locality is ProviderLocality.LOCAL:
            return True
        if self.remote_remaining <= 0:
            return False
        return not (cost is CallCostClass.HIGH and self.high_cost_remaining <= 0)

    def charge(
        self, *, locality: ProviderLocality, cost: CallCostClass, called_provider: bool
    ) -> EnrichmentBudget:
        """Account for a completed run.

        ``called_provider`` is the authority, not the status. A cache hit, a
        cooldown short-circuit, an unconfigured credential and an unsupported
        observable all return without contacting anyone, and charging them would
        make a well-cached investigation look expensive — the opposite of what
        the cache is for.
        """
        if locality is ProviderLocality.LOCAL or not called_provider:
            return self
        return self.model_copy(
            update={
                "remote_runs_used": self.remote_runs_used + 1,
                "high_cost_runs_used": self.high_cost_runs_used
                + (1 if cost is CallCostClass.HIGH else 0),
            }
        )


class PlannedProviderCall(FrozenTiReconModel):
    """One provider run the planner has decided to make.

    One *run*, not one capability. A provider that answers several active goals
    with one read is asked once, for all of them: repeating the request per
    capability would spend a budget unit and an API call per goal and return the
    same document each time.

    Three capability sets, deliberately distinct:

    * :attr:`capability` — the one that won the ranking. It is what the decision
      is explained by, and what the cost class was computed from.
    * :attr:`capabilities` — everything the request asks for. Always includes
      :attr:`capability`, and never includes an elevated-cost capability that was
      not itself selected.
    * :attr:`answered_capabilities` — everything one response from this provider
      answers. Larger than :attr:`capabilities` only when the provider declares
      its response is capability-invariant.
    """

    provider_id: str = Field(min_length=1, max_length=64)
    capability: ProviderCapability
    #: What the provider request will carry. Defaults to the primary capability
    #: alone, so a hand-built call needs nothing extra.
    capabilities: frozenset[ProviderCapability] = frozenset()
    #: What this one response covers. Defaults to :attr:`capabilities`.
    answered_capabilities: frozenset[ProviderCapability] = frozenset()
    source_family: str = Field(min_length=1, max_length=64)
    locality: ProviderLocality
    cost_class: CallCostClass
    depth: InvestigationDepth
    reason: SelectionReason
    novelty: NoveltyClass
    #: Short human-readable accompaniment to :attr:`reason`. Never load-bearing.
    detail: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def _validate_capabilities(self) -> PlannedProviderCall:
        requested = self.capabilities or frozenset({self.capability})
        answered = self.answered_capabilities or requested
        if self.capability not in requested:
            msg = "the selected capability must be part of the request"
            raise ValueError(msg)
        if not requested <= answered:
            msg = "answered_capabilities must include everything requested"
            raise ValueError(msg)
        object.__setattr__(self, "capabilities", requested)
        object.__setattr__(self, "answered_capabilities", answered)
        return self


class SkippedCandidate(FrozenTiReconModel):
    """A provider that was considered and passed over, with why."""

    provider_id: str = Field(min_length=1, max_length=64)
    capability: ProviderCapability | None = None
    reason: SkipReason
    detail: str | None = Field(default=None, max_length=200)


class PlanningDecision(FrozenTiReconModel):
    """The planner's answer to "what next?".

    Exactly one of :attr:`call` or :attr:`stop` is set. Skipped candidates travel
    with either, because *why something was not chosen* is often the more useful
    half of an explanation.
    """

    sequence: int = Field(ge=0)
    call: PlannedProviderCall | None = None
    stop: StopReason | None = None
    skipped: tuple[SkippedCandidate, ...] = ()

    @model_validator(mode="after")
    def _validate_decision(self) -> PlanningDecision:
        if (self.call is None) == (self.stop is None):
            msg = "a planning decision is either a call or a stop"
            raise ValueError(msg)
        return self

    @property
    def is_stop(self) -> bool:
        return self.stop is not None


class ProviderAttempt(FrozenTiReconModel):
    """What one executed decision actually produced.

    Deliberately a summary. Raw provider payloads stay in the execution outcome
    where they belong; a planning trace that embedded them would be unbounded,
    unserializable in practice, and a place for provider text to end up
    somewhere nobody expected.
    """

    sequence: int = Field(ge=0)
    provider_id: str = Field(min_length=1, max_length=64)
    capability: ProviderCapability
    #: Every capability the request *carried* -- the bundle, primary included.
    #: One attempt, one call, several questions: a failure answered none of
    #: them and a refusal refused all of them, and a ledger keyed on the
    #: primary alone typed the others "not attempted" when the provider had in
    #: fact been asked and said NOT_CONFIGURED (Task 24 Phase 3). Never the
    #: *answered* set: what a success credited is Task 13's coverage record.
    capabilities: frozenset[ProviderCapability] = frozenset()
    source_family: str = Field(min_length=1, max_length=64)
    locality: ProviderLocality
    cost_class: CallCostClass
    reason: SelectionReason
    novelty: NoveltyClass
    status: ProviderRunStatus
    error_category: ProviderErrorCategory | None = None
    #: Whether a provider was actually contacted. Distinct from "selected" and
    #: from "succeeded", and the only thing the budget is charged on.
    called_provider: bool = False
    cache_hit: bool = False
    coalesced: bool = False
    attempts: int = Field(default=0, ge=0)
    duration_ms: float = Field(default=0.0, ge=0.0)
    #: Whether this attempt counted as coverage for its capability.
    coverage_gained: bool = False
    #: Whether it produced any evidence at all. Never "was it benign".
    produced_evidence: bool = False
    recorded_at: UtcDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _validate_capabilities(self) -> ProviderAttempt:
        """An empty bundle is the primary alone; a bundle always contains it."""
        if not self.capabilities:
            object.__setattr__(self, "capabilities", frozenset({self.capability}))
        elif self.capability not in self.capabilities:
            msg = "an attempt's bundle must include its primary capability"
            raise ValueError(msg)
        return self


class AdaptiveEnrichmentResult(FrozenTiReconModel):
    """Everything one enrichment run decided, did and learned.

    Deliberately **not** an assessment. There is no verdict field, no confidence
    and no risk score, because producing one is the future fusion layer's job and
    a planner that guessed at it would be the hardest kind of error to find: a
    plausible number with nothing behind it.

    What a caller gets is the provider outcomes, an explainable trace of why each
    was chosen, coverage per capability, and an operational stop reason.
    """

    target: IntelObject
    depth: InvestigationDepth
    requested_capabilities: frozenset[ProviderCapability] = frozenset()
    attempts: tuple[ProviderAttempt, ...] = ()
    decisions: tuple[PlanningDecision, ...] = ()
    coverage: tuple[CoverageItem, ...] = ()
    budget: EnrichmentBudget
    stop_reason: StopReason

    @property
    def providers_selected(self) -> tuple[str, ...]:
        return tuple(item.provider_id for item in self.attempts)

    @property
    def providers_called(self) -> tuple[str, ...]:
        """Providers actually contacted, which is a smaller set than selected."""
        return tuple(item.provider_id for item in self.attempts if item.called_provider)

    @property
    def cache_hits(self) -> int:
        return sum(1 for item in self.attempts if item.cache_hit)

    @property
    def source_families_consulted(self) -> frozenset[str]:
        """Families that produced coverage. The anti-vote-inflation view."""
        return frozenset(item.source_family for item in self.attempts if item.coverage_gained)

    @property
    def has_uncovered_required_capability(self) -> bool:
        """Whether a required capability ended the run unsatisfied.

        The honest counterpart to :attr:`StopReason.GOALS_SATISFIED`: a run can
        finish having done everything permitted and still not have learned what
        it set out to.
        """
        return any(
            item.relevance is CoverageRelevance.REQUIRED
            and item.status is not CoverageStatus.COVERED
            for item in self.coverage
        )
