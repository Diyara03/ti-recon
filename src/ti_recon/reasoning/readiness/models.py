"""Readiness vocabulary and structures (Task 18).

Task 17 says what assessment the evidence justifies. Task 18 asks a different
question about the same investigation: **was the collection behind it adequate**
for the purpose the analyst asked for, and if not, what is still missing?

Those two questions come apart in both directions, which is the whole reason this
layer exists:

* MALICIOUS at HIGH confidence with no sandbox coverage is a *correct* assessment
  with an incomplete investigation. The confidence is not lowered; a limitation is
  recorded beside it.
* LIKELY_BENIGN from a single unopposed benign assertion is a correct assessment
  that nobody has yet tried to contradict. The verdict stands; readiness says an
  independent adverse search has not run.

Two axes, never one
-------------------

:class:`CoverageAdequacy` answers "is there enough external-TI coverage for this
purpose?". :class:`ContinuationState` answers "could more enrichment still help?".
:class:`ReadinessStatus` is *derived* from the pair and exists for convenience —
collapsing the two into one enum up front would hide the difference between "we
could learn more" and "there is nothing left to ask".

Completion is not yield
-----------------------

:class:`CheckCompletion` says whether a check happened. :class:`InformationYield`
says what came back. A source that was queried and answered "nothing known"
completed its check and yielded ``NO_DATA`` — which is real coverage and is *not*
evidence of anything. Collapsing that into "not run" loses the difference between
an unasked question and an answered one; collapsing it into benign evidence is
the mistake Tasks 15-17 spend most of their rules preventing.

What is deliberately absent
---------------------------

No score, no percentage, no severity, no priority, no risk number and no action.
TI Recon does not know asset criticality, business impact, user context or
incident policy, so it cannot say whether something should be blocked, closed or
escalated. It can say whether it has looked in the places that were worth looking.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Final

from pydantic import Field, model_validator

from ti_recon.enums import (
    CoverageRelevance,
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
)
from ti_recon.models.base import FrozenTiReconModel

__all__ = [
    "GAP_ID_LENGTH",
    "READINESS_ID_LENGTH",
    "REQUIREMENT_ID_LENGTH",
    "CheckCompletion",
    "ContinuationState",
    "CoverageAdequacy",
    "CoverageRequirement",
    "GapOutlook",
    "GapType",
    "InformationNeed",
    "InformationYield",
    "ReadinessGap",
    "ReadinessLimitation",
    "ReadinessPurpose",
    "ReadinessStatus",
    "RequirementActivation",
    "RequirementEvaluation",
    "RequirementStatus",
    "SourceCheck",
    "gap_id_for",
    "readiness_id_for",
    "requirement_id_for",
]

REQUIREMENT_ID_LENGTH: Final[int] = 24
GAP_ID_LENGTH: Final[int] = 24
READINESS_ID_LENGTH: Final[int] = 32


class ReadinessPurpose(StrEnum):
    """What the readiness question is being asked *for*.

    Exactly one member in v1, and that is a deliberate limit rather than an
    oversight. "Ready to block", "ready to close the alert" and "ready to declare
    an incident" all depend on asset criticality, business impact, user context
    and incident policy — none of which TI Recon has any access to. Offering a
    purpose this engine cannot actually evaluate would be worse than offering
    none, because the answer would look authoritative.
    """

    #: Is the external-TI picture complete enough to hand an analyst for triage?
    ANALYST_TRIAGE = "analyst_triage"


class ReadinessStatus(StrEnum):
    """The derived headline, never the whole answer.

    Deliberately free of anything that reads as a recommendation: no SAFE, no
    CLEAR, no BLOCK, no ACTIONABLE. Every member describes the state of the
    *investigation*, not of the observable.
    """

    #: Adequate coverage for this purpose, nothing material outstanding.
    READY = "ready"
    #: Usable for triage; non-fatal coverage limitations remain.
    READY_WITH_LIMITATIONS = "ready_with_limitations"
    #: Inadequate, and an applicable path could still address the gap.
    NEEDS_MORE_DATA = "needs_more_data"
    #: Inadequate, and no currently available path can address it -- or an
    #: integrity problem in the inputs prevents a clean answer.
    UNRESOLVED = "unresolved"


class CoverageAdequacy(StrEnum):
    """Is there enough external-TI coverage for this purpose?"""

    ADEQUATE = "adequate"
    LIMITED = "limited"
    INADEQUATE = "inadequate"


class ContinuationState(StrEnum):
    """Could further external enrichment still address a material gap?

    ``EXHAUSTED`` is emphatically not a synonym for ``COMPLETE``. Having asked
    everything available and learned nothing is a finished search with an
    unresolved question, and reporting that as adequate coverage would turn the
    absence of sources into the presence of an answer.
    """

    #: No material gap remains for this profile.
    COMPLETE = "complete"
    #: A material requirement is unmet and an applicable path remains.
    MORE_DATA_AVAILABLE = "more_data_available"
    #: A material requirement has candidates, but every one is currently
    #: unusable -- unconfigured, out of quota, or unavailable.
    BLOCKED = "blocked"
    #: Applicable checks are done, or no compatible source exists at all.
    EXHAUSTED = "exhausted"


class CheckCompletion(StrEnum):
    """Did the check happen?"""

    COMPLETE = "complete"
    PARTIAL = "partial"
    NOT_ATTEMPTED = "not_attempted"
    BLOCKED = "blocked"
    #: Outside what this depth or this observable calls for. Not a failure.
    OUT_OF_SCOPE = "out_of_scope"


class InformationYield(StrEnum):
    """What came back, quite separately from whether the check ran.

    ``NO_DATA`` is a source that answered. ``NONE`` is a source that did not.
    Both are honest, and they are not the same fact.
    """

    #: A directional claim reached the assessment layer.
    DIRECTIONAL = "directional"
    #: Something was learned, but nothing that points either way.
    CONTEXT_ONLY = "context_only"
    #: The source answered, and held nothing about this observable.
    NO_DATA = "no_data"
    #: Nothing came back at all.
    NONE = "none"


class RequirementStatus(StrEnum):
    """How well one information requirement was met."""

    SATISFIED = "satisfied"
    #: Met, but with a stated caveat -- a bounded search horizon, a partial
    #: result, or a check whose quality was too low to be informative.
    LIMITED = "limited"
    UNSATISFIED = "unsatisfied"
    #: Never applied: wrong observable type, deeper than the requested depth, or
    #: a conditional goal whose trigger never occurred.
    NOT_APPLICABLE = "not_applicable"


class RequirementActivation(StrEnum):
    """Whether this requirement was ever in play.

    Read from what Task 13 *recorded*, never re-derived. A goal the planner
    declined to activate is a decision that was already made with information
    this layer does not have, and second-guessing it would invent requirements
    the investigation never had.
    """

    ACTIVE = "active"
    #: The goal exists for this observable but its trigger never fired.
    NOT_ACTIVATED = "not_activated"
    #: Deeper than the requested depth, so never in scope.
    OUT_OF_DEPTH = "out_of_depth"


class GapType(StrEnum):
    """Why a requirement went unmet, in generic terms.

    Categories, not one member per provider status: the raw status stays in the
    :class:`SourceCheck` trace, and policy reasons about the category. A gap
    names a *capability*, never a provider -- choosing who could serve it is
    Task 13's decision, made later and with the catalogue in front of it.
    """

    NOT_ATTEMPTED = "not_attempted"
    BUDGET_LIMITED = "budget_limited"
    NOT_CONFIGURED = "not_configured"
    #: The credential is valid but the account's plan does not include this
    #: data or endpoint. A different operator action from a missing credential,
    #: so it gets its own category rather than being folded into one.
    PLAN_LIMITED = "plan_limited"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
    QUOTA_EXCEEDED = "quota_exceeded"
    PARTIAL_COVERAGE = "partial_coverage"
    LIMITED_SOURCE_HORIZON = "limited_source_horizon"
    STALE_CONTEXT_DATA = "stale_context_data"
    LOW_INFORMATION_YIELD = "low_information_yield"
    #: A directional claim could not be attributed to a known object, so its
    #: relevance to the target cannot be established either way.
    UNRESOLVED_INPUT = "unresolved_input"
    #: No registered source can serve this capability for this observable.
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    #: A benign assessment that nothing independent has tried to contradict.
    INDEPENDENT_CHALLENGE_MISSING = "independent_challenge_missing"


class GapOutlook(StrEnum):
    """Whether enrichment could still address this gap.

    Deliberately hedged. ``MAY_ADDRESS_MATERIAL_GAP`` says an applicable
    requirement is unfulfilled and a path exists — never that running it would
    change the verdict, which is unknowable before it runs.
    """

    MAY_ADDRESS_MATERIAL_GAP = "may_address_material_gap"
    NO_REMAINING_PATH = "no_remaining_path"


def _digest(material: str, length: int) -> str:
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:length]


def requirement_id_for(
    *, policy_version: str, capability: ProviderCapability, object_type: IntelObjectType
) -> str:
    """A requirement's identity: what is needed, about what kind of thing."""
    return _digest(
        f"{policy_version}|{capability.value}|{object_type.value}", REQUIREMENT_ID_LENGTH
    )


def gap_id_for(*, policy_version: str, requirement_id: str, gap_type: GapType) -> str:
    """A gap's identity: which requirement, and why it is unmet."""
    return _digest(f"{policy_version}|{requirement_id}|{gap_type.value}", GAP_ID_LENGTH)


def readiness_id_for(
    *,
    policy_version: str,
    purpose: ReadinessPurpose,
    target_key: str,
    depth: InvestigationDepth,
    assessment_id: str,
    requirement_refs: tuple[str, ...],
    gap_ids: tuple[str, ...],
) -> str:
    """A readiness result's record identity.

    **Record identity, not a cross-run semantic fingerprint.** It incorporates
    the Task 17 ``assessment_id``, which is itself built over ``Evidence.id`` —
    a UUID minted when the evidence was collected. So this id is deterministic
    for one stored investigation and differs across fresh collections of the
    same intelligence, exactly as Task 17's is. The stable cross-run identity
    remains the proposition and the requirement, not the run.
    """
    material = "|".join(
        (
            policy_version,
            purpose.value,
            target_key,
            depth.value,
            assessment_id,
            ",".join(sorted(requirement_refs)),
            ",".join(sorted(gap_ids)),
        )
    )
    return _digest(material, READINESS_ID_LENGTH)


class CoverageRequirement(FrozenTiReconModel):
    """One thing this investigation needed to find out.

    Derived from Task 13's own :class:`~ti_recon.planning.goals.CapabilityGoal`
    rather than restated here, so provider applicability, depth thresholds and
    activation stay in the one place that already models them.
    """

    requirement_id: str = Field(min_length=8, max_length=REQUIREMENT_ID_LENGTH)
    capability: ProviderCapability
    #: Criticality, reusing Task 3's vocabulary rather than inventing a parallel
    #: one. Never a number: a weight would invite arithmetic across requirements
    #: that are not commensurable.
    criticality: CoverageRelevance
    activation: RequirementActivation
    object_type: IntelObjectType
    requested_depth: InvestigationDepth
    #: Why the profile asks for this, as a stable code rather than prose.
    rationale: str = Field(min_length=1, max_length=64)


class SourceCheck(FrozenTiReconModel):
    """One execution attempt, kept so the trace shows what actually happened.

    A requirement can be satisfied while individual attempts failed, and hiding
    those would make the result look tidier than the investigation was. This is
    the one place in the package where a provider id legitimately appears: it is
    an observed fact about a run, not an input to policy.
    """

    provider_id: str = Field(min_length=1, max_length=64)
    source_family: str = Field(min_length=1, max_length=64)
    capability: ProviderCapability
    #: The provider status verbatim, so a category never has to be reverse
    #: engineered from the completion it produced.
    raw_status: str = Field(min_length=1, max_length=64)
    completion: CheckCompletion
    information_yield: InformationYield
    #: True when the answer came from Task 6's cache or a coalesced request. The
    #: information was available either way, which is what readiness asks.
    served_without_call: bool = False
    local_source: bool = False


class ReadinessLimitation(FrozenTiReconModel):
    """A caveat that does not prevent the assessment being useful."""

    requirement_id: str = Field(min_length=8, max_length=REQUIREMENT_ID_LENGTH)
    gap_type: GapType
    capability: ProviderCapability | None = None
    detail: str = Field(min_length=1, max_length=200)


class RequirementEvaluation(FrozenTiReconModel):
    """What happened to one requirement, and why it landed there."""

    requirement: CoverageRequirement
    status: RequirementStatus
    completion: CheckCompletion
    information_yield: InformationYield
    checks: tuple[SourceCheck, ...] = ()
    #: Independent originating families that completed a check for this
    #: capability. Grouping follows Task 17, so three datasets from one
    #: organisation are one origin.
    independent_families: tuple[str, ...] = ()
    limitations: tuple[ReadinessLimitation, ...] = ()
    gap_type: GapType | None = None
    #: Whether an unmet requirement actually bears on the assessment in hand.
    material: bool = False


class ReadinessGap(FrozenTiReconModel):
    """A material requirement that was not met."""

    gap_id: str = Field(min_length=8, max_length=GAP_ID_LENGTH)
    requirement_id: str = Field(min_length=8, max_length=REQUIREMENT_ID_LENGTH)
    gap_type: GapType
    capability: ProviderCapability | None = None
    criticality: CoverageRelevance
    outlook: GapOutlook
    #: Provider ids observed to have failed for this capability, for the trace.
    #: Never read by policy -- a gap is about a capability, not about who could
    #: have served it.
    observed_sources: tuple[str, ...] = ()
    detail: str = Field(min_length=1, max_length=200)


class InformationNeed(FrozenTiReconModel):
    """A capability worth obtaining, stated without choosing a provider.

    Task 19 may hand this back to Task 13, which will decide who can serve it.
    It is not a provider selection, not a request, and not a recommendation to
    act on the observable.
    """

    capability: ProviderCapability
    criticality: CoverageRelevance
    reason: str = Field(min_length=1, max_length=64)
    outlook: GapOutlook


class ReadinessCoverageSummary(FrozenTiReconModel):
    """Counts, and deliberately not a ratio.

    "Seven of nine requirements met" invites reading 78% as readiness, which is
    meaningless when the two unmet ones are the only capabilities that could
    resolve the question. The absolute numbers say the same thing without
    inviting the division.
    """

    requirements_total: int = Field(default=0, ge=0)
    requirements_satisfied: int = Field(default=0, ge=0)
    requirements_limited: int = Field(default=0, ge=0)
    requirements_unsatisfied: int = Field(default=0, ge=0)
    requirements_not_applicable: int = Field(default=0, ge=0)

    checks_complete: int = Field(default=0, ge=0)
    checks_partial: int = Field(default=0, ge=0)
    checks_no_data: int = Field(default=0, ge=0)
    checks_blocked: int = Field(default=0, ge=0)
    checks_not_attempted: int = Field(default=0, ge=0)

    material_gaps: int = Field(default=0, ge=0)
    optional_gaps: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _consistent(self) -> ReadinessCoverageSummary:
        parts = (
            self.requirements_satisfied
            + self.requirements_limited
            + self.requirements_unsatisfied
            + self.requirements_not_applicable
        )
        if parts != self.requirements_total:
            msg = "requirement counts must sum to requirements_total"
            raise ValueError(msg)
        return self
