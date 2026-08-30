"""Versioned readiness policy (Task 18).

Everything here is a judgement someone should be able to argue with, so it is
written down as data and a small number of named rules rather than distributed
through the engine as conditionals.

Three things this module decides
--------------------------------

1. **Which requirements applied.** Not restated here: Task 13's
   :meth:`~ti_recon.planning.policy.EnrichmentPolicy.goals_for` already knows
   what an observable of this type needs at this depth, including which goals do
   not exist below a depth threshold. Readiness adds criticality framing and
   nothing else.

2. **Whether an unmet requirement is material.** A gap matters when resolving it
   could legitimately address something the assessment has not settled. That
   depends on how strong the existing basis is -- an exact decisive claim about
   the object leaves little for another source to add, while a single generic
   reputation claim leaves a great deal. It never depends on which providers
   exist.

3. **What the pair of axes means.** Adequacy and continuation are computed
   independently and then read together; the headline status is derived last.

Basis strength, read from Task 17's own rule ids
------------------------------------------------

The verdict rule that fired is the honest description of how well founded the
assessment is, and it is already provider-neutral. A decisive exact claim and an
independently corroborated one are both strong; residual suspicion and an
unopposed single benign assertion are not. Reading the rule id means readiness
never re-derives an evidential judgement Task 17 already made.

The benign asymmetry
--------------------

A malicious finding is self-limiting: something was found, and finding more would
not unfind it. A benign finding is an absence, and an absence is only as good as
the search behind it. So a LIKELY_BENIGN reached from one unopposed assertion
requires an *independent* adverse search to have completed before it is fully
ready -- where independence follows Task 17's provenance grouping, not a count of
provider ids. The independent check may return nothing at all; that satisfies the
requirement that somebody looked, and adds no benign evidence whatsoever.
"""

from __future__ import annotations

from typing import Final

from ti_recon.enums import CoverageRelevance, InvestigationDepth, ProviderCapability, Verdict
from ti_recon.reasoning.fusion.policy import FUSION_POLICY_VERSION, VERDICT_RULES
from ti_recon.reasoning.readiness.models import (
    ContinuationState,
    CoverageAdequacy,
    GapType,
    ReadinessPurpose,
    ReadinessStatus,
    RequirementStatus,
)

__all__ = [
    "BASIS_RATIONALE",
    "BLOCKING_GAP_TYPES",
    "CONTINUABLE_GAP_TYPES",
    "DIRECTIONAL_SEARCH_CAPABILITIES",
    "READINESS_POLICY_VERSION",
    "STRONG_BASIS_RULES",
    "SUPPORTED_FUSION_POLICY_VERSION",
    "SUPPORTED_PURPOSES",
    "TERMINAL_GAP_TYPES",
    "adequacy_for",
    "continuation_for",
    "is_material",
    "requires_independent_challenge",
    "status_for",
]

#: Version of the readiness rules, the criticality framing and the status
#: derivation. Recorded on every result: a policy change alters what "ready"
#: asserts, and reusing the version would make two incomparable answers look
#: like the same one.
READINESS_POLICY_VERSION: Final[str] = "1.0.0"

#: The one purpose v1 can actually evaluate.
SUPPORTED_PURPOSES: Final[frozenset[ReadinessPurpose]] = frozenset(
    {ReadinessPurpose.ANALYST_TRIAGE}
)

#: The Task 17 fusion policy whose verdict-rule vocabulary :data:`STRONG_BASIS_RULES`
#: was written against.
#:
#: Readiness interprets Task 17's rule ids, so it is bound to the policy that
#: defines them. The mapping is by *exact identity* -- the ids are imported from
#: ``VERDICT_RULES`` rather than matched, so a rename is a build error rather
#: than a silent behaviour change. An id this table does not know is treated as
#: a weak basis, which keeps relevant requirements material: assuming an unknown
#: rule is strong would suppress requirements on the strength of a rule nobody
#: here has reviewed.
SUPPORTED_FUSION_POLICY_VERSION: Final[str] = FUSION_POLICY_VERSION

#: Verdict rules whose basis is specific enough that optional coverage adds
#: little. Two malicious routes -- a decisive exact claim, and independent
#: corroboration -- plus the benign route where every malicious claim was
#: specifically explained at exact scope.
STRONG_BASIS_RULES: Final[frozenset[str]] = frozenset(
    {
        VERDICT_RULES["malicious_decisive"],
        VERDICT_RULES["malicious_corroborated"],
        VERDICT_RULES["likely_benign_explained"],
    }
)

#: The benign route that rests on one source's say-so. Strong enough for Task 17
#: to state a verdict, not strong enough for Task 18 to call the search finished.
_SINGLE_SOURCE_BENIGN_RULE: Final[str] = VERDICT_RULES["likely_benign_directional"]

#: Capabilities whose job is to look for adverse information about the object.
#: Used only to decide whether *something* challenged a benign assessment; it is
#: never a list of providers and never a requirement to find anything.
DIRECTIONAL_SEARCH_CAPABILITIES: Final[frozenset[ProviderCapability]] = frozenset(
    {
        ProviderCapability.REPUTATION,
        ProviderCapability.MALWARE_INTELLIGENCE,
        ProviderCapability.THREAT_ASSOCIATIONS,
    }
)

#: Gap types where a path exists and only the current run stopped short.
CONTINUABLE_GAP_TYPES: Final[frozenset[GapType]] = frozenset(
    {
        GapType.NOT_ATTEMPTED,
        GapType.BUDGET_LIMITED,
        GapType.PARTIAL_COVERAGE,
        GapType.LIMITED_SOURCE_HORIZON,
        GapType.LOW_INFORMATION_YIELD,
        GapType.INDEPENDENT_CHALLENGE_MISSING,
        GapType.STALE_CONTEXT_DATA,
    }
)

#: Gap types where candidates exist but none can currently be used.
BLOCKING_GAP_TYPES: Final[frozenset[GapType]] = frozenset(
    {
        GapType.NOT_CONFIGURED,
        GapType.PLAN_LIMITED,
        GapType.QUOTA_EXCEEDED,
        GapType.TEMPORARILY_UNAVAILABLE,
    }
)

#: Gap types with no remaining path at all.
TERMINAL_GAP_TYPES: Final[frozenset[GapType]] = frozenset(
    {
        GapType.CAPABILITY_UNAVAILABLE,
        GapType.UNRESOLVED_INPUT,
    }
)

#: Stable rationale codes, so a requirement says why it exists without prose.
BASIS_RATIONALE: Final[dict[str, str]] = {
    "planner_goal": "task13.capability_goal",
    "benign_challenge": "readiness.independent_adverse_search",
}


def requires_independent_challenge(verdict: Verdict, verdict_rule_id: str) -> bool:
    """Whether this assessment must have been challenged to be fully ready.

    Only the single-source benign route. A benign verdict reached by explaining
    every malicious claim at exact scope has already engaged with adverse
    evidence -- there was some, and it was accounted for individually. A benign
    verdict resting on one provider's assertion has engaged with none.
    """
    return verdict is Verdict.LIKELY_BENIGN and verdict_rule_id == _SINGLE_SOURCE_BENIGN_RULE


def is_material(
    *,
    criticality: CoverageRelevance,
    verdict: Verdict,
    verdict_rule_id: str,
) -> bool:
    """Whether an unmet requirement of this criticality bears on this assessment.

    ``REQUIRED`` always matters. ``RELEVANT`` matters only where the assessment
    has not settled the question: a decisive exact identification is not made
    more correct by a sandbox report, whereas a lone generic reputation claim
    genuinely could be. ``OPTIONAL`` never makes a result unready; it becomes a
    limitation, which is recorded and does not block.

    This is the rule that stops "a provider exists and did not run" from
    becoming a gap. Materiality comes from what remains unresolved, never from
    what the catalogue happens to contain.
    """
    if criticality is CoverageRelevance.NOT_APPLICABLE:
        return False
    if criticality is CoverageRelevance.REQUIRED:
        return True
    if criticality is CoverageRelevance.OPTIONAL:
        return False
    return verdict_rule_id not in STRONG_BASIS_RULES


def adequacy_for(
    *,
    verdict: Verdict,
    material_gaps: int,
    limitations: int,
    unresolved_inputs: int,
) -> CoverageAdequacy:
    """How well covered this assessment is, on its own axis.

    ``INCONCLUSIVE`` is never adequate, however much was checked. The purpose is
    triage of an observable, and an engine that looked everywhere and still
    cannot say anything has not covered the question -- it has established that
    its sources do not answer it. Reporting that as adequate would let
    "exhausted" quietly become "fine".
    """
    if material_gaps or unresolved_inputs:
        return CoverageAdequacy.INADEQUATE
    if verdict is Verdict.INCONCLUSIVE:
        return CoverageAdequacy.INADEQUATE
    if limitations:
        return CoverageAdequacy.LIMITED
    return CoverageAdequacy.ADEQUATE


def continuation_for(*, material_gap_types: frozenset[GapType]) -> ContinuationState:
    """Whether anything further could still be asked.

    Order matters and is deliberate: a run that could simply continue is
    reported as continuable even when something else is blocked, because the
    cheapest honest next step is the one worth naming. Blocked outranks
    exhausted for the same reason -- a credential can be supplied, whereas a
    capability nobody implements cannot.
    """
    if not material_gap_types:
        return ContinuationState.COMPLETE
    if material_gap_types & CONTINUABLE_GAP_TYPES:
        return ContinuationState.MORE_DATA_AVAILABLE
    if material_gap_types & BLOCKING_GAP_TYPES:
        return ContinuationState.BLOCKED
    return ContinuationState.EXHAUSTED


def status_for(
    *, adequacy: CoverageAdequacy, continuation: ContinuationState, limitations: int
) -> ReadinessStatus:
    """The derived headline.

    Read the two axes together rather than collapsing them earlier: inadequate
    coverage that can be continued is a different situation from inadequate
    coverage that cannot, and an analyst deciding whether to wait needs to know
    which one they have.
    """
    if adequacy is CoverageAdequacy.INADEQUATE:
        if continuation is ContinuationState.MORE_DATA_AVAILABLE:
            return ReadinessStatus.NEEDS_MORE_DATA
        return ReadinessStatus.UNRESOLVED
    if continuation is ContinuationState.COMPLETE and not limitations:
        return ReadinessStatus.READY
    return ReadinessStatus.READY_WITH_LIMITATIONS


def satisfied_statuses() -> frozenset[RequirementStatus]:
    """Requirement statuses that leave nothing outstanding."""
    return frozenset({RequirementStatus.SATISFIED, RequirementStatus.NOT_APPLICABLE})


def depth_covers(requested: InvestigationDepth, minimum: InvestigationDepth) -> bool:
    """Whether a goal needing ``minimum`` depth was in scope for ``requested``."""
    from ti_recon.planning.goals import depth_at_least

    return depth_at_least(requested, minimum)
