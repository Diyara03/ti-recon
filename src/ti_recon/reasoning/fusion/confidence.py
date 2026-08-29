"""How sure TI Recon is that its own assessment is right (Task 17D).

Confidence answers **"how confident are we that this assessment is correct?"**
It does not answer "what are the odds this object is malicious?". Those are
different questions, and a system that conflated them would report 85 and have it
read as "85% likely bad" -- a number nobody measured, describing a quantity
nobody computed.

Decided separately from the verdict, from different inputs
----------------------------------------------------------

Nothing here reads the verdict's ordinal. MALICIOUS at MEDIUM is an ordinary
thing to say when one good source is unopposed but alone; SUSPICIOUS at MEDIUM is
ordinary when the concern is well established but does not meet the malicious
bar. Deriving confidence from verdict severity would make both impossible and
would quietly push analysts toward false certainty.

Caps, not penalties
-------------------

An unresolved conflict, an unclassified basis, a partial source, sandbox
divergence or a decision resting on stale context each *cap* confidence rather
than subtracting from it. There is no number to subtract from, and a cap is
auditable in a way a decremented score is not: it says which condition held the
band down, by name.

Stale context is scoped
-----------------------

Task 16 fixed the bug where one stale dataset annotated every finding in the run.
That fix is preserved here: only a stale limitation on a finding that touches a
claim the verdict actually rested on can cap confidence. An unrelated stale
warninglist leaves an independent malware-sample assessment alone.
"""

from __future__ import annotations

from collections.abc import Sequence

from ti_recon.enums import Verdict
from ti_recon.reasoning.claims.models import ClaimSemantic, NormalizedClaim
from ti_recon.reasoning.false_positive.models import (
    FindingLimitation,
    LinkTarget,
    ReasonCode,
)
from ti_recon.reasoning.false_positive.results import FalsePositiveReasoningResult
from ti_recon.reasoning.fusion.independence import independence_index
from ti_recon.reasoning.fusion.models import (
    AssessmentConfidence,
    ClaimDecisionRole,
    ClaimDisposition,
    CorroborationGroup,
    FusionConflict,
    SupportBreadth,
)
from ti_recon.reasoning.fusion.policy import (
    CONFIDENCE_CAPS,
    CONFIDENCE_RULES,
    VERDICT_RULES,
    decision_role_for,
)

__all__ = ["decide_confidence"]


def decide_confidence(
    *,
    verdict: Verdict,
    verdict_rule_id: str,
    claims: Sequence[NormalizedClaim],
    dispositions: dict[str, ClaimDisposition],
    corroboration: Sequence[CorroborationGroup],
    conflicts: Sequence[FusionConflict],
    basis_claim_ids: tuple[str, ...],
    reasoning: FalsePositiveReasoningResult,
) -> tuple[AssessmentConfidence, str, tuple[str, ...]]:
    """Pick a confidence band, the rule that picked it, and what capped it."""
    by_id = {item.claim_id: item for item in claims}
    basis = [by_id[item] for item in basis_claim_ids if item in by_id]

    caps = _caps(
        basis=basis,
        claims=claims,
        dispositions=dispositions,
        conflicts=conflicts,
        reasoning=reasoning,
    )

    band, rule = _band(
        verdict=verdict,
        verdict_rule_id=verdict_rule_id,
        basis=basis,
        corroboration=corroboration,
    )
    return _apply_caps(band, caps), rule, tuple(sorted(caps))


def _band(
    *,
    verdict: Verdict,
    verdict_rule_id: str,
    basis: Sequence[NormalizedClaim],
    corroboration: Sequence[CorroborationGroup],
) -> tuple[AssessmentConfidence, str]:
    """The band the evidence structure earns, before any cap applies."""
    if verdict is Verdict.INCONCLUSIVE:
        # Nothing was concluded, so there is nothing to be confident about. This
        # is the one band that is not a judgement about strength. Which of the two
        # ways it was reached still matters to whoever reads the trace: sources
        # disagreeing is not the same situation as no source saying anything.
        if verdict_rule_id == VERDICT_RULES["inconclusive_conflict"]:
            return AssessmentConfidence.UNSPECIFIED, CONFIDENCE_RULES["unspecified_conflicted"]
        return AssessmentConfidence.UNSPECIFIED, CONFIDENCE_RULES["unspecified_no_support"]

    if verdict is Verdict.LIKELY_BENIGN:
        if verdict_rule_id == VERDICT_RULES["likely_benign_explained"]:
            # Every malicious claim specifically accounted for by an exact-object
            # explanation, with none left over. A complete account, which is a
            # strong structure -- but only MEDIUM by default, because "we
            # explained everything we saw" depends on having seen enough.
            return AssessmentConfidence.MEDIUM, CONFIDENCE_RULES["medium_explained"]
        return AssessmentConfidence.MEDIUM, CONFIDENCE_RULES["medium_corroborated"]

    decisive = [item for item in basis if decision_role_for(item) is ClaimDecisionRole.DECISIVE]
    # Independence components rather than families, for the same reason the
    # verdict uses them: a relay that crosses a family boundary is one source.
    index = independence_index(basis)
    origins = {index[item.claim_id] for item in basis}

    if decisive and len(origins) >= 2:
        # A specific claim about the artifact, and a separate origin agreeing.
        # The strongest structure this engine recognises.
        return AssessmentConfidence.HIGH, CONFIDENCE_RULES["high_decisive_corroborated"]
    if decisive:
        return AssessmentConfidence.MEDIUM, CONFIDENCE_RULES["medium_decisive"]

    broad = any(
        group.breadth is SupportBreadth.MULTIPLE_INDEPENDENT_SOURCES for group in corroboration
    )
    if broad and len(origins) >= 2:
        return AssessmentConfidence.MEDIUM, CONFIDENCE_RULES["medium_corroborated"]

    return AssessmentConfidence.LOW, CONFIDENCE_RULES["low_single_weak"]


def _caps(
    *,
    basis: Sequence[NormalizedClaim],
    claims: Sequence[NormalizedClaim],
    dispositions: dict[str, ClaimDisposition],
    conflicts: Sequence[FusionConflict],
    reasoning: FalsePositiveReasoningResult,
) -> set[str]:
    """Named conditions that hold the band below HIGH."""
    found: set[str] = set()

    if conflicts:
        found.add(CONFIDENCE_CAPS["unresolved_conflict"])

    if any(item.semantic is ClaimSemantic.UNCLASSIFIED_DIRECTIONAL for item in basis):
        found.add(CONFIDENCE_CAPS["unclassified_basis"])

    if any(item.source_partial for item in basis):
        found.add(CONFIDENCE_CAPS["partial_source"])

    # Sandbox divergence is a property of the sample, not a defect -- but two
    # environments disagreeing means one of them would have told us less, so the
    # assessment cannot be at its firmest. Scoped like the stale cap below: a
    # divergent detonation of some *other* object reached on a pivot says nothing
    # about this verdict's basis.
    basis_evidence = {item.evidence_id for item in basis}
    if _bears_on_basis(
        reasoning,
        basis_evidence,
        reason_code=ReasonCode.SANDBOX_RESULT_ENVIRONMENT_DEPENDENT,
    ):
        found.add(CONFIDENCE_CAPS["sandbox_divergence"])

    if _bears_on_basis(
        reasoning,
        basis_evidence,
        limitation=FindingLimitation.SUPPORTING_CONTEXT_DATASET_STALE,
    ):
        found.add(CONFIDENCE_CAPS["stale_supporting_context"])

    supporting = [
        item
        for item in claims
        if dispositions[item.claim_id]
        in {ClaimDisposition.UNEXPLAINED, ClaimDisposition.QUALIFIED_ONLY}
    ]
    if basis and all(decision_role_for(item) is ClaimDecisionRole.WEAK for item in supporting):
        found.add(CONFIDENCE_CAPS["single_weak_support"])

    return found


def _bears_on_basis(
    reasoning: FalsePositiveReasoningResult,
    basis_evidence: set[str],
    *,
    reason_code: ReasonCode | None = None,
    limitation: FindingLimitation | None = None,
) -> bool:
    """Whether a qualification actually touches what the verdict relied on.

    This is the Task 16 scoping fix, generalised. A stale warninglist snapshot
    somewhere else in the run says nothing about an independent malware-sample
    claim, and a divergent sandbox report on an object reached two pivots away
    says nothing about this address -- capping either assessment would attach a
    caveat to evidence the condition never touched.

    So a cap requires two things at once: a finding carrying the condition, *and*
    that finding linking to a piece of evidence the basis actually used. A
    run-level ``any()`` over findings is the shape of the original bug, and it is
    deliberately not available here.
    """
    if not basis_evidence:
        return False
    for finding in reasoning.findings:
        if reason_code is not None and finding.reason_code is not reason_code:
            continue
        if limitation is not None and limitation not in finding.limitations:
            continue
        for link in finding.links:
            if link.target is LinkTarget.EVIDENCE and link.ref in basis_evidence:
                return True
    return False


def _apply_caps(band: AssessmentConfidence, caps: set[str]) -> AssessmentConfidence:
    """Lower a band to the ceiling its caps allow.

    Caps only ever lower, and only by one step: they say "not at its firmest",
    which is a statement about structure rather than a quantity to accumulate.
    Stacking three caps does not reach a fourth band -- there isn't one, and
    inventing arithmetic here would be the weighted score by another route.
    """
    if not caps:
        return band
    if band is AssessmentConfidence.HIGH:
        return AssessmentConfidence.MEDIUM
    if band is AssessmentConfidence.MEDIUM:
        return AssessmentConfidence.LOW
    return band
