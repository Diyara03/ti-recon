"""Fusion vocabulary and the assessment shape (Task 17).

Task 17 is the first layer allowed to reach a verdict. Everything below it
refused to: Task 15 qualified, Task 16 explained, and both went out of their way
to avoid producing a number somebody downstream would read instead of reasoning.

This module holds what a verdict is allowed to be made of.

What is deliberately absent
---------------------------

No score. No weight. No probability. No risk number. The Task 3 ``Assessment``
placeholder carries a ``risk_score`` and a set of multiplicative dampening
factors -- ``base_strength``, ``freshness_factor``, ``independence_factor`` -- and
that arithmetic model is the one this task is forbidden to build. It is left
untouched as the Task 3 shape it always was; Task 17 owns its own assessment,
built from rules rather than products.

The reason is not squeamishness about numbers. It is that there is no calibration
data behind any weight anybody could write here, so a formula would manufacture
precision that looks defensible and is not, and the first person to tune a
coefficient would be tuning noise.

Confidence is not maliciousness
-------------------------------

:class:`AssessmentConfidence` answers "how confident is TI Recon that this
assessment is correct?" -- not "what are the odds this is malicious?". A
MALICIOUS verdict at MEDIUM confidence is an ordinary, useful thing to say, and a
system that could not say it would be pushing analysts toward false certainty.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Final

from pydantic import Field, model_validator

from ti_recon.enums import EvidenceEffect, MatchScope, Verdict
from ti_recon.models.base import FrozenTiReconModel, UtcDatetime
from ti_recon.reasoning.claims.models import ClaimPropositionKey, ClaimSemantic

__all__ = [
    "ASSESSMENT_ID_LENGTH",
    "AssessmentConfidence",
    "ClaimContribution",
    "ClaimDecisionRole",
    "ClaimDisposition",
    "ContributionRole",
    "CorroborationGroup",
    "FusionAssessment",
    "FusionConflict",
    "FusionIssue",
    "FusionIssueType",
    "IndependenceGroup",
    "PropositionGroup",
    "SupportBreadth",
    "assessment_id_for",
]


class AssessmentConfidence(StrEnum):
    """How confident TI Recon is that its own assessment is right.

    Qualitative on purpose. The STIX confidence scale offers canonical integers
    for exactly these three bands, and :data:`STIX_CONFIDENCE` maps onto them for
    anybody who needs the numeric form -- but the enum is authoritative, because
    an integer invites arithmetic and there is no calibration to justify any.

    Emphatically **not** a probability that the object is malicious. Those are
    different questions, and conflating them is how "85" starts being read as
    "85% likely bad".
    """

    UNSPECIFIED = "unspecified"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


#: The canonical STIX 2.1 confidence values for a three-band qualitative scale.
#:
#: Provided because callers integrating with STIX need the integer, not because
#: anything here computes one. No other value is ever produced: an assessment
#: reporting 63 would be claiming a precision nobody measured.
STIX_CONFIDENCE: Final[dict[AssessmentConfidence, int | None]] = {
    AssessmentConfidence.UNSPECIFIED: None,
    AssessmentConfidence.LOW: 15,
    AssessmentConfidence.MEDIUM: 50,
    AssessmentConfidence.HIGH: 85,
}


class ClaimDisposition(StrEnum):
    """What Task 16 said about one claim, translated for fusion.

    Derived inside fusion and never written back. Task 16's findings are the
    authority; this is how one run reads them.
    """

    #: Nothing accounted for this claim. The default, and the one that matters.
    UNEXPLAINED = "unexplained"
    #: A Task 16 ``ALTERNATIVE_EXPLANATION`` specifically explains this claim
    #: through an ``EXPLAINS`` link. Only that link counts.
    EXPLAINED_BY_ALTERNATIVE = "explained_by_alternative"
    #: A Task 16 finding narrowed how to read it without explaining it. An
    #: attribution caution, a scope limitation, a temporal note. Still support.
    QUALIFIED_ONLY = "qualified_only"
    #: Another claim about the same proposition points the other way.
    OPPOSED = "opposed"
    #: Real, and not a second source: the same information already counted,
    #: reached through a different transport or the same lineage.
    DEPENDENT_DUPLICATE = "dependent_duplicate"


class ClaimDecisionRole(StrEnum):
    """How much weight a claim's *kind* can carry, before anything else.

    Determined from generic properties only -- semantic, evidence class, scope,
    assertion strength. No provider appears in the calculation, which is what
    stops "this vendor is reliable" becoming policy.
    """

    #: Specific enough to justify a verdict on its own. A curated repository
    #: holding this exact sample; a tracked URL that delivered malware.
    DECISIVE = "decisive"
    #: Real support that wants company. A curated reputation verdict, a threat
    #: association, a sandbox classification.
    CORROBORATIVE = "corroborative"
    #: Support that cannot carry a verdict alone under any combination. An
    #: aggregate of other people's opinions, a hedged verdict, a claim nobody
    #: could classify, a claim about something broader than the observable.
    WEAK = "weak"


class SupportBreadth(StrEnum):
    """How many genuinely independent origins back a proposition.

    A category rather than a count, because the count is the thing that must not
    become a vote tally. Provenance structure, deliberately coarse.
    """

    NONE = "none"
    ONE_INDEPENDENT_SOURCE = "one_independent_source"
    MULTIPLE_INDEPENDENT_SOURCES = "multiple_independent_sources"


class ContributionRole(StrEnum):
    """Why one claim mattered to one assessment.

    Named separately from Task 3's three-member ``ContributionRole`` because
    fusion needs distinctions that model does not carry -- above all the
    difference between evidence that was explained away and evidence that merely
    had a caution attached.
    """

    #: Part of the basis for the verdict.
    SUPPORTS_VERDICT = "supports_verdict"
    #: Points the other way and was not resolved.
    OPPOSES_VERDICT = "opposes_verdict"
    #: A Task 16 alternative explanation accounts for it, so the verdict did not
    #: rest on it. The claim is retained in full; it was not deleted.
    EXPLAINED_NOT_RELIED_UPON = "explained_not_relied_upon"
    #: Real, and already counted through another transport or lineage.
    DEPENDENT_CORROBORATION = "dependent_corroboration"
    #: Bore on how much the assessment can be trusted rather than on which way
    #: it went.
    LIMITS_CONFIDENCE = "limits_confidence"


class FusionIssueType(StrEnum):
    """Something about the inputs that a reader needs to know.

    Deliberately short. Every member is actionable: a missing optional field is
    not an issue, and a result full of harmless notices trains people to skip
    them.
    """

    #: A directional claim nothing could classify. Visible, never decisive.
    UNMAPPED_DIRECTIONAL_CLAIM = "unmapped_directional_claim"
    #: A Task 16 finding references evidence this run never saw, so the inputs
    #: describe different investigations and must not be fused.
    INPUT_REFERENCE_MISMATCH = "input_reference_mismatch"
    #: Directional evidence exists but no claim could be built for it.
    INCOMPLETE_DIRECTIONAL_COVERAGE = "incomplete_directional_coverage"


class FusionIssue(FrozenTiReconModel):
    """One input problem, recorded rather than swallowed."""

    issue_type: FusionIssueType
    detail: str = Field(default="", max_length=300)
    #: Claim or evidence ids the issue concerns. Never a provider payload.
    refs: tuple[str, ...] = ()


class IndependenceGroup(FrozenTiReconModel):
    """Claims that are not independent of one another.

    Grouping is by provenance Tasks 3 and 10 already recorded -- lineage first,
    then the originating source family -- because that is what determines whether
    two findings are two observations or one observation seen twice.

    Three abuse.ch datasets answering is one group. A VirusTotal ratio relayed
    through URLhaus joins the group a direct GTI result belongs to. Neither is
    discarded: both claims stay visible, and only their *corroborative* weight
    collapses.
    """

    #: Deterministic key: the family, plus the lineage where one is stated.
    group_key: str = Field(min_length=1, max_length=300)
    source_family: str = Field(min_length=1, max_length=64)
    claim_ids: tuple[str, ...] = ()
    #: Origins inside this group, sorted. Provenance, not a count to compare.
    origin_providers: tuple[str, ...] = ()
    #: Lineage groups inside this family. Narrower than the family and carried
    #: for traceability; it does not decide independence, because Task 3 defaults
    #: it to "{family}:{origin}" and keying on it would split one family into
    #: several apparent origins.
    lineage_group_ids: tuple[str, ...] = ()


class CorroborationGroup(FrozenTiReconModel):
    """One proposition, and everything that bears on it.

    ``independent_support_group_count`` is provenance structure, not a vote
    tally: it says how many separate origins reached the same conclusion, which
    is a different question from how many HTTP APIs were queried. Policy consumes
    :attr:`breadth` rather than the number wherever it can.
    """

    proposition: ClaimPropositionKey
    effect: EvidenceEffect
    claim_ids: tuple[str, ...] = ()
    independence_groups: tuple[IndependenceGroup, ...] = ()
    #: Claims nothing accounted for. The support that actually counts.
    unexplained_claim_ids: tuple[str, ...] = ()
    #: Claims a Task 16 alternative explanation specifically covers.
    explained_claim_ids: tuple[str, ...] = ()
    breadth: SupportBreadth = SupportBreadth.NONE
    #: The strongest decision role among the *unexplained* claims here.
    strongest_role: ClaimDecisionRole | None = None

    @property
    def independent_support_group_count(self) -> int:
        """Independent origins backing this proposition, after explanations."""
        return len(self.independence_groups)


class PropositionGroup(FrozenTiReconModel):
    """Every claim asserting one proposition, in either direction.

    Kept beside :class:`CorroborationGroup` because a proposition can be argued
    both ways, and the disagreement has to survive long enough for policy to see
    it rather than being resolved during grouping.
    """

    proposition: ClaimPropositionKey
    malicious_claim_ids: tuple[str, ...] = ()
    benign_claim_ids: tuple[str, ...] = ()


class FusionConflict(FrozenTiReconModel):
    """Two genuinely opposing claims about one proposition.

    A conflict needs the same subject, the same semantic dimension and the same
    scope, pointing opposite ways. A malicious URL that is currently offline is
    not a conflict; nor is a malicious address in a shared cloud range, nor a
    file that contacted a public resolver. Those are different questions, and
    Tasks 15 and 16 already said so.

    Nothing here resolves it. There is no cancellation, no balance and no winner:
    if policy has no deterministic rule that applies, the verdict says so.
    """

    proposition: ClaimPropositionKey
    malicious_claim_ids: tuple[str, ...] = ()
    benign_claim_ids: tuple[str, ...] = ()
    #: Distinct source families on each side, so a reader can see whether the
    #: disagreement is between two sources or one source with itself.
    malicious_source_families: tuple[str, ...] = ()
    benign_source_families: tuple[str, ...] = ()


class ClaimContribution(FrozenTiReconModel):
    """How one claim influenced one assessment, and why.

    Every field is a reference or a reason code. There is no strength, no factor
    and no effective value, because a contribution that carried a number would be
    a weight, and the sum of those weights would be the score this task must not
    produce.
    """

    claim_id: str = Field(min_length=1, max_length=64)
    evidence_id: str = Field(min_length=1, max_length=200)
    role: ContributionRole
    disposition: ClaimDisposition
    decision_role: ClaimDecisionRole
    semantic: ClaimSemantic
    effect: EvidenceEffect
    scope: MatchScope
    source_family: str = Field(min_length=1, max_length=64)
    #: The proposition this claim asserted, so a reader can group by argument.
    proposition_ref: str = Field(min_length=1, max_length=900)
    #: Task 16 findings that bear on this claim.
    reasoning_finding_ids: tuple[str, ...] = ()
    #: Stable reason codes. Never prose, never a provider string.
    reason_codes: tuple[str, ...] = ()


class FusionAssessment(FrozenTiReconModel):
    """The conclusion, with its working attached.

    Deliberately not Task 3's ``Assessment``: that model requires a
    ``risk_score`` this layer must not produce and a float confidence that
    invites arithmetic. It reuses Task 3's :class:`~ti_recon.enums.Verdict`
    vocabulary, which is the part that was always right.

    Verdict and confidence are independent. Neither is derived from the other,
    and a test asserts that a MALICIOUS verdict can carry MEDIUM confidence.
    """

    #: Content-derived, so the same evidence under the same policy always
    #: produces the same identity and two runs can be diffed.
    assessment_id: str = Field(min_length=1, max_length=64)
    target_key: str = Field(min_length=1, max_length=700)

    verdict: Verdict
    confidence: AssessmentConfidence

    #: The rule that produced the verdict, and the rule that produced the
    #: confidence. Two separate decisions, two separate traces.
    verdict_rule_id: str = Field(min_length=1, max_length=128)
    confidence_rule_id: str = Field(min_length=1, max_length=128)
    #: Named caps that prevented a higher confidence, in order.
    confidence_caps: tuple[str, ...] = ()

    #: The temporal reference, carried through from Task 15. Never a clock read.
    as_of: UtcDatetime

    fusion_policy_version: str = Field(min_length=1, max_length=32)
    claim_semantics_policy_version: str = Field(min_length=1, max_length=32)
    qualification_policy_version: str = Field(min_length=1, max_length=32)
    false_positive_policy_version: str = Field(min_length=1, max_length=32)
    engine_version: str = Field(min_length=1, max_length=32)

    @property
    def stix_confidence(self) -> int | None:
        """The canonical STIX integer for this band, or ``None``."""
        return STIX_CONFIDENCE[self.confidence]

    @model_validator(mode="after")
    def _validate(self) -> FusionAssessment:
        if self.verdict is not Verdict.INCONCLUSIVE and (
            self.confidence is AssessmentConfidence.UNSPECIFIED
        ):
            msg = "a directional verdict must state a confidence band"
            raise ValueError(msg)
        return self


#: Length of an assessment's content-derived identity.
ASSESSMENT_ID_LENGTH: Final[int] = 32


def assessment_id_for(
    *,
    fusion_policy_version: str,
    target_key: str,
    verdict: Verdict,
    confidence: AssessmentConfidence,
    claim_ids: tuple[str, ...],
    finding_ids: tuple[str, ...],
    as_of: str,
) -> str:
    """An assessment's stable identity, derived from what it concluded and why.

    Sorted refs, so discovery order cannot mint two identities for one
    conclusion. The policy version participates because a rule change alters what
    the verdict means, and reusing an id would make two incomparable assessments
    look like the same one revised.
    """
    material = "|".join(
        (
            fusion_policy_version,
            target_key,
            verdict.value,
            confidence.value,
            as_of,
            ",".join(sorted(claim_ids)),
            ",".join(sorted(finding_ids)),
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:ASSESSMENT_ID_LENGTH]
