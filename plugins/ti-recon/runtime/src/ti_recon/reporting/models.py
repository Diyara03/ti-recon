"""The analyst-facing result contract (Task 20).

:class:`~ti_recon.investigation.results.InvestigationResult` is the complete
record of what the workflow did. It is the wrong thing to hand an application:
it carries planner decisions, graph internals and every engine's coverage
counters, it changes whenever any of those layers is refactored, and reading it
correctly requires knowing what all seven layers mean.

This module is the curated view instead — bounded, versioned, and stable across
internal refactors. A CLI, an MCP server and a future UI all consume *this*, so
none of them has to interpret the engine on its own and none of them can drift
from the others.

What this layer may not do
--------------------------

Nothing here reasons. The verdict is Task 17's, the readiness is Task 18's, the
explanations are Task 16's and the temporal qualifications are Task 15's; this
module selects, orders, labels and bounds them. A presentation layer that
re-derived any of those would eventually disagree with the engine, and the
disagreement would surface as a report that contradicted its own trace.

Bounded, and never silently
---------------------------

Every list is capped. An analyst who cannot see that a list was cut has been
told something false about the investigation, so each section carries the total
and the number omitted alongside the items it shows.
"""

from __future__ import annotations

from typing import Final

from pydantic import Field

from ti_recon.enums import IntelObjectType, InvestigationDepth, Verdict
from ti_recon.models.base import FrozenTiReconModel, UtcDatetime

__all__ = [
    "ANALYST_REPORT_SCHEMA_VERSION",
    "MAX_BASIS_ITEMS",
    "MAX_CONFLICTS",
    "MAX_COVERAGE_CHECKS",
    "MAX_EXPLANATIONS",
    "MAX_GAPS",
    "MAX_INFORMATION_NEEDS",
    "MAX_ISSUES",
    "MAX_LIMITATIONS",
    "MAX_QUALIFICATIONS",
    "MAX_RELATED_OBSERVABLES",
    "MAX_SOURCE_CHECKS",
    "MAX_UNEXPLAINED_EVIDENCE",
    "AnalystInvestigationReport",
    "AssessmentSummary",
    "BasisItem",
    "ConflictItem",
    "CoverageCheckItem",
    "ExplanationItem",
    "GapItem",
    "InformationNeedItem",
    "InvestigationSummary",
    "IssueItem",
    "LimitationItem",
    "QualificationItem",
    "ReadinessSummary",
    "RelatedObservableItem",
    "ReportSection",
    "ReportVersions",
    "RequestSummary",
    "SourceCheckItem",
    "TargetSummary",
    "UnexplainedEvidenceItem",
]

#: The version of this contract, and of nothing else.
#:
#: Deliberately separate from the workflow and policy versions it reports. Those
#: describe how a conclusion was reached; this describes the shape an
#: application receives it in, and the two change for entirely different
#: reasons. A fusion policy bump does not oblige every consumer to re-integrate,
#: and a field rename here does not mean the engine decided anything differently.
#:
#: Within 1.x, optional fields may be added. Removing or renaming a field,
#: changing what an existing field means, or changing the meaning of a value
#: requires a deliberate version review — consumers key on this string.
ANALYST_REPORT_SCHEMA_VERSION: Final[str] = "1.0.0"

# --------------------------------------------------------------------------- #
# Bounds
# --------------------------------------------------------------------------- #
#
# Chosen so a report stays readable and stays small enough to hand to another
# process. A graph can hold hundreds of related objects and a long investigation
# can accumulate dozens of checks; an analyst needs the shape of that, not all
# of it. Nothing is dropped without saying so.

MAX_BASIS_ITEMS: Final[int] = 20
MAX_EXPLANATIONS: Final[int] = 20
MAX_UNEXPLAINED_EVIDENCE: Final[int] = 20
MAX_CONFLICTS: Final[int] = 10
MAX_QUALIFICATIONS: Final[int] = 25
MAX_COVERAGE_CHECKS: Final[int] = 30
MAX_GAPS: Final[int] = 15
MAX_INFORMATION_NEEDS: Final[int] = 15
MAX_LIMITATIONS: Final[int] = 15
MAX_RELATED_OBSERVABLES: Final[int] = 25
MAX_SOURCE_CHECKS: Final[int] = 30
MAX_ISSUES: Final[int] = 15


class ReportSection[Item](FrozenTiReconModel):
    """A bounded list that admits what it left out.

    ``total`` is what the investigation held and ``omitted`` is what this report
    does not show. Both are present even when nothing was cut, so a consumer
    never has to infer completeness from a length.
    """

    items: tuple[Item, ...] = ()
    total: int = Field(default=0, ge=0)
    omitted: int = Field(default=0, ge=0)


class TargetSummary(FrozenTiReconModel):
    """The observable the assessment is about."""

    object_type: IntelObjectType
    #: The canonical form the engine used, unchanged.
    canonical_value: str = Field(min_length=1, max_length=700)
    #: The graph/claim key, so a consumer can join back to the trace.
    canonical_key: str = Field(min_length=1, max_length=700)


class RequestSummary(FrozenTiReconModel):
    """What the caller asked for, as ceilings the run never exceeded."""

    depth: InvestigationDepth
    pivot_mode: str = Field(min_length=1, max_length=32)
    #: Whether an enriching pivot was permitted to reach external providers.
    #:
    #: Recorded because it changes what the investigation *disclosed*, not only
    #: what it found. A reader comparing two reports needs to know whether the
    #: related observables were merely graphed or were themselves sent to third
    #: parties, and that is not inferable from ``pivot_mode`` alone.
    allow_remote_pivot_lookup: bool = False


class AssessmentSummary(FrozenTiReconModel):
    """The engine's conclusion, copied rather than recomputed.

    ``verdict`` and ``confidence`` answer different questions, and any
    combination of them is coherent. The verdict is what the evidence supports
    about the observable; the confidence is whether *that assessment* is
    correct. MALICIOUS at MEDIUM is an ordinary result, and neither field is a
    severity, a risk score or a probability of maliciousness.
    """

    verdict: Verdict = Field(
        description=(
            "What the collected intelligence supports about this observable. "
            "'malicious': the evidence supports a malicious assessment. "
            "'suspicious': there is meaningful adverse evidence that does not "
            "meet the policy for a malicious verdict. "
            "'likely_benign': a positive benign assertion, or adverse evidence "
            "fully accounted for by an alternative explanation -- never derived "
            "from an absence of detections, and never a guarantee of safety. "
            "'inconclusive': the engine cannot justify either direction from "
            "the available evidence. Inconclusive does NOT mean clean, safe, "
            "harmless or not malicious."
        )
    )
    confidence: str = Field(
        min_length=1,
        max_length=32,
        description=(
            "How strongly the available evidence supports this assessment "
            "being correct: unspecified, low, medium or high. It is NOT the "
            "probability that the observable is malicious, and not a severity "
            "or risk score. Do not render it as a percentage or as a chance of "
            "compromise."
        ),
    )
    #: The canonical STIX integer for the band, for consumers that need one.
    #: Provided because STIX defines it, not because it may be arithmetic on.
    confidence_stix: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description=(
            "The canonical STIX integer for the confidence band (15, 50 or 85), "
            "for consumers that need one. It is not a percentage likelihood of "
            "maliciousness; shown beside a verdict it invites exactly that "
            "misreading, so prefer the band."
        ),
    )
    verdict_rule_id: str = Field(
        min_length=1,
        max_length=128,
        description=(
            "Identifier of the policy rule that produced the verdict, for "
            "traceability. Internal: explain the verdict in plain language "
            "rather than by quoting this."
        ),
    )
    confidence_rule_id: str = Field(min_length=1, max_length=128)
    #: Named reasons the confidence band was held down, from Task 17.
    confidence_caps: tuple[str, ...] = Field(
        default=(),
        description=(
            "Named reasons the confidence band was held down. These are the "
            "answer to 'why is confidence low'; missing coverage is not, unless "
            "a cap says so -- coverage is reported separately under 'readiness'."
        ),
    )
    assessment_id: str = Field(min_length=1, max_length=64)


class ReadinessSummary(FrozenTiReconModel):
    """The answer to a different question from the verdict.

    Whether the *collection* was adequate for analyst triage. An assessment can
    be correct and its coverage incomplete at the same time.

    Never authorization to act. Whether to block, quarantine, allowlist, close
    an alert or declare an incident needs asset criticality, business impact
    and response policy this engine has no access to.
    """

    status: str = Field(
        min_length=1,
        max_length=40,
        description=(
            "Whether the intelligence collection behind this assessment was "
            "adequate for analyst triage. "
            "'ready': no material intelligence gap remains for triage. "
            "'ready_with_limitations': sufficient, with non-material caveats. "
            "'needs_more_data': a material gap remains and further permitted "
            "collection could still help. "
            "'unresolved': a material gap remains that the external-intelligence "
            "path cannot resolve. "
            "This describes evidence adequacy only. It is NOT permission to "
            "block, allow, remediate or close anything, and 'ready' never means "
            "safe. Present it as intelligence coverage, not readiness to act."
        ),
    )
    coverage_adequacy: str = Field(
        min_length=1,
        max_length=40,
        description=(
            "Whether the collection met the material requirements for this "
            "observable: adequate, limited or inadequate."
        ),
    )
    continuation_state: str = Field(
        min_length=1,
        max_length=40,
        description=(
            "Whether further collection could still help: complete, "
            "more_data_available, blocked or exhausted. 'exhausted' means the "
            "available sources were asked and the question remains open -- not "
            "that coverage was adequate."
        ),
    )
    requirements_total: int = Field(default=0, ge=0)
    requirements_satisfied: int = Field(default=0, ge=0)
    requirements_limited: int = Field(default=0, ge=0)


class BasisItem(FrozenTiReconModel):
    """One claim the engine weighed, with the role it gave it.

    Used for the supporting basis and for opposing evidence alike, because they
    are the same kind of record and differ only in ``role`` — which every item
    carries, so a consumer reading either section can always see the engine's
    own disposition rather than inferring it from which list it arrived in.

    Not "the most important provider" and not the strongest-looking finding:
    the contributions the assessment produced, with the role it assigned.
    Choosing here would be presentation inventing an argument the engine did
    not make.
    """

    role: str = Field(min_length=1, max_length=40)
    decision_role: str = Field(min_length=1, max_length=40)
    disposition: str = Field(min_length=1, max_length=40)
    #: The proposition, in Task 17's provider-neutral vocabulary.
    semantic: str = Field(min_length=1, max_length=64)
    effect: str = Field(min_length=1, max_length=40)
    scope: str = Field(min_length=1, max_length=40)
    #: Provenance, never a vote.
    source_family: str = Field(
        min_length=1,
        max_length=64,
        description=(
            "The originating organisation behind the claim. Provenance, never a "
            "vote: claims sharing a family are one origin and cannot corroborate "
            "each other, so never justify a verdict by counting sources."
        ),
    )
    origin_provider: str = Field(default="", max_length=64)
    transport_provider: str = Field(default="", max_length=64)
    subject_key: str = Field(default="", max_length=700)
    claim_id: str = Field(min_length=1, max_length=64)
    evidence_id: str = Field(min_length=1, max_length=200)
    reason_codes: tuple[str, ...] = ()
    #: What the provider's own versioned test said about the basis behind the
    #: claim, and its stable reason codes. Copied from Task 17A, never
    #: re-derived here.
    qualification: str = Field(
        default="unqualified",
        max_length=40,
        description=(
            "What the provider's own versioned test said about the basis behind "
            "this claim: strong_direct (enough evaluations agreeing with stated "
            "confidence and no contrary verdict), not_strong (tested and short of "
            "that; the reasons say why) or unqualified (no test applies). A "
            "statement about evidence strength from one origin, never about "
            "source independence and never a probability."
        ),
    )
    qualification_reasons: tuple[str, ...] = Field(default=(), max_length=8)
    #: What the source actually said, in its own bounded terms.
    highlights: tuple[str, ...] = Field(
        default=(),
        max_length=8,
        description=(
            "Short statements of what the source actually said about this claim -- "
            "a verdict category, a confidence, a classification label, a rule "
            "title -- chosen by the provider's own translation and bounded. "
            "Presentation of the source's words, never additional evidence, never "
            "a score, and never a reason to weigh the claim differently from "
            "its decision_role."
        ),
    )


class ExplanationItem(FrozenTiReconModel):
    """An alternative explanation, and exactly what it covers.

    Only findings that are an ``ALTERNATIVE_EXPLANATION`` *and* carry an
    ``EXPLAINS`` link reach this section. A limitation, an attribution caution or
    a temporal note qualifies a finding without explaining it, and presenting one
    as an explanation would clear evidence nobody accounted for.
    """

    finding_id: str = Field(min_length=1, max_length=64)
    rule_id: str = Field(min_length=1, max_length=128)
    reason_code: str = Field(min_length=1, max_length=64)
    dimension: str = Field(min_length=1, max_length=40)
    scope: str = Field(min_length=1, max_length=40)
    #: The evidence this explanation is linked to, and only that evidence.
    explains_evidence_ids: tuple[str, ...] = Field(
        default=(),
        description=(
            "Exactly which evidence this explanation accounts for, and nothing "
            "else. It does not explain the investigation, and one explained "
            "detection does not make the case a false positive -- check "
            "'unexplained_evidence' for what survives."
        ),
    )
    #: What the explanation explicitly does not establish.
    does_not_establish: tuple[str, ...] = Field(
        default=(),
        description=(
            "What this explanation explicitly does NOT prove. Worth quoting "
            "when a reader is inclined to over-read it."
        ),
    )


class UnexplainedEvidenceItem(FrozenTiReconModel):
    """Directional evidence no alternative explanation accounted for."""

    claim_id: str = Field(min_length=1, max_length=64)
    evidence_id: str = Field(min_length=1, max_length=200)
    semantic: str = Field(min_length=1, max_length=64)
    effect: str = Field(min_length=1, max_length=40)
    scope: str = Field(min_length=1, max_length=40)
    source_family: str = Field(min_length=1, max_length=64)
    subject_key: str = Field(default="", max_length=700)
    highlights: tuple[str, ...] = Field(
        default=(),
        max_length=8,
        description="What the source actually said, bounded. See assessment_basis.",
    )


class ConflictItem(FrozenTiReconModel):
    """Sources disagreeing about one proposition, preserved rather than resolved.

    Nothing is averaged, balanced or overruled: the disagreement is recorded and
    the confidence band is capped. A conflict is a real finding to report, not
    noise to tidy away.
    """

    proposition_ref: str = Field(min_length=1, max_length=900)
    malicious_claim_ids: tuple[str, ...] = ()
    benign_claim_ids: tuple[str, ...] = ()
    malicious_source_families: tuple[str, ...] = ()
    benign_source_families: tuple[str, ...] = ()


class QualificationItem(FrozenTiReconModel):
    """What a finding means in time and context.

    Carries the source's own lifecycle where it stated one. There is no decay
    model and no freshness label: an age is a number, and what it is worth
    depends on what kind of thing is ageing.
    """

    kind: str = Field(min_length=1, max_length=40)
    subject_key: str = Field(default="", max_length=700)
    evidence_id: str = Field(default="", max_length=200)
    #: The provider's own field name, so a reader can tell a scan time from an
    #: observation.
    detail: str = Field(default="", max_length=200)
    source_family: str = Field(default="", max_length=64)
    observed_at: UtcDatetime | None = None
    age_days: int | None = Field(default=None, ge=0)
    lifecycle_state: str = Field(default="", max_length=40)


class CoverageCheckItem(FrozenTiReconModel):
    """One capability requirement and what the collection did about it.

    ``completion`` and ``information_yield`` are separate on purpose. "Nobody
    was asked" and "somebody was asked and held nothing" are different facts,
    and neither is evidence of safety.
    """

    capability: str = Field(
        min_length=1,
        max_length=64,
        description=(
            "The kind of intelligence this requirement asked for. Capabilities, "
            "not providers: which source answers one is the engine's automatic "
            "decision."
        ),
    )
    requirement_id: str = Field(min_length=1, max_length=64)
    criticality: str = Field(min_length=1, max_length=40)
    status: str = Field(
        min_length=1,
        max_length=40,
        description=(
            "Whether the requirement was met: satisfied, limited, unsatisfied or not_applicable."
        ),
    )
    completion: str = Field(
        min_length=1,
        max_length=40,
        description=(
            "How far the check got, kept separate from what it returned: "
            "complete, partial, not_attempted, blocked or out_of_scope. "
            "'not_attempted' means nobody was asked -- which is not the same as "
            "being asked and finding nothing."
        ),
    )
    information_yield: str = Field(
        min_length=1,
        max_length=40,
        description=(
            "What the check actually returned. "
            "'directional': evidence pointing one way. "
            "'context_only': context that attaches no direction. "
            "'no_data': a source was consulted and held nothing applicable -- "
            "this is NOT evidence of safety and never means clean or benign; it "
            "is equally true of every threat nobody has caught yet. "
            "'none': nothing was returned. "
            "'unattributed': one call answered several capabilities and the "
            "record cannot say which of them returned what -- it is neither "
            "'no_data' nor an absence, and must not be reported as either."
        ),
    )
    material: bool = Field(
        default=False,
        description=(
            "Whether this requirement bears on the assessment that was actually "
            "reached. An unmet requirement that is not material does not "
            "undermine the verdict."
        ),
    )
    gap_type: str = Field(default="", max_length=40)


class GapItem(FrozenTiReconModel):
    """A material requirement the collection did not meet."""

    gap_id: str = Field(min_length=1, max_length=64)
    requirement_id: str = Field(min_length=1, max_length=64)
    capability: str = Field(default="", max_length=64)
    gap_type: str = Field(min_length=1, max_length=40)
    criticality: str = Field(min_length=1, max_length=40)
    outlook: str = Field(min_length=1, max_length=40)
    detail: str = Field(default="", max_length=200)


class InformationNeedItem(FrozenTiReconModel):
    """A capability that would help, stated without choosing a provider."""

    capability: str = Field(min_length=1, max_length=64)
    criticality: str = Field(min_length=1, max_length=40)
    outlook: str = Field(min_length=1, max_length=40)
    reason: str = Field(default="", max_length=64)


class LimitationItem(FrozenTiReconModel):
    """Something that bounds how far the assessment should be read."""

    limitation_id: str = Field(default="", max_length=64)
    detail: str = Field(default="", max_length=200)
    capability: str = Field(default="", max_length=64)


class RelatedObservableItem(FrozenTiReconModel):
    """Something the investigation touched — not, by itself, an indicator.

    A contacted host, a resolved address and a dropped file are relationships.
    None of them is malicious because it appeared here: an object carries a
    verdict only when this investigation separately assessed *it*, which for
    anything but the root is a question this run may not have asked.
    """

    object_type: IntelObjectType
    canonical_key: str = Field(min_length=1, max_length=700)
    canonical_value: str = Field(min_length=1, max_length=700)
    relationship_type: str = Field(
        default="",
        max_length=64,
        description=(
            "How this object was connected to the target -- a contact, a "
            "resolution, a dropped file. A relationship is not an accusation."
        ),
    )
    #: ``provider_observed`` means a source watched it happen;
    #: ``provider_reported`` means a source said so. Different epistemic
    #: standing, kept apart.
    observation_basis: str = Field(
        default="",
        max_length=40,
        description=(
            "How the relationship was learned. 'provider_observed': a source "
            "watched it happen. 'provider_reported': a source said so. This is "
            "provenance and says nothing about maliciousness in either "
            "direction."
        ),
    )
    direction: str = Field(default="", max_length=16)
    source_families: tuple[str, ...] = ()
    hop: int = Field(default=0, ge=0)
    #: Whether Task 17 separately assessed this object in this run.
    assessed: bool = Field(
        default=False,
        description=(
            "Whether this run separately reached a verdict about THIS object. "
            "When false no verdict about it is implied: it is a relationship "
            "and a possible pivot lead, not an indicator, and it must not be "
            "described as malicious or listed as a confirmed IOC. Investigating "
            "it directly is a separate request."
        ),
    )


class SourceCheckItem(FrozenTiReconModel):
    """One provider execution, as provenance.

    Provider identity belongs here because it says where information came from.
    It is never a tally: this section has no score, no ratio and no count of who
    agreed with whom.

    **This section is the authority for what was actually consulted.** A source
    being shipped by this installation, or being configured for this caller, is
    not the same as its having been asked: only an entry here says a check ran.
    Anything without an entry was not queried in this investigation.
    """

    provider_id: str = Field(
        min_length=1,
        max_length=64,
        description=(
            "Which source ran this check. Provenance, never a vote: the engine "
            "does not count how many sources agreed."
        ),
    )
    source_family: str = Field(
        min_length=1,
        max_length=64,
        description=(
            "The originating organisation behind this source. Datasets run by "
            "one organisation share a family and cannot corroborate each other, "
            "however many product names they carry."
        ),
    )
    capability: str = Field(min_length=1, max_length=64)
    status: str = Field(
        min_length=1,
        max_length=40,
        description=(
            "What happened to this check. "
            "'success': it ran and returned a usable result. "
            "'no_data': it ran and held nothing applicable -- never clean, safe "
            "or benign. "
            "'not_configured': it was NOT checked, because no usable credential "
            "is available for this caller. It does not mean the source was "
            "contacted, is offline or unreachable, rejected a key, or found "
            "nothing. "
            "'not_supported': the source does not answer this kind of "
            "observable. "
            "'plan_limited', 'quota_exceeded', 'temporarily_unavailable', "
            "'error': the check did not complete. "
            "'partial': something was learned, short of the whole check."
        ),
    )
    error_category: str = Field(default="", max_length=40)
    called_provider: bool = Field(
        default=False,
        description="Whether the source was physically contacted during this run.",
    )
    cache_hit: bool = Field(
        default=False,
        description=(
            "The result was reused from this caller's own cache. The source was "
            "not contacted again for this check, so do not describe it as "
            "freshly queried."
        ),
    )
    produced_evidence: bool = Field(
        default=False,
        description="Whether this check contributed any evidence to the investigation.",
    )


class IssueItem(FrozenTiReconModel):
    """Something a layer recorded rather than swallowed."""

    layer: str = Field(min_length=1, max_length=32)
    issue_type: str = Field(min_length=1, max_length=64)
    detail: str = Field(default="", max_length=300)


class InvestigationSummary(FrozenTiReconModel):
    """What the workflow did, at the altitude an analyst reads."""

    result_id: str = Field(min_length=1, max_length=64)
    investigation_id: str = Field(min_length=1, max_length=128)
    workflow_version: str = Field(min_length=1, max_length=32)
    rounds: int = Field(default=0, ge=0)
    stop_reason: str = Field(min_length=1, max_length=64)
    evaluated_at: UtcDatetime


class ReportVersions(FrozenTiReconModel):
    """Every policy that shaped this result, so it stays explainable later."""

    report_schema: str = Field(min_length=1, max_length=32)
    workflow: str = Field(min_length=1, max_length=32)
    qualification: str = Field(min_length=1, max_length=32)
    false_positive: str = Field(min_length=1, max_length=32)
    claim_semantics: str = Field(min_length=1, max_length=32)
    fusion: str = Field(min_length=1, max_length=32)
    readiness: str = Field(min_length=1, max_length=32)


class AnalystInvestigationReport(FrozenTiReconModel):
    """One investigation, as an application receives it.

    Derived deterministically from an ``InvestigationResult``: the same result
    always produces the same report, and the same report always produces the
    same bytes.
    """

    schema_version: str = Field(min_length=1, max_length=32)
    #: Derived from the schema version and the investigation's own id, so it is
    #: reproducible. Task 19's identity is run-scoped, and so is this: it is not
    #: a cross-run fingerprint of the intelligence.
    report_id: str = Field(min_length=8, max_length=64)

    investigation: InvestigationSummary
    target: TargetSummary
    request: RequestSummary
    assessment: AssessmentSummary
    readiness: ReadinessSummary

    assessment_basis: ReportSection[BasisItem] = Field(
        default=ReportSection[BasisItem](),
        description=(
            "The claims the verdict rested on: this is why the assessment was "
            "reached, and the only section that answers that question."
        ),
    )
    #: Claims Task 17 recorded as pushing *against* the verdict it reached.
    #:
    #: Separate from the basis on purpose. Both are contributions and both
    #: carry their Task 17 role, but presenting them in one list under a
    #: heading meaning "why" would put a benign assertion among the reasons an
    #: object was called malicious — which is the opposite of what the engine
    #: said about it.
    opposing_evidence: ReportSection[BasisItem] = Field(
        default=ReportSection[BasisItem](),
        description=(
            "Claims that argued against the verdict and did not prevail. Real, "
            "and kept apart from the basis on purpose: under one heading "
            "meaning 'why', a benign assertion would read as a reason the "
            "object was called malicious. Present the two separately."
        ),
    )
    alternative_explanations: ReportSection[ExplanationItem] = ReportSection[ExplanationItem]()
    unexplained_evidence: ReportSection[UnexplainedEvidenceItem] = ReportSection[
        UnexplainedEvidenceItem
    ]()
    conflicts: ReportSection[ConflictItem] = ReportSection[ConflictItem]()
    qualifications: ReportSection[QualificationItem] = ReportSection[QualificationItem]()
    coverage: ReportSection[CoverageCheckItem] = ReportSection[CoverageCheckItem]()
    gaps: ReportSection[GapItem] = ReportSection[GapItem]()
    information_needs: ReportSection[InformationNeedItem] = ReportSection[InformationNeedItem]()
    limitations: ReportSection[LimitationItem] = ReportSection[LimitationItem]()
    related_observables: ReportSection[RelatedObservableItem] = ReportSection[
        RelatedObservableItem
    ]()
    source_checks: ReportSection[SourceCheckItem] = ReportSection[SourceCheckItem]()
    issues: ReportSection[IssueItem] = ReportSection[IssueItem]()

    versions: ReportVersions
