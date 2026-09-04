"""Turning an investigation into the analyst contract (Task 20).

A projection, not an analysis. Every value here is copied from the layer that
decided it: the verdict and its basis from Task 17, the explanations from Task
16, the temporal qualifications from Task 15, the coverage and gaps from Task
18, the related objects from Task 14 and the workflow shape from Task 19.

Two rules govern everything below.

**Nothing is inferred.** There is no rule here that decides which claim matters,
whether two sources are independent, whether an explanation applies or whether
coverage is adequate. A presentation layer that re-derived any of those would
eventually disagree with the engine, and an analyst reading the disagreement
would have no way to tell which half was wrong.

**Nothing is dropped silently.** Every section is bounded, ordered by a stable
key, and reports how many items the investigation actually held.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence

from ti_recon.correlation.models import GraphEdge, GraphNode, RelationBasis
from ti_recon.investigation.results import InvestigationResult
from ti_recon.reasoning.claims.models import NormalizedClaim
from ti_recon.reasoning.false_positive.models import LinkRelation, ReasoningRole
from ti_recon.reasoning.fusion.models import (
    STIX_CONFIDENCE,
    ClaimContribution,
    ClaimDisposition,
    ContributionRole,
)
from ti_recon.reporting.models import (
    ANALYST_REPORT_SCHEMA_VERSION,
    MAX_BASIS_ITEMS,
    MAX_CONFLICTS,
    MAX_COVERAGE_CHECKS,
    MAX_EXPLANATIONS,
    MAX_GAPS,
    MAX_INFORMATION_NEEDS,
    MAX_ISSUES,
    MAX_LIMITATIONS,
    MAX_QUALIFICATIONS,
    MAX_RELATED_OBSERVABLES,
    MAX_SOURCE_CHECKS,
    MAX_UNEXPLAINED_EVIDENCE,
    AnalystInvestigationReport,
    AssessmentSummary,
    BasisItem,
    ConflictItem,
    CoverageCheckItem,
    ExplanationItem,
    GapItem,
    InformationNeedItem,
    InvestigationSummary,
    IssueItem,
    LimitationItem,
    QualificationItem,
    ReadinessSummary,
    RelatedObservableItem,
    ReportSection,
    ReportVersions,
    RequestSummary,
    SourceCheckItem,
    TargetSummary,
    UnexplainedEvidenceItem,
)

__all__ = ["build_analyst_report", "report_id_for"]

#: The role that describes what the verdict rested on.
#:
#: Only this one. The explained and dependent contributions are real and stay
#: in the trace, but calling them "basis" would say the verdict rested on
#: evidence Task 17 explicitly set aside — and opposition is not basis either,
#: which is why it gets its own section rather than a shared list.
_SUPPORTING_ROLE: ContributionRole = ContributionRole.SUPPORTS_VERDICT

#: The role that pushed against the verdict Task 17 nonetheless reached.
_OPPOSING_ROLE: ContributionRole = ContributionRole.OPPOSES_VERDICT


def report_id_for(*, schema_version: str, result_id: str) -> str:
    """A reproducible id for one report of one investigation.

    Derived rather than generated, so building the same report twice produces
    the same identity and a consumer can deduplicate. Run-scoped, exactly like
    the investigation id it is built from: it identifies *this run's* report,
    not the intelligence in it.
    """
    digest = hashlib.sha256(f"{schema_version}|{result_id}".encode())
    return digest.hexdigest()[:32]


def _section[Item](items: Sequence[Item], limit: int) -> ReportSection[Item]:
    """Bound a list and say what that cost."""
    shown = tuple(items[:limit])
    return ReportSection[Item](items=shown, total=len(items), omitted=max(0, len(items) - limit))


def build_analyst_report(result: InvestigationResult) -> AnalystInvestigationReport:
    """Project one investigation onto the public contract.

    Pure: no clock, no network, no filesystem and no randomness. The instant is
    Task 19's own ``evaluated_at`` and the identity is derived from the result,
    so the same investigation always yields the same report and the same bytes.
    """
    fusion = result.assessment
    assessment = fusion.assessment
    readiness = result.readiness
    claims = {claim.claim_id: claim for claim in fusion.normalized_claims}

    return AnalystInvestigationReport(
        schema_version=ANALYST_REPORT_SCHEMA_VERSION,
        report_id=report_id_for(
            schema_version=ANALYST_REPORT_SCHEMA_VERSION, result_id=result.result_id
        ),
        investigation=InvestigationSummary(
            result_id=result.result_id,
            investigation_id=result.investigation_id,
            workflow_version=result.workflow_version,
            rounds=len(result.rounds),
            stop_reason=result.stop_reason.value,
            evaluated_at=result.evaluated_at,
        ),
        target=TargetSummary(
            object_type=result.root.object_type,
            canonical_value=result.root.canonical_value,
            canonical_key=result.root.canonical_key,
        ),
        request=RequestSummary(
            depth=result.requested_depth,
            pivot_mode=result.pivot_mode,
            allow_remote_pivot_lookup=result.allow_remote_pivot_lookup,
        ),
        assessment=AssessmentSummary(
            verdict=assessment.verdict,
            confidence=assessment.confidence.value,
            confidence_stix=STIX_CONFIDENCE.get(assessment.confidence),
            verdict_rule_id=assessment.verdict_rule_id,
            confidence_rule_id=assessment.confidence_rule_id,
            confidence_caps=tuple(sorted(assessment.confidence_caps)),
            assessment_id=assessment.assessment_id,
        ),
        readiness=ReadinessSummary(
            status=readiness.readiness_status.value,
            coverage_adequacy=readiness.coverage_adequacy.value,
            continuation_state=readiness.continuation_state.value,
            requirements_total=readiness.coverage_summary.requirements_total,
            requirements_satisfied=readiness.coverage_summary.requirements_satisfied,
            requirements_limited=readiness.coverage_summary.requirements_limited,
        ),
        assessment_basis=_section(
            _contributions(fusion.contributions, claims, _SUPPORTING_ROLE), MAX_BASIS_ITEMS
        ),
        opposing_evidence=_section(
            _contributions(fusion.contributions, claims, _OPPOSING_ROLE), MAX_BASIS_ITEMS
        ),
        alternative_explanations=_section(_explanations(result), MAX_EXPLANATIONS),
        unexplained_evidence=_section(
            _unexplained(fusion.contributions, claims), MAX_UNEXPLAINED_EVIDENCE
        ),
        conflicts=_section(_conflicts(result), MAX_CONFLICTS),
        qualifications=_section(_qualifications(result), MAX_QUALIFICATIONS),
        coverage=_section(_coverage(result), MAX_COVERAGE_CHECKS),
        gaps=_section(_gaps(result), MAX_GAPS),
        information_needs=_section(_needs(result), MAX_INFORMATION_NEEDS),
        limitations=_section(_limitations(result), MAX_LIMITATIONS),
        related_observables=_section(_related(result), MAX_RELATED_OBSERVABLES),
        source_checks=_section(_source_checks(result), MAX_SOURCE_CHECKS),
        issues=_section(_issues(result), MAX_ISSUES),
        versions=ReportVersions(
            report_schema=ANALYST_REPORT_SCHEMA_VERSION,
            workflow=result.workflow_version,
            qualification=result.qualification.context_policy_version,
            false_positive=result.reasoning.policy_version,
            claim_semantics=assessment.claim_semantics_policy_version,
            fusion=assessment.fusion_policy_version,
            readiness=readiness.policy_versions.readiness_policy_version,
        ),
    )


# --------------------------------------------------------------------------- #
# Task 17
# --------------------------------------------------------------------------- #


def _contributions(
    contributions: Iterable[ClaimContribution],
    claims: dict[str, NormalizedClaim],
    role: ContributionRole,
) -> list[BasisItem]:
    """Task 17's contributions carrying one role, in a stable order.

    No ranking of our own. Not the provider with the most detections, not the
    newest evidence, not the source that appeared most often — the contributions
    Task 17 recorded, with the role it gave them. Provenance is joined from the
    claim so a reader can see *who*, which is a different question from *how
    much it counted*.
    """
    items = [item for item in contributions if item.role is role]
    return [_basis_item(item, claims.get(item.claim_id)) for item in _ordered(items)]


def _ordered(contributions: Sequence[ClaimContribution]) -> list[ClaimContribution]:
    """Decisive before weak, then semantic, then a stable id."""
    return sorted(
        contributions,
        key=lambda item: (item.decision_role.value, item.semantic.value, item.claim_id),
    )


def _basis_item(item: ClaimContribution, claim: NormalizedClaim | None) -> BasisItem:
    return BasisItem(
        role=item.role.value,
        decision_role=item.decision_role.value,
        disposition=item.disposition.value,
        semantic=item.semantic.value,
        effect=item.effect.value,
        scope=item.scope.value,
        source_family=item.source_family,
        origin_provider="" if claim is None else claim.origin_provider,
        transport_provider="" if claim is None else claim.transport_provider,
        subject_key="" if claim is None else claim.subject_key,
        claim_id=item.claim_id,
        evidence_id=item.evidence_id,
        reason_codes=tuple(sorted(item.reason_codes)),
        qualification="unqualified" if claim is None else claim.qualification.value,
        qualification_reasons=() if claim is None else claim.qualification_reasons,
        highlights=() if claim is None else claim.highlights,
    )


def _unexplained(
    contributions: Iterable[ClaimContribution], claims: dict[str, NormalizedClaim]
) -> list[UnexplainedEvidenceItem]:
    """Directional claims no alternative explanation accounted for.

    Read from Task 17's disposition, never re-derived by checking findings here.
    """
    found = [item for item in contributions if item.disposition is ClaimDisposition.UNEXPLAINED]
    return [
        UnexplainedEvidenceItem(
            claim_id=item.claim_id,
            evidence_id=item.evidence_id,
            semantic=item.semantic.value,
            effect=item.effect.value,
            scope=item.scope.value,
            source_family=item.source_family,
            subject_key=(
                "" if claims.get(item.claim_id) is None else claims[item.claim_id].subject_key
            ),
            highlights=(
                () if claims.get(item.claim_id) is None else claims[item.claim_id].highlights
            ),
        )
        for item in sorted(found, key=lambda entry: (entry.semantic.value, entry.claim_id))
    ]


def _conflicts(result: InvestigationResult) -> list[ConflictItem]:
    """Disagreements, preserved. Nothing here picks a winner."""
    return [
        ConflictItem(
            proposition_ref=item.proposition.ref,
            malicious_claim_ids=tuple(sorted(item.malicious_claim_ids)),
            benign_claim_ids=tuple(sorted(item.benign_claim_ids)),
            malicious_source_families=tuple(sorted(item.malicious_source_families)),
            benign_source_families=tuple(sorted(item.benign_source_families)),
        )
        for item in sorted(result.assessment.conflicts, key=lambda x: x.proposition.ref)
    ]


# --------------------------------------------------------------------------- #
# Task 16
# --------------------------------------------------------------------------- #


def _explanations(result: InvestigationResult) -> list[ExplanationItem]:
    """Only findings that actually explain something.

    An ``ALTERNATIVE_EXPLANATION`` role *and* an ``EXPLAINS`` link. An
    attribution caution, a temporal note, a scope limitation and a
    source-dependence finding all qualify a piece of evidence without accounting
    for it, and presenting one of them as an explanation would clear a real
    detection behind wording nobody in the engine chose.

    The linked evidence ids travel with the finding, so a reader can see the
    explanation applies to *that* evidence and not to the investigation.
    """
    found: list[ExplanationItem] = []
    for finding in result.reasoning.findings:
        if finding.role is not ReasoningRole.ALTERNATIVE_EXPLANATION:
            continue
        explains = tuple(
            sorted(link.ref for link in finding.links if link.relation is LinkRelation.EXPLAINS)
        )
        if not explains:
            continue
        found.append(
            ExplanationItem(
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                reason_code=finding.reason_code.value,
                dimension=finding.dimension.value,
                scope=finding.match_scope.value,
                explains_evidence_ids=explains,
                does_not_establish=tuple(sorted(item.value for item in finding.does_not_establish)),
            )
        )
    return sorted(found, key=lambda item: item.finding_id)


# --------------------------------------------------------------------------- #
# Task 15
# --------------------------------------------------------------------------- #


def _qualifications(result: InvestigationResult) -> list[QualificationItem]:
    """What each finding means in time, in the source's own terms.

    The provider's field name travels with the instant, because a scan time and
    an observation are different facts and collapsing them turns "we rescanned
    it yesterday" into "it attacked somebody yesterday". Ages are exact and
    unlabelled: there is no freshness verdict to render.
    """
    found = [
        QualificationItem(
            kind=item.fact.kind.value,
            subject_key=item.fact.subject.key,
            evidence_id="" if item.fact.evidence is None else item.fact.evidence.evidence_id,
            detail=item.fact.raw_field or "",
            source_family=item.fact.source_family or "",
            observed_at=item.fact.instant,
            age_days=None if item.age_days is None else int(item.age_days),
            lifecycle_state="" if item.fact.lifecycle is None else item.fact.lifecycle.value,
        )
        for item in result.qualification.temporal_qualifications
    ]
    return sorted(
        found,
        key=lambda item: (item.subject_key, item.kind, item.evidence_id, item.detail),
    )


# --------------------------------------------------------------------------- #
# Task 18
# --------------------------------------------------------------------------- #


def _coverage(result: InvestigationResult) -> list[CoverageCheckItem]:
    """One row per requirement, with completion and yield kept apart.

    ``NOT_ATTEMPTED`` and ``NO_DATA`` are different facts and neither means
    benign; ``UNATTRIBUTED`` means a bundled call answered and the record cannot
    say what it returned. Flattening any of them into another would report a
    search that did not happen, or a source holding nothing as reassurance.
    """
    found = [
        CoverageCheckItem(
            capability=item.requirement.capability.value,
            requirement_id=item.requirement.requirement_id,
            criticality=item.requirement.criticality.value,
            status=item.status.value,
            completion=item.completion.value,
            information_yield=item.information_yield.value,
            material=item.material,
            gap_type="" if item.gap_type is None else item.gap_type.value,
        )
        for item in result.readiness.requirement_evaluations
    ]
    return sorted(found, key=lambda item: (item.capability, item.requirement_id))


def _gaps(result: InvestigationResult) -> list[GapItem]:
    """Material shortfalls, most critical first."""
    found = [
        GapItem(
            gap_id=item.gap_id,
            requirement_id=item.requirement_id,
            capability="" if item.capability is None else item.capability.value,
            gap_type=item.gap_type.value,
            criticality=item.criticality.value,
            outlook=item.outlook.value,
            detail=item.detail,
        )
        for item in result.readiness.gaps
    ]
    return sorted(found, key=lambda item: (item.criticality, item.capability, item.gap_id))


def _needs(result: InvestigationResult) -> list[InformationNeedItem]:
    found = [
        InformationNeedItem(
            capability=item.capability.value,
            criticality=item.criticality.value,
            outlook=item.outlook.value,
            reason=item.reason,
        )
        for item in result.readiness.information_needs
    ]
    return sorted(found, key=lambda item: (item.capability, item.outlook))


def _limitations(result: InvestigationResult) -> list[LimitationItem]:
    found = [
        LimitationItem(
            limitation_id=item.requirement_id,
            detail=item.detail,
            capability="" if item.capability is None else item.capability.value,
        )
        for item in result.readiness.limitations
    ]
    return sorted(found, key=lambda item: (item.capability, item.limitation_id, item.detail))


# --------------------------------------------------------------------------- #
# Task 14
# --------------------------------------------------------------------------- #


def _related(result: InvestigationResult) -> list[RelatedObservableItem]:
    """Things the investigation touched, described as relationships.

    Nothing here is called an indicator. A contacted host, a resolved address
    and a dropped file are objects a source connected to the root; whether any
    of them is malicious is a separate assessment, and ``assessed`` says whether
    this run actually made one. Marking them all as IOCs would turn every
    resolver, CDN edge and shared host the sample touched into something an
    analyst might block.

    ``observation_basis`` is preserved rather than flattened: a sandbox watching
    a connection happen and a provider reporting a historical association are
    different kinds of knowledge.
    """
    correlation = result.correlation
    root_key = correlation.root_node_key
    nodes = {node.node_key: node for node in correlation.graph_nodes}
    assessed = _assessed_keys(result)

    found: list[RelatedObservableItem] = []
    for edge in correlation.graph_edges:
        for key, direction in ((edge.target_key, "outbound"), (edge.source_key, "inbound")):
            if key == root_key or root_key not in (edge.source_key, edge.target_key):
                continue
            node = nodes.get(key)
            if node is None:  # pragma: no cover - edges come from the graph
                continue
            found.append(_related_item(node, edge, direction, assessed))
    return sorted(found, key=lambda item: (item.canonical_key, item.relationship_type))


def _related_item(
    node: GraphNode, edge: GraphEdge, direction: str, assessed: frozenset[str]
) -> RelatedObservableItem:
    return RelatedObservableItem(
        object_type=node.intel_object.object_type,
        canonical_key=node.node_key,
        canonical_value=node.intel_object.canonical_value,
        relationship_type=edge.relationship_type.value,
        observation_basis=_basis_of(edge),
        direction=direction,
        source_families=tuple(
            sorted({item.source_family for item in edge.assertions if item.source_family})
        ),
        hop=node.discovered_at_hop,
        assessed=node.node_key in assessed,
    )


def _basis_of(edge: GraphEdge) -> str:
    """The strongest observation basis any source claimed for this link.

    ``PROVIDER_OBSERVED`` outranks ``PROVIDER_REPORTED`` because somebody
    watched it happen — provenance, not significance. It says nothing about
    whether either endpoint is malicious.
    """
    bases = {item.basis for item in edge.assertions}
    for candidate in (
        RelationBasis.PROVIDER_OBSERVED,
        RelationBasis.PROVIDER_REPORTED,
        RelationBasis.ENGINE_DERIVED,
    ):
        if candidate in bases:
            return candidate.value
    return ""


def _assessed_keys(result: InvestigationResult) -> frozenset[str]:
    """Objects Task 17 actually reached a verdict about.

    Only the assessment's own target, because that is the only object Task 17
    votes on. A pivot's claims exist in the trace and deliberately do not decide
    anything, so calling the pivot "assessed" here would promote exactly what
    Task 17 declines to.
    """
    return frozenset({result.assessment.assessment.target_key})


# --------------------------------------------------------------------------- #
# Task 13 and Task 19
# --------------------------------------------------------------------------- #


def _source_checks(result: InvestigationResult) -> list[SourceCheckItem]:
    """Who was asked and what happened. Provenance, never a tally."""
    found = [
        SourceCheckItem(
            provider_id=item.provider_id,
            source_family=item.source_family,
            capability=item.capability.value,
            status=item.status.value,
            error_category="" if item.error_category is None else item.error_category.value,
            called_provider=item.called_provider,
            cache_hit=item.cache_hit,
            produced_evidence=item.produced_evidence,
        )
        for item in result.enrichment.attempts
    ]
    return sorted(found, key=lambda item: (item.provider_id, item.capability))


def _issues(result: InvestigationResult) -> list[IssueItem]:
    """What each layer recorded rather than swallowed."""
    found = [
        IssueItem(layer="workflow", issue_type=item.issue_type.value, detail=item.detail)
        for item in result.issues
    ]
    found += [
        IssueItem(layer="fusion", issue_type=item.issue_type.value, detail=item.detail)
        for item in result.assessment.issues
    ]
    return sorted(found, key=lambda item: (item.layer, item.issue_type, item.detail))
