"""A model-only investigation graph.

Builds the full Task 3 object graph for a domain investigation with no network
access, no provider integration and no engine: it exercises the model
relationships and their invariants end to end.

The scenario deliberately includes the hard cases:

* one piece of evidence relayed by a second provider (transport != origin), so
  lineage handling is exercised;
* a directional conflict between a curated threat assertion and a
  false-positive context claim;
* a capability that no configured provider could serve, so coverage reports a
  genuine gap.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict

from ti_recon.enums import (
    ActivityMode,
    AssessmentState,
    ConflictSeverity,
    ConflictStatus,
    ConflictType,
    ContributionRole,
    CoverageRelevance,
    CoverageStatus,
    EvidenceClass,
    EvidenceEffect,
    InformationCredibilityGrade,
    IntelObjectType,
    InvestigationDepth,
    InvestigationStatus,
    MatchScope,
    ObjectClass,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
    RelationshipType,
    SourceReliabilityGrade,
    Verdict,
)
from ti_recon.models import (
    Assessment,
    AssessmentContribution,
    CoverageItem,
    Evidence,
    EvidenceConflict,
    IntelObject,
    Investigation,
    ProviderRun,
    RawEvidenceReference,
    Relationship,
)
from ti_recon.normalization import normalize_observable
from ti_recon.versions import ENGINE_VERSION, POLICY_VERSION

T0 = datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC)


class InvestigationGraph(BaseModel):
    """Every model instance produced by :func:`build_investigation_graph`."""

    model_config = ConfigDict(frozen=True)

    investigation: Investigation
    domain_object: IntelObject
    ip_object: IntelObject
    provider_runs: tuple[ProviderRun, ...]
    raw_references: tuple[RawEvidenceReference, ...]
    evidence: tuple[Evidence, ...]
    relationships: tuple[Relationship, ...]
    conflicts: tuple[EvidenceConflict, ...]
    coverage: tuple[CoverageItem, ...]
    assessment: Assessment
    contributions: tuple[AssessmentContribution, ...]


def build_investigation_graph() -> InvestigationGraph:
    """Build a complete, valid investigation graph from models alone."""
    submitted = "evil[.]example"
    normalized = normalize_observable(submitted)
    domain_object = normalized.intel_object

    ip_object = IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.IPV4_ADDR,
        canonical_value="198.51.100.7",
        display_value="198.51.100.7",
    )

    investigation = Investigation(
        primary_object_id=domain_object.id,
        original_input=submitted,
        depth=InvestigationDepth.STANDARD,
        activity_mode=ActivityMode.PASSIVE,
        status=InvestigationStatus.PARTIAL,
        requested_capabilities=[
            ProviderCapability.REPUTATION,
            ProviderCapability.MALWARE_INTELLIGENCE,
            ProviderCapability.CURRENT_INFRASTRUCTURE,
            ProviderCapability.FALSE_POSITIVE_CONTEXT,
            ProviderCapability.HISTORICAL_INFRASTRUCTURE,
        ],
        started_at=T0,
        completed_at=T0 + timedelta(seconds=9),
        engine_version=ENGINE_VERSION,
        policy_version=POLICY_VERSION,
    )

    raw_reputation = RawEvidenceReference(
        investigation_id=investigation.id,
        provider="fake_aggregator",
        operation=ProviderOperation.LOOKUP,
        storage_key="raw/fake_aggregator/lookup/1",
        content_sha256="a" * 64,
        size_bytes=2048,
        retrieved_at=T0 + timedelta(seconds=1),
    )
    raw_threatfeed = RawEvidenceReference(
        investigation_id=investigation.id,
        provider="fake_threatfeed",
        operation=ProviderOperation.LOOKUP,
        storage_key="raw/fake_threatfeed/lookup/1",
        retrieved_at=T0 + timedelta(seconds=2),
    )
    raw_scanview = RawEvidenceReference(
        investigation_id=investigation.id,
        provider="fake_scanview",
        operation=ProviderOperation.LOOKUP,
        storage_key="raw/fake_scanview/lookup/1",
        retrieved_at=T0 + timedelta(seconds=3),
    )

    run_reputation = ProviderRun(
        investigation_id=investigation.id,
        provider="fake_aggregator",
        capability=ProviderCapability.REPUTATION,
        operation=ProviderOperation.LOOKUP,
        status=ProviderRunStatus.SUCCESS,
        started_at=T0,
        completed_at=T0 + timedelta(seconds=1),
        api_version="v3",
        adapter_version="0.1.0",
        raw_reference_id=raw_reputation.id,
    )
    run_threatfeed = ProviderRun(
        investigation_id=investigation.id,
        provider="fake_threatfeed",
        capability=ProviderCapability.MALWARE_INTELLIGENCE,
        operation=ProviderOperation.LOOKUP,
        status=ProviderRunStatus.SUCCESS,
        started_at=T0 + timedelta(seconds=1),
        completed_at=T0 + timedelta(seconds=2),
        api_version="v1",
        adapter_version="0.1.0",
        raw_reference_id=raw_threatfeed.id,
    )
    run_scanview = ProviderRun(
        investigation_id=investigation.id,
        provider="fake_scanview",
        capability=ProviderCapability.CURRENT_INFRASTRUCTURE,
        operation=ProviderOperation.LOOKUP,
        status=ProviderRunStatus.SUCCESS,
        started_at=T0 + timedelta(seconds=2),
        completed_at=T0 + timedelta(seconds=3),
        api_version="v2",
        adapter_version="0.1.0",
        raw_reference_id=raw_scanview.id,
    )
    run_history = ProviderRun(
        investigation_id=investigation.id,
        provider="fake_history",
        capability=ProviderCapability.HISTORICAL_INFRASTRUCTURE,
        operation=ProviderOperation.LOOKUP,
        status=ProviderRunStatus.NOT_CONFIGURED,
        started_at=T0 + timedelta(seconds=3),
        completed_at=T0 + timedelta(seconds=3),
        adapter_version="0.1.0",
    )
    run_failed = ProviderRun(
        investigation_id=investigation.id,
        provider="fake_aggregator",
        capability=ProviderCapability.RELATIONSHIPS,
        operation=ProviderOperation.PIVOT,
        status=ProviderRunStatus.ERROR,
        started_at=T0 + timedelta(seconds=4),
        completed_at=T0 + timedelta(seconds=5),
        api_version="v3",
        adapter_version="0.1.0",
        error_code=ProviderErrorCategory.RATE_LIMITED,
    )

    reputation_evidence = Evidence(
        investigation_id=investigation.id,
        subject_object_id=domain_object.id,
        evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
        claim_type="multi-vendor.detection-count",
        effect=EvidenceEffect.SUPPORTS_MALICIOUS,
        transport_provider="fake_aggregator",
        origin_provider="fake_aggregator",
        source_family="aggregator",
        provider_confidence=60.0,
        source_reliability=SourceReliabilityGrade.B,
        information_credibility=InformationCredibilityGrade.POSSIBLY_TRUE,
        match_scope=MatchScope.EXACT_OBSERVABLE,
        first_seen=T0 - timedelta(days=30),
        last_seen=T0 - timedelta(days=1),
        retrieved_at=T0 + timedelta(seconds=1),
        attributes={"malicious_vendors": 7, "total_vendors": 89},
        raw_reference_id=raw_reputation.id,
    )
    malware_evidence = Evidence(
        investigation_id=investigation.id,
        subject_object_id=domain_object.id,
        evidence_class=EvidenceClass.CURATED_THREAT_ASSERTION,
        claim_type="malware.c2-association",
        effect=EvidenceEffect.SUPPORTS_MALICIOUS,
        transport_provider="fake_threatfeed",
        origin_provider="fake_threatfeed",
        source_family="curated_feed",
        provider_confidence=95.0,
        source_reliability=SourceReliabilityGrade.A,
        information_credibility=InformationCredibilityGrade.CONFIRMED,
        match_scope=MatchScope.EXACT_OBSERVABLE,
        first_seen=T0 - timedelta(days=5),
        last_seen=T0 - timedelta(hours=6),
        retrieved_at=T0 + timedelta(seconds=2),
        attributes={"malware_family": "ExampleRAT"},
        raw_reference_id=raw_threatfeed.id,
    )
    resolution_evidence = Evidence(
        investigation_id=investigation.id,
        subject_object_id=domain_object.id,
        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
        claim_type="dns.a-record",
        effect=EvidenceEffect.CONTEXT_ONLY,
        transport_provider="fake_scanview",
        origin_provider="fake_scanview",
        source_family="scanner",
        match_scope=MatchScope.EXACT_OBSERVABLE,
        observed_at=T0 - timedelta(minutes=30),
        retrieved_at=T0 + timedelta(seconds=3),
        attributes={"resolved_ip": "198.51.100.7"},
        raw_reference_id=raw_scanview.id,
    )
    # Relayed: reached us via fake_scanview but produced by fake_noise. Without
    # the origin_provider distinction this would look like independent
    # confirmation of the same benign-scanner claim.
    relayed_benign_evidence = Evidence(
        investigation_id=investigation.id,
        subject_object_id=ip_object.id,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="scanner.benign-classification",
        effect=EvidenceEffect.CONTEXT_ONLY,
        transport_provider="fake_scanview",
        origin_provider="fake_noise",
        source_family="scanner_noise",
        provider_confidence=80.0,
        source_reliability=SourceReliabilityGrade.B,
        information_credibility=InformationCredibilityGrade.PROBABLY_TRUE,
        match_scope=MatchScope.SAME_IP,
        observed_at=T0 - timedelta(hours=2),
        retrieved_at=T0 + timedelta(seconds=3),
        attributes={"classification": "benign", "actor": "example-research"},
        raw_reference_id=raw_scanview.id,
    )
    false_positive_evidence = Evidence(
        investigation_id=investigation.id,
        subject_object_id=domain_object.id,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="warninglist.known-good-infrastructure",
        effect=EvidenceEffect.CONTEXT_ONLY,
        transport_provider="fake_warninglist",
        origin_provider="fake_warninglist",
        source_family="warning_list",
        match_scope=MatchScope.PARENT_DOMAIN,
        retrieved_at=T0 + timedelta(seconds=4),
        attributes={"list": "example-cdn-ranges"},
    )

    resolves_to = Relationship(
        source_object_id=domain_object.id,
        relationship_type=RelationshipType.RESOLVES_TO,
        target_object_id=ip_object.id,
        first_seen=T0 - timedelta(days=2),
        last_seen=T0 - timedelta(minutes=30),
        confidence=90.0,
        evidence_refs=(resolution_evidence.id,),
    )

    conflict = EvidenceConflict(
        investigation_id=investigation.id,
        evidence_a_id=malware_evidence.id,
        evidence_b_id=false_positive_evidence.id,
        conflict_type=ConflictType.DIRECTIONAL,
        severity=ConflictSeverity.MEDIUM,
        status=ConflictStatus.UNRESOLVED,
        detected_at=T0 + timedelta(seconds=6),
    )

    coverage = (
        CoverageItem(
            capability=ProviderCapability.REPUTATION,
            relevance=CoverageRelevance.RELEVANT,
            status=CoverageStatus.COVERED,
            providers_considered=("fake_aggregator",),
        ),
        CoverageItem(
            capability=ProviderCapability.MALWARE_INTELLIGENCE,
            relevance=CoverageRelevance.REQUIRED,
            status=CoverageStatus.COVERED,
            providers_considered=("fake_threatfeed",),
        ),
        CoverageItem(
            capability=ProviderCapability.CURRENT_INFRASTRUCTURE,
            relevance=CoverageRelevance.RELEVANT,
            status=CoverageStatus.COVERED,
            providers_considered=("fake_scanview",),
        ),
        CoverageItem(
            capability=ProviderCapability.FALSE_POSITIVE_CONTEXT,
            relevance=CoverageRelevance.RELEVANT,
            status=CoverageStatus.COVERED,
            providers_considered=("fake_warninglist",),
        ),
        CoverageItem(
            capability=ProviderCapability.HISTORICAL_INFRASTRUCTURE,
            relevance=CoverageRelevance.RELEVANT,
            status=CoverageStatus.NOT_COVERED,
            providers_considered=("fake_history",),
            reason="no credential configured for fake_history",
        ),
    )

    assessment = Assessment(
        investigation_id=investigation.id,
        verdict=Verdict.MALICIOUS,
        risk_score=78.0,
        confidence=64.0,
        assessment_state=AssessmentState.CONFLICTED,
        supporting_evidence_refs=(malware_evidence.id, reputation_evidence.id),
        benign_evidence_refs=(),
        context_evidence_refs=(
            resolution_evidence.id,
            relayed_benign_evidence.id,
            false_positive_evidence.id,
        ),
        conflict_refs=(conflict.id,),
        coverage=coverage,
        policy_version=POLICY_VERSION,
        engine_version=ENGINE_VERSION,
        assessed_at=T0 + timedelta(seconds=9),
    )

    contributions = (
        AssessmentContribution(
            assessment_id=assessment.id,
            evidence_id=malware_evidence.id,
            role=ContributionRole.SUPPORTING,
            base_strength=90.0,
            freshness_factor=0.95,
            independence_factor=1.0,
            specificity_factor=1.0,
            false_positive_factor=0.9,
            effective_contribution=76.95,
            reason_codes=("exact_artifact_match", "curated_source"),
        ),
        AssessmentContribution(
            assessment_id=assessment.id,
            evidence_id=reputation_evidence.id,
            role=ContributionRole.SUPPORTING,
            base_strength=40.0,
            freshness_factor=0.8,
            independence_factor=0.5,
            specificity_factor=1.0,
            false_positive_factor=1.0,
            effective_contribution=16.0,
            reason_codes=("aggregated_not_independent",),
        ),
        AssessmentContribution(
            assessment_id=assessment.id,
            evidence_id=relayed_benign_evidence.id,
            role=ContributionRole.CONTEXT,
            base_strength=0.0,
            effective_contribution=0.0,
            reason_codes=("relayed_via_transport_provider",),
        ),
    )

    return InvestigationGraph(
        investigation=investigation,
        domain_object=domain_object,
        ip_object=ip_object,
        provider_runs=(
            run_reputation,
            run_threatfeed,
            run_scanview,
            run_history,
            run_failed,
        ),
        raw_references=(raw_reputation, raw_threatfeed, raw_scanview),
        evidence=(
            reputation_evidence,
            malware_evidence,
            resolution_evidence,
            relayed_benign_evidence,
            false_positive_evidence,
        ),
        relationships=(resolves_to,),
        conflicts=(conflict,),
        coverage=coverage,
        assessment=assessment,
        contributions=contributions,
    )
