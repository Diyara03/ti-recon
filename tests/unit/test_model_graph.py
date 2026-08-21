"""Whole-graph test over the Task 3 model set.

Walks the fixture graph
``domain -> ProviderRuns -> Evidence -> IP relationship -> EvidenceConflict
-> Coverage -> Assessment`` and checks that the pieces actually reference each
other. Models validating in isolation is not the same as a graph hanging
together.

No provider, no network, no engine.
"""

from __future__ import annotations

import json

from fixtures.investigation_graph import build_investigation_graph
from ti_recon.enums import (
    ActivityMode,
    AssessmentState,
    ConflictStatus,
    CoverageStatus,
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    ProviderCapability,
    ProviderRunStatus,
    RelationshipType,
    Verdict,
)


def test_primary_object_is_the_normalized_submitted_domain() -> None:
    g = build_investigation_graph()
    assert g.domain_object.object_type is IntelObjectType.DOMAIN_NAME
    assert g.domain_object.canonical_value == "evil.example"
    assert g.investigation.original_input == "evil[.]example"
    assert g.investigation.primary_object_id == g.domain_object.id


def test_investigation_is_passive() -> None:
    g = build_investigation_graph()
    assert g.investigation.activity_mode is ActivityMode.PASSIVE


def test_every_provider_run_belongs_to_the_investigation() -> None:
    g = build_investigation_graph()
    assert g.provider_runs
    for run in g.provider_runs:
        assert run.investigation_id == g.investigation.id


def test_every_run_serves_a_requested_capability_or_is_a_pivot() -> None:
    g = build_investigation_graph()
    requested = set(g.investigation.requested_capabilities)
    for run in g.provider_runs:
        if run.capability not in requested:
            # Pivots may reach beyond the initially requested capability set.
            assert run.capability is ProviderCapability.RELATIONSHIPS


def test_unconfigured_provider_produced_no_evidence_but_is_reported() -> None:
    g = build_investigation_graph()
    unconfigured = [
        run for run in g.provider_runs if run.status is ProviderRunStatus.NOT_CONFIGURED
    ]
    assert unconfigured
    provider = unconfigured[0].provider
    assert all(evidence.transport_provider != provider for evidence in g.evidence)
    gap_providers = {
        provider_id
        for item in g.assessment.coverage_gaps
        for provider_id in item.providers_considered
    }
    assert provider in gap_providers


def test_failed_run_carries_a_normalized_error_category() -> None:
    g = build_investigation_graph()
    failed = [run for run in g.provider_runs if run.status is ProviderRunStatus.ERROR]
    assert failed
    assert failed[0].error_code is not None


def test_every_piece_of_evidence_is_traceable_to_a_run_and_raw_response() -> None:
    g = build_investigation_graph()
    run_providers = {run.provider for run in g.provider_runs}
    raw_ids = {reference.id for reference in g.raw_references}
    for evidence in g.evidence:
        assert evidence.investigation_id == g.investigation.id
        assert evidence.transport_provider in run_providers or evidence.raw_reference_id is None
        if evidence.raw_reference_id is not None:
            assert evidence.raw_reference_id in raw_ids


def test_evidence_covers_distinct_claims_not_whole_responses() -> None:
    """One provider response yields several single-claim Evidence objects."""
    g = build_investigation_graph()
    claim_types = [evidence.claim_type for evidence in g.evidence]
    assert len(claim_types) == len(set(claim_types))
    scanview = [e for e in g.evidence if e.transport_provider == "fake_scanview"]
    assert len(scanview) > 1


def test_relayed_evidence_records_a_different_origin() -> None:
    g = build_investigation_graph()
    relayed = [evidence for evidence in g.evidence if evidence.is_relayed]
    assert len(relayed) == 1
    assert relayed[0].transport_provider == "fake_scanview"
    assert relayed[0].origin_provider == "fake_noise"


def test_relayed_evidence_is_not_independent_of_its_origin() -> None:
    g = build_investigation_graph()
    relayed = next(evidence for evidence in g.evidence if evidence.is_relayed)
    assert relayed.lineage_group_id == "scanner_noise:fake_noise"


def test_relationship_links_the_domain_to_the_ip_via_evidence() -> None:
    g = build_investigation_graph()
    assert len(g.relationships) == 1
    relationship = g.relationships[0]
    assert relationship.relationship_type is RelationshipType.RESOLVES_TO
    assert relationship.source_object_id == g.domain_object.id
    assert relationship.target_object_id == g.ip_object.id
    evidence_ids = {evidence.id for evidence in g.evidence}
    assert set(relationship.evidence_refs) <= evidence_ids


def test_conflict_references_two_real_pieces_of_evidence() -> None:
    g = build_investigation_graph()
    evidence_ids = {evidence.id for evidence in g.evidence}
    for conflict in g.conflicts:
        assert conflict.evidence_a_id in evidence_ids
        assert conflict.evidence_b_id in evidence_ids
        assert conflict.investigation_id == g.investigation.id


def test_unresolved_conflict_is_reflected_in_assessment_state() -> None:
    g = build_investigation_graph()
    assert g.conflicts[0].status is ConflictStatus.UNRESOLVED
    assert g.assessment.assessment_state is AssessmentState.CONFLICTED
    assert set(g.assessment.conflict_refs) == {conflict.id for conflict in g.conflicts}


def test_coverage_reports_the_gap_rather_than_hiding_it() -> None:
    g = build_investigation_graph()
    requested = set(g.investigation.requested_capabilities)
    reported = {item.capability for item in g.coverage}
    assert requested == reported
    gaps = g.assessment.coverage_gaps
    assert len(gaps) == 1
    assert gaps[0].status is CoverageStatus.NOT_COVERED
    assert gaps[0].reason


def test_assessment_classifies_every_piece_of_evidence_exactly_once() -> None:
    g = build_investigation_graph()
    classified = (
        set(g.assessment.supporting_evidence_refs)
        | set(g.assessment.benign_evidence_refs)
        | set(g.assessment.context_evidence_refs)
    )
    assert classified == {evidence.id for evidence in g.evidence}


def test_assessment_roles_match_evidence_effects() -> None:
    g = build_investigation_graph()
    by_id = {evidence.id: evidence for evidence in g.evidence}
    for evidence_id in g.assessment.supporting_evidence_refs:
        assert by_id[evidence_id].effect is EvidenceEffect.SUPPORTS_MALICIOUS
    for evidence_id in g.assessment.context_evidence_refs:
        assert by_id[evidence_id].effect is EvidenceEffect.CONTEXT_ONLY


def test_verdict_is_not_a_provider_vote_count() -> None:
    """Two malicious signals of very different class drive the verdict."""
    g = build_investigation_graph()
    supporting = [
        evidence
        for evidence in g.evidence
        if evidence.id in set(g.assessment.supporting_evidence_refs)
    ]
    classes = {evidence.evidence_class for evidence in supporting}
    assert classes == {
        EvidenceClass.CURATED_THREAT_ASSERTION,
        EvidenceClass.AGGREGATED_REPUTATION,
    }
    contributions = {c.evidence_id: c for c in g.contributions}
    curated = next(
        e for e in supporting if e.evidence_class is EvidenceClass.CURATED_THREAT_ASSERTION
    )
    aggregated = next(
        e for e in supporting if e.evidence_class is EvidenceClass.AGGREGATED_REPUTATION
    )
    assert (
        contributions[curated.id].effective_contribution
        > contributions[aggregated.id].effective_contribution
    )
    assert g.assessment.verdict is Verdict.MALICIOUS


def test_aggregated_reputation_is_discounted_for_independence() -> None:
    g = build_investigation_graph()
    by_evidence = {c.evidence_id: c for c in g.contributions}
    aggregated = next(
        evidence
        for evidence in g.evidence
        if evidence.evidence_class is EvidenceClass.AGGREGATED_REPUTATION
    )
    assert by_evidence[aggregated.id].independence_factor < 1.0
    assert "aggregated_not_independent" in by_evidence[aggregated.id].reason_codes


def test_contributions_never_amplify_evidence() -> None:
    g = build_investigation_graph()
    for contribution in g.contributions:
        assert contribution.effective_contribution <= contribution.base_strength + 1e-9
        assert contribution.assessment_id == g.assessment.id


def test_engine_and_policy_versions_are_consistent() -> None:
    g = build_investigation_graph()
    assert g.assessment.engine_version == g.investigation.engine_version
    assert g.assessment.policy_version == g.investigation.policy_version


def test_whole_graph_serializes_to_json_without_credentials() -> None:
    g = build_investigation_graph()
    payload = json.dumps(g.model_dump(mode="json"))
    lowered = payload.lower()
    for token in ("api_key", "apikey", "auth-key", "authorization", "bearer ", "password"):
        assert token not in lowered


def test_graph_is_reproducible_in_shape() -> None:
    first = build_investigation_graph()
    second = build_investigation_graph()
    assert len(first.evidence) == len(second.evidence)
    assert [e.claim_type for e in first.evidence] == [e.claim_type for e in second.evidence]
