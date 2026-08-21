"""Evidence, relationship, conflict and coverage invariants (Task 3)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from ti_recon.enums import (
    ConflictSeverity,
    ConflictStatus,
    ConflictType,
    CoverageRelevance,
    CoverageStatus,
    EvidenceClass,
    EvidenceEffect,
    InformationCredibilityGrade,
    MatchScope,
    ProviderCapability,
    ProviderOperation,
    RelationshipType,
    SourceReliabilityGrade,
)
from ti_recon.models import (
    CoverageItem,
    Evidence,
    EvidenceConflict,
    RawEvidenceReference,
    Relationship,
)

T0 = datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC)


def make_evidence(**overrides: Any) -> Evidence:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "subject_object_id": "obj-1",
        "evidence_class": EvidenceClass.CURATED_THREAT_ASSERTION,
        "claim_type": "malware.c2-association",
        "effect": EvidenceEffect.SUPPORTS_MALICIOUS,
        "transport_provider": "fake_threatfeed",
        "origin_provider": "fake_threatfeed",
        "source_family": "curated_feed",
    }
    kwargs.update(overrides)
    return Evidence(**kwargs)


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #


def test_evidence_is_immutable() -> None:
    evidence = make_evidence()
    with pytest.raises(ValidationError, match="frozen"):
        evidence.effect = EvidenceEffect.SUPPORTS_BENIGN


def test_confidence_signals_stay_separate() -> None:
    evidence = make_evidence(
        provider_confidence=95.0,
        source_reliability=SourceReliabilityGrade.A,
        information_credibility=InformationCredibilityGrade.CONFIRMED,
    )
    assert evidence.provider_confidence == 95.0
    assert evidence.source_reliability is SourceReliabilityGrade.A
    assert evidence.information_credibility is InformationCredibilityGrade.CONFIRMED
    # There is deliberately no merged/overall confidence on evidence.
    assert "confidence" not in set(Evidence.model_fields) - {"provider_confidence"}


def test_evidence_has_no_verdict_or_risk_field() -> None:
    """Evidence records facts; verdicts live in Assessment."""
    fields = set(Evidence.model_fields)
    assert fields.isdisjoint({"verdict", "risk_score", "score", "assessment"})


@pytest.mark.parametrize("value", [-0.1, 100.1])
def test_provider_confidence_range_is_enforced(value: float) -> None:
    with pytest.raises(ValidationError):
        make_evidence(provider_confidence=value)


@pytest.mark.parametrize(
    "claim_type",
    ["malware.c2-association", "dns.a-record", "scanner_benign", "a", "x1.y2-z3"],
)
def test_valid_claim_types(claim_type: str) -> None:
    assert make_evidence(claim_type=claim_type).claim_type == claim_type


@pytest.mark.parametrize(
    "claim_type",
    ["Malware.C2", "malware..c2", ".malware", "malware.", "malware c2", "malware/c2", ""],
)
def test_invalid_claim_types(claim_type: str) -> None:
    with pytest.raises(ValidationError):
        make_evidence(claim_type=claim_type)


def test_last_seen_before_first_seen_is_rejected() -> None:
    with pytest.raises(ValidationError, match="last_seen must not precede"):
        make_evidence(first_seen=T0, last_seen=T0 - timedelta(days=1))


def test_context_evidence_must_be_directionless() -> None:
    with pytest.raises(ValidationError, match="context_only"):
        make_evidence(
            evidence_class=EvidenceClass.CONTEXT,
            effect=EvidenceEffect.SUPPORTS_MALICIOUS,
        )


def test_attributes_reject_credential_like_keys() -> None:
    for key in ("api_key", "x-apikey", "Auth-Key", "authorization", "bearer_token"):
        with pytest.raises(ValidationError, match="credential-like key"):
            make_evidence(attributes={key: "value"})


def test_attributes_reject_nested_credential_like_keys() -> None:
    with pytest.raises(ValidationError, match="credential-like key"):
        make_evidence(attributes={"request": {"headers": {"x-apikey": "value"}}})


def test_attributes_reject_credential_like_keys_inside_lists() -> None:
    with pytest.raises(ValidationError, match="credential-like key"):
        make_evidence(attributes={"items": [{"secret": "value"}]})


def test_credential_guard_does_not_echo_the_value() -> None:
    with pytest.raises(ValidationError) as excinfo:
        make_evidence(attributes={"api_key": "super-secret-value"})
    assert "super-secret-value" not in str(excinfo.value)


def test_ordinary_attributes_are_allowed() -> None:
    evidence = make_evidence(attributes={"malware_family": "ExampleRAT", "ports": [80, 443]})
    assert evidence.attributes["malware_family"] == "ExampleRAT"


# --------------------------------------------------------------------------- #
# Lineage
# --------------------------------------------------------------------------- #


def test_transport_and_origin_may_differ() -> None:
    evidence = make_evidence(transport_provider="fake_scanview", origin_provider="fake_noise")
    assert evidence.is_relayed is True


def test_direct_evidence_is_not_relayed() -> None:
    assert make_evidence().is_relayed is False


def test_lineage_group_defaults_to_origin_and_family() -> None:
    evidence = make_evidence(origin_provider="fake_noise", source_family="scanner_noise")
    assert evidence.lineage_group_id == "scanner_noise:fake_noise"


def test_explicit_lineage_group_is_preserved() -> None:
    evidence = make_evidence(lineage_group_id="custom-group")
    assert evidence.lineage_group_id == "custom-group"


def test_same_origin_via_different_transports_shares_lineage() -> None:
    """Relayed intelligence must not look like independent confirmation."""
    direct = make_evidence(
        transport_provider="fake_noise",
        origin_provider="fake_noise",
        source_family="scanner_noise",
    )
    relayed = make_evidence(
        transport_provider="fake_scanview",
        origin_provider="fake_noise",
        source_family="scanner_noise",
    )
    assert direct.shares_lineage_with(relayed)


def test_different_origins_do_not_share_lineage() -> None:
    a = make_evidence(origin_provider="fake_noise", source_family="scanner_noise")
    b = make_evidence(origin_provider="fake_threatfeed", source_family="curated_feed")
    assert not a.shares_lineage_with(b)


def test_match_scope_defaults_to_unknown() -> None:
    """An adapter that forgets to state scope must not imply an exact match."""
    assert make_evidence().match_scope is MatchScope.UNKNOWN


def test_match_scope_distinguishes_exact_from_broad_claims() -> None:
    exact = make_evidence(match_scope=MatchScope.EXACT_OBSERVABLE)
    broad = make_evidence(match_scope=MatchScope.IP_NETWORK)
    assert exact.match_scope is not broad.match_scope


def test_upstream_evidence_refs_are_recorded() -> None:
    evidence = make_evidence(upstream_evidence_refs=("ev-1", "ev-2"))
    assert evidence.upstream_evidence_refs == ("ev-1", "ev-2")


# --------------------------------------------------------------------------- #
# Raw references
# --------------------------------------------------------------------------- #


def test_raw_reference_holds_a_pointer_not_a_payload() -> None:
    reference = RawEvidenceReference(
        investigation_id="inv-1",
        provider="fake_provider",
        operation=ProviderOperation.LOOKUP,
        storage_key="raw/fake_provider/lookup/1",
    )
    dumped = reference.model_dump()
    assert "body" not in dumped
    assert "payload" not in dumped
    assert "headers" not in dumped
    assert reference.redacted is True


def test_raw_reference_content_hash_must_be_sha256_hex() -> None:
    with pytest.raises(ValidationError):
        RawEvidenceReference(
            investigation_id="inv-1",
            provider="fake_provider",
            operation=ProviderOperation.LOOKUP,
            storage_key="k",
            content_sha256="not-a-hash",
        )


# --------------------------------------------------------------------------- #
# Relationships
# --------------------------------------------------------------------------- #


def test_relationship_requires_evidence() -> None:
    with pytest.raises(ValidationError):
        Relationship(
            source_object_id="obj-1",
            relationship_type=RelationshipType.RESOLVES_TO,
            target_object_id="obj-2",
            evidence_refs=(),
        )


def test_relationship_with_evidence_is_valid() -> None:
    relationship = Relationship(
        source_object_id="obj-1",
        relationship_type=RelationshipType.RESOLVES_TO,
        target_object_id="obj-2",
        evidence_refs=("ev-1",),
        confidence=90.0,
    )
    assert relationship.evidence_refs == ("ev-1",)


def test_relationship_rejects_self_reference() -> None:
    with pytest.raises(ValidationError, match="two different objects"):
        Relationship(
            source_object_id="obj-1",
            relationship_type=RelationshipType.SIMILAR_TO,
            target_object_id="obj-1",
            evidence_refs=("ev-1",),
        )


def test_relationship_rejects_inverted_timeline() -> None:
    with pytest.raises(ValidationError, match="last_seen must not precede"):
        Relationship(
            source_object_id="obj-1",
            relationship_type=RelationshipType.HOSTS,
            target_object_id="obj-2",
            evidence_refs=("ev-1",),
            first_seen=T0,
            last_seen=T0 - timedelta(days=1),
        )


def test_relationship_vocabulary_matches_the_initial_set() -> None:
    assert {member.value for member in RelationshipType} == {
        "resolves-to",
        "redirects-to",
        "contacts",
        "downloads",
        "drops",
        "hosts",
        "uses-certificate",
        "belongs-to-asn",
        "associated-with-malware",
        "similar-to",
        "derived-from",
        "duplicate-of",
        "related-to",
    }


# --------------------------------------------------------------------------- #
# Conflicts
# --------------------------------------------------------------------------- #


def test_conflict_defaults_to_open() -> None:
    conflict = EvidenceConflict(
        investigation_id="inv-1",
        evidence_a_id="ev-1",
        evidence_b_id="ev-2",
        conflict_type=ConflictType.DIRECTIONAL,
        severity=ConflictSeverity.HIGH,
    )
    assert conflict.status is ConflictStatus.OPEN


def test_conflict_requires_two_distinct_pieces_of_evidence() -> None:
    with pytest.raises(ValidationError, match="two different pieces"):
        EvidenceConflict(
            investigation_id="inv-1",
            evidence_a_id="ev-1",
            evidence_b_id="ev-1",
            conflict_type=ConflictType.DIRECTIONAL,
            severity=ConflictSeverity.LOW,
        )


def test_resolved_conflict_requires_a_note() -> None:
    with pytest.raises(ValidationError, match="how it was resolved"):
        EvidenceConflict(
            investigation_id="inv-1",
            evidence_a_id="ev-1",
            evidence_b_id="ev-2",
            conflict_type=ConflictType.TEMPORAL,
            severity=ConflictSeverity.LOW,
            status=ConflictStatus.RESOLVED,
        )


def test_unresolved_conflict_needs_no_note() -> None:
    conflict = EvidenceConflict(
        investigation_id="inv-1",
        evidence_a_id="ev-1",
        evidence_b_id="ev-2",
        conflict_type=ConflictType.TEMPORAL,
        severity=ConflictSeverity.LOW,
        status=ConflictStatus.UNRESOLVED,
    )
    assert conflict.resolution_note is None


# --------------------------------------------------------------------------- #
# Coverage
# --------------------------------------------------------------------------- #


def test_covered_capability_needs_no_reason() -> None:
    item = CoverageItem(
        capability=ProviderCapability.REPUTATION,
        relevance=CoverageRelevance.RELEVANT,
        status=CoverageStatus.COVERED,
        providers_considered=("fake_aggregator",),
    )
    assert item.is_gap is False


@pytest.mark.parametrize("status", [CoverageStatus.NOT_COVERED, CoverageStatus.PARTIAL])
def test_incomplete_coverage_requires_a_reason(status: CoverageStatus) -> None:
    with pytest.raises(ValidationError, match="must state a reason"):
        CoverageItem(
            capability=ProviderCapability.HISTORICAL_INFRASTRUCTURE,
            relevance=CoverageRelevance.RELEVANT,
            status=status,
        )


def test_gap_detection_ignores_irrelevant_capabilities() -> None:
    item = CoverageItem(
        capability=ProviderCapability.CERTIFICATE_CONTEXT,
        relevance=CoverageRelevance.NOT_APPLICABLE,
        status=CoverageStatus.NOT_COVERED,
        reason="certificates do not apply to a file hash",
    )
    assert item.is_gap is False


def test_required_but_uncovered_capability_is_a_gap() -> None:
    item = CoverageItem(
        capability=ProviderCapability.MALWARE_INTELLIGENCE,
        relevance=CoverageRelevance.REQUIRED,
        status=CoverageStatus.NOT_COVERED,
        reason="no credential configured",
    )
    assert item.is_gap is True


def test_coverage_item_serializes_without_credential_state() -> None:
    item = CoverageItem(
        capability=ProviderCapability.REPUTATION,
        relevance=CoverageRelevance.RELEVANT,
        status=CoverageStatus.COVERED,
        providers_considered=("fake_aggregator",),
    )
    dumped = json.dumps(item.model_dump(mode="json"))
    for token in ("key", "token", "secret", "credential"):
        assert token not in dumped.lower()
