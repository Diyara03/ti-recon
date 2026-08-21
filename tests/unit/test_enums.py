"""Vocabulary invariants (Task 1/Task 3)."""

from __future__ import annotations

import pytest

from ti_recon.enums import (
    SUBMITTABLE_OBJECT_TYPES,
    ActivityMode,
    AssessmentState,
    CoverageRelevance,
    CoverageStatus,
    EvidenceClass,
    EvidenceEffect,
    InformationCredibilityGrade,
    IntelObjectType,
    InvestigationDepth,
    MatchScope,
    ObjectClass,
    ProviderRunStatus,
    SourceReliabilityGrade,
    Verdict,
)

ALL_VOCABULARIES = [
    ObjectClass,
    IntelObjectType,
    InvestigationDepth,
    ActivityMode,
    ProviderRunStatus,
    EvidenceClass,
    EvidenceEffect,
    MatchScope,
    CoverageStatus,
    CoverageRelevance,
    Verdict,
    AssessmentState,
    SourceReliabilityGrade,
    InformationCredibilityGrade,
]


@pytest.mark.parametrize("vocabulary", ALL_VOCABULARIES)
def test_vocabularies_serialize_as_strings(vocabulary: type[object]) -> None:
    members = list(vocabulary)  # type: ignore[call-overload]
    assert members, "vocabulary must not be empty"
    for member in members:
        assert isinstance(member.value, str)
        assert member.value == member.value.strip()


@pytest.mark.parametrize("vocabulary", ALL_VOCABULARIES)
def test_vocabulary_values_are_unique(vocabulary: type[object]) -> None:
    members = list(vocabulary)  # type: ignore[call-overload]
    values = [member.value for member in members]
    assert len(values) == len(set(values))


def test_object_types_use_stix_friendly_names() -> None:
    assert IntelObjectType.IPV4_ADDR == "ipv4-addr"
    assert IntelObjectType.IPV6_ADDR == "ipv6-addr"
    assert IntelObjectType.DOMAIN_NAME == "domain-name"
    assert IntelObjectType.URL == "url"
    assert IntelObjectType.FILE == "file"
    assert IntelObjectType.AUTONOMOUS_SYSTEM == "autonomous-system"
    assert IntelObjectType.X509_CERTIFICATE == "x509-certificate"
    assert IntelObjectType.MALWARE == "malware"


def test_there_are_no_hash_object_types() -> None:
    """Hashes are properties of a ``file`` object, never object types."""
    values = {member.value for member in IntelObjectType}
    assert values.isdisjoint({"md5", "sha1", "sha256", "sha-1", "sha-256"})


def test_submittable_object_types_match_v1_scope() -> None:
    expected = {
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.IPV6_ADDR,
        IntelObjectType.DOMAIN_NAME,
        IntelObjectType.URL,
        IntelObjectType.FILE,
    }
    assert SUBMITTABLE_OBJECT_TYPES == expected


def test_passive_is_the_default_activity_vocabulary_entry() -> None:
    assert ActivityMode.PASSIVE == "passive"
    assert ActivityMode.ACTIVE == "active"


def test_verdict_vocabulary_has_no_absolute_benign() -> None:
    values = {member.value for member in Verdict}
    assert values == {"malicious", "suspicious", "inconclusive", "likely_benign"}


def test_admiralty_grades() -> None:
    assert [member.value for member in SourceReliabilityGrade] == list("ABCDEF")
    assert [member.value for member in InformationCredibilityGrade] == [
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
    ]


def test_provider_run_statuses_cover_the_required_set() -> None:
    assert {member.value for member in ProviderRunStatus} == {
        "success",
        "no_data",
        "not_configured",
        "not_supported",
        "plan_limited",
        "quota_exceeded",
        "partial",
        "temporarily_unavailable",
        "error",
    }


def test_evidence_classes_and_effects() -> None:
    assert {member.value for member in EvidenceClass} == {
        "direct_observation",
        "curated_threat_assertion",
        "aggregated_reputation",
        "context",
        "relationship",
    }
    assert {member.value for member in EvidenceEffect} == {
        "supports_malicious",
        "supports_benign",
        "context_only",
    }
