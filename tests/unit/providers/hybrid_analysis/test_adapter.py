"""Hybrid Analysis adapter semantics (Task 12).

The invariant every test defends: this provider says what happened when a sample
was run, and never that a sample is safe.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import SecretStr

from fixtures.hybrid_analysis import payloads
from fixtures.hybrid_analysis.fake_client import ClientFactory, FakeHybridAnalysisClient
from ti_recon.credentials.enums import AuthType, CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    ActivityMode,
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
    RelationshipType,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRegistry, ProviderRequest, UnsupportedProviderOperation
from ti_recon.providers.errors import ProviderInvalidRequestError, provider_error_for
from ti_recon.providers.hybrid_analysis import (
    ASSESSMENT_CLAIM_TYPE,
    BEHAVIOUR_CLAIM_TYPE,
    COVERAGE_CLAIM_TYPE,
    HYBRID_ANALYSIS_NOT_SUPPORTED,
    HYBRID_ANALYSIS_PROVIDER_ID,
    HYBRID_ANALYSIS_SOURCE_FAMILY,
    MAX_REQUESTS_PER_LOOKUP,
    NO_REPORT_CLAIM_TYPE,
    HybridAnalysisAdapter,
    build_hybrid_analysis_descriptor,
    lineage_group_for_sample,
)

FAKE_KEY = "ha-key-SHOULD-NOT-LEAK-1234567890"


def credential(user_id: str = "analyst-a") -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id=user_id,
        provider_id=HYBRID_ANALYSIS_PROVIDER_ID,
        credential_group=HYBRID_ANALYSIS_PROVIDER_ID,
        auth_type=AuthType.API_KEY,
        secret=SecretStr(FAKE_KEY),
    )


def file_object(hashes: dict[str, str] | None = None) -> IntelObject:
    resolved = hashes or {"SHA-256": payloads.SAMPLE_SHA256}
    strongest = resolved.get("SHA-256") or resolved.get("SHA-1") or next(iter(resolved.values()))
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=strongest,
        display_value=strongest,
        properties={"hashes": resolved},
    )


def request_for(subject: str | IntelObject | None = None, **overrides: Any) -> ProviderRequest:
    if subject is None:
        target = file_object()
    elif isinstance(subject, IntelObject):
        target = subject
    else:
        target = normalize_observable(subject).intel_object
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": target,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.FILE_BEHAVIOR}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


def build(
    client: FakeHybridAnalysisClient | None = None,
) -> tuple[HybridAnalysisAdapter, FakeHybridAnalysisClient]:
    fake = client if client is not None else FakeHybridAnalysisClient()
    return HybridAnalysisAdapter(client_factory=ClientFactory(fake)), fake  # type: ignore[arg-type]


def evidence_of(envelope: Any, claim_type: str) -> Any:
    return next((item for item in envelope.evidence if item.claim_type == claim_type), None)


def claims(envelope: Any) -> set[str]:
    return {item.claim_type for item in envelope.evidence}


def directional(envelope: Any) -> list[Any]:
    return [item for item in envelope.evidence if item.effect is not EvidenceEffect.CONTEXT_ONLY]


# --------------------------------------------------------------------------- #
# Descriptor
# --------------------------------------------------------------------------- #


def test_the_capability_is_dynamic_analysis_not_reputation() -> None:
    """A sandbox and a reputation service are not interchangeable.

    GTI cannot say what a sample did when executed; a sandbox cannot say what the
    industry thinks of it. Declaring REPUTATION would tell the planner otherwise,
    and make a sandbox non-detection look substitutable for a clean verdict.
    """
    descriptor = build_hybrid_analysis_descriptor()
    assert descriptor.capabilities == frozenset({ProviderCapability.FILE_BEHAVIOR})
    assert ProviderCapability.REPUTATION not in descriptor.capabilities


def test_files_are_the_only_supported_observable() -> None:
    """Host/domain/URL search is database hunting, and urlscan covers the web."""
    assert build_hybrid_analysis_descriptor().supported_object_types == {IntelObjectType.FILE}


def test_nothing_active_is_declared() -> None:
    """The API can detonate; this integration searches for runs that happened."""
    descriptor = build_hybrid_analysis_descriptor()
    assert descriptor.supports_active is False
    assert descriptor.supports_batch is False
    assert ProviderCapability.ACTIVE_SCAN not in descriptor.capabilities


def test_the_source_family_is_this_sandbox_not_sandboxes_in_general() -> None:
    """Two independent sandboxes agreeing is real corroboration.

    A shared "sandbox" family would suppress it — the opposite of the abuse.ch
    case, where one organization's three datasets must not read as three sources.
    """
    assert build_hybrid_analysis_descriptor().source_family == "hybrid_analysis"
    assert build_hybrid_analysis_descriptor().source_family != "sandbox"


def test_the_provider_is_discoverable_by_capability() -> None:
    registry = ProviderRegistry([HybridAnalysisAdapter()])
    matches = registry.find_compatible(IntelObjectType.FILE, ProviderCapability.FILE_BEHAVIOR)
    assert [item.descriptor.provider_id for item in matches] == [HYBRID_ANALYSIS_PROVIDER_ID]


@pytest.mark.parametrize(
    "object_type",
    [
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.IPV6_ADDR,
        IntelObjectType.DOMAIN_NAME,
        IntelObjectType.URL,
    ],
)
def test_the_provider_is_never_offered_for_a_network_observable(
    object_type: IntelObjectType,
) -> None:
    registry = ProviderRegistry([HybridAnalysisAdapter()])
    assert registry.find_compatible(object_type, ProviderCapability.FILE_BEHAVIOR) == ()


# --------------------------------------------------------------------------- #
# Request budget
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("depth", "expected_requests", "expected_summaries"),
    [
        (InvestigationDepth.QUICK, 1, 0),
        (InvestigationDepth.STANDARD, 2, 1),
        (InvestigationDepth.DEEP, 3, 2),
    ],
)
async def test_each_depth_spends_its_documented_budget(
    depth: InvestigationDepth, expected_requests: int, expected_summaries: int
) -> None:
    """A restricted key allows ~5 requests a minute; this is the whole reason."""
    adapter, client = build()
    await adapter.lookup(request_for(depth=depth), credential())
    assert client.request_count == expected_requests
    assert client.call_count("search_hash") == 1
    assert client.call_count("report_summary") == expected_summaries


async def test_a_well_studied_hash_still_costs_three_requests() -> None:
    """Forty detonations must not become forty summary requests."""
    crowded = payloads.search_hash_malicious(
        reports=[
            {
                "report_id": f"job-x:{index}",
                "environment_id": str(index),
                "environment_description": f"env {index}",
                "state": "SUCCESS",
                "verdict": "malicious",
            }
            for index in range(40)
        ]
    )
    adapter, client = build(FakeHybridAnalysisClient(search_payload=crowded))
    await adapter.lookup(request_for(depth=InvestigationDepth.DEEP), credential())
    assert client.request_count <= MAX_REQUESTS_PER_LOOKUP
    assert client.call_count("report_summary") == 2


async def test_only_the_strongest_hash_is_searched_once() -> None:
    """The API resolves any digest to the same sample."""
    adapter, client = build()
    await adapter.lookup(
        request_for(
            file_object(
                {
                    "SHA-256": payloads.SAMPLE_SHA256,
                    "SHA-1": payloads.SAMPLE_SHA1,
                    "MD5": payloads.SAMPLE_MD5,
                }
            )
        ),
        credential(),
    )
    assert client.details("search_hash") == [payloads.SAMPLE_SHA256]


@pytest.mark.parametrize(
    ("hashes", "expected"),
    [
        ({"SHA-1": payloads.SAMPLE_SHA1, "MD5": payloads.SAMPLE_MD5}, payloads.SAMPLE_SHA1),
        ({"MD5": payloads.SAMPLE_MD5}, payloads.SAMPLE_MD5),
    ],
)
async def test_a_weaker_digest_is_used_when_it_is_all_there_is(
    hashes: dict[str, str], expected: str
) -> None:
    adapter, client = build()
    await adapter.lookup(request_for(file_object(hashes)), credential())
    assert client.details("search_hash") == [expected]


async def test_the_queried_algorithm_is_recorded_in_coverage() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(
        request_for(file_object({"MD5": payloads.SAMPLE_MD5})), credential()
    )
    coverage = evidence_of(envelope, COVERAGE_CLAIM_TYPE)
    assert coverage is not None
    assert coverage.attributes["queried_hash_algorithm"] == "MD5"


# --------------------------------------------------------------------------- #
# Verdict semantics
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("verdict", "expected_effect"),
    [
        ("malicious", EvidenceEffect.SUPPORTS_MALICIOUS),
        ("suspicious", EvidenceEffect.SUPPORTS_MALICIOUS),
        ("no specific threat", EvidenceEffect.CONTEXT_ONLY),
        ("no verdict", EvidenceEffect.CONTEXT_ONLY),
        ("whitelisted", EvidenceEffect.CONTEXT_ONLY),
    ],
)
async def test_provider_verdicts_map_to_the_documented_effect(
    verdict: str, expected_effect: EvidenceEffect
) -> None:
    search = payloads.search_hash_malicious(
        reports=[
            {
                "report_id": "job-1:140",
                "environment_id": "140",
                "environment_description": "Windows 11 64 bit",
                "state": "SUCCESS",
                "verdict": verdict,
            }
        ]
    )
    adapter, _ = build(FakeHybridAnalysisClient(search_payload=search))
    envelope = await adapter.lookup(request_for(depth=InvestigationDepth.QUICK), credential())
    assessment = evidence_of(envelope, ASSESSMENT_CLAIM_TYPE)
    assert assessment is not None
    assert assessment.effect is expected_effect
    assert assessment.effect is not EvidenceEffect.SUPPORTS_BENIGN


async def test_suspicious_keeps_the_providers_own_weaker_word() -> None:
    search = payloads.search_hash_malicious(
        reports=[
            {
                "report_id": "job-1:140",
                "environment_id": "140",
                "environment_description": "Windows 11",
                "state": "SUCCESS",
                "verdict": "suspicious",
            }
        ]
    )
    adapter, _ = build(FakeHybridAnalysisClient(search_payload=search))
    envelope = await adapter.lookup(request_for(depth=InvestigationDepth.QUICK), credential())
    assessment = evidence_of(envelope, ASSESSMENT_CLAIM_TYPE)
    assert assessment is not None
    assert assessment.attributes["sandbox_verdict"] == "suspicious"
    assert assessment.attributes["raw_verdicts"] == ["suspicious"]
    assert assessment.effect is EvidenceEffect.SUPPORTS_MALICIOUS


async def test_a_malicious_verdict_is_a_curated_assertion() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    assessment = evidence_of(envelope, ASSESSMENT_CLAIM_TYPE)
    assert assessment is not None
    assert assessment.evidence_class is EvidenceClass.CURATED_THREAT_ASSERTION


async def test_a_non_positive_verdict_is_context_and_cannot_have_a_direction() -> None:
    """`EvidenceClass.CONTEXT` makes the Task 3 model enforce it."""
    search = payloads.search_hash_malicious(
        reports=[
            {
                "report_id": "job-1:120",
                "environment_id": "120",
                "environment_description": "Windows 7",
                "state": "SUCCESS",
                "verdict": "no specific threat",
            }
        ]
    )
    adapter, _ = build(FakeHybridAnalysisClient(search_payload=search))
    envelope = await adapter.lookup(request_for(depth=InvestigationDepth.QUICK), credential())
    assessment = evidence_of(envelope, ASSESSMENT_CLAIM_TYPE)
    assert assessment is not None
    assert assessment.evidence_class is EvidenceClass.CONTEXT
    assert assessment.effect is EvidenceEffect.CONTEXT_ONLY


# --------------------------------------------------------------------------- #
# Nothing is ever benign
# --------------------------------------------------------------------------- #


async def test_an_absent_report_is_no_data_and_says_it_is_not_benign() -> None:
    """An absence of detonations is the normal state of a fresh implant."""
    adapter, _ = build(FakeHybridAnalysisClient(search_payload=payloads.search_hash_no_reports()))
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.status is ProviderRunStatus.NO_DATA
    record = evidence_of(envelope, NO_REPORT_CLAIM_TYPE)
    assert record is not None
    assert record.attributes["sandbox_report_available"] is False
    assert record.attributes["means_benign"] is False
    assert directional(envelope) == []


async def test_reports_that_all_failed_produce_no_benign_evidence() -> None:
    adapter, client = build(
        FakeHybridAnalysisClient(search_payload=payloads.search_hash_failed_only())
    )
    envelope = await adapter.lookup(request_for(depth=InvestigationDepth.DEEP), credential())
    assert directional(envelope) == []
    # Nothing was worth summarizing, so nothing was fetched.
    assert client.call_count("report_summary") == 0
    coverage = evidence_of(envelope, COVERAGE_CLAIM_TYPE)
    assert coverage is not None
    assert coverage.attributes["only_failed_reports"] is True


async def test_a_completed_run_that_observed_nothing_is_not_benign() -> None:
    """The most tempting false conclusion in the whole provider."""
    adapter, _ = build(
        FakeHybridAnalysisClient(
            search_payload=payloads.search_hash_divergent(),
            summaries={"job-200:120": payloads.summary_no_specific_threat()},
            default_summary=payloads.summary_no_specific_threat(),
        )
    )
    envelope = await adapter.lookup(request_for(depth=InvestigationDepth.STANDARD), credential())
    for item in envelope.evidence:
        assert item.effect is not EvidenceEffect.SUPPORTS_BENIGN
    behaviour = evidence_of(envelope, BEHAVIOUR_CLAIM_TYPE)
    assert behaviour is not None
    # And the quality context that makes the emptiness interpretable.
    assert behaviour.attributes["observed_execution"] is False
    assert behaviour.attributes["total_processes"] == 0
    assert behaviour.attributes["warnings"]


async def test_no_evidence_anywhere_is_ever_benign() -> None:
    """Across every fixture shape, exhaustively."""
    for search, summary in (
        (payloads.search_hash_malicious(), payloads.summary_malicious()),
        (payloads.search_hash_divergent(), payloads.summary_no_specific_threat()),
        (payloads.search_hash_failed_only(), payloads.summary_malicious()),
        (payloads.search_hash_no_reports(), payloads.summary_malicious()),
    ):
        adapter, _ = build(FakeHybridAnalysisClient(search_payload=search, default_summary=summary))
        envelope = await adapter.lookup(request_for(depth=InvestigationDepth.DEEP), credential())
        assert envelope.evidence
        for item in envelope.evidence:
            assert item.effect is not EvidenceEffect.SUPPORTS_BENIGN


# --------------------------------------------------------------------------- #
# One sample-level finding, not one vote per report
# --------------------------------------------------------------------------- #


async def test_three_malicious_reports_produce_one_directional_finding() -> None:
    """Otherwise one provider's diligence reads as agreement between sources."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(depth=InvestigationDepth.DEEP), credential())
    assert len(directional(envelope)) == 1
    assert directional(envelope)[0].claim_type == ASSESSMENT_CLAIM_TYPE


async def test_behaviour_records_are_context_even_when_full_of_malice() -> None:
    """The direction was stated once; repeating it is the same sandbox voting twice."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(depth=InvestigationDepth.DEEP), credential())
    behaviour = [item for item in envelope.evidence if item.claim_type == BEHAVIOUR_CLAIM_TYPE]
    assert len(behaviour) == 2
    for item in behaviour:
        assert item.effect is EvidenceEffect.CONTEXT_ONLY
        assert item.evidence_class is EvidenceClass.CONTEXT


async def test_every_record_shares_one_sample_lineage_group() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(depth=InvestigationDepth.DEEP), credential())
    expected = lineage_group_for_sample(payloads.SAMPLE_SHA256)
    for item in envelope.evidence:
        assert item.lineage_group_id == expected
        assert item.transport_provider == HYBRID_ANALYSIS_PROVIDER_ID
        assert item.origin_provider == HYBRID_ANALYSIS_PROVIDER_ID
        assert item.source_family == HYBRID_ANALYSIS_SOURCE_FAMILY


async def test_hundreds_of_signatures_do_not_become_findings() -> None:
    """One detonation can trip hundreds; they are attributes, not votes."""
    noisy = payloads.summary_malicious(
        signatures=[
            {"name": f"signature {index}", "threat_level": 5, "category": "General"}
            for index in range(400)
        ]
    )
    adapter, _ = build(FakeHybridAnalysisClient(default_summary=noisy))
    envelope = await adapter.lookup(request_for(), credential())
    assert len(directional(envelope)) == 1
    behaviour = evidence_of(envelope, BEHAVIOUR_CLAIM_TYPE)
    assert behaviour is not None
    assert len(behaviour.attributes["signatures"]) <= 25
    assert behaviour.attributes["truncated"]["signatures"] is True


async def test_the_provider_never_grades_its_own_reliability() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    for item in envelope.evidence:
        assert item.source_reliability is None
        assert item.information_credibility is None
        assert item.provider_confidence is None


# --------------------------------------------------------------------------- #
# Divergence
# --------------------------------------------------------------------------- #


async def test_disagreeing_environments_are_preserved_not_collapsed() -> None:
    adapter, _ = build(
        FakeHybridAnalysisClient(
            search_payload=payloads.search_hash_divergent(),
            summaries={
                "job-200:140": payloads.summary_malicious(),
                "job-200:120": payloads.summary_no_specific_threat(),
            },
        )
    )
    envelope = await adapter.lookup(request_for(depth=InvestigationDepth.DEEP), credential())
    assessment = evidence_of(envelope, ASSESSMENT_CLAIM_TYPE)
    assert assessment is not None
    assert assessment.attributes["divergent_verdicts"] is True
    assert assessment.attributes["verdicts_by_environment"] == {
        "100": "suspicious",
        "120": "no_specific_threat",
        "140": "malicious",
    }
    # The strongest still leads, and it is still one finding.
    assert assessment.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert len(directional(envelope)) == 1


async def test_deep_selects_contrasting_reports_when_they_exist() -> None:
    adapter, client = build(
        FakeHybridAnalysisClient(search_payload=payloads.search_hash_divergent())
    )
    envelope = await adapter.lookup(request_for(depth=InvestigationDepth.DEEP), credential())
    coverage = evidence_of(envelope, COVERAGE_CLAIM_TYPE)
    assert coverage is not None
    assert coverage.attributes["contrasting_selection"] is True
    assert client.call_count("report_summary") == 2


# --------------------------------------------------------------------------- #
# Coverage
# --------------------------------------------------------------------------- #


async def test_coverage_never_claims_it_read_every_report() -> None:
    """One report of four was read. That must be visible."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    coverage = evidence_of(envelope, COVERAGE_CLAIM_TYPE)
    assert coverage is not None
    assert coverage.attributes["report_count"] == 4
    assert coverage.attributes["summaries_retrieved"] == 1
    assert coverage.attributes["all_reports_summarized"] is False
    assert coverage.attributes["skipped_over_budget_reports"] == 2
    assert coverage.attributes["skipped_incomplete_reports"] == 1


async def test_coverage_records_states_environments_and_strategy() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    coverage = evidence_of(envelope, COVERAGE_CLAIM_TYPE)
    assert coverage is not None
    assert coverage.attributes["report_states"] == {"success": 3, "error": 1}
    assert coverage.attributes["environments"] == ["100", "110", "120", "140"]
    assert "verdict" in coverage.attributes["selection_strategy"]
    assert coverage.attributes["provider_requests"] == 2


async def test_not_summarizing_most_reports_is_not_partial() -> None:
    """It is the designed behaviour; PARTIAL for it would mean nothing."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.status is ProviderRunStatus.SUCCESS
    coverage = evidence_of(envelope, COVERAGE_CLAIM_TYPE)
    assert coverage is not None
    assert "partial_reason" not in coverage.attributes


# --------------------------------------------------------------------------- #
# Containers and missing reports
# --------------------------------------------------------------------------- #


#: The deterministic primary pick from `search_hash_malicious`: three completed
#: reports are all malicious, so the tiebreak is the lowest environment identity.
SELECTED_AT_STANDARD = "job-100:110"


async def test_the_primary_pick_is_deterministic() -> None:
    """Named here because the container and missing-report tests depend on it."""
    adapter, client = build()
    await adapter.lookup(request_for(), credential())
    assert client.details("report_summary") == [SELECTED_AT_STANDARD]


async def test_a_container_report_is_recorded_and_not_followed() -> None:
    """410 is a real answer about a real report, not an outage."""
    client = FakeHybridAnalysisClient()
    client.mark_container(SELECTED_AT_STANDARD, ("job-500:140", "job-501:140"))
    adapter, _ = build(client)
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.status is ProviderRunStatus.PARTIAL
    coverage = evidence_of(envelope, COVERAGE_CLAIM_TYPE)
    assert coverage is not None
    assert coverage.attributes["container_reports"] == [SELECTED_AT_STANDARD]
    assert "container" in coverage.attributes["partial_reason"]
    # The children were named and deliberately not fetched.
    assert client.call_count("report_summary") == 1


async def test_a_report_that_vanished_costs_one_report_not_the_lookup() -> None:
    """The index described it moments ago, so it has gone rather than never existed."""
    client = FakeHybridAnalysisClient()
    client.mark_missing(SELECTED_AT_STANDARD)
    adapter, _ = build(client)
    envelope = await adapter.lookup(request_for(), credential())
    assert envelope.status is ProviderRunStatus.PARTIAL
    assert envelope.status is not ProviderRunStatus.NO_DATA
    coverage = evidence_of(envelope, COVERAGE_CLAIM_TYPE)
    assert coverage is not None
    assert coverage.attributes["unavailable_reports"] == [SELECTED_AT_STANDARD]
    # The sample-level assessment survives: the index still told us what it knows.
    assert evidence_of(envelope, ASSESSMENT_CLAIM_TYPE) is not None


async def test_a_container_in_deep_still_leaves_the_other_report_usable() -> None:
    client = FakeHybridAnalysisClient(search_payload=payloads.search_hash_divergent())
    # The malicious report leads at DEEP; marking it a container must leave the
    # contrasting one usable.
    client.mark_container("job-200:140")
    adapter, _ = build(client)
    envelope = await adapter.lookup(request_for(depth=InvestigationDepth.DEEP), credential())
    behaviour = [item for item in envelope.evidence if item.claim_type == BEHAVIOUR_CLAIM_TYPE]
    assert len(behaviour) == 1


# --------------------------------------------------------------------------- #
# Refusals and hygiene
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("observable", ["8.8.8.8", "example.com", "https://example.com/a"])
async def test_a_non_file_is_not_supported_and_costs_no_request(observable: str) -> None:
    adapter, client = build()
    envelope = await adapter.lookup(request_for(observable), credential())
    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert HYBRID_ANALYSIS_NOT_SUPPORTED in envelope.warnings
    assert client.calls == []


async def test_an_active_request_is_refused() -> None:
    """A caller bypassing the executor still cannot make this submit anything."""
    adapter, client = build()
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.lookup(request_for(activity_mode=ActivityMode.ACTIVE), credential())
    assert client.calls == []


async def test_an_active_action_is_refused() -> None:
    adapter, _ = build()
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.active_action(request_for(), credential())


async def test_a_lookup_without_a_credential_is_refused() -> None:
    adapter, client = build()
    with pytest.raises(ProviderInvalidRequestError, match="requires a credential"):
        await adapter.lookup(request_for(), None)
    assert client.calls == []


async def test_credential_validation_uses_the_key_endpoint_once() -> None:
    """Never before a lookup: a successful search already proves the key works."""
    adapter, client = build()
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.ACTIVE
    assert client.call_count("key_current") == 1
    assert client.call_count("search_hash") == 0


async def test_a_lookup_never_calls_the_key_endpoint() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(depth=InvestigationDepth.DEEP), credential())
    assert client.called("key_current") is False


async def test_a_rejected_key_validates_as_invalid() -> None:
    client = FakeHybridAnalysisClient()
    client.fail(
        "key_current",
        provider_error_for(ProviderErrorCategory.AUTHENTICATION_ERROR, HYBRID_ANALYSIS_PROVIDER_ID),
    )
    adapter, _ = build(client)
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.INVALID


async def test_a_restricted_key_is_not_reported_invalid() -> None:
    """Hitting an endpoint above your authorization level is expected."""
    client = FakeHybridAnalysisClient()
    client.fail(
        "key_current",
        provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, HYBRID_ANALYSIS_PROVIDER_ID),
    )
    adapter, _ = build(client)
    validation = await adapter.validate_credentials(credential())
    assert validation.status is not CredentialStatus.INVALID


async def test_the_client_is_closed_after_every_lookup() -> None:
    adapter, client = build()
    await adapter.lookup(request_for(), credential())
    assert client.closed is True


async def test_nothing_in_the_envelope_carries_the_key() -> None:
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(depth=InvestigationDepth.DEEP), credential())
    serialized = json.dumps(envelope.model_dump(mode="json"))
    assert FAKE_KEY not in serialized
    assert "SHOULD-NOT-LEAK" not in serialized


def test_normalize_reads_an_index_without_any_io() -> None:
    adapter, client = build()
    payload = adapter.normalize(request_for(), payloads.search_hash_malicious()[0])
    assert payload.evidence
    assert {item.claim_type for item in payload.evidence} == {
        ASSESSMENT_CLAIM_TYPE,
        COVERAGE_CLAIM_TYPE,
    }
    assert client.calls == []


# --------------------------------------------------------------------------- #
# Related objects
# --------------------------------------------------------------------------- #


async def test_contacted_infrastructure_becomes_objects_without_accusation() -> None:
    """A detonating sample also reaches CRLs, CDNs and telemetry."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    kinds = {item.object_type for item in envelope.objects}
    assert IntelObjectType.DOMAIN_NAME in kinds
    assert IntelObjectType.IPV4_ADDR in kinds
    assert IntelObjectType.IPV6_ADDR in kinds
    contacts = [
        item
        for item in envelope.relationships
        if item.relationship_type is RelationshipType.CONTACTS
    ]
    assert contacts
    # The evidence they hang off is context, so nothing here accuses them.
    behaviour = evidence_of(envelope, BEHAVIOUR_CLAIM_TYPE)
    assert behaviour is not None
    assert behaviour.effect is EvidenceEffect.CONTEXT_ONLY


async def test_a_value_that_is_not_a_host_is_not_made_into_one() -> None:
    """The fixture's domain list contains "not a domain"."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    assert all(" " not in item.canonical_value for item in envelope.objects)


async def test_a_compromised_host_keeps_the_providers_own_classification() -> None:
    """Not reinterpreted as attacker-owned: it may be a hijacked WordPress site."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    roles = {
        item.properties.get("sandbox_role")
        for item in envelope.objects
        if item.object_type is IntelObjectType.IPV4_ADDR
    }
    assert "compromised_host" in roles
    assert "contacted" in roles


async def test_dropped_files_become_objects_and_are_never_downloaded() -> None:
    adapter, client = build()
    envelope = await adapter.lookup(request_for(), credential())
    drops = [
        item for item in envelope.relationships if item.relationship_type is RelationshipType.DROPS
    ]
    assert len(drops) == 1
    # Only the two permitted read operations were used.
    assert {name for name, _ in client.calls} <= {"search_hash", "report_summary"}


async def test_an_extracted_file_without_a_hash_produces_no_object() -> None:
    """Half an identity is not an object."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(), credential())
    files = [item for item in envelope.objects if item.object_type is IntelObjectType.FILE]
    assert len(files) == 1


async def test_the_same_host_across_two_reports_is_one_object() -> None:
    """A graph where one C2 appears twice is a graph nothing can correlate on."""
    adapter, _ = build()
    envelope = await adapter.lookup(request_for(depth=InvestigationDepth.DEEP), credential())
    identities = [(item.object_type, item.canonical_value) for item in envelope.objects]
    assert len(identities) == len(set(identities))
    # Both reports still contribute their own relationship.
    assert len(envelope.relationships) == 2 * len(identities)
