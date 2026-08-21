"""GTI assessment and reputation normalization semantics (Task 7).

The mappings in here are the ones with real consequences: getting UNDETECTED
wrong waves a fresh sample through, and letting engine counts become independent
votes reproduces exactly the reasoning TI Recon exists to avoid.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from fixtures.gti import payloads
from ti_recon.enums import EvidenceClass, EvidenceEffect, IntelObjectType, MatchScope
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers.gti.client import GTIObject
from ti_recon.providers.gti.descriptor import (
    GTI_ORIGIN_PROVIDER,
    GTI_PROVIDER_ID,
    GTI_SOURCE_FAMILY,
)
from ti_recon.providers.gti.normalizer import (
    ANALYSIS_STAT_FIELDS,
    CONTRIBUTING_FACTORS,
    GTI_ANALYSIS_STATS_UNREADABLE,
    GTI_ASSESSMENT_UNAVAILABLE,
    GTI_ASSESSMENT_UNREADABLE,
    GTI_LINEAGE_GROUP,
    VERDICT_EFFECTS,
    GTINormalization,
    NormalizationContext,
    effect_for_verdict,
    enrich_primary_object,
    epoch_to_utc,
    gti_hashes,
    normalize_analysis_stats,
    normalize_assessment,
)

NOW = datetime(2026, 8, 1, 12, 0, 0, tzinfo=UTC)


def context(**overrides: Any) -> NormalizationContext:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "subject_object_id": "obj-1",
        "now": NOW,
        "raw_reference_id": "raw-1",
    }
    kwargs.update(overrides)
    return NormalizationContext(**kwargs)


def gti_object(payload: dict[str, Any]) -> GTIObject:
    return GTIObject(
        object_type=str(payload["type"]),
        object_id=str(payload["id"]),
        attributes=dict(payload.get("attributes", {})),
        relationships=dict(payload.get("relationships", {})),
    )


def assess(verdict: str, **assessment_kwargs: Any) -> GTINormalization:
    payload = payloads.file_object()
    payload["attributes"]["gti_assessment"] = payloads.assessment(verdict, **assessment_kwargs)
    return normalize_assessment(context(), gti_object(payload))


def core(result: GTINormalization) -> Any:
    """The parent assessment evidence."""
    return next(e for e in result.evidence if e.claim_type == "gti_assessment")


# --------------------------------------------------------------------------- #
# Verdict mapping — the required semantics
# --------------------------------------------------------------------------- #


def test_malicious_supports_malicious() -> None:
    evidence = core(assess("VERDICT_MALICIOUS"))
    assert evidence.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert evidence.attributes["verdict"] == "VERDICT_MALICIOUS"


def test_suspicious_supports_malicious_but_keeps_its_raw_verdict() -> None:
    """Same direction, different strength — the strength is fusion's to weigh."""
    evidence = core(assess("VERDICT_SUSPICIOUS"))
    assert evidence.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert evidence.attributes["verdict"] == "VERDICT_SUSPICIOUS"


def test_malicious_and_suspicious_are_distinguishable_after_normalization() -> None:
    malicious = core(assess("VERDICT_MALICIOUS"))
    suspicious = core(assess("VERDICT_SUSPICIOUS"))
    assert malicious.effect is suspicious.effect
    assert malicious.attributes["verdict"] != suspicious.attributes["verdict"]


def test_benign_supports_benign() -> None:
    evidence = core(assess("VERDICT_BENIGN"))
    assert evidence.effect is EvidenceEffect.SUPPORTS_BENIGN


def test_undetected_is_context_and_never_benign() -> None:
    """Undetected is equally true of every threat nobody has caught yet."""
    evidence = core(assess("VERDICT_UNDETECTED"))
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY
    assert evidence.effect is not EvidenceEffect.SUPPORTS_BENIGN
    assert evidence.attributes["verdict"] == "VERDICT_UNDETECTED"


def test_unknown_is_context_only() -> None:
    assert core(assess("VERDICT_UNKNOWN")).effect is EvidenceEffect.CONTEXT_ONLY


def test_a_future_verdict_name_does_not_inherit_a_direction() -> None:
    assert core(assess("VERDICT_SOMETHING_NEW")).effect is EvidenceEffect.CONTEXT_ONLY


def test_an_absent_verdict_is_directionless() -> None:
    assert effect_for_verdict(None) is EvidenceEffect.CONTEXT_ONLY


def test_only_benign_maps_to_supports_benign() -> None:
    """A guard against a future edit quietly making undetected mean safe."""
    benign_verdicts = [
        verdict
        for verdict, effect in VERDICT_EFFECTS.items()
        if effect is EvidenceEffect.SUPPORTS_BENIGN
    ]
    assert benign_verdicts == ["VERDICT_BENIGN"]


# --------------------------------------------------------------------------- #
# Assessment shape
# --------------------------------------------------------------------------- #


def test_the_assessment_is_a_curated_threat_assertion() -> None:
    """GTI's own judgement, not an aggregation of other vendors' opinions."""
    assert core(assess("VERDICT_MALICIOUS")).evidence_class is (
        EvidenceClass.CURATED_THREAT_ASSERTION
    )


def test_the_class_stays_curated_even_when_the_verdict_is_directionless() -> None:
    """An undetected assessment is still GTI having looked."""
    assert core(assess("VERDICT_UNDETECTED")).evidence_class is (
        EvidenceClass.CURATED_THREAT_ASSERTION
    )


def test_severity_threat_score_and_description_are_preserved() -> None:
    evidence = core(
        assess(
            "VERDICT_MALICIOUS",
            severity="SEVERITY_CRITICAL",
            threat_score=97,
            description="Synthetic detail.",
        )
    )
    assert evidence.attributes["severity"] == "SEVERITY_CRITICAL"
    assert evidence.attributes["threat_score"] == 97
    assert evidence.attributes["description"] == "Synthetic detail."


def test_the_threat_score_is_never_turned_into_a_risk_score() -> None:
    """Different quantities on different scales owned by different layers."""
    evidence = core(assess("VERDICT_MALICIOUS", threat_score=88))
    assert evidence.attributes["threat_score"] == 88
    assert "risk_score" not in evidence.attributes
    assert "risk_score" not in set(type(evidence).model_fields)


def test_the_confidence_score_becomes_provider_confidence() -> None:
    result = assess("VERDICT_MALICIOUS")
    evidence = core(result)
    assert evidence.provider_confidence == 91.0
    # Also kept raw, for traceability back to what GTI actually said.
    assert evidence.attributes["gti_confidence_score"] == 91


def test_an_out_of_range_confidence_is_kept_raw_but_not_asserted() -> None:
    payload = payloads.file_object(confidence=None)
    payload["attributes"]["gti_confidence_score"] = 250
    result = normalize_assessment(context(), gti_object(payload))
    evidence = core(result)
    assert evidence.provider_confidence is None
    assert evidence.attributes["gti_confidence_score"] == 250


def test_no_admiralty_grade_is_invented() -> None:
    """Both grades are TI Recon policy; an adapter has no basis to assign one."""
    evidence = core(assess("VERDICT_MALICIOUS"))
    assert evidence.source_reliability is None
    assert evidence.information_credibility is None


def test_the_assessment_applies_to_the_exact_observable() -> None:
    assert core(assess("VERDICT_MALICIOUS")).match_scope is MatchScope.EXACT_OBSERVABLE


def test_the_assessment_records_when_it_was_retrieved_and_last_analysed() -> None:
    evidence = core(assess("VERDICT_MALICIOUS"))
    assert evidence.retrieved_at == NOW
    assert evidence.last_seen is not None
    assert evidence.raw_reference_id == "raw-1"


# --------------------------------------------------------------------------- #
# Missing or unreadable assessment
# --------------------------------------------------------------------------- #


def test_a_missing_assessment_warns_without_failing() -> None:
    """An entitlement or a not-yet-assessed object; the reason is not guessed."""
    result = normalize_assessment(
        context(), gti_object(payloads.file_object(with_assessment=False))
    )
    assert result.evidence == ()
    assert result.warnings == (GTI_ASSESSMENT_UNAVAILABLE,)
    assert result.degraded is False


def test_an_unreadable_verdict_degrades_rather_than_failing() -> None:
    payload = payloads.file_object()
    payload["attributes"]["gti_assessment"] = {"verdict": {"value": ["unexpected"]}}
    result = normalize_assessment(context(), gti_object(payload))
    assert result.warnings == (GTI_ASSESSMENT_UNREADABLE,)
    assert result.degraded is True
    assert result.evidence == ()


def test_an_assessment_with_only_a_verdict_still_normalizes() -> None:
    payload = payloads.file_object()
    payload["attributes"]["gti_assessment"] = {"verdict": {"value": "VERDICT_MALICIOUS"}}
    evidence = core(normalize_assessment(context(), gti_object(payload)))
    assert evidence.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert "severity" not in evidence.attributes


def test_a_bare_verdict_without_a_value_wrapper_is_accepted() -> None:
    """GTI nests values; tolerating both shapes costs nothing."""
    payload = payloads.file_object()
    payload["attributes"]["gti_assessment"] = {"verdict": "VERDICT_BENIGN"}
    assert core(normalize_assessment(context(), gti_object(payload))).effect is (
        EvidenceEffect.SUPPORTS_BENIGN
    )


def test_an_empty_description_is_omitted_rather_than_stored_blank() -> None:
    evidence = core(assess("VERDICT_MALICIOUS", description="   "))
    assert "description" not in evidence.attributes


# --------------------------------------------------------------------------- #
# Contributing factors
# --------------------------------------------------------------------------- #


def test_recognized_factors_become_their_own_evidence() -> None:
    result = assess(
        "VERDICT_MALICIOUS",
        contributing_factors={
            "mandiant_association_actor": ["APT-SYNTHETIC"],
            "malicious_sandbox_verdict": True,
        },
    )
    claims = {e.claim_type for e in result.evidence}
    assert "gti.threat_actor_association" in claims
    assert "gti.sandbox_verdict.malicious" in claims


def test_a_falsy_factor_produces_nothing() -> None:
    """`"report": false` means there is no association, not that there is one."""
    result = assess(
        "VERDICT_MALICIOUS",
        contributing_factors={
            "mandiant_association_report": False,
            "mandiant_association_actor": [],
            "malicious_sandbox_verdict": None,
        },
    )
    assert [e.claim_type for e in result.evidence] == ["gti_assessment"]


def test_an_unrecognized_factor_is_recorded_but_not_exploded() -> None:
    """Adding one later is a table entry, not an archaeology exercise."""
    result = assess(
        "VERDICT_MALICIOUS",
        contributing_factors={"some_new_google_factor": True, "another_one": ["x"]},
    )
    evidence = core(result)
    assert evidence.attributes["unmapped_contributing_factors"] == [
        "another_one",
        "some_new_google_factor",
    ]
    assert [e.claim_type for e in result.evidence] == ["gti_assessment"]


def test_a_score_factor_stays_on_the_parent_rather_than_becoming_a_claim() -> None:
    result = assess("VERDICT_MALICIOUS", contributing_factors={"mandiant_confidence_score": 80})
    evidence = core(result)
    assert evidence.attributes["mandiant_confidence_score"] == 80
    assert len(result.evidence) == 1


def test_a_benign_factor_points_benign() -> None:
    result = assess("VERDICT_BENIGN", contributing_factors={"legitimate_software": True})
    factor = next(e for e in result.evidence if e.claim_type == "gti.legitimate_software")
    assert factor.effect is EvidenceEffect.SUPPORTS_BENIGN


def test_a_value_dependent_factor_is_context_with_its_value_kept() -> None:
    result = assess(
        "VERDICT_MALICIOUS",
        contributing_factors={"safebrowsing_verdict": "SOCIAL_ENGINEERING"},
    )
    factor = next(e for e in result.evidence if e.claim_type == "gti.safebrowsing_verdict")
    assert factor.effect is EvidenceEffect.CONTEXT_ONLY
    assert factor.attributes["value"] == "SOCIAL_ENGINEERING"


def test_every_context_class_factor_is_directionless() -> None:
    """Task 3 requires it, and a directional 'context' signal is a contradiction."""
    for factor in CONTRIBUTING_FACTORS.values():
        if factor.evidence_class is EvidenceClass.CONTEXT:
            assert factor.effect is EvidenceEffect.CONTEXT_ONLY


def test_factor_claim_types_are_namespaced_and_unique() -> None:
    claim_types = [factor.claim_type for factor in CONTRIBUTING_FACTORS.values()]
    assert len(claim_types) == len(set(claim_types))
    assert all(claim_type.startswith("gti.") for claim_type in claim_types)


def test_a_mandiant_factor_records_its_origin_component() -> None:
    """Traceable as a Mandiant-curated component of the GTI assessment."""
    result = assess(
        "VERDICT_MALICIOUS",
        contributing_factors={
            "mandiant_association_actor": ["APT-SYNTHETIC"],
            "malicious_sandbox_verdict": True,
        },
    )
    by_claim = {e.claim_type: e for e in result.evidence}
    assert by_claim["gti.threat_actor_association"].attributes["origin_component"] == ("mandiant")
    assert by_claim["gti.sandbox_verdict.malicious"].attributes["origin_component"] == ("gti")


# --------------------------------------------------------------------------- #
# Lineage — GTI's internals must not look like independent providers
# --------------------------------------------------------------------------- #


def test_every_gti_signal_shares_one_source_family() -> None:
    result = assess("VERDICT_MALICIOUS").merge(
        normalize_analysis_stats(context(), gti_object(payloads.file_object()))
    )
    assert result.evidence
    for evidence in result.evidence:
        assert evidence.transport_provider == GTI_PROVIDER_ID
        assert evidence.origin_provider == GTI_ORIGIN_PROVIDER
        assert evidence.source_family == GTI_SOURCE_FAMILY == "google_ti"


def test_assessment_factors_and_stats_all_share_one_lineage_group() -> None:
    """One provider's internal reasoning is not several providers agreeing."""
    result = assess("VERDICT_MALICIOUS").merge(
        normalize_analysis_stats(context(), gti_object(payloads.file_object()))
    )
    groups = {evidence.lineage_group_id for evidence in result.evidence}
    assert groups == {GTI_LINEAGE_GROUP}


def test_a_mandiant_factor_does_not_get_its_own_source_family() -> None:
    result = assess(
        "VERDICT_MALICIOUS",
        contributing_factors={"mandiant_association_actor": ["APT-SYNTHETIC"]},
    )
    factor = next(e for e in result.evidence if e.claim_type == "gti.threat_actor_association")
    assert factor.source_family == GTI_SOURCE_FAMILY
    assert factor.origin_provider == GTI_ORIGIN_PROVIDER
    assert factor.attributes["origin_component"] == "mandiant"


def test_factors_point_back_at_the_assessment_they_came_from() -> None:
    result = assess("VERDICT_MALICIOUS", contributing_factors={"malicious_sandbox_verdict": True})
    parent = core(result)
    factor = next(e for e in result.evidence if e.claim_type != "gti_assessment")
    assert factor.upstream_evidence_refs == (parent.id,)


def test_all_gti_evidence_is_mutually_non_independent() -> None:
    result = assess("VERDICT_MALICIOUS").merge(
        normalize_analysis_stats(context(), gti_object(payloads.file_object()))
    )
    for evidence in result.evidence:
        for other in result.evidence:
            assert evidence.shares_lineage_with(other)


def test_gti_evidence_is_not_relayed_from_a_third_party() -> None:
    """Transport and origin are both GTI: nothing here is somebody else's data."""
    for evidence in assess("VERDICT_MALICIOUS").evidence:
        assert evidence.is_relayed is False


# --------------------------------------------------------------------------- #
# last_analysis_stats
# --------------------------------------------------------------------------- #


def stats_evidence(**stat_overrides: int) -> Any:
    payload = payloads.file_object()
    stats = dict(payload["attributes"]["last_analysis_stats"])
    stats.update(stat_overrides)
    payload["attributes"]["last_analysis_stats"] = stats
    result = normalize_analysis_stats(context(), gti_object(payload))
    return result.evidence[0]


def test_engine_counts_become_exactly_one_aggregated_signal() -> None:
    """Never one per engine: a roll-up is one source, not dozens."""
    result = normalize_analysis_stats(context(), gti_object(payloads.file_object()))
    assert len(result.evidence) == 1
    evidence = result.evidence[0]
    assert evidence.evidence_class is EvidenceClass.AGGREGATED_REPUTATION
    assert evidence.claim_type == "gti_analysis_stats"


def test_the_counters_are_preserved_verbatim() -> None:
    evidence = stats_evidence()
    assert evidence.attributes["malicious"] == 12
    assert evidence.attributes["suspicious"] == 3
    assert evidence.attributes["harmless"] == 4
    assert evidence.attributes["undetected"] == 55
    assert evidence.attributes["timeout"] == 1
    assert evidence.attributes["failure"] == 0
    assert evidence.attributes["type-unsupported"] == 2
    assert evidence.attributes["engines_total"] == 77


def test_detections_point_toward_malicious() -> None:
    assert stats_evidence(malicious=3, suspicious=0).effect is (EvidenceEffect.SUPPORTS_MALICIOUS)


def test_a_suspicious_only_result_still_points_toward_malicious() -> None:
    assert stats_evidence(malicious=0, suspicious=1).effect is (EvidenceEffect.SUPPORTS_MALICIOUS)


def test_undetected_counts_never_produce_benign_evidence() -> None:
    """0 malicious and 60 undetected is not a statement that anything is safe."""
    evidence = stats_evidence(malicious=0, suspicious=0, harmless=0, undetected=60)
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY
    assert evidence.effect is not EvidenceEffect.SUPPORTS_BENIGN


def test_harmless_counts_never_produce_benign_evidence_either() -> None:
    """For most engines "harmless" only means "not in my database"."""
    evidence = stats_evidence(malicious=0, suspicious=0, harmless=60, undetected=0)
    assert evidence.effect is EvidenceEffect.CONTEXT_ONLY


def test_no_ratio_or_threshold_is_computed() -> None:
    """Counting providers is exactly the reasoning TI Recon rejects."""
    evidence = stats_evidence(malicious=40, harmless=1)
    assert "score" not in evidence.attributes
    assert "ratio" not in evidence.attributes
    assert "risk" not in evidence.attributes
    assert evidence.provider_confidence is None


def test_per_engine_results_are_never_normalized() -> None:
    payload = payloads.file_object(
        extra_attributes={"last_analysis_results": {"EngineA": {"category": "malicious"}}}
    )
    result = normalize_analysis_stats(context(), gti_object(payload))
    assert "last_analysis_results" not in result.evidence[0].attributes
    assert "EngineA" not in str(result.evidence[0].attributes)


def test_the_community_reputation_travels_with_the_aggregate() -> None:
    assert stats_evidence().attributes["reputation"] == -18


def test_analysis_timestamps_are_recorded() -> None:
    evidence = stats_evidence()
    assert evidence.first_seen is not None
    assert evidence.last_seen is not None
    assert evidence.first_seen <= evidence.last_seen


def test_inverted_provider_timestamps_are_tolerated() -> None:
    """An inverted range would be rejected outright; keep the stronger value."""
    payload = payloads.file_object()
    payload["attributes"]["first_submission_date"] = 1_785_326_400
    payload["attributes"]["last_analysis_date"] = 1_685_326_400
    evidence = normalize_analysis_stats(context(), gti_object(payload)).evidence[0]
    assert evidence.first_seen is None
    assert evidence.last_seen is not None


def test_an_object_with_no_stats_and_no_reputation_yields_nothing() -> None:
    payload = payloads.file_object(with_stats=False)
    payload["attributes"].pop("reputation")
    assert normalize_analysis_stats(context(), gti_object(payload)).evidence == ()


def test_reputation_alone_still_produces_the_aggregate() -> None:
    payload = payloads.file_object(with_stats=False)
    result = normalize_analysis_stats(context(), gti_object(payload))
    assert len(result.evidence) == 1
    assert result.evidence[0].attributes["reputation"] == -18


def test_unreadable_stats_degrade_rather_than_failing() -> None:
    payload = payloads.file_object()
    payload["attributes"]["last_analysis_stats"] = {"malicious": "lots"}
    result = normalize_analysis_stats(context(), gti_object(payload))
    assert result.warnings == (GTI_ANALYSIS_STATS_UNREADABLE,)
    assert result.degraded is True


def test_a_partially_readable_stats_block_keeps_what_parsed() -> None:
    payload = payloads.file_object()
    payload["attributes"]["last_analysis_stats"] = {
        "malicious": 4,
        "undetected": "many",
    }
    evidence = normalize_analysis_stats(context(), gti_object(payload)).evidence[0]
    assert evidence.attributes["malicious"] == 4
    assert "undetected" not in evidence.attributes


def test_the_stat_field_list_is_fixed() -> None:
    """A new key must not silently change what "malicious" means."""
    assert "malicious" in ANALYSIS_STAT_FIELDS
    assert "suspicious" in ANALYSIS_STAT_FIELDS
    assert len(set(ANALYSIS_STAT_FIELDS)) == len(ANALYSIS_STAT_FIELDS)


# --------------------------------------------------------------------------- #
# Metadata helpers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", [None, "1785326400", True, -1, 99_999_999_999, [1], {"a": 1}])
def test_an_implausible_epoch_reads_as_absent(value: Any) -> None:
    assert epoch_to_utc(value) is None


def test_a_plausible_epoch_becomes_an_aware_utc_instant() -> None:
    moment = epoch_to_utc(1_785_326_400)
    assert moment is not None
    assert moment.tzinfo is not None
    assert moment.year == 2026


def test_hashes_are_renamed_to_the_task_3_vocabulary() -> None:
    assert gti_hashes(gti_object(payloads.file_object())) == {
        "MD5": payloads.EMPTY_FILE_MD5,
        "SHA-1": payloads.EMPTY_FILE_SHA1,
        "SHA-256": payloads.EMPTY_FILE_SHA256,
    }


@pytest.mark.parametrize(
    "bad", [{"md5": "tooshort"}, {"md5": "z" * 32}, {"md5": 12345}, {"md5": None}]
)
def test_a_malformed_digest_is_dropped_not_fatal(bad: dict[str, Any]) -> None:
    """IntelObject would reject the whole object for one bad digest."""
    payload = payloads.file_object()
    payload["attributes"].update(bad)
    hashes = gti_hashes(gti_object(payload))
    assert "MD5" not in hashes
    assert "SHA-256" in hashes


def test_an_uppercase_digest_is_normalized() -> None:
    payload = payloads.file_object()
    payload["attributes"]["md5"] = payloads.EMPTY_FILE_MD5.upper()
    assert gti_hashes(gti_object(payload))["MD5"] == payloads.EMPTY_FILE_MD5


def test_enrichment_never_mutates_the_submitted_object() -> None:
    submitted = normalize_observable("evil.example").intel_object
    original = dict(submitted.properties)
    enriched = enrich_primary_object(submitted, gti_object(payloads.domain_object()))
    assert submitted.properties == original
    assert enriched is not submitted


def test_enrichment_cannot_be_mutated_through_the_provider_payload() -> None:
    payload = payloads.domain_object()
    submitted = normalize_observable("evil.example").intel_object
    enriched = enrich_primary_object(submitted, gti_object(payload))

    payload["attributes"]["categories"]["synthetic-feed"] = "tampered"

    assert enriched.properties["gti"]["categories"]["synthetic-feed"] == "malware"


def test_an_unserializable_value_is_stringified_rather_than_smuggled() -> None:
    class Weird:
        def __str__(self) -> str:
            return "weird-value"

    payload = payloads.domain_object(extra_attributes={"registrar": Weird()})
    enriched = enrich_primary_object(
        normalize_observable("evil.example").intel_object, gti_object(payload)
    )
    assert enriched.properties["gti"]["registrar"] == "weird-value"
    enriched.model_dump_json()


def test_enrichment_of_a_non_file_leaves_hashes_alone() -> None:
    enriched = enrich_primary_object(
        normalize_observable("evil.example").intel_object,
        gti_object(payloads.domain_object()),
    )
    assert "hashes" not in enriched.properties


def test_a_normalization_merges_cleanly() -> None:
    first = GTINormalization(warnings=("A",), degraded=False)
    second = GTINormalization(warnings=("B",), degraded=True)
    merged = first.merge(second)
    assert merged.warnings == ("A", "B")
    assert merged.degraded is True


def test_the_file_metadata_allowlist_excludes_assessments() -> None:
    """Assessments are evidence, not properties."""
    from ti_recon.enums import IntelObjectType
    from ti_recon.providers.gti.normalizer import GTI_METADATA_FIELDS

    for fields in GTI_METADATA_FIELDS.values():
        assert "gti_assessment" not in fields
        assert "last_analysis_stats" not in fields
        assert "last_analysis_results" not in fields
        assert "reputation" not in fields
    assert (
        GTI_METADATA_FIELDS[IntelObjectType.IPV6_ADDR]
        == GTI_METADATA_FIELDS[IntelObjectType.IPV4_ADDR]
    )


def test_an_intel_object_with_gti_properties_serializes() -> None:
    enriched = enrich_primary_object(
        normalize_observable(payloads.EMPTY_FILE_SHA256).intel_object,
        gti_object(payloads.file_object()),
    )
    assert isinstance(enriched, IntelObject)
    enriched.model_dump_json()


# --------------------------------------------------------------------------- #
# Defensive paths
# --------------------------------------------------------------------------- #


def test_a_null_metadata_value_is_omitted_rather_than_stored() -> None:
    """An explicit null is absence, not a value worth recording."""
    from ti_recon.providers.gti.normalizer import gti_metadata

    payload = payloads.domain_object(extra_attributes={"registrar": None})
    metadata = gti_metadata(IntelObjectType.DOMAIN_NAME, gti_object(payload))
    assert "registrar" not in metadata


def test_an_implausible_timestamp_is_omitted_rather_than_stored() -> None:
    from ti_recon.providers.gti.normalizer import gti_metadata

    payload = payloads.domain_object(extra_attributes={"creation_date": "yesterday"})
    metadata = gti_metadata(IntelObjectType.DOMAIN_NAME, gti_object(payload))
    assert "creation_date" not in metadata


def test_a_file_with_no_readable_hashes_keeps_what_it_had() -> None:
    payload = payloads.file_object()
    for attribute in ("md5", "sha1", "sha256"):
        payload["attributes"][attribute] = "nonsense"
    submitted = normalize_observable(payloads.EMPTY_FILE_SHA256).intel_object
    enriched = enrich_primary_object(submitted, gti_object(payload))
    assert enriched.hashes == submitted.hashes


def test_an_assessment_without_a_confidence_score_omits_it() -> None:
    payload = payloads.file_object(confidence=None)
    evidence = core(normalize_assessment(context(), gti_object(payload)))
    assert evidence.provider_confidence is None
    assert "gti_confidence_score" not in evidence.attributes


def test_stats_without_a_reputation_omit_it() -> None:
    payload = payloads.file_object()
    payload["attributes"].pop("reputation")
    evidence = normalize_analysis_stats(context(), gti_object(payload)).evidence[0]
    assert "reputation" not in evidence.attributes


# --------------------------------------------------------------------------- #
# Relationship item edge cases
# --------------------------------------------------------------------------- #


def related(object_type: str, object_id: str, **extra: Any) -> Any:
    from ti_recon.providers.gti.normalizer import RelatedItem

    return RelatedItem(
        object_type=object_type,
        object_id=object_id,
        attributes=extra.get("attributes", {}),
        context_attributes=extra.get("context_attributes", {}),
    )


def subject_file() -> Any:
    return normalize_observable(payloads.EMPTY_FILE_SHA256).intel_object


@pytest.mark.parametrize(
    ("object_type", "object_id"),
    [
        ("collection", "c-1"),  # not a descriptor-identifiable type
        ("domain", "   "),  # blank identity
        ("file", "not-a-hash"),  # wrong length
        ("file", "z" * 64),  # right length, not hex
        ("ip_address", "999.999.999.999"),
    ],
)
def test_an_unidentifiable_descriptor_target_is_counted_not_invented(
    object_type: str, object_id: str
) -> None:
    from ti_recon.providers.gti.normalizer import normalize_related_items
    from ti_recon.providers.gti.relationships import RELATIONSHIP_SPECS

    result = normalize_related_items(
        context(),
        subject_file(),
        RELATIONSHIP_SPECS["contacted_ips"],
        [related(object_type, object_id)],
    )
    assert result.objects == ()
    assert result.warnings == ("GTI_RELATED_ITEM_UNRESOLVABLE",)


def test_a_url_target_can_be_recovered_from_context_attributes() -> None:
    """GTI puts the URL in either place depending on the endpoint."""
    from ti_recon.providers.gti.normalizer import normalize_related_items
    from ti_recon.providers.gti.relationships import RELATIONSHIP_SPECS

    result = normalize_related_items(
        context(),
        subject_file(),
        RELATIONSHIP_SPECS["contacted_urls"],
        [
            related(
                "url",
                "u-opaque",
                context_attributes={"url": "http://c2.evil.example/gate"},
            )
        ],
    )
    assert result.objects[0].canonical_value == "http://c2.evil.example/gate"


def test_relationship_context_attributes_are_preserved_on_the_evidence() -> None:
    from ti_recon.providers.gti.normalizer import normalize_related_items
    from ti_recon.providers.gti.relationships import RELATIONSHIP_SPECS

    result = normalize_related_items(
        context(),
        subject_file(),
        RELATIONSHIP_SPECS["contacted_domains"],
        [related("domain", "c2.evil.example", context_attributes={"timestamp": 1})],
    )
    assert result.evidence[0].attributes["context"] == {"timestamp": 1}


def test_a_resolution_without_usable_attributes_is_counted() -> None:
    from ti_recon.providers.gti.normalizer import normalize_related_items
    from ti_recon.providers.gti.relationships import RELATIONSHIP_SPECS

    domain = normalize_observable("evil.example").intel_object
    result = normalize_related_items(
        context(),
        domain,
        RELATIONSHIP_SPECS["resolutions"],
        [related("resolution", "x", attributes={})],
    )
    assert result.objects == ()
    assert result.warnings == ("GTI_RELATED_ITEM_UNRESOLVABLE",)


def test_a_resolution_for_an_unexpected_subject_type_is_skipped() -> None:
    """Only domains and addresses have a counterpart in a resolution."""
    from ti_recon.providers.gti.normalizer import normalize_related_items
    from ti_recon.providers.gti.relationships import RELATIONSHIP_SPECS

    result = normalize_related_items(
        context(),
        subject_file(),
        RELATIONSHIP_SPECS["resolutions"],
        [related("resolution", "x", attributes={"ip_address": "198.51.100.7"})],
    )
    assert result.objects == ()


def test_a_resolution_from_an_ip_without_a_hostname_is_skipped() -> None:
    from ti_recon.providers.gti.normalizer import normalize_related_items
    from ti_recon.providers.gti.relationships import RELATIONSHIP_SPECS

    address = normalize_observable("198.51.100.7").intel_object
    result = normalize_related_items(
        context(),
        address,
        RELATIONSHIP_SPECS["resolutions"],
        [related("resolution", "x", attributes={"ip_address": "198.51.100.7"})],
    )
    assert result.objects == ()


def test_inline_relationships_are_ignored_when_expansion_is_off() -> None:
    from ti_recon.providers.gti.normalizer import normalize_inline_relationships
    from ti_recon.providers.gti.relationships import RELATIONSHIP_SPECS

    payload = payloads.file_object(
        relationships={"contacted_domains": {"data": [{"type": "domain", "id": "a.example"}]}}
    )
    result = normalize_inline_relationships(
        context(),
        subject_file(),
        gti_object(payload),
        RELATIONSHIP_SPECS,
        max_per_relationship=0,
    )
    assert result.objects == ()


def test_inline_relationships_skip_unknown_names_and_malformed_blocks() -> None:
    from ti_recon.providers.gti.normalizer import normalize_inline_relationships
    from ti_recon.providers.gti.relationships import RELATIONSHIP_SPECS

    payload = payloads.file_object(
        relationships={
            "not_a_relationship": {"data": [{"type": "domain", "id": "a.example"}]},
            "contacted_domains": "not-a-mapping",
            "contacted_ips": {"data": [{"type": "ip_address"}, "junk"]},
        }
    )
    result = normalize_inline_relationships(
        context(),
        subject_file(),
        gti_object(payload),
        RELATIONSHIP_SPECS,
        max_per_relationship=5,
    )
    # An unknown name, a non-mapping block and malformed entries all yield
    # nothing without taking the rest of the response down with them.
    assert result.objects == ()
    assert result.evidence == ()


# --------------------------------------------------------------------------- #
# Threat association edge cases
# --------------------------------------------------------------------------- #


def test_a_malware_family_matching_the_subject_is_not_self_related() -> None:
    from ti_recon.enums import ObjectClass
    from ti_recon.models.intel_object import IntelObject as Obj
    from ti_recon.providers.gti.normalizer import normalize_related_items
    from ti_recon.providers.gti.relationships import RELATIONSHIP_SPECS

    malware_subject = Obj(
        object_class=ObjectClass.THREAT,
        object_type=IntelObjectType.MALWARE,
        canonical_value="syntheticrat",
        display_value="SyntheticRAT",
    )
    result = normalize_related_items(
        context(),
        malware_subject,
        RELATIONSHIP_SPECS["malware_families"],
        [
            related(
                "collection",
                "c-1",
                attributes={"name": "SyntheticRAT", "collection_type": "malware-family"},
            )
        ],
    )
    assert result.objects == ()
    assert result.relationships == ()
    # The association claim survives; only the duplicate node is dropped.
    assert len(result.evidence) == 1


def test_a_collection_type_can_come_from_context_attributes() -> None:
    from ti_recon.providers.gti.normalizer import normalize_related_items
    from ti_recon.providers.gti.relationships import RELATIONSHIP_SPECS

    result = normalize_related_items(
        context(),
        subject_file(),
        RELATIONSHIP_SPECS["associations"],
        [
            related(
                "collection",
                "c-1",
                context_attributes={"collection_type": "campaign"},
            )
        ],
    )
    assert result.evidence[0].attributes["gti_collection_type"] == "campaign"


def test_a_named_collection_of_an_unmodelled_type_stays_a_claim() -> None:
    from ti_recon.providers.gti.normalizer import normalize_related_items
    from ti_recon.providers.gti.relationships import RELATIONSHIP_SPECS

    result = normalize_related_items(
        context(),
        subject_file(),
        RELATIONSHIP_SPECS["campaigns"],
        [
            related(
                "collection",
                "c-1",
                attributes={"name": "Operation Synthetic", "collection_type": "campaign"},
            )
        ],
    )
    assert result.objects == ()
    assert result.evidence[0].attributes["name"] == "Operation Synthetic"


# --------------------------------------------------------------------------- #
# Behaviour edge cases
# --------------------------------------------------------------------------- #


def test_behaviour_normalization_of_nothing_yields_nothing() -> None:
    from ti_recon.providers.gti.normalizer import normalize_file_behavior

    assert normalize_file_behavior(context(), subject_file(), {}, max_per_source=5).evidence == ()
    assert (
        normalize_file_behavior(
            context(),
            subject_file(),
            payloads.behaviour_summary_payload()["data"],
            max_per_source=0,
        ).evidence
        == ()
    )


def test_behaviour_ignores_malformed_entries() -> None:
    from ti_recon.providers.gti.normalizer import normalize_file_behavior

    summary = {
        "dns_lookups": "not-a-list",
        "ip_traffic": [{"destination_ip": None}, "junk", {"destination_ip": "  "}],
        "files_dropped": [{"sha256": "not-a-hash"}],
    }
    result = normalize_file_behavior(context(), subject_file(), summary, max_per_source=5)
    assert result.objects == ()


def test_behaviour_skips_a_dropped_file_identical_to_the_sample() -> None:
    from ti_recon.providers.gti.normalizer import normalize_file_behavior

    summary = {"files_dropped": [{"sha256": payloads.EMPTY_FILE_SHA256}]}
    result = normalize_file_behavior(context(), subject_file(), summary, max_per_source=5)
    assert result.objects == ()


def test_behaviour_records_connection_details_when_present() -> None:
    from ti_recon.providers.gti.normalizer import normalize_file_behavior

    summary = {"ip_traffic": [{"destination_ip": "198.51.100.9", "destination_port": 8443}]}
    result = normalize_file_behavior(context(), subject_file(), summary, max_per_source=5)
    assert result.evidence[0].attributes["destination_port"] == 8443


def test_inline_relationships_are_normalized_when_present() -> None:
    """The path that makes QUICK still useful when GTI volunteers data."""
    from ti_recon.providers.gti.normalizer import normalize_inline_relationships
    from ti_recon.providers.gti.relationships import RELATIONSHIP_SPECS

    payload = payloads.file_object(
        relationships={
            "contacted_domains": {
                "data": [
                    {"type": "domain", "id": "inline-a.example"},
                    {"type": "domain", "id": "inline-b.example"},
                ]
            }
        }
    )
    result = normalize_inline_relationships(
        context(),
        subject_file(),
        gti_object(payload),
        RELATIONSHIP_SPECS,
        max_per_relationship=5,
    )
    assert {obj.canonical_value for obj in result.objects} == {
        "inline-a.example",
        "inline-b.example",
    }


def test_inline_relationships_respect_the_per_relationship_cap() -> None:
    from ti_recon.providers.gti.normalizer import normalize_inline_relationships
    from ti_recon.providers.gti.relationships import RELATIONSHIP_SPECS

    payload = payloads.file_object(
        relationships={
            "contacted_domains": {
                "data": [{"type": "domain", "id": f"host{index}.example"} for index in range(20)]
            }
        }
    )
    result = normalize_inline_relationships(
        context(),
        subject_file(),
        gti_object(payload),
        RELATIONSHIP_SPECS,
        max_per_relationship=3,
    )
    assert len(result.objects) == 3


def test_the_adapter_and_client_expose_their_configuration() -> None:
    """Readable configuration, with no credential anywhere in it."""
    from pydantic import SecretStr

    from fixtures.gti.fake_client import FakeGTIClient, FakeGTIClientFactory
    from ti_recon.execution import ManualClock
    from ti_recon.providers.gti import DEFAULT_X_TOOL, GTIAdapter
    from ti_recon.providers.gti.client import VtPyGTIClient

    adapter = GTIAdapter(
        client_factory=FakeGTIClientFactory(client=FakeGTIClient()), clock=ManualClock()
    )
    assert adapter.config.x_tool == DEFAULT_X_TOOL
    assert adapter.lookup_policy.excluded_attributes == ("last_analysis_results",)

    client = VtPyGTIClient(SecretStr("vt-key-SHOULD-NOT-LEAK-12345"))
    assert client.config.x_tool == DEFAULT_X_TOOL
    assert "vt-key" not in client.config.model_dump_json()
