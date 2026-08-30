"""What verdict follows, and what may corroborate what (Task 17).

Written in generic vocabulary -- synthetic families, claims described by semantic
and scope -- because the invariant is that fusion works for anything producing
those semantics, not for a particular vendor.

The recurring shape is a pair: one assertion about the verdict, and one about
what the verdict did *not* rest on. The second half is usually load-bearing.
"""

from __future__ import annotations

import pytest

from fixtures.fusion import (
    caution,
    envelope,
    evidence,
    explanation,
    file_object,
    fuse,
    fuse_as,
    fuse_with_semantics,
    observable,
    scenario,
)
from ti_recon.enums import EvidenceClass, EvidenceEffect, MatchScope, Verdict
from ti_recon.reasoning.false_positive.models import ReasonCode, ReasoningRole
from ti_recon.reasoning.fusion import (
    VERDICT_RULES,
    AssessmentConfidence,
    ClaimDecisionRole,
    ClaimDisposition,
    ContributionRole,
    SupportBreadth,
)

# --------------------------------------------------------------------------- #
# MALICIOUS
# --------------------------------------------------------------------------- #


def test_one_decisive_exact_claim_reaches_malicious_without_a_second_vote() -> None:
    """The case a voting engine gets wrong.

    One curated repository holding this exact file as a known malware sample is a
    statement about the artifact. Demanding a second provider before believing it
    would be treating specificity as if it were popularity.
    """
    sample = file_object(sha256="a" * 64)
    record = evidence(sample, claim_type="alpha_sample_record", provider="alpha")
    scene = scenario(sample).with_envelope(envelope(record, objects=(sample,)))

    result = fuse_as(scene, "malware_sample_identity")

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert result.assessment.verdict_rule_id == VERDICT_RULES["malicious_decisive"]
    basis = result.contributions_with_role(ContributionRole.SUPPORTS_VERDICT)
    assert [item.evidence_id for item in basis] == [record.id]
    assert basis[0].decision_role is ClaimDecisionRole.DECISIVE


def test_one_generic_reputation_claim_reaches_suspicious_not_malicious() -> None:
    """A provider saying "malicious" is not the same as a source saying what the
    artifact is. One generic reputation claim is a reason for concern, and
    concern is what SUSPICIOUS means."""
    target = observable("198.51.100.7")
    record = evidence(target, claim_type="alpha_reputation", provider="alpha")
    scene = scenario(target).with_envelope(envelope(record, objects=(target,)))

    result = fuse_as(scene, "malicious_reputation")

    assert result.assessment.verdict is Verdict.SUSPICIOUS
    assert result.assessment.verdict_rule_id == VERDICT_RULES["suspicious_residual"]


def test_two_independent_compatible_sources_can_reach_malicious() -> None:
    """Corroboration from genuinely separate origins.

    Two families, compatible propositions, neither explained. The result exposes
    independent support *groups* -- provenance structure -- and nothing anywhere
    calls them votes.
    """
    sample = file_object(sha256="b" * 64)
    first = evidence(sample, claim_type="alpha_reputation", provider="alpha")
    second = evidence(
        sample, claim_type="beta_sandbox", provider="beta", source_family="beta_family"
    )
    scene = (
        scenario(sample)
        .with_envelope(envelope(first, objects=(sample,)))
        .with_envelope(envelope(second, provider="beta", objects=(sample,)))
    )

    result = fuse_with_semantics(
        scene, {first.id: "malicious_reputation", second.id: "sandbox_classification"}
    )

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert result.assessment.verdict_rule_id == VERDICT_RULES["malicious_corroborated"]
    dumped = result.model_dump_json().lower()
    for word in ("vote", "provider_count", "detection_ratio"):
        assert word not in dumped


def test_two_providers_in_one_family_are_one_independent_origin() -> None:
    """Three abuse.ch datasets answering is one ecosystem agreeing with itself.

    Both claims are retained in full; what collapses is only the second one's
    ability to corroborate the first.
    """
    target = observable("198.51.100.8")
    first = evidence(target, claim_type="alpha_ioc", provider="alpha", source_family="shared")
    second = evidence(target, claim_type="beta_ioc", provider="beta", source_family="shared")
    scene = (
        scenario(target)
        .with_envelope(envelope(first, objects=(target,)))
        .with_envelope(envelope(second, provider="beta", objects=(target,)))
    )

    result = fuse_as(scene, "malicious_reputation")

    # Both survive.
    assert len(result.normalized_claims) == 2
    # One origin, so no corroborated-malicious rule fires.
    groups = [item for item in result.corroboration_groups if item.claim_ids]
    assert all(item.breadth is not SupportBreadth.MULTIPLE_INDEPENDENT_SOURCES for item in groups)
    assert result.assessment.verdict is Verdict.SUSPICIOUS
    dependent = result.contributions_with_role(ContributionRole.DEPENDENT_CORROBORATION)
    assert len(dependent) == 1


def test_a_relayed_finding_is_not_a_second_origin() -> None:
    """A ratio relayed through one transport and the direct result from its
    author are one upstream source arriving twice. Both stay visible."""
    target = observable("198.51.100.9")
    direct = evidence(
        target, claim_type="beta_reputation", provider="beta", source_family="upstream"
    )
    relayed = evidence(
        target,
        claim_type="alpha_relayed",
        provider="alpha",
        origin_provider="beta",
        source_family="upstream",
    )
    scene = (
        scenario(target)
        .with_envelope(envelope(relayed, objects=(target,)))
        .with_envelope(envelope(direct, provider="beta", objects=(target,)))
    )

    result = fuse_as(scene, "malicious_reputation")

    assert len(result.normalized_claims) == 2
    assert result.assessment.verdict is Verdict.SUSPICIOUS
    assert result.contributions_with_role(ContributionRole.DEPENDENT_CORROBORATION)


def test_incompatible_semantics_never_corroborate_each_other() -> None:
    """The Task 16 limitation, resolved.

    Two independent families, both pointing malicious, about the same address --
    but one says it scans the internet and the other says it serves command and
    control. Those are different accusations, so neither corroborates the other
    and the verdict does not escalate.
    """
    target = observable("162.142.125.1")
    scanner = evidence(target, claim_type="alpha_scanner", provider="alpha")
    c2 = evidence(target, claim_type="beta_c2", provider="beta", source_family="beta_family")
    scene = (
        scenario(target)
        .with_envelope(envelope(scanner, objects=(target,)))
        .with_envelope(envelope(c2, provider="beta", objects=(target,)))
    )

    result = fuse_with_semantics(scene, {scanner.id: "scanner_activity", c2.id: "c2_association"})

    # Two propositions, not one.
    assert len({item.proposition.ref for item in result.proposition_groups}) == 2
    assert result.assessment.verdict is Verdict.SUSPICIOUS
    assert result.assessment.verdict_rule_id != VERDICT_RULES["malicious_corroborated"]


def test_aggregated_reputation_never_corroborates_anything() -> None:
    """One source reporting forty opinions is one source.

    Two aggregates from two families still corroborate nothing, because letting
    them would be vendor counting with an extra step.
    """
    sample = file_object(sha256="c" * 64)
    first = evidence(
        sample,
        claim_type="alpha_aggregate",
        provider="alpha",
        evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
        attributes={"malicious": 40, "engines_total": 70},
    )
    second = evidence(
        sample,
        claim_type="beta_aggregate",
        provider="beta",
        source_family="beta_family",
        evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
    )
    scene = (
        scenario(sample)
        .with_envelope(envelope(first, objects=(sample,)))
        .with_envelope(envelope(second, provider="beta", objects=(sample,)))
    )

    result = fuse_as(scene, "aggregated_reputation")

    assert result.assessment.verdict is Verdict.SUSPICIOUS
    assert result.assessment.verdict_rule_id != VERDICT_RULES["malicious_corroborated"]
    assert result.assessment.confidence is not AssessmentConfidence.HIGH


# --------------------------------------------------------------------------- #
# INCONCLUSIVE
# --------------------------------------------------------------------------- #


def test_no_directional_evidence_is_inconclusive_not_benign() -> None:
    """Warninglist context, business-service context and shared hosting produce
    no claims at all, so there is nothing to assess.

    Absence of accusation is not evidence of innocence, and reporting it as
    LIKELY_BENIGN would be a clean-looking verdict on something never examined.
    """
    target = observable("203.0.113.7")
    context = evidence(
        target,
        claim_type="alpha_warninglist",
        effect=EvidenceEffect.CONTEXT_ONLY,
        evidence_class=EvidenceClass.CONTEXT,
    )
    scene = scenario(target).with_envelope(envelope(context, objects=(target,)))

    result = fuse(scene)

    assert result.assessment.verdict is Verdict.INCONCLUSIVE
    assert result.assessment.confidence is AssessmentConfidence.UNSPECIFIED
    assert result.normalized_claims == ()


def test_providers_returning_no_data_are_inconclusive() -> None:
    """A provider that looked and found nothing has told us about its coverage,
    not about the object."""
    from ti_recon.enums import ProviderRunStatus

    target = observable("203.0.113.8")
    scene = scenario(target)
    for name in ("alpha", "beta", "gamma"):
        scene.with_envelope(
            envelope(provider=name, objects=(target,), status=ProviderRunStatus.NO_DATA)
        )

    result = fuse(scene)

    assert result.assessment.verdict is Verdict.INCONCLUSIVE
    assert result.coverage.directional_evidence_examined == 0


# --------------------------------------------------------------------------- #
# Explanations
# --------------------------------------------------------------------------- #


def test_a_specifically_explained_classification_can_reach_likely_benign() -> None:
    """The narrow, legitimate path.

    A known test artifact, a malicious classification, and a Task 16 alternative
    explanation that specifically accounts for that classification. Nothing else
    unexplained.

    The source detection is retained in full -- it was not deleted, and the trace
    says the verdict did not rest on it rather than that the source was wrong.
    """
    sample = file_object(md5="44d88612fea8a8f36de82e1278abb02f")
    record = evidence(sample, claim_type="alpha_reputation", provider="alpha")
    scene = (
        scenario(sample)
        .with_envelope(envelope(record, objects=(sample,)))
        .with_finding(explanation(sample, record))
    )

    result = fuse_as(scene, "malicious_reputation")

    assert result.assessment.verdict is Verdict.LIKELY_BENIGN
    assert result.assessment.verdict_rule_id == VERDICT_RULES["likely_benign_explained"]
    # Retained, and visibly not relied upon.
    assert record.id in result.explained_evidence_ids
    explained = result.contributions_with_role(ContributionRole.EXPLAINED_NOT_RELIED_UPON)
    assert [item.evidence_id for item in explained] == [record.id]
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS


def test_an_explanation_does_not_cover_unrelated_malicious_evidence() -> None:
    """Test-artifact context accounts for a scanner flagging the file. It
    accounts for nothing a second, independent source separately claims."""
    sample = file_object(md5="44d88612fea8a8f36de82e1278abb02f")
    explained_record = evidence(sample, claim_type="alpha_reputation", provider="alpha")
    unrelated = evidence(
        sample, claim_type="beta_sample_record", provider="beta", source_family="beta_family"
    )
    scene = (
        scenario(sample)
        .with_envelope(envelope(explained_record, objects=(sample,)))
        .with_envelope(envelope(unrelated, provider="beta", objects=(sample,)))
        .with_finding(explanation(sample, explained_record))
    )

    result = fuse_with_semantics(
        scene,
        {
            explained_record.id: "malicious_reputation",
            unrelated.id: "malware_sample_identity",
        },
    )

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert unrelated.id in result.unexplained_directional_evidence_ids
    assert explained_record.id in result.explained_evidence_ids


@pytest.mark.parametrize(
    ("role", "reason", "dimension", "rule_key"),
    [
        (
            ReasoningRole.ATTRIBUTION_CAUTION,
            ReasonCode.SHARED_INFRASTRUCTURE_LIMITS_ATTRIBUTION,
            "attribution",
            "shared_infrastructure",
        ),
        (
            ReasoningRole.ATTRIBUTION_CAUTION,
            ReasonCode.COMPROMISED_INFRASTRUCTURE_SEPARATES_OWNER_FROM_ACTOR,
            "attribution",
            "compromised_infrastructure",
        ),
        (
            ReasoningRole.TEMPORAL_RELEVANCE,
            ReasonCode.CURRENT_INACTIVITY_DOES_NOT_ERASE_HISTORICAL_MALICIOUSNESS,
            "current_activity",
            "inactive_by_source",
        ),
        (
            ReasoningRole.ANALYSIS_QUALITY_LIMITATION,
            ReasonCode.SANDBOX_NEGATIVE_NOT_INFORMATIVE_WITHOUT_EXECUTION,
            "analysis_quality",
            "sandbox_low_execution",
        ),
        (
            ReasoningRole.INTERPRETATION_LIMITATION,
            ReasonCode.HOST_CONTEXT_DOES_NOT_EXPLAIN_EXACT_URL,
            "infrastructure_context",
            "host_context",
        ),
        (
            ReasoningRole.SOURCE_DEPENDENCE,
            ReasonCode.RELAYED_FINDINGS_NOT_INDEPENDENT,
            "source_independence",
            "relayed_source",
        ),
    ],
)
def test_no_caution_role_ever_marks_evidence_explained(
    role: ReasoningRole, reason: ReasonCode, dimension: str, rule_key: str
) -> None:
    """The most expensive possible bug, checked across every non-explanation role.

    An attribution caution says a compromised host has a victim. A temporal note
    says a malicious URL stopped serving. An analysis-quality limitation says a
    sandbox ran nothing. None of them says the detection was wrong, and treating
    any of them as an explanation would clear real evidence while producing a
    verdict that looked thoroughly reasoned.
    """
    from ti_recon.reasoning.false_positive.models import ReasoningDimension

    sample = file_object(sha256="d" * 64)
    record = evidence(sample, claim_type="alpha_sample_record", provider="alpha")
    scene = (
        scenario(sample)
        .with_envelope(envelope(record, objects=(sample,)))
        .with_finding(
            caution(
                sample,
                record,
                role=role,
                reason=reason,
                dimension=ReasoningDimension(dimension),
                rule_key=rule_key,
            )
        )
    )

    result = fuse_as(scene, "malware_sample_identity")

    assert result.explained_evidence_ids == ()
    assert record.id in result.unexplained_directional_evidence_ids
    assert result.assessment.verdict is Verdict.MALICIOUS
    # The caution is visible on the contribution, having qualified rather than
    # removed the support.
    contribution = result.contributions[0]
    assert contribution.disposition is ClaimDisposition.QUALIFIED_ONLY
    assert contribution.reasoning_finding_ids


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #


def test_a_host_scoped_claim_is_never_decisive() -> None:
    """A claim about the neighbourhood is not a claim about the artifact.

    Host-level suspicion has never established what a specific file or URL is,
    so it corroborates at most.
    """
    url = observable("https://common.example/bad/payload.exe")
    host_claim = evidence(
        url, claim_type="alpha_host_association", provider="alpha", match_scope=MatchScope.SAME_HOST
    )
    scene = scenario(url).with_envelope(envelope(host_claim, objects=(url,)))

    result = fuse_as(scene, "malware_distribution")

    assert result.assessment.verdict is Verdict.SUSPICIOUS
    assert result.contributions[0].decision_role is ClaimDecisionRole.CORROBORATIVE


def test_an_exact_malicious_url_survives_common_host_context() -> None:
    """The exact claim decides; the host caution rides alongside."""
    url = observable("https://common.example/bad/payload.exe")
    record = evidence(url, claim_type="alpha_malware_url", provider="alpha")
    scene = (
        scenario(url)
        .with_envelope(envelope(record, objects=(url,)))
        .with_finding(
            caution(
                url,
                record,
                role=ReasoningRole.INTERPRETATION_LIMITATION,
                reason=ReasonCode.HOST_CONTEXT_DOES_NOT_EXPLAIN_EXACT_URL,
                dimension=__import__(
                    "ti_recon.reasoning.false_positive.models", fromlist=["ReasoningDimension"]
                ).ReasoningDimension.INFRASTRUCTURE_CONTEXT,
                rule_key="host_context",
            )
        )
    )

    result = fuse_as(scene, "malware_distribution")

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert record.id in result.unexplained_directional_evidence_ids
