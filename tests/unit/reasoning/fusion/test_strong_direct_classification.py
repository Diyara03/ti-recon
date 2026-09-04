"""One strong direct origin can carry MALICIOUS; one weak origin cannot (Task 24 1B).

Source independence and evidence strength are different concepts. A claim
whose own provider qualified it ``STRONG_DIRECT`` -- several evaluations
agreeing, with stated confidence, no contrary verdict -- decides alone at
exact scope; an unqualified or not-strong sandbox classification corroborates
as before. Independence is still counted the same way: the strong claim is one
origin, so confidence stays at MEDIUM until a separate origin agrees, and the
alternative-explanation layer still runs first.
"""

from __future__ import annotations

from fixtures.fusion import (
    envelope,
    evidence,
    explanation,
    file_object,
    fuse,
    fuse_with_semantics,
    scenario,
)
from fixtures.gti import payloads
from ti_recon.enums import EvidenceClass, EvidenceEffect, MatchScope, Verdict
from ti_recon.reasoning.claims import ClaimQualification, ClaimSemantic, claim_from
from ti_recon.reasoning.claims.policy import CLAIM_SEMANTICS_POLICY_VERSION
from ti_recon.reasoning.fusion.models import (
    AssessmentConfidence,
    ClaimDecisionRole,
    ContributionRole,
    SupportBreadth,
)
from ti_recon.reasoning.fusion.policy import (
    CONFIDENCE_RULES,
    FUSION_POLICY_VERSION,
    QUALIFIED_DECISIVE_SEMANTICS,
    REASON_CODES,
    VERDICT_RULES,
    decision_role_for,
)

SHA = "f" * 64
SANDBOX = "sandbox_classification"
STRONG = ClaimQualification.STRONG_DIRECT.value


def _breadths(result):
    return {
        group.breadth
        for group in result.corroboration_groups
        if group.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    }


def _sandbox_record(sample, provider="alpha", **kwargs):
    return evidence(sample, claim_type=f"{provider}_sandbox", provider=provider, **kwargs)


# --------------------------------------------------------------------------- #
# Policy shape
# --------------------------------------------------------------------------- #


def test_the_policy_version_moved_with_the_qualification() -> None:
    assert FUSION_POLICY_VERSION == "1.2.0"
    assert CLAIM_SEMANTICS_POLICY_VERSION == "1.2.0"
    assert QUALIFIED_DECISIVE_SEMANTICS == frozenset({ClaimSemantic.SANDBOX_CLASSIFICATION})
    assert REASON_CODES["strong_direct"] == "basis.strong_direct_classification"


def test_decision_role_reads_the_qualification_and_nothing_else_new() -> None:
    sample = file_object(sha256=SHA)
    record = _sandbox_record(sample)
    base = {
        "policy_version": CLAIM_SEMANTICS_POLICY_VERSION,
        "semantic": ClaimSemantic.SANDBOX_CLASSIFICATION,
        "subject_key": sample.canonical_key,
    }
    assert decision_role_for(claim_from(record, **base)) is ClaimDecisionRole.CORROBORATIVE
    assert (
        decision_role_for(claim_from(record, qualification=ClaimQualification.NOT_STRONG, **base))
        is ClaimDecisionRole.CORROBORATIVE
    )
    assert (
        decision_role_for(
            claim_from(record, qualification=ClaimQualification.STRONG_DIRECT, **base)
        )
        is ClaimDecisionRole.DECISIVE
    )


def test_a_strong_qualification_does_not_rescue_a_hedged_claim_or_a_wider_scope() -> None:
    from ti_recon.reasoning.claims import ClaimAssertionStrength

    sample = file_object(sha256=SHA)
    hedged = claim_from(
        _sandbox_record(sample),
        policy_version=CLAIM_SEMANTICS_POLICY_VERSION,
        semantic=ClaimSemantic.SANDBOX_CLASSIFICATION,
        subject_key=sample.canonical_key,
        strength=ClaimAssertionStrength.SUSPECTED,
        qualification=ClaimQualification.STRONG_DIRECT,
    )
    host_scope = claim_from(
        _sandbox_record(sample, match_scope=MatchScope.SAME_HOST),
        policy_version=CLAIM_SEMANTICS_POLICY_VERSION,
        semantic=ClaimSemantic.SANDBOX_CLASSIFICATION,
        subject_key=sample.canonical_key,
        qualification=ClaimQualification.STRONG_DIRECT,
    )
    other_semantic = claim_from(
        _sandbox_record(sample),
        policy_version=CLAIM_SEMANTICS_POLICY_VERSION,
        semantic=ClaimSemantic.MALICIOUS_REPUTATION,
        subject_key=sample.canonical_key,
        qualification=ClaimQualification.STRONG_DIRECT,
    )
    assert decision_role_for(hedged) is ClaimDecisionRole.WEAK
    assert decision_role_for(host_scope) is ClaimDecisionRole.CORROBORATIVE
    assert decision_role_for(other_semantic) is ClaimDecisionRole.CORROBORATIVE


# --------------------------------------------------------------------------- #
# Verdict and confidence, generically
# --------------------------------------------------------------------------- #


def test_a_strong_direct_sandbox_claim_alone_reaches_malicious_at_medium() -> None:
    """Case A: strong, exact, unexplained, unopposed, one origin."""
    sample = file_object(sha256=SHA)
    record = _sandbox_record(sample)
    scene = scenario(sample).with_envelope(envelope(record, provider="alpha", objects=(sample,)))

    result = fuse_with_semantics(scene, {record.id: SANDBOX}, qualifications={record.id: STRONG})

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert result.assessment.verdict_rule_id == VERDICT_RULES["malicious_decisive"]
    assert result.assessment.confidence is AssessmentConfidence.MEDIUM
    assert result.assessment.confidence_rule_id == CONFIDENCE_RULES["medium_decisive"]
    assert _breadths(result) == {SupportBreadth.ONE_INDEPENDENT_SOURCE}
    basis = result.contributions_with_role(ContributionRole.SUPPORTS_VERDICT)
    assert [item.decision_role for item in basis] == [ClaimDecisionRole.DECISIVE]
    assert REASON_CODES["strong_direct"] in basis[0].reason_codes
    assert REASON_CODES["decisive_basis"] in basis[0].reason_codes


def test_an_unqualified_sandbox_claim_alone_still_reaches_only_suspicious() -> None:
    sample = file_object(sha256=SHA)
    record = _sandbox_record(sample)
    scene = scenario(sample).with_envelope(envelope(record, provider="alpha", objects=(sample,)))

    for qualification in ("unqualified", "not_strong"):
        result = fuse_with_semantics(
            scene, {record.id: SANDBOX}, qualifications={record.id: qualification}
        )
        assert result.assessment.verdict is Verdict.SUSPICIOUS, qualification
        assert result.assessment.confidence is AssessmentConfidence.LOW


def test_a_complete_test_artifact_explanation_consumes_the_strong_claim() -> None:
    """Case B: strength is not a shortcut past false-positive reasoning."""
    sample = file_object(sha256=SHA)
    record = _sandbox_record(sample)
    scene = (
        scenario(sample)
        .with_envelope(envelope(record, provider="alpha", objects=(sample,)))
        .with_finding(explanation(sample, record))
    )

    result = fuse_with_semantics(scene, {record.id: SANDBOX}, qualifications={record.id: STRONG})

    assert result.assessment.verdict is Verdict.LIKELY_BENIGN
    assert result.assessment.verdict_rule_id == VERDICT_RULES["likely_benign_explained"]
    explained = result.contributions_with_role(ContributionRole.EXPLAINED_NOT_RELIED_UPON)
    assert [item.claim_id for item in explained] == [
        item.claim_id for item in result.normalized_claims
    ]
    assert result.contributions_with_role(ContributionRole.SUPPORTS_VERDICT) == ()


def test_an_independent_origin_agreeing_widens_breadth_and_keeps_the_verdict() -> None:
    """Independence is counted exactly as before: the second family is a second
    independent source in the corroboration record. The band stays MEDIUM
    because the existing model reserves HIGH for two *decisive* origins -- a
    pre-existing rule this change does not touch."""
    sample = file_object(sha256=SHA)
    strong = _sandbox_record(sample)
    other = evidence(sample, claim_type="beta_reputation", provider="beta", source_family="beta")
    scene = (
        scenario(sample)
        .with_envelope(envelope(strong, provider="alpha", objects=(sample,)))
        .with_envelope(envelope(other, provider="beta", objects=(sample,)))
    )

    result = fuse_with_semantics(
        scene,
        {strong.id: SANDBOX, other.id: "malicious_reputation"},
        qualifications={strong.id: STRONG},
    )

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert result.assessment.verdict_rule_id == VERDICT_RULES["malicious_decisive"]
    assert result.assessment.confidence is AssessmentConfidence.MEDIUM
    assert {item.source_family for item in result.normalized_claims} == {"alpha", "beta"}


def test_a_same_origin_second_record_does_not_lift_the_band() -> None:
    """Case F: many records from one family remain one independent source."""
    sample = file_object(sha256=SHA)
    strong = _sandbox_record(sample)
    aggregate = evidence(
        sample,
        claim_type="alpha_stats",
        provider="alpha",
        evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
    )
    scene = scenario(sample).with_envelope(
        envelope(strong, aggregate, provider="alpha", objects=(sample,))
    )

    result = fuse_with_semantics(
        scene,
        {strong.id: SANDBOX, aggregate.id: "aggregated_reputation"},
        qualifications={strong.id: STRONG},
    )

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert result.assessment.confidence is AssessmentConfidence.MEDIUM
    assert _breadths(result) == {SupportBreadth.ONE_INDEPENDENT_SOURCE}


def test_a_benign_assertion_against_a_strong_claim_is_a_conflict_not_a_verdict() -> None:
    sample = file_object(sha256=SHA)
    strong = _sandbox_record(sample)
    benign = evidence(
        sample,
        claim_type="beta_verdict",
        provider="beta",
        source_family="beta",
        effect=EvidenceEffect.SUPPORTS_BENIGN,
    )
    scene = (
        scenario(sample)
        .with_envelope(envelope(strong, provider="alpha", objects=(sample,)))
        .with_envelope(envelope(benign, provider="beta", objects=(sample,)))
    )

    result = fuse_with_semantics(
        scene,
        {strong.id: SANDBOX, benign.id: "benign_reputation"},
        qualifications={strong.id: STRONG},
    )

    assert result.assessment.verdict is not Verdict.LIKELY_BENIGN
    assert result.contributions_with_role(ContributionRole.OPPOSES_VERDICT)


# --------------------------------------------------------------------------- #
# Through the real GTI translator
# --------------------------------------------------------------------------- #


def _gti_sandbox_record(sample, block):
    """A ``gti.sandbox_verdicts`` record built by the real normalizer."""
    from datetime import UTC, datetime

    from ti_recon.providers.gti.client import GTIObject
    from ti_recon.providers.gti.normalizer import NormalizationContext, normalize_sandbox_verdicts

    context = NormalizationContext(
        investigation_id="inv-1",
        subject_object_id=sample.id,
        now=datetime(2026, 1, 1, tzinfo=UTC),
        raw_reference_id=None,
    )
    gti_object = GTIObject(
        object_type="file",
        object_id=sample.canonical_value,
        attributes={"sandbox_verdicts": block},
        relationships={},
        context_attributes={},
    )
    record = normalize_sandbox_verdicts(context, gti_object).evidence[0]
    return record.model_copy(update={"investigation_id": "inv-1"})


def _stats(sample):
    return evidence(
        sample,
        claim_type="gti_analysis_stats",
        provider="gti",
        source_family="google_ti",
        lineage_group_id="google_ti:gti",
        evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
        attributes={"malicious": 63, "undetected": 8},
    )


def _unanimous(count: int, confidence: int | None = 90):
    return payloads.sandbox_verdicts(
        *[(f"Sandbox {n}", "malicious", confidence, ("RANSOM", "TROJAN")) for n in range(count)]
    )


def test_a_unanimous_confident_gti_sandbox_block_reaches_malicious_at_medium() -> None:
    """The live shape: seven sandboxes, all malicious, confidence stated, an
    aggregate beside it, no GTI assessment block, one origin."""
    sample = file_object(sha256=SHA)
    sandboxes = _gti_sandbox_record(sample, _unanimous(7))
    scene = scenario(sample).with_envelope(
        envelope(sandboxes, _stats(sample), provider="gti", objects=(sample,))
    )

    result = fuse(scene)

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert result.assessment.verdict_rule_id == VERDICT_RULES["malicious_decisive"]
    assert result.assessment.confidence is AssessmentConfidence.MEDIUM
    assert result.assessment.confidence_rule_id == CONFIDENCE_RULES["medium_decisive"]
    assert _breadths(result) == {SupportBreadth.ONE_INDEPENDENT_SOURCE}
    claim = next(item for item in result.normalized_claims if item.evidence_id == sandboxes.id)
    assert claim.qualification is ClaimQualification.STRONG_DIRECT
    assert any(item.startswith("qualification: strong_direct") for item in claim.highlights)
    assert any(
        item.startswith("confidence: 7 of 7 malicious verdicts stated >= 50, 0 stated none")
        for item in claim.highlights
    )


def test_a_gti_sandbox_block_with_a_harmless_verdict_stays_suspicious() -> None:
    """Case G through the real translator: the contradiction is preserved on
    the record, defeats the qualification, and the verdict is concern."""
    sample = file_object(sha256=SHA)
    block = payloads.sandbox_verdicts(
        ("A", "malicious", 100, ("RANSOM",)),
        ("B", "malicious", 100, ("RANSOM",)),
        ("C", "malicious", 100, ("RANSOM",)),
        ("D", "harmless", 100, ()),
    )
    sandboxes = _gti_sandbox_record(sample, block)
    scene = scenario(sample).with_envelope(envelope(sandboxes, provider="gti", objects=(sample,)))

    result = fuse(scene)

    assert result.assessment.verdict is Verdict.SUSPICIOUS
    claim = next(item for item in result.normalized_claims if item.evidence_id == sandboxes.id)
    assert claim.qualification is ClaimQualification.NOT_STRONG
    assert "sandbox.harmless_verdict_present" in claim.qualification_reasons
    assert any(item == "divergent: True" for item in claim.highlights)


def test_one_malicious_gti_sandbox_among_disagreeing_peers_is_not_malicious() -> None:
    """Case C through the real translator."""
    sample = file_object(sha256=SHA)
    block = payloads.sandbox_verdicts(
        ("A", "malicious", None, ()),
        ("B", "suspicious", 60, ()),
        ("C", "undetected", None, ()),
    )
    sandboxes = _gti_sandbox_record(sample, block)
    scene = scenario(sample).with_envelope(envelope(sandboxes, provider="gti", objects=(sample,)))

    result = fuse(scene)

    assert result.assessment.verdict is Verdict.SUSPICIOUS


def test_suspicious_only_gti_sandboxes_never_reach_malicious() -> None:
    """Case D through the real translator."""
    sample = file_object(sha256=SHA)
    block = payloads.sandbox_verdicts(
        ("A", "suspicious", 100, ()), ("B", "suspicious", 100, ()), ("C", "suspicious", 100, ())
    )
    sandboxes = _gti_sandbox_record(sample, block)
    scene = scenario(sample).with_envelope(envelope(sandboxes, provider="gti", objects=(sample,)))

    result = fuse(scene)

    assert result.assessment.verdict is Verdict.SUSPICIOUS
    assert result.assessment.confidence is AssessmentConfidence.LOW


def test_a_test_artifact_explanation_still_wins_over_a_strong_gti_block() -> None:
    """Case B through the real translator: the EICAR shape."""
    sample = file_object(sha256=SHA)
    sandboxes = _gti_sandbox_record(sample, _unanimous(5, 100))
    stats = _stats(sample)
    scene = (
        scenario(sample)
        .with_envelope(envelope(sandboxes, stats, provider="gti", objects=(sample,)))
        .with_finding(explanation(sample, sandboxes))
        .with_finding(explanation(sample, stats))
    )

    result = fuse(scene)

    assert result.assessment.verdict is Verdict.LIKELY_BENIGN
    assert result.assessment.verdict_rule_id == VERDICT_RULES["likely_benign_explained"]
    assert result.contributions_with_role(ContributionRole.SUPPORTS_VERDICT) == ()
