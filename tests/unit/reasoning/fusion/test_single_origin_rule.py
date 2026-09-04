"""One origin, two firm kinds of knowledge (Task 24).

The rule this suite pins: a firm curated verdict about the exact object *and*
a firm sandbox classification of the same object, from one origin, reach
MALICIOUS at MEDIUM. It counts propositions -- different questions with
compatible answers -- never records, never providers, and never a hedge. Every
test below is written in generic vocabulary, and the last ones drive the real
GTI translator over GTI-shaped records so the two live cases have a
deterministic twin: a known-malware sample (verdict plus sandbox), and a test
artifact where the same two claims are fully explained.
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
from ti_recon.enums import EvidenceClass, EvidenceEffect, MatchScope, Verdict
from ti_recon.reasoning.fusion import (
    CONFIDENCE_RULES,
    VERDICT_RULES,
    AssessmentConfidence,
    ContributionRole,
    SupportBreadth,
)
from ti_recon.reasoning.fusion.policy import FUSION_POLICY_VERSION, REASON_CODES

SHA = "b" * 64


def _pair(family: str = "alpha"):
    sample = file_object(sha256=SHA)
    verdict = evidence(sample, claim_type=f"{family}_verdict", provider=family)
    sandbox = evidence(sample, claim_type=f"{family}_sandbox", provider=family)
    scene = scenario(sample).with_envelope(
        envelope(verdict, sandbox, provider=family, objects=(sample,))
    )
    semantics = {verdict.id: "malicious_reputation", sandbox.id: "sandbox_classification"}
    return sample, verdict, sandbox, scene, semantics


def test_the_policy_version_moved_with_the_rule() -> None:
    assert FUSION_POLICY_VERSION == "1.1.0"
    assert VERDICT_RULES["malicious_single_origin"].endswith(".v1")


def test_a_firm_verdict_and_a_firm_sandbox_classification_from_one_origin_reach_malicious() -> None:
    _, verdict, sandbox, scene, semantics = _pair()

    result = fuse_with_semantics(scene, semantics)

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert result.assessment.verdict_rule_id == VERDICT_RULES["malicious_single_origin"]
    basis = result.contributions_with_role(ContributionRole.SUPPORTS_VERDICT)
    assert {item.evidence_id for item in basis} == {verdict.id, sandbox.id}
    for item in basis:
        assert REASON_CODES["compatible_same_origin"] in item.reason_codes


def test_that_verdict_is_medium_confidence_and_never_high() -> None:
    """Nobody independent agreed, and the band says so by name."""
    _, _, _, scene, semantics = _pair()

    result = fuse_with_semantics(scene, semantics)

    assert result.assessment.confidence is AssessmentConfidence.MEDIUM
    assert result.assessment.confidence_rule_id == CONFIDENCE_RULES["medium_single_origin"]
    assert result.assessment.confidence_caps == ()


def test_a_firm_sandbox_classification_alone_stops_at_suspicious() -> None:
    sample = file_object(sha256=SHA)
    sandbox = evidence(sample, claim_type="alpha_sandbox")
    scene = scenario(sample).with_envelope(envelope(sandbox, objects=(sample,)))

    result = fuse_with_semantics(scene, {sandbox.id: "sandbox_classification"})

    assert result.assessment.verdict is Verdict.SUSPICIOUS
    assert result.assessment.verdict_rule_id == VERDICT_RULES["suspicious_residual"]


def test_a_firm_verdict_alone_still_stops_at_suspicious() -> None:
    sample = file_object(sha256=SHA)
    verdict = evidence(sample, claim_type="alpha_verdict")
    scene = scenario(sample).with_envelope(envelope(verdict, objects=(sample,)))

    result = fuse_with_semantics(scene, {verdict.id: "malicious_reputation"})

    assert result.assessment.verdict is Verdict.SUSPICIOUS


def test_a_hedged_verdict_beside_a_firm_sandbox_classification_does_not_qualify() -> None:
    """ "Suspicious" is not "malicious", and the rule needs two firm answers."""
    _, verdict, _, scene, semantics = _pair()

    result = fuse_with_semantics(scene, semantics, strengths={verdict.id: "suspected"})

    assert result.assessment.verdict is Verdict.SUSPICIOUS
    assert result.assessment.verdict_rule_id != VERDICT_RULES["malicious_single_origin"]


def test_an_aggregate_never_participates() -> None:
    """A roll-up of other vendors' opinions is weak, and weak is not a kind of
    knowledge this rule recognises."""
    sample = file_object(sha256=SHA)
    stats = evidence(
        sample, claim_type="alpha_stats", evidence_class=EvidenceClass.AGGREGATED_REPUTATION
    )
    sandbox = evidence(sample, claim_type="alpha_sandbox")
    scene = scenario(sample).with_envelope(envelope(stats, sandbox, objects=(sample,)))

    result = fuse_with_semantics(
        scene, {stats.id: "aggregated_reputation", sandbox.id: "sandbox_classification"}
    )

    assert result.assessment.verdict is Verdict.SUSPICIOUS


def test_many_sandbox_records_from_one_family_are_one_proposition_not_corroboration() -> None:
    """Five sandboxes are one source observing one sample, and one proposition
    repeated is not two kinds of knowledge."""
    sample = file_object(sha256=SHA)
    records = [
        evidence(sample, claim_type=f"alpha_sandbox_{index}", lineage_group_id="alpha:sandboxes")
        for index in range(5)
    ]
    scene = scenario(sample).with_envelope(envelope(*records, objects=(sample,)))

    result = fuse_with_semantics(scene, {item.id: "sandbox_classification" for item in records})

    assert result.assessment.verdict is Verdict.SUSPICIOUS
    groups = [
        g for g in result.corroboration_groups if g.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    ]
    assert all(g.breadth is SupportBreadth.ONE_INDEPENDENT_SOURCE for g in groups)


def test_incompatible_propositions_from_one_origin_do_not_qualify() -> None:
    """The compatibility table decides, never a name comparison: a verdict and
    an actor association are two different accusations."""
    sample = file_object(sha256=SHA)
    verdict = evidence(sample, claim_type="alpha_verdict")
    actor = evidence(sample, claim_type="alpha_actor")
    scene = scenario(sample).with_envelope(envelope(verdict, actor, objects=(sample,)))

    result = fuse_with_semantics(
        scene, {verdict.id: "malicious_reputation", actor.id: "threat_actor_association"}
    )

    assert result.assessment.verdict is Verdict.SUSPICIOUS


def test_host_scope_never_qualifies() -> None:
    sample = file_object(sha256=SHA)
    verdict = evidence(sample, claim_type="alpha_verdict", match_scope=MatchScope.SAME_HOST)
    sandbox = evidence(sample, claim_type="alpha_sandbox")
    scene = scenario(sample).with_envelope(envelope(verdict, sandbox, objects=(sample,)))

    result = fuse_with_semantics(
        scene, {verdict.id: "malicious_reputation", sandbox.id: "sandbox_classification"}
    )

    assert result.assessment.verdict is Verdict.SUSPICIOUS


def test_independent_corroboration_still_takes_precedence() -> None:
    sample = file_object(sha256=SHA)
    verdict = evidence(sample, claim_type="alpha_verdict", provider="alpha")
    sandbox = evidence(sample, claim_type="beta_sandbox", provider="beta")
    scene = (
        scenario(sample)
        .with_envelope(envelope(verdict, provider="alpha", objects=(sample,)))
        .with_envelope(envelope(sandbox, provider="beta", objects=(sample,)))
    )

    result = fuse_with_semantics(
        scene, {verdict.id: "malicious_reputation", sandbox.id: "sandbox_classification"}
    )

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert result.assessment.verdict_rule_id == VERDICT_RULES["malicious_corroborated"]


# --------------------------------------------------------------------------- #
# Explanations still come first
# --------------------------------------------------------------------------- #


def test_both_claims_explained_by_a_test_artifact_finding_reach_likely_benign() -> None:
    """The EICAR shape. Strong claims are still claims something can explain."""
    sample, verdict, sandbox, scene, semantics = _pair()
    scene = scene.with_finding(explanation(sample, verdict)).with_finding(
        explanation(sample, sandbox)
    )

    result = fuse_with_semantics(scene, semantics)

    assert result.assessment.verdict is Verdict.LIKELY_BENIGN
    assert result.assessment.verdict_rule_id == VERDICT_RULES["likely_benign_explained"]


def test_one_claim_explained_leaves_the_other_as_residual_suspicion_not_malicious() -> None:
    sample, verdict, sandbox, scene, semantics = _pair()
    scene = scene.with_finding(explanation(sample, verdict))

    result = fuse_with_semantics(scene, semantics)

    assert result.assessment.verdict is Verdict.SUSPICIOUS
    residual = result.contributions_with_role(ContributionRole.SUPPORTS_VERDICT)
    assert [item.evidence_id for item in residual] == [sandbox.id]


# --------------------------------------------------------------------------- #
# The two live cases, deterministically, through the real GTI translator
# --------------------------------------------------------------------------- #


def _gti_records(sample):
    assessment = evidence(
        sample,
        claim_type="gti_assessment",
        provider="gti",
        source_family="google_ti",
        lineage_group_id="google_ti:gti",
        attributes={"verdict": "VERDICT_MALICIOUS", "severity": "SEVERITY_HIGH"},
    )
    sandboxes = evidence(
        sample,
        claim_type="gti.sandbox_verdicts",
        provider="gti",
        source_family="google_ti",
        lineage_group_id="google_ti:gti",
        attributes={
            "verdict": "malicious",
            "malware_classification": ["RANSOM"],
            "sandbox_count": 3,
        },
    )
    return assessment, sandboxes


def test_a_known_malware_sample_shaped_gti_response_reaches_malicious_at_medium() -> None:
    """Only the semantics the live response would carry: GTI's own malicious
    verdict and its sandboxes' malicious classification. No hash, no family
    name, no sample-specific rule."""
    sample = file_object(sha256=SHA)
    assessment, sandboxes = _gti_records(sample)
    scene = scenario(sample).with_envelope(
        envelope(assessment, sandboxes, provider="gti", objects=(sample,))
    )

    result = fuse(scene)

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert result.assessment.verdict_rule_id == VERDICT_RULES["malicious_single_origin"]
    assert result.assessment.confidence is AssessmentConfidence.MEDIUM
    basis = result.contributions_with_role(ContributionRole.SUPPORTS_VERDICT)
    assert {item.evidence_id for item in basis} == {assessment.id, sandboxes.id}
    # The report will be able to say what GTI classified.
    sandbox_claim = result.claim(next(c.claim_id for c in basis if c.evidence_id == sandboxes.id))
    assert any(item.startswith("verdict: malicious") for item in sandbox_claim.highlights)


def test_a_test_artifact_shaped_gti_response_stays_likely_benign() -> None:
    """The same two strong claims, both accounted for by an exact-object
    test-artifact explanation: the pipeline order is candidate evidence, then
    explanation, then fusion -- and strength never skips the middle step."""
    sample = file_object(sha256=SHA)
    assessment, sandboxes = _gti_records(sample)
    scene = (
        scenario(sample)
        .with_envelope(envelope(assessment, sandboxes, provider="gti", objects=(sample,)))
        .with_finding(explanation(sample, assessment))
        .with_finding(explanation(sample, sandboxes))
    )

    result = fuse(scene)

    assert result.assessment.verdict is Verdict.LIKELY_BENIGN
    assert result.assessment.verdict_rule_id == VERDICT_RULES["likely_benign_explained"]
    assert result.contributions_with_role(ContributionRole.SUPPORTS_VERDICT) == ()


def test_a_sandbox_classification_without_a_gti_verdict_is_suspicious_with_a_real_basis() -> None:
    """What a VirusTotal-keyed account without the GTI assessment block sees:
    the sandboxes' verdict reaches the basis and is not weak, but one firm kind
    of knowledge is concern, not a malicious verdict."""
    sample = file_object(sha256=SHA)
    _, sandboxes = _gti_records(sample)
    stats = evidence(
        sample,
        claim_type="gti_analysis_stats",
        provider="gti",
        source_family="google_ti",
        lineage_group_id="google_ti:gti",
        evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
        attributes={"malicious": 60, "undetected": 5},
    )
    scene = scenario(sample).with_envelope(
        envelope(sandboxes, stats, provider="gti", objects=(sample,))
    )

    result = fuse(scene)

    assert result.assessment.verdict is Verdict.SUSPICIOUS
    basis = result.contributions_with_role(ContributionRole.SUPPORTS_VERDICT)
    assert sandboxes.id in {item.evidence_id for item in basis}
    assert "cap.single_weak_support.v1" not in result.assessment.confidence_caps
