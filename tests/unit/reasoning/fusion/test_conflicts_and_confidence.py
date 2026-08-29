"""Conflicts, confidence, and the rules that deliberately do not exist (Task 17).

Two themes. The first is that a disagreement is preserved rather than resolved:
nothing cancels, averages or picks a winner, and if no deterministic rule applies
the verdict says so.

The second is a set of rules TI Recon refuses to have. A low detection count, a
valid code signature, an absence of detections, a sandbox that ran nothing --
each is a plausible-sounding path to "benign" that this system will not take, and
each has a regression here saying so.
"""

from __future__ import annotations

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
from ti_recon.enums import EvidenceClass, EvidenceEffect, Verdict
from ti_recon.reasoning.false_positive.models import (
    FindingLimitation,
    ReasonCode,
    ReasoningDimension,
    ReasoningRole,
)
from ti_recon.reasoning.fusion import (
    CONFIDENCE_CAPS,
    STIX_CONFIDENCE,
    VERDICT_RULES,
    AssessmentConfidence,
)

# --------------------------------------------------------------------------- #
# Conflict
# --------------------------------------------------------------------------- #


def test_opposing_independent_claims_are_preserved_not_cancelled() -> None:
    """Same object, same proposition, opposite directions, two families.

    Nothing cancels to zero. Both sides stay in the trace with their own
    provenance, and the verdict is reached by a named rule rather than by
    arithmetic that happened to land somewhere.
    """
    sample = file_object(sha256="a" * 64)
    malicious = evidence(sample, claim_type="alpha_reputation", provider="alpha")
    benign = evidence(
        sample,
        claim_type="beta_reputation",
        provider="beta",
        source_family="beta_family",
        effect=EvidenceEffect.SUPPORTS_BENIGN,
    )
    scene = (
        scenario(sample)
        .with_envelope(envelope(malicious, objects=(sample,)))
        .with_envelope(envelope(benign, provider="beta", objects=(sample,)))
    )

    result = fuse_with_semantics(
        scene, {malicious.id: "malicious_reputation", benign.id: "malicious_reputation"}
    )

    assert len(result.conflicts) == 1
    conflict = result.conflicts[0]
    assert conflict.malicious_claim_ids and conflict.benign_claim_ids
    assert conflict.malicious_source_families == ("alpha",)
    assert conflict.benign_source_families == ("beta_family",)

    # Residual malicious support exists, so the verdict is affirmative concern
    # rather than a shrug -- and the conflict caps confidence.
    assert result.assessment.verdict is Verdict.SUSPICIOUS
    assert result.assessment.verdict_rule_id == VERDICT_RULES["suspicious_conflict"]
    assert CONFIDENCE_CAPS["unresolved_conflict"] in result.assessment.confidence_caps
    assert result.assessment.confidence is not AssessmentConfidence.HIGH

    dumped = result.model_dump_json().lower()
    for word in ("cancel", "balance", "winner", "net_score"):
        assert word not in dumped


def test_a_conflict_between_weak_claims_only_is_inconclusive() -> None:
    """When both sides are weak, there is no residual concern to report.

    SUSPICIOUS means affirmative reason for worry. Two aggregates disagreeing is
    not that; it is a picture the engine cannot resolve.
    """
    sample = file_object(sha256="b" * 64)
    malicious = evidence(
        sample,
        claim_type="alpha_aggregate",
        provider="alpha",
        evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
    )
    benign = evidence(
        sample,
        claim_type="beta_aggregate",
        provider="beta",
        source_family="beta_family",
        evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
        effect=EvidenceEffect.SUPPORTS_BENIGN,
    )
    scene = (
        scenario(sample)
        .with_envelope(envelope(malicious, objects=(sample,)))
        .with_envelope(envelope(benign, provider="beta", objects=(sample,)))
    )

    result = fuse_as(scene, "aggregated_reputation")

    assert result.assessment.verdict is Verdict.INCONCLUSIVE
    assert result.assessment.verdict_rule_id == VERDICT_RULES["inconclusive_conflict"]
    assert len(result.conflicts) == 1


def test_different_dimensions_are_not_a_conflict() -> None:
    """A malicious sample and a scanner classification about different subjects
    are two facts, not a disagreement.

    Conflicts need the same subject, the same semantic and the same scope. Tasks
    15 and 16 already established that offline URLs, shared hosting and resolver
    contacts are different questions rather than contradictions.
    """
    sample = file_object(sha256="c" * 64)
    address = observable("198.51.100.7")
    identity = evidence(sample, claim_type="alpha_sample", provider="alpha")
    scanner = evidence(
        address, claim_type="beta_scanner", provider="beta", source_family="beta_family"
    )
    scene = (
        scenario(sample)
        .with_envelope(envelope(identity, objects=(sample,)))
        .with_envelope(envelope(scanner, provider="beta", objects=(address,)))
    )

    result = fuse_with_semantics(
        scene, {identity.id: "malware_sample_identity", scanner.id: "scanner_activity"}
    )

    assert result.conflicts == ()
    assert result.assessment.verdict is Verdict.MALICIOUS


# --------------------------------------------------------------------------- #
# Confidence
# --------------------------------------------------------------------------- #


def test_malicious_can_carry_medium_confidence() -> None:
    """One decisive source, unopposed and alone. A confident verdict about the
    object, and an honest admission that only one source said so."""
    sample = file_object(sha256="d" * 64)
    record = evidence(sample, claim_type="alpha_sample", provider="alpha")
    scene = scenario(sample).with_envelope(envelope(record, objects=(sample,)))

    result = fuse_as(scene, "malware_sample_identity")

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert result.assessment.confidence is AssessmentConfidence.MEDIUM


def test_confidence_is_not_derived_from_verdict_severity() -> None:
    """A stronger verdict does not mean a firmer one.

    Constructed so the MALICIOUS case is MEDIUM and a SUSPICIOUS case reaches at
    least the same band -- which is impossible if confidence is a function of
    verdict ordinal.
    """
    sample = file_object(sha256="e" * 64)
    decisive = evidence(sample, claim_type="alpha_sample", provider="alpha")
    malicious = fuse_as(
        scenario(sample).with_envelope(envelope(decisive, objects=(sample,))),
        "malware_sample_identity",
    )

    target = observable("198.51.100.20")
    first = evidence(target, claim_type="alpha_rep", provider="alpha")
    second = evidence(target, claim_type="beta_rep", provider="beta", source_family="beta_family")
    suspicious_scene = (
        scenario(target)
        .with_envelope(envelope(first, objects=(target,)))
        .with_envelope(envelope(second, provider="beta", objects=(target,)))
    )
    suspicious = fuse_with_semantics(
        suspicious_scene, {first.id: "scanner_activity", second.id: "c2_association"}
    )

    assert malicious.assessment.verdict is Verdict.MALICIOUS
    assert malicious.assessment.confidence is AssessmentConfidence.MEDIUM
    assert suspicious.assessment.verdict is Verdict.SUSPICIOUS
    # Both reach a real band; neither is ranked by its verdict.
    assert suspicious.assessment.confidence is not AssessmentConfidence.UNSPECIFIED


def test_only_canonical_stix_confidence_values_are_ever_produced() -> None:
    """15, 50, 85 or nothing. An assessment reporting 63 would be claiming a
    precision nobody measured."""
    assert set(STIX_CONFIDENCE.values()) == {None, 15, 50, 85}

    sample = file_object(sha256="f" * 64)
    record = evidence(sample, claim_type="alpha_sample", provider="alpha")
    result = fuse_as(
        scenario(sample).with_envelope(envelope(record, objects=(sample,))),
        "malware_sample_identity",
    )
    assert result.assessment.stix_confidence in {None, 15, 50, 85}


def test_a_partial_source_caps_confidence() -> None:
    from ti_recon.enums import ProviderRunStatus

    sample = file_object(sha256="1" * 64)
    record = evidence(sample, claim_type="alpha_sample", provider="alpha")
    scene = scenario(sample).with_envelope(
        envelope(record, objects=(sample,), status=ProviderRunStatus.PARTIAL)
    )

    result = fuse_as(scene, "malware_sample_identity")

    assert CONFIDENCE_CAPS["partial_source"] in result.assessment.confidence_caps
    assert result.assessment.confidence is AssessmentConfidence.LOW


def test_an_unclassified_basis_caps_confidence() -> None:
    """A claim nobody could interpret can never underwrite a firm assessment."""
    target = observable("198.51.100.30")
    record = evidence(target, claim_type="newprovider_finding", provider="newprovider")
    scene = scenario(target).with_envelope(
        envelope(record, provider="newprovider", objects=(target,))
    )

    result = fuse(scene)

    assert result.assessment.verdict is Verdict.SUSPICIOUS
    assert CONFIDENCE_CAPS["unclassified_basis"] in result.assessment.confidence_caps
    assert result.assessment.confidence is not AssessmentConfidence.HIGH
    assert result.coverage.claims_unclassified == 1
    assert result.issues


def test_an_unrelated_stale_dataset_does_not_cap_an_independent_assessment() -> None:
    """Task 16's stale-scoping fix, carried into fusion.

    A stale warninglist snapshot elsewhere in the run says nothing about an
    independent malware-sample claim. Capping that assessment's confidence would
    attach a caveat to evidence the stale data never touched -- the exact bug
    Task 16 fixed, and it would have reappeared here if the cap were run-level.
    """
    sample = file_object(sha256="2" * 64)
    other = observable("203.0.113.50")
    decisive = evidence(sample, claim_type="alpha_sample", provider="alpha")
    unrelated = evidence(other, claim_type="beta_rep", provider="beta", source_family="beta_family")

    scene = (
        scenario(sample)
        .with_envelope(envelope(decisive, objects=(sample,)))
        .with_envelope(envelope(unrelated, provider="beta", objects=(other,)))
        # The stale limitation sits on a finding about the *other* object.
        .with_finding(
            caution(
                other,
                unrelated,
                limitations=(FindingLimitation.SUPPORTING_CONTEXT_DATASET_STALE,),
            )
        )
    )
    scene.stale_context_datasets = 1

    result = fuse_with_semantics(
        scene,
        {decisive.id: "malware_sample_identity", unrelated.id: "malicious_reputation"},
    )

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert CONFIDENCE_CAPS["stale_supporting_context"] not in result.assessment.confidence_caps


def test_a_stale_dataset_the_verdict_relies_on_does_cap_confidence() -> None:
    """The other half: when the basis really did lean on the stale corpus."""
    sample = file_object(sha256="3" * 64)
    record = evidence(sample, claim_type="alpha_sample", provider="alpha")
    scene = (
        scenario(sample)
        .with_envelope(envelope(record, objects=(sample,)))
        .with_finding(
            caution(
                sample,
                record,
                limitations=(FindingLimitation.SUPPORTING_CONTEXT_DATASET_STALE,),
            )
        )
    )

    result = fuse_as(scene, "malware_sample_identity")

    assert CONFIDENCE_CAPS["stale_supporting_context"] in result.assessment.confidence_caps


def test_sandbox_divergence_caps_confidence_without_voting() -> None:
    """Environments disagreeing is a property of the sample. Neither result
    cancels the other, and nothing is averaged."""
    sample = file_object(sha256="4" * 64)
    record = evidence(sample, claim_type="alpha_sample", provider="alpha")
    scene = (
        scenario(sample)
        .with_envelope(envelope(record, objects=(sample,)))
        .with_finding(
            caution(
                sample,
                record,
                role=ReasoningRole.ANALYSIS_QUALITY_LIMITATION,
                reason=ReasonCode.SANDBOX_RESULT_ENVIRONMENT_DEPENDENT,
                dimension=ReasoningDimension.ANALYSIS_QUALITY,
                rule_key="sandbox_divergence",
            )
        )
    )

    result = fuse_as(scene, "malware_sample_identity")

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert CONFIDENCE_CAPS["sandbox_divergence"] in result.assessment.confidence_caps
    dumped = result.model_dump_json().lower()
    for word in ("average", "majority", "vote"):
        assert word not in dumped


# --------------------------------------------------------------------------- #
# The rules TI Recon refuses to have
# --------------------------------------------------------------------------- #


def test_a_low_detection_count_produces_no_benign_direction() -> None:
    """One engine out of sixty is not a false positive, and TI Recon counts no
    vendor votes.

    The counters sit on the evidence for an analyst to read. Nothing in fusion
    touches them, and the claim is an aggregate -- which corroborates nothing,
    including itself.
    """
    sample = file_object(sha256="5" * 64)
    aggregate = evidence(
        sample,
        claim_type="alpha_aggregate",
        provider="alpha",
        evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
        attributes={"malicious": 1, "undetected": 60, "engines_total": 61},
    )
    scene = scenario(sample).with_envelope(envelope(aggregate, objects=(sample,)))

    result = fuse_as(scene, "aggregated_reputation")

    assert result.assessment.verdict is not Verdict.LIKELY_BENIGN
    assert result.assessment.verdict is Verdict.SUSPICIOUS
    assert result.explained_evidence_ids == ()
    assert result.coverage.benign_directional_claims == 0


def test_a_code_signature_produces_no_benign_direction() -> None:
    """A valid signature establishes a publisher, not benign behaviour. Signing
    keys get stolen, and signed malware is ordinary."""
    sample = file_object(sha256="6" * 64)
    malicious = evidence(sample, claim_type="alpha_sample", provider="alpha")
    signing = evidence(
        sample,
        claim_type="alpha_code_signing",
        effect=EvidenceEffect.CONTEXT_ONLY,
        evidence_class=EvidenceClass.CONTEXT,
        attributes={"signed": True, "signature_valid": True, "subject_cn": "Example Ltd"},
    )
    scene = scenario(sample).with_envelope(envelope(malicious, signing, objects=(sample,)))

    result = fuse_as(scene, "malware_sample_identity")

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert result.coverage.benign_directional_claims == 0
    # The signing record is context and never became a claim at all.
    assert len(result.normalized_claims) == 1


def test_a_sandbox_that_observed_nothing_contributes_no_benign_direction() -> None:
    """Task 16 says a no-execution negative is uninformative. It is a limitation
    on the analysis, never support for benignness."""
    sample = file_object(sha256="7" * 64)
    reputation = evidence(sample, claim_type="alpha_reputation", provider="alpha")
    scene = (
        scenario(sample)
        .with_envelope(envelope(reputation, objects=(sample,)))
        .with_finding(
            caution(
                sample,
                reputation,
                role=ReasoningRole.ANALYSIS_QUALITY_LIMITATION,
                reason=ReasonCode.SANDBOX_NEGATIVE_NOT_INFORMATIVE_WITHOUT_EXECUTION,
                dimension=ReasoningDimension.ANALYSIS_QUALITY,
                rule_key="sandbox_low_execution",
            )
        )
    )

    result = fuse_as(scene, "malicious_reputation")

    assert result.assessment.verdict is Verdict.SUSPICIOUS
    assert result.explained_evidence_ids == ()
    assert reputation.id in result.unexplained_directional_evidence_ids
    assert result.coverage.benign_directional_claims == 0


def test_a_meaningful_negative_alone_does_not_reach_likely_benign() -> None:
    """More informative than a run that executed nothing, and still not a
    verdict. It cannot overturn a known-malware claim."""
    sample = file_object(sha256="8" * 64)
    identity = evidence(sample, claim_type="alpha_sample", provider="alpha")
    scene = (
        scenario(sample)
        .with_envelope(envelope(identity, objects=(sample,)))
        .with_finding(
            caution(
                sample,
                identity,
                role=ReasoningRole.ANALYSIS_QUALITY_LIMITATION,
                reason=ReasonCode.SANDBOX_NEGATIVE_REMAINS_NON_VERDICT,
                dimension=ReasoningDimension.ANALYSIS_QUALITY,
                rule_key="sandbox_meaningful_execution",
            )
        )
    )

    result = fuse_as(scene, "malware_sample_identity")

    assert result.assessment.verdict is Verdict.MALICIOUS


def test_a_genuine_benign_assertion_can_reach_likely_benign() -> None:
    """The other legitimate path: a provider actually asserting benignness, with
    nothing pointing the other way.

    Only a real directional claim qualifies -- warninglist context, popularity
    and an offline state never reach this rule because they are not claims.
    """
    sample = file_object(sha256="9" * 64)
    benign = evidence(
        sample,
        claim_type="alpha_benign",
        provider="alpha",
        effect=EvidenceEffect.SUPPORTS_BENIGN,
    )
    scene = scenario(sample).with_envelope(envelope(benign, objects=(sample,)))

    result = fuse_as(scene, "benign_reputation")

    assert result.assessment.verdict is Verdict.LIKELY_BENIGN
    assert result.assessment.verdict_rule_id == VERDICT_RULES["likely_benign_directional"]


def test_a_benign_assertion_does_not_override_unexplained_malicious_support() -> None:
    """One provider saying benign does not clear another provider's decisive
    claim. The disagreement is preserved."""
    sample = file_object(sha256="0" * 64)
    benign = evidence(
        sample,
        claim_type="alpha_benign",
        provider="alpha",
        effect=EvidenceEffect.SUPPORTS_BENIGN,
    )
    malicious = evidence(
        sample, claim_type="beta_sample", provider="beta", source_family="beta_family"
    )
    scene = (
        scenario(sample)
        .with_envelope(envelope(benign, objects=(sample,)))
        .with_envelope(envelope(malicious, provider="beta", objects=(sample,)))
    )

    result = fuse_with_semantics(
        scene, {benign.id: "benign_reputation", malicious.id: "malware_sample_identity"}
    )

    assert result.assessment.verdict is not Verdict.LIKELY_BENIGN
    assert malicious.id in result.unexplained_directional_evidence_ids


def test_an_explained_classification_still_loses_to_unexplained_behaviour() -> None:
    """Test-artifact context explains a scanner flagging the file, and explains
    nothing a separate decisive source claims."""
    sample = file_object(md5="44d88612fea8a8f36de82e1278abb02f")
    classification = evidence(sample, claim_type="alpha_reputation", provider="alpha")
    behaviour = evidence(
        sample,
        claim_type="beta_sandbox",
        provider="beta",
        source_family="beta_family",
        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
    )
    scene = (
        scenario(sample)
        .with_envelope(envelope(classification, objects=(sample,)))
        .with_envelope(envelope(behaviour, provider="beta", objects=(sample,)))
        .with_finding(explanation(sample, classification, opposing=(behaviour,)))
    )

    result = fuse_with_semantics(
        scene,
        {
            classification.id: "malicious_reputation",
            behaviour.id: "sandbox_classification",
        },
    )

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert classification.id in result.explained_evidence_ids
    assert behaviour.id in result.unexplained_directional_evidence_ids


def test_every_contribution_names_its_claim_and_reason() -> None:
    """No untraceable prose. Every claim that existed gets a contribution, and
    each one carries a role, a disposition and stable reason codes."""
    sample = file_object(sha256="ab" * 32)
    record = evidence(sample, claim_type="alpha_sample", provider="alpha")
    result = fuse_as(
        scenario(sample).with_envelope(envelope(record, objects=(sample,))),
        "malware_sample_identity",
    )

    assert len(result.contributions) == len(result.normalized_claims)
    for item in result.contributions:
        assert item.claim_id and item.evidence_id and item.proposition_ref
        assert item.reason_codes
    assert result.assessment.verdict_rule_id
    assert result.assessment.confidence_rule_id
