"""Analysis quality, temporal relevance and source dependence (Task 16).

Four kinds of context that are cautionary without being candidate false
positives, and one that is a genuine disagreement Task 16 refuses to resolve.

The common failure these guard against is filing everything doubtful under
"potential false positive". A sandbox that ran nothing, a URL that stopped
serving, a finding that arrived through a relay and two sources that disagree are
four different problems with four different answers, and only one of them is even
adjacent to "the detection was wrong".
"""

from __future__ import annotations

from datetime import UTC, datetime

from fixtures.false_positive import (
    AS_OF,
    envelope,
    evidence,
    file_object,
    inactive_qualification,
    observable,
    scenario,
    signal,
)
from ti_recon.enums import EvidenceEffect, MatchScope
from ti_recon.reasoning.false_positive import (
    DoesNotEstablish,
    FalsePositiveReasoningEngine,
    FalsePositiveReasoningResult,
    LinkRelation,
    ReasonCode,
    ReasoningDimension,
    ReasoningRole,
)
from ti_recon.reasoning.models import ContextSignalType, SourceLifecycleState


def reason(scene: object) -> FalsePositiveReasoningResult:
    return FalsePositiveReasoningEngine().evaluate(
        qualification=scene.qualification(),  # type: ignore[attr-defined]
        results=scene.envelopes,  # type: ignore[attr-defined]
        graph=scene.graph,  # type: ignore[attr-defined]
        root=scene.root,  # type: ignore[attr-defined]
    )


# --------------------------------------------------------------------------- #
# Temporal relevance
# --------------------------------------------------------------------------- #


def test_current_inactivity_is_temporal_relevance_and_never_an_explanation() -> None:
    """A URL that distributed malware in March and stopped in April distributed
    malware.

    The source's current state answers a different question, and the finding is
    filed under a different role and dimension so nothing can read the two as
    being in conflict.
    """
    url = observable("https://malware.example/bin/loader.exe")
    malicious = evidence(url, claim_type="alpha_exact_url")
    scene = (
        scenario(url)
        .with_envelope(envelope(malicious, objects=(url,)))
        .with_temporal(inactive_qualification(url, malicious))
    )

    result = reason(scene)

    found = result.of_reason(ReasonCode.CURRENT_INACTIVITY_DOES_NOT_ERASE_HISTORICAL_MALICIOUSNESS)
    assert found
    assert found[0].role is ReasoningRole.TEMPORAL_RELEVANCE
    assert found[0].dimension is ReasoningDimension.CURRENT_ACTIVITY
    assert DoesNotEstablish.HISTORICAL_EVIDENCE_FALSE in found[0].does_not_establish

    # Never an explanation, and the evidence stays unaccounted for.
    assert result.of_role(ReasoningRole.ALTERNATIVE_EXPLANATION) == ()
    assert malicious.id not in result.explained_evidence_ids
    assert result.coverage.directional_evidence_without_explanations == 1
    # And the provider's own finding is untouched.
    assert malicious.effect is EvidenceEffect.SUPPORTS_MALICIOUS


def test_an_active_lifecycle_raises_no_temporal_finding() -> None:
    """The rule keys on the source's stated inactivity, not on age."""
    url = observable("https://malware.example/bin/loader.exe")
    malicious = evidence(url)
    scene = (
        scenario(url)
        .with_envelope(envelope(malicious, objects=(url,)))
        .with_temporal(
            inactive_qualification(url, malicious, lifecycle=SourceLifecycleState.ACTIVE_BY_SOURCE)
        )
    )
    assert reason(scene).of_role(ReasoningRole.TEMPORAL_RELEVANCE) == ()


def test_a_source_horizon_is_not_a_temporal_finding() -> None:
    """``WITHIN_SOURCE_API_HORIZON`` means the record has not expired from an
    API. It is not activity, not recency, and not a reason to doubt anything."""
    ip = observable("198.51.100.7")
    malicious = evidence(ip)
    scene = (
        scenario(ip)
        .with_envelope(envelope(malicious, objects=(ip,)))
        .with_temporal(
            inactive_qualification(
                ip, malicious, lifecycle=SourceLifecycleState.WITHIN_SOURCE_API_HORIZON
            )
        )
    )
    result = reason(scene)
    assert result.of_role(ReasoningRole.TEMPORAL_RELEVANCE) == ()
    assert result.of_role(ReasoningRole.ALTERNATIVE_EXPLANATION) == ()


def test_no_age_threshold_exists_anywhere_in_the_findings() -> None:
    """Old evidence is not suspect evidence.

    A two-year-old malware hash and a two-year-old cloud address age nothing
    alike, so this layer applies no threshold and the exact ages stay in Task 15
    where they belong.
    """
    url = observable("https://malware.example/old.exe")
    malicious = evidence(url)
    ancient = inactive_qualification(url, malicious, instant=datetime(2019, 1, 1, tzinfo=UTC))
    scene = scenario(url).with_envelope(envelope(malicious, objects=(url,))).with_temporal(ancient)

    result = reason(scene)
    dumped = result.model_dump_json().lower()
    for word in ("stale", "expired", "fresh", "days_threshold", "too_old"):
        assert word not in dumped
    assert result.of_role(ReasoningRole.ALTERNATIVE_EXPLANATION) == ()


# --------------------------------------------------------------------------- #
# Sandbox analysis quality
# --------------------------------------------------------------------------- #


def test_a_sandbox_that_executed_nothing_supports_no_explanation() -> None:
    """ "Nothing happened" and "nothing could have happened" must not read alike.

    The sample may have wanted a click, the wrong OS, a live C2, or have noticed
    it was being watched. The finding exists precisely so Task 17 cannot read the
    absence of findings as evidence of safety.
    """
    sample = file_object(sha256="a" * 64)
    reputation = evidence(sample, claim_type="alpha_reputation")
    scene = (
        scenario(sample)
        .with_envelope(envelope(reputation, objects=(sample,)))
        .with_signal(
            signal(sample, ContextSignalType.SANDBOX_LOW_EXECUTION, provider="sandbox_alpha")
        )
    )

    result = reason(scene)

    found = result.of_reason(ReasonCode.SANDBOX_NEGATIVE_NOT_INFORMATIVE_WITHOUT_EXECUTION)
    assert found
    assert found[0].role is ReasoningRole.ANALYSIS_QUALITY_LIMITATION
    assert DoesNotEstablish.OBJECT_BENIGN in found[0].does_not_establish

    # The final Task 16 invariant, in one assertion: the malicious evidence
    # remains unexplained and the sandbox negative is worth little.
    assert result.of_role(ReasoningRole.ALTERNATIVE_EXPLANATION) == ()
    assert reputation.id not in result.explained_evidence_ids
    assert result.coverage.directional_evidence_without_explanations == 1


def test_a_meaningful_negative_alone_is_still_not_an_explanation() -> None:
    """Better grounded than a run that executed nothing, and still one
    environment and still not a verdict."""
    sample = file_object(sha256="b" * 64)
    reputation = evidence(sample, claim_type="alpha_reputation")
    scene = (
        scenario(sample)
        .with_envelope(envelope(reputation, objects=(sample,)))
        .with_signal(
            signal(
                sample,
                ContextSignalType.SANDBOX_MEANINGFUL_EXECUTION,
                provider="sandbox_alpha",
            )
        )
    )

    result = reason(scene)

    assert result.of_reason(ReasonCode.SANDBOX_NEGATIVE_REMAINS_NON_VERDICT)
    assert result.of_role(ReasoningRole.ALTERNATIVE_EXPLANATION) == ()
    assert reputation.id not in result.explained_evidence_ids


def test_a_meaningful_negative_may_support_an_explanation_another_rule_earned() -> None:
    """Test-artifact context explains the classification; the sandbox result
    supports it.

    The distinction matters: the explanation exists because of what the object
    *is*, and the sandbox run is corroboration linked as ``SUPPORTED_BY`` rather
    than a second reason. Nothing is added up.
    """
    sample = file_object(md5="44d88612fea8a8f36de82e1278abb02f")
    classification = evidence(sample, claim_type="alpha_reputation")
    scene = (
        scenario(sample)
        .with_envelope(envelope(classification, objects=(sample,)))
        .with_signal(signal(sample, ContextSignalType.TEST_ARTIFACT, source_key="eicar.com"))
        .with_signal(
            signal(
                sample,
                ContextSignalType.SANDBOX_MEANINGFUL_EXECUTION,
                provider="sandbox_alpha",
            )
        )
    )

    result = reason(scene)

    explanation = result.of_reason(ReasonCode.EXPECTED_TEST_ARTIFACT_DETECTION)[0]
    assert explanation.explained_evidence_ids == (classification.id,)
    support = [link.ref for link in explanation.links if link.relation is LinkRelation.SUPPORTED_BY]
    assert len(support) == 2  # the test-artifact context and the sandbox run
    # Still no verdict, and the boundary travels with it.
    assert explanation.does_not_establish == (DoesNotEstablish.OBJECT_BENIGN,)


def test_environment_divergence_is_preserved_rather_than_voted_on() -> None:
    """Malicious on one machine and quiet on another is how targeted malware
    behaves. Neither result cancels the other."""
    sample = file_object(sha256="c" * 64)
    scene = scenario(sample).with_signal(
        signal(sample, ContextSignalType.SANDBOX_DIVERGENCE, provider="sandbox_alpha")
    )

    result = reason(scene)

    found = result.of_reason(ReasonCode.SANDBOX_RESULT_ENVIRONMENT_DEPENDENT)
    assert found
    assert found[0].role is ReasoningRole.ANALYSIS_QUALITY_LIMITATION
    assert result.of_role(ReasoningRole.ALTERNATIVE_EXPLANATION) == ()
    dumped = result.model_dump_json().lower()
    for word in ("average", "majority", "vote", "winner"):
        assert word not in dumped


# --------------------------------------------------------------------------- #
# Source dependence
# --------------------------------------------------------------------------- #


def test_a_relayed_finding_is_dependent_rather_than_doubted() -> None:
    """One upstream source arriving twice is one source.

    ``DEPENDENT_WITH`` rather than ``OPPOSES`` or ``LIMITS``: the finding is real
    and is not diminished. What the link says is that counting it beside the
    direct result would inflate one source into two.
    """
    url = observable("https://malware.example/bin/loader.exe")
    relayed = evidence(
        url,
        claim_type="alpha_relayed_reputation",
        provider="alpha",
        origin_provider="upstream",
        source_family="upstream_family",
        effect=EvidenceEffect.CONTEXT_ONLY,
    )
    direct = evidence(
        url,
        claim_type="beta_reputation",
        provider="beta",
        source_family="upstream_family",
    )
    scene = (
        scenario(url)
        .with_envelope(envelope(relayed, objects=(url,)))
        .with_envelope(envelope(direct, provider="beta", objects=(url,)))
        .with_signal(
            signal(
                url,
                ContextSignalType.RELAYED_SOURCE,
                provider="alpha",
                for_evidence=relayed,
                detail={"direct_family_present": True},
            )
        )
    )

    result = reason(scene)

    found = result.of_reason(ReasonCode.RELAYED_FINDINGS_NOT_INDEPENDENT)
    assert found
    assert found[0].role is ReasoningRole.SOURCE_DEPENDENCE
    assert found[0].dimension is ReasoningDimension.SOURCE_INDEPENDENCE
    assert DoesNotEstablish.INDEPENDENT_CORROBORATION in found[0].does_not_establish
    # Not doubted: nothing marks it false or opposes it.
    assert DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE in found[0].does_not_establish
    assert found[0].opposing_evidence_ids == ()
    assert [link.relation for link in found[0].links if link.ref == relayed.id] == [
        LinkRelation.DEPENDENT_WITH
    ]
    assert found[0].detail["direct_family_present"] is True


def test_two_providers_in_one_family_are_never_counted_as_confirmations() -> None:
    """Three sibling datasets agreeing is one ecosystem agreeing with itself.

    Nothing here counts them, and nothing exposes a field that could be read as a
    provider vote -- which is asserted directly rather than left to inspection.
    """
    ip = observable("198.51.100.7")
    first = evidence(ip, claim_type="alpha_ioc", provider="alpha", source_family="shared")
    second = evidence(ip, claim_type="beta_ioc", provider="beta", source_family="shared")
    scene = (
        scenario(ip)
        .with_envelope(envelope(first, objects=(ip,)))
        .with_envelope(envelope(second, provider="beta", objects=(ip,)))
    )

    result = reason(scene)

    dumped = result.model_dump_json().lower()
    for word in ("votes", "confirmations", "corroborations", "provider_count", "agree_count"):
        assert word not in dumped
    # Both remain individually visible and unexplained.
    assert result.coverage.directional_evidence_without_explanations == 2


# --------------------------------------------------------------------------- #
# Opposing evidence
# --------------------------------------------------------------------------- #


def test_opposing_directional_evidence_is_left_unresolved() -> None:
    """No vote, no balance, no winner.

    Both sides are linked, so Task 17 receives the disagreement intact rather
    than a number that hid it.
    """
    sample = file_object(sha256="d" * 64)
    malicious = evidence(sample, claim_type="alpha_reputation", provider="alpha")
    benign = evidence(
        sample,
        claim_type="beta_reputation",
        provider="beta",
        effect=EvidenceEffect.SUPPORTS_BENIGN,
    )
    scene = (
        scenario(sample)
        .with_envelope(envelope(malicious, objects=(sample,)))
        .with_envelope(envelope(benign, provider="beta", objects=(sample,)))
    )

    result = reason(scene)

    found = result.of_reason(ReasonCode.OPPOSING_DIRECTIONAL_EVIDENCE_UNRESOLVED)
    assert found
    tension = found[0]
    assert tension.role is ReasoningRole.UNRESOLVED_TENSION
    assert tension.opposing_evidence_ids == (benign.id,)
    assert {link.ref for link in tension.links if link.relation is LinkRelation.QUALIFIES} == {
        malicious.id
    }
    assert tension.detail["malicious_evidence"] == 1
    assert tension.detail["benign_evidence"] == 1
    assert tension.detail["source_families"] == 2
    # Nothing resolved it.
    assert tension.explained_evidence_ids == ()
    assert result.of_role(ReasoningRole.ALTERNATIVE_EXPLANATION) == ()


# --------------------------------------------------------------------------- #
# Stale supporting context
# --------------------------------------------------------------------------- #


def test_a_stale_context_dataset_annotates_rather_than_suppresses() -> None:
    """The list was right about EICAR last month and still is.

    So the explanation survives and carries a limitation naming its footing. A
    numerical penalty would be a made-up number standing in for a fact that is
    already available.
    """
    sample = file_object(md5="44d88612fea8a8f36de82e1278abb02f")
    classification = evidence(sample, claim_type="alpha_reputation")
    scene = (
        scenario(sample)
        .with_envelope(envelope(classification, objects=(sample,)))
        .with_signal(signal(sample, ContextSignalType.TEST_ARTIFACT, source_key="eicar.com"))
    )
    scene.stale_context_datasets = 1

    result = reason(scene)

    found = result.of_reason(ReasonCode.EXPECTED_TEST_ARTIFACT_DETECTION)
    assert found
    assert found[0].limitations == ("supporting_context_dataset_stale",)
    # Still explained, and no number was invented to discount it.
    assert found[0].explained_evidence_ids == (classification.id,)
    dumped = result.model_dump_json().lower()
    for word in ("penalty", "discount", "strength", "score"):
        assert word not in dumped


def test_a_partial_supporting_result_is_recorded_on_the_finding() -> None:
    sample = file_object(md5="44d88612fea8a8f36de82e1278abb02f")
    classification = evidence(sample, claim_type="alpha_reputation")
    scene = (
        scenario(sample)
        .with_envelope(envelope(classification, objects=(sample,)))
        .with_signal(
            signal(
                sample,
                ContextSignalType.TEST_ARTIFACT,
                source_key="eicar.com",
                source_partial=True,
            )
        )
    )

    found = reason(scene).of_reason(ReasonCode.EXPECTED_TEST_ARTIFACT_DETECTION)
    assert found[0].limitations == ("supporting_result_partial",)


# --------------------------------------------------------------------------- #
# Result metadata
# --------------------------------------------------------------------------- #


def test_the_result_carries_both_policy_versions_and_task_15s_as_of() -> None:
    """No clock of its own, and both versions recorded.

    A finding derived from context a later qualification policy would categorise
    differently is a finding somebody needs to be able to spot.
    """
    sample = file_object(sha256="e" * 64)
    scene = scenario(sample).with_signal(
        signal(sample, ContextSignalType.SANDBOX_DIVERGENCE, provider="sandbox_alpha")
    )

    result = reason(scene)

    assert result.as_of == AS_OF
    assert result.policy_version == "1.0.0"
    assert result.qualification_policy_version == "1.0.0"
    assert result.findings[0].policy_version == result.policy_version


def test_coverage_separates_explained_from_unexplained_evidence() -> None:
    """The split Task 17 needs, and the reason it is computed from the findings'
    own links rather than tracked beside them."""
    explained_sample = file_object(md5="44d88612fea8a8f36de82e1278abb02f")
    classification = evidence(explained_sample, claim_type="alpha_reputation")
    unexplained = evidence(
        explained_sample, claim_type="beta_ioc", provider="beta", match_scope=MatchScope.SAME_HOST
    )
    scene = (
        scenario(explained_sample)
        .with_envelope(envelope(classification, objects=(explained_sample,)))
        .with_envelope(envelope(unexplained, provider="beta", objects=(explained_sample,)))
        .with_signal(
            signal(explained_sample, ContextSignalType.TEST_ARTIFACT, source_key="eicar.com")
        )
    )

    result = reason(scene)

    assert result.explained_evidence_ids == (classification.id,)
    assert result.coverage.directional_evidence_examined == 2
    assert result.coverage.directional_evidence_with_explanations == 1
    # The host-scoped claim was never explained, and stays visible as such.
    assert result.coverage.directional_evidence_without_explanations == 1
    assert unexplained.id not in result.explained_evidence_ids
