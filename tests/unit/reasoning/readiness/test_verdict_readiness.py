"""Readiness by assessment basis (Task 18).

The same coverage means different things depending on what the assessment rests
on. A decisive exact identification is not made more correct by another source;
a lone generic reputation claim genuinely could be. And a benign finding is an
absence, which is only as good as the search behind it — so it is held to a
stricter standard than a malicious one, without the verdict ever moving.

Every case here drives the real Task 17 engine, so readiness is always reasoning
about an assessment fusion actually reached.
"""

from __future__ import annotations

import pytest

from fixtures.readiness import (
    assess,
    attempt,
    coverage_item,
    file_object,
    observable,
    scenario,
    skipped,
)
from ti_recon.enums import (
    EvidenceEffect,
    InvestigationDepth,
    ProviderCapability,
    ProviderRunStatus,
    Verdict,
)
from ti_recon.planning.models import SkipReason
from ti_recon.reasoning.readiness import (
    ContinuationState,
    CoverageAdequacy,
    GapType,
    ReadinessStatus,
)

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
BEHAVIOUR = ProviderCapability.FILE_BEHAVIOR
THREAT = ProviderCapability.THREAT_ASSOCIATIONS


def _baseline_file(**claim):
    """A file whose REQUIRED and RELEVANT checks both ran."""
    root = file_object(sha256="a" * 64)
    return (
        scenario(root)
        .with_claim(**claim)
        .with_attempt(attempt(REPUTATION, provider="rep", source_family="fam_rep"))
        .with_attempt(attempt(INTELLIGENCE, provider="intel", source_family="fam_intel"))
        .with_coverage(coverage_item(REPUTATION))
        .with_coverage(coverage_item(INTELLIGENCE))
    )


# --------------------------------------------------------------------------- #
# MALICIOUS: a decisive identification does not need everything else
# --------------------------------------------------------------------------- #


def test_a_decisive_sample_is_ready_without_behavioural_coverage() -> None:
    """Sandbox unavailable, and the assessment is still usable.

    A curated repository holding this exact sample has established what the file
    is. A behavioural report would be interesting; demanding one before the
    external-TI picture counts as useful would make every known-malware
    identification permanently incomplete.
    """
    result = assess(
        _baseline_file(
            semantic="malware_sample_identity", provider="alpha", source_family="fam_a"
        ).with_attempt(
            attempt(BEHAVIOUR, provider="sandbox", status=ProviderRunStatus.NOT_CONFIGURED)
        )
    )

    assert result.verdict is Verdict.MALICIOUS
    assert result.readiness_status in {
        ReadinessStatus.READY,
        ReadinessStatus.READY_WITH_LIMITATIONS,
    }
    assert result.readiness_status is not ReadinessStatus.NEEDS_MORE_DATA
    assert not [gap for gap in result.gaps if gap.capability is BEHAVIOUR]


def test_an_exact_malicious_url_survives_missing_web_forensics() -> None:
    """Optional retrieval that never ran does not unmake an exact finding."""
    root = observable("http://malware.example/payload.bin")
    result = assess(
        scenario(root)
        .with_claim("malware_distribution", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(REPUTATION, provider="rep", source_family="fam_rep"))
        .with_attempt(attempt(ProviderCapability.WEB_BEHAVIOR, provider="web"))
        .with_coverage(coverage_item(REPUTATION))
    )

    assert result.verdict is Verdict.MALICIOUS
    assert result.coverage_adequacy is not CoverageAdequacy.INADEQUATE
    assert result.readiness_status is not ReadinessStatus.NEEDS_MORE_DATA


def test_a_budget_stop_does_not_make_a_decisive_assessment_unready() -> None:
    """The planner stopping is an operational fact, not a coverage verdict.

    What matters is whether anything *material* was still outstanding when it
    stopped — and against a decisive exact claim, an optional follow-up is not.
    """
    result = assess(
        _baseline_file(
            semantic="malware_sample_identity", provider="alpha", source_family="fam_a"
        ).with_skip(skipped(BEHAVIOUR, SkipReason.BUDGET_EXHAUSTED))
    )

    assert result.readiness_status is not ReadinessStatus.NEEDS_MORE_DATA


# --------------------------------------------------------------------------- #
# SUSPICIOUS: a thin basis makes remaining capabilities matter
# --------------------------------------------------------------------------- #


def test_suspicious_with_an_unrun_material_goal_needs_more_data() -> None:
    """Affirmative concern, and something applicable left unasked.

    At DEEP depth behavioural analysis is a RELEVANT goal, and a lone aggregated
    reputation claim is exactly the basis it could speak to. Budget ended the
    run; a larger one could continue it.
    """
    root = file_object(sha256="b" * 64)
    result = assess(
        scenario(root, depth=InvestigationDepth.DEEP)
        .with_claim("aggregated_reputation", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(REPUTATION, provider="alpha", source_family="fam_a"))
        .with_attempt(attempt(INTELLIGENCE, provider="intel", source_family="fam_intel"))
        .with_coverage(coverage_item(REPUTATION))
        .with_coverage(coverage_item(INTELLIGENCE))
        .with_skip(skipped(BEHAVIOUR, SkipReason.BUDGET_EXHAUSTED))
    )

    assert result.verdict is Verdict.SUSPICIOUS
    assert result.readiness_status is ReadinessStatus.NEEDS_MORE_DATA
    assert result.continuation_state is ContinuationState.MORE_DATA_AVAILABLE
    assert [gap.gap_type for gap in result.gaps if gap.capability is BEHAVIOUR] == [
        GapType.BUDGET_LIMITED
    ]


def test_suspicious_with_everything_asked_is_ready_with_limitations() -> None:
    """External TI has done what it can; the residual suspicion is the finding.

    This is a handoff, not a resolution — and calling it READY would suggest a
    completeness the analytical outcome does not have.
    """
    root = file_object(sha256="b" * 64)
    result = assess(
        scenario(root, depth=InvestigationDepth.DEEP)
        .with_claim("aggregated_reputation", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(REPUTATION, provider="alpha", source_family="fam_a"))
        .with_attempt(attempt(INTELLIGENCE, provider="intel", source_family="fam_i"))
        .with_attempt(attempt(BEHAVIOUR, provider="sandbox", status=ProviderRunStatus.NO_DATA))
        .with_attempt(attempt(THREAT, provider="threat", source_family="fam_t"))
        .with_coverage(coverage_item(REPUTATION))
        .with_coverage(coverage_item(INTELLIGENCE))
    )

    assert result.verdict is Verdict.SUSPICIOUS
    assert result.readiness_status in {
        ReadinessStatus.READY,
        ReadinessStatus.READY_WITH_LIMITATIONS,
    }
    assert result.continuation_state is ContinuationState.COMPLETE


# --------------------------------------------------------------------------- #
# INCONCLUSIVE: exhausted is not adequate
# --------------------------------------------------------------------------- #


def test_inconclusive_with_an_available_path_needs_more_data() -> None:
    """Nothing concluded, and somewhere left to look."""
    root = file_object(sha256="c" * 64)
    result = assess(scenario(root).with_coverage(coverage_item(REPUTATION)))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.readiness_status is ReadinessStatus.NEEDS_MORE_DATA
    assert result.continuation_state is ContinuationState.MORE_DATA_AVAILABLE


def test_inconclusive_with_everything_asked_is_unresolved_not_ready() -> None:
    """The distinction that matters most in this file.

    Every applicable source answered, and none of them knew anything. The search
    is finished and the question is open. Reporting that as READY would turn the
    absence of sources into the presence of an answer.
    """
    root = file_object(sha256="c" * 64)
    result = assess(
        scenario(root)
        .with_attempt(attempt(REPUTATION, provider="rep", status=ProviderRunStatus.NO_DATA))
        .with_attempt(attempt(INTELLIGENCE, provider="intel", status=ProviderRunStatus.NO_DATA))
        .with_attempt(
            attempt(
                ProviderCapability.FALSE_POSITIVE_CONTEXT,
                provider="local",
                status=ProviderRunStatus.NO_DATA,
            )
        )
        .with_coverage(coverage_item(REPUTATION))
        .with_coverage(coverage_item(INTELLIGENCE))
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.readiness_status is ReadinessStatus.UNRESOLVED
    assert result.coverage_adequacy is CoverageAdequacy.INADEQUATE
    assert result.continuation_state is ContinuationState.COMPLETE


def test_inconclusive_blocked_by_configuration_is_unresolved() -> None:
    """No credential, so the material check could not run at all.

    Blocked rather than exhausted: a credential can be supplied, and the result
    says so instead of implying the question is unanswerable.
    """
    root = file_object(sha256="c" * 64)
    result = assess(
        scenario(root)
        .with_attempt(attempt(REPUTATION, provider="rep", status=ProviderRunStatus.NOT_CONFIGURED))
        .with_attempt(
            attempt(INTELLIGENCE, provider="intel", status=ProviderRunStatus.NOT_CONFIGURED)
        )
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.readiness_status is ReadinessStatus.UNRESOLVED
    assert result.continuation_state is ContinuationState.BLOCKED
    assert GapType.NOT_CONFIGURED in {gap.gap_type for gap in result.gaps}


# --------------------------------------------------------------------------- #
# LIKELY_BENIGN: held to a stricter standard, without moving the verdict
# --------------------------------------------------------------------------- #


def _single_benign(root):
    """One source asserted benign, and only that source has looked at all.

    Every check comes from the same family on purpose. An adverse search from a
    *different* origin would itself satisfy the challenge, so a helper that
    quietly included one would make these tests pass for the wrong reason.
    """
    return (
        scenario(root)
        .with_claim(
            semantic="benign_reputation",
            provider="alpha",
            source_family="fam_a",
            effect=EvidenceEffect.SUPPORTS_BENIGN,
        )
        .with_attempt(attempt(REPUTATION, provider="alpha", source_family="fam_a"))
        .with_attempt(attempt(INTELLIGENCE, provider="alpha_intel", source_family="fam_a"))
        .with_coverage(coverage_item(REPUTATION))
        .with_coverage(coverage_item(INTELLIGENCE))
    )


def test_one_unchallenged_benign_source_is_not_fully_ready() -> None:
    """Nobody has tried to contradict it.

    Task 17 is right to state the verdict — a provider made an affirmative
    determination and nothing opposed it. Readiness asks a different question:
    has anything independent actually looked? Here nothing has.
    """
    result = assess(_single_benign(file_object(sha256="d" * 64)))

    assert result.verdict is Verdict.LIKELY_BENIGN
    assert result.readiness_status is ReadinessStatus.NEEDS_MORE_DATA
    assert GapType.INDEPENDENT_CHALLENGE_MISSING in {gap.gap_type for gap in result.gaps}


def test_an_independent_no_data_search_satisfies_the_challenge() -> None:
    """Somebody independent looked and found nothing. That is the requirement.

    The requirement is that a search happened, never that it found something —
    and the empty answer adds no benign evidence, which is why the verdict and
    confidence are identical either way.
    """
    root = file_object(sha256="d" * 64)
    unchallenged = assess(_single_benign(root))
    challenged = assess(
        _single_benign(root).with_attempt(
            attempt(
                THREAT,
                provider="gamma",
                source_family="fam_gamma",
                status=ProviderRunStatus.NO_DATA,
            )
        )
    )

    assert GapType.INDEPENDENT_CHALLENGE_MISSING not in {gap.gap_type for gap in challenged.gaps}
    assert challenged.readiness_status is not ReadinessStatus.NEEDS_MORE_DATA
    # Coverage improved; the assessment did not.
    assert challenged.verdict is unchallenged.verdict
    assert challenged.confidence is unchallenged.confidence


def test_a_same_family_search_does_not_challenge_anything() -> None:
    """Independence follows Task 17's provenance, not a count of providers.

    A second dataset from the organisation that made the benign claim has not
    challenged it; it has agreed with itself under a different name.
    """
    root = file_object(sha256="d" * 64)
    result = assess(
        _single_benign(root).with_attempt(
            attempt(
                THREAT,
                provider="alpha_two",
                source_family="fam_a",
                status=ProviderRunStatus.NO_DATA,
            )
        )
    )

    assert result.verdict is Verdict.LIKELY_BENIGN
    assert GapType.INDEPENDENT_CHALLENGE_MISSING in {gap.gap_type for gap in result.gaps}


def test_a_fully_explained_benign_result_needs_no_separate_challenge() -> None:
    """The explained route has already engaged with adverse evidence.

    There *was* malicious evidence, and every piece of it was accounted for
    individually at exact scope. That is a different epistemic position from one
    provider's unopposed say-so, and readiness treats it accordingly.
    """
    from fixtures.fusion import envelope, evidence, explanation, fuse_with_semantics
    from fixtures.fusion import scenario as fusion_scenario
    from fixtures.readiness import AS_OF  # noqa: F401  (documents the shared instant)
    from ti_recon.reasoning.readiness import AssessmentReadinessEngine

    sample = file_object(md5="44d88612fea8a8f36de82e1278abb02f")
    classification = evidence(sample, provider="alpha", source_family="fam_a")
    fusion = fuse_with_semantics(
        fusion_scenario(sample)
        .with_envelope(envelope(classification, provider="alpha", objects=(sample,)))
        .with_finding(explanation(sample, classification)),
        {classification.id: "malicious_reputation"},
    )
    scene = (
        scenario(sample)
        .with_attempt(attempt(REPUTATION, provider="alpha", source_family="fam_a"))
        .with_attempt(attempt(INTELLIGENCE, provider="intel", source_family="fam_intel"))
        .with_coverage(coverage_item(REPUTATION))
        .with_coverage(coverage_item(INTELLIGENCE))
    )
    result = AssessmentReadinessEngine().evaluate(
        fusion=fusion,
        planning=scene.planning(),
        qualification=scene.qualification(),
        reasoning=scene.reasoning(),
    )

    assert result.verdict is Verdict.LIKELY_BENIGN
    assert GapType.INDEPENDENT_CHALLENGE_MISSING not in {gap.gap_type for gap in result.gaps}
    assert result.readiness_status in {
        ReadinessStatus.READY,
        ReadinessStatus.READY_WITH_LIMITATIONS,
    }


# --------------------------------------------------------------------------- #
# Context never satisfies a directional need
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "capability",
    [ProviderCapability.FALSE_POSITIVE_CONTEXT, ProviderCapability.SCANNER_CONTEXT],
)
def test_context_capabilities_do_not_cover_directional_requirements(
    capability: ProviderCapability,
) -> None:
    """Warninglist and scanner context answer their own question and no other.

    Running them is real coverage of the context requirement. It leaves the
    reputation requirement exactly as unmet as it was.
    """
    root = observable("198.51.100.20")
    result = assess(
        scenario(root)
        .with_attempt(attempt(capability, provider="ctx", source_family="fam_ctx"))
        .with_coverage(coverage_item(capability))
    )

    unmet = {
        item.requirement.capability
        for item in result.requirement_evaluations
        if item.status.value == "unsatisfied"
    }
    assert REPUTATION in unmet
    assert result.readiness_status is not ReadinessStatus.READY
