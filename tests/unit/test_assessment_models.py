"""Assessment invariants (Task 3)."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from ti_recon.enums import (
    AssessmentState,
    ContributionRole,
    CoverageRelevance,
    CoverageStatus,
    ProviderCapability,
    Verdict,
)
from ti_recon.models import Assessment, AssessmentContribution, CoverageItem
from ti_recon.versions import ENGINE_VERSION, POLICY_VERSION


def make_assessment(**overrides: Any) -> Assessment:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "verdict": Verdict.SUSPICIOUS,
        "risk_score": 50.0,
        "confidence": 40.0,
        "assessment_state": AssessmentState.COMPLETE,
        "policy_version": POLICY_VERSION,
        "engine_version": ENGINE_VERSION,
    }
    kwargs.update(overrides)
    return Assessment(**kwargs)


def make_contribution(**overrides: Any) -> AssessmentContribution:
    kwargs: dict[str, Any] = {
        "assessment_id": "as-1",
        "evidence_id": "ev-1",
        "role": ContributionRole.SUPPORTING,
        "base_strength": 80.0,
        "effective_contribution": 80.0,
    }
    kwargs.update(overrides)
    return AssessmentContribution(**kwargs)


@pytest.mark.parametrize("score", [-0.1, 100.1])
def test_risk_score_range(score: float) -> None:
    with pytest.raises(ValidationError):
        make_assessment(risk_score=score)


@pytest.mark.parametrize("score", [-0.1, 100.1])
def test_confidence_range(score: float) -> None:
    with pytest.raises(ValidationError):
        make_assessment(confidence=score)


@pytest.mark.parametrize("score", [0.0, 50.0, 100.0])
def test_boundary_scores_are_accepted(score: float) -> None:
    assessment = make_assessment(risk_score=score, confidence=score)
    assert assessment.risk_score == score
    assert assessment.confidence == score


def test_verdict_and_state_are_separate_dimensions() -> None:
    assessment = make_assessment(
        verdict=Verdict.MALICIOUS,
        assessment_state=AssessmentState.INSUFFICIENT_COVERAGE,
    )
    assert assessment.verdict is Verdict.MALICIOUS
    assert assessment.assessment_state is AssessmentState.INSUFFICIENT_COVERAGE


def test_evidence_cannot_hold_two_roles() -> None:
    with pytest.raises(ValidationError, match="cannot be both"):
        make_assessment(
            supporting_evidence_refs=("ev-1", "ev-2"),
            benign_evidence_refs=("ev-2",),
        )


def test_context_and_supporting_roles_must_not_overlap() -> None:
    with pytest.raises(ValidationError, match="cannot be both"):
        make_assessment(
            supporting_evidence_refs=("ev-1",),
            context_evidence_refs=("ev-1",),
        )


def test_distinct_roles_are_accepted() -> None:
    assessment = make_assessment(
        supporting_evidence_refs=("ev-1",),
        benign_evidence_refs=("ev-2",),
        context_evidence_refs=("ev-3",),
        conflict_refs=("cf-1",),
    )
    assert assessment.supporting_evidence_refs == ("ev-1",)
    assert assessment.conflict_refs == ("cf-1",)


def test_assessment_records_versions() -> None:
    assessment = make_assessment()
    assert assessment.engine_version == ENGINE_VERSION
    assert assessment.policy_version == POLICY_VERSION


def test_coverage_gaps_are_surfaced_with_the_verdict() -> None:
    assessment = make_assessment(
        coverage=(
            CoverageItem(
                capability=ProviderCapability.REPUTATION,
                relevance=CoverageRelevance.RELEVANT,
                status=CoverageStatus.COVERED,
            ),
            CoverageItem(
                capability=ProviderCapability.MALWARE_INTELLIGENCE,
                relevance=CoverageRelevance.REQUIRED,
                status=CoverageStatus.NOT_COVERED,
                reason="no configured provider",
            ),
        )
    )
    gaps = assessment.coverage_gaps
    assert len(gaps) == 1
    assert gaps[0].capability is ProviderCapability.MALWARE_INTELLIGENCE


# --------------------------------------------------------------------------- #
# Contributions
# --------------------------------------------------------------------------- #


def test_contribution_is_immutable() -> None:
    contribution = make_contribution()
    with pytest.raises(ValidationError, match="frozen"):
        contribution.base_strength = 10.0


def test_contribution_keeps_factors_separate_from_base_strength() -> None:
    contribution = make_contribution(
        base_strength=100.0,
        freshness_factor=0.5,
        independence_factor=0.5,
        specificity_factor=1.0,
        false_positive_factor=1.0,
        effective_contribution=25.0,
    )
    assert contribution.base_strength == 100.0
    assert contribution.combined_factor == pytest.approx(0.25)
    assert contribution.effective_contribution == 25.0


def test_factors_default_to_neutral() -> None:
    contribution = make_contribution()
    assert contribution.combined_factor == 1.0


@pytest.mark.parametrize(
    "field",
    [
        "freshness_factor",
        "independence_factor",
        "specificity_factor",
        "false_positive_factor",
    ],
)
@pytest.mark.parametrize("value", [-0.01, 1.01])
def test_factors_are_bounded_dampeners(field: str, value: float) -> None:
    with pytest.raises(ValidationError):
        make_contribution(**{field: value})


def test_effective_contribution_cannot_exceed_base_strength() -> None:
    with pytest.raises(ValidationError, match="must not exceed base_strength"):
        make_contribution(base_strength=10.0, effective_contribution=20.0)


def test_context_contributions_must_not_move_the_score() -> None:
    with pytest.raises(ValidationError, match="must not move the score"):
        make_contribution(
            role=ContributionRole.CONTEXT,
            base_strength=10.0,
            effective_contribution=5.0,
        )


def test_context_contribution_with_zero_effect_is_valid() -> None:
    contribution = make_contribution(
        role=ContributionRole.CONTEXT,
        base_strength=0.0,
        effective_contribution=0.0,
        reason_codes=("relayed_via_transport_provider",),
    )
    assert contribution.reason_codes == ("relayed_via_transport_provider",)


def test_contribution_is_separate_from_evidence() -> None:
    """Interpretation must not be storable on the fact itself."""
    from ti_recon.models import Evidence

    interpretation_fields = {
        "base_strength",
        "freshness_factor",
        "independence_factor",
        "specificity_factor",
        "false_positive_factor",
        "effective_contribution",
    }
    assert set(Evidence.model_fields).isdisjoint(interpretation_fields)
