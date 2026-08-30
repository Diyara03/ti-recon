"""Was the check run, and what did it return? (Task 18)

The distinction the whole layer rests on. A source that was asked and answered
"nothing known about this" is not the same as a source nobody asked, and neither
is evidence that the observable is safe. Every test here exists to keep those
three states apart, because collapsing any pair of them produces a readiness
answer that is confidently wrong in a way nobody would notice.
"""

from __future__ import annotations

import pytest

from fixtures.readiness import assess, attempt, coverage_item, file_object, scenario
from ti_recon.enums import (
    CoverageStatus,
    ProviderCapability,
    ProviderRunStatus,
)
from ti_recon.planning.models import ProviderLocality
from ti_recon.reasoning.readiness import (
    STATUS_COMPLETION,
    CheckCompletion,
    InformationYield,
    RequirementStatus,
    completion_for,
)

CAPABILITY = ProviderCapability.REPUTATION


def _evaluation(result, capability: ProviderCapability):
    for item in result.requirement_evaluations:
        if item.requirement.capability is capability:
            return item
    raise AssertionError(f"no evaluation for {capability.value}")


def _reputation_scenario(**attempt_kwargs):
    """A file whose REQUIRED reputation check is the thing under test."""
    root = file_object(sha256="a" * 64)
    scene = scenario(root).with_claim(
        "malware_sample_identity", provider="alpha", source_family="fam_a"
    )
    if attempt_kwargs:
        scene = scene.with_attempt(attempt(CAPABILITY, **attempt_kwargs))
    return scene


# --------------------------------------------------------------------------- #
# The status matrix
# --------------------------------------------------------------------------- #


def test_every_provider_status_is_mapped_on_purpose() -> None:
    """No default branch, now or after someone adds a status.

    Defaulting an unknown status to "complete" would report an unasked question
    as answered; defaulting it to "blocked" would invent a gap. Either way the
    mistake is silent, so the table must be total.
    """
    assert set(STATUS_COMPLETION) == set(ProviderRunStatus)
    for status in ProviderRunStatus:
        assert completion_for(status) in set(CheckCompletion)


STATUS_EXPECTATIONS = {
    ProviderRunStatus.SUCCESS: CheckCompletion.COMPLETE,
    ProviderRunStatus.NO_DATA: CheckCompletion.COMPLETE,
    ProviderRunStatus.PARTIAL: CheckCompletion.PARTIAL,
    ProviderRunStatus.PLAN_LIMITED: CheckCompletion.PARTIAL,
    ProviderRunStatus.NOT_CONFIGURED: CheckCompletion.BLOCKED,
    ProviderRunStatus.QUOTA_EXCEEDED: CheckCompletion.BLOCKED,
    ProviderRunStatus.TEMPORARILY_UNAVAILABLE: CheckCompletion.BLOCKED,
    ProviderRunStatus.ERROR: CheckCompletion.BLOCKED,
    ProviderRunStatus.NOT_SUPPORTED: CheckCompletion.OUT_OF_SCOPE,
}


@pytest.mark.parametrize(
    "status,expected", sorted(STATUS_EXPECTATIONS.items(), key=lambda item: item[0].value)
)
def test_each_status_reaches_its_intended_completion(
    status: ProviderRunStatus, expected: CheckCompletion
) -> None:
    """Deliberate, per status, and asserted rather than assumed.

    ``NOT_SUPPORTED`` is the one worth reading twice: a source saying it cannot
    answer this question about this observable is not a failure and not a gap.
    Another source may serve the capability, and if none can, that is recorded
    as a catalogue fact instead.
    """
    assert completion_for(status) is expected


# --------------------------------------------------------------------------- #
# NO_DATA is not NOT_RUN
# --------------------------------------------------------------------------- #


def test_a_source_that_answered_nothing_is_not_a_source_nobody_asked() -> None:
    """The mandatory distinction, at the requirement level.

    Both scenarios end with no information about the observable. One of them
    asked; the other did not. Reporting them identically would let an
    unattempted check masquerade as an exhausted one.
    """
    answered = assess(_reputation_scenario(status=ProviderRunStatus.NO_DATA))
    never_asked = assess(_reputation_scenario())

    answered_evaluation = _evaluation(answered, CAPABILITY)
    unasked_evaluation = _evaluation(never_asked, CAPABILITY)

    assert answered_evaluation.completion is CheckCompletion.COMPLETE
    assert answered_evaluation.information_yield is InformationYield.NO_DATA
    assert answered_evaluation.status is RequirementStatus.SATISFIED

    assert unasked_evaluation.completion is CheckCompletion.NOT_ATTEMPTED
    assert unasked_evaluation.information_yield is InformationYield.NONE
    assert unasked_evaluation.status is RequirementStatus.UNSATISFIED

    assert answered.readiness_status is not never_asked.readiness_status


def test_no_data_never_becomes_benign_evidence() -> None:
    """Coverage improved; the assessment did not move an inch.

    A source holding nothing about an observable is true of everything nobody
    has caught yet. Task 17 refuses it a direction, and readiness counting it as
    coverage must not smuggle one back in.
    """
    answered = assess(_reputation_scenario(status=ProviderRunStatus.NO_DATA))
    never_asked = assess(_reputation_scenario())

    assert answered.verdict is never_asked.verdict
    assert answered.confidence is never_asked.confidence
    assert answered.verdict_rule_id == never_asked.verdict_rule_id


def test_completed_no_data_counts_in_the_coverage_summary() -> None:
    """Visible as what it is: a completed check that yielded nothing."""
    result = assess(_reputation_scenario(status=ProviderRunStatus.NO_DATA))

    assert result.coverage_summary.checks_complete == 1
    assert result.coverage_summary.checks_no_data == 1
    assert result.coverage_summary.checks_not_attempted == 0


# --------------------------------------------------------------------------- #
# Coverage without a network call
# --------------------------------------------------------------------------- #


def test_a_cache_hit_is_complete_coverage() -> None:
    """Readiness asks whether the information was available, not whether a
    socket was opened for it. Task 13's budget cares about the call; this layer
    does not."""
    result = assess(
        _reputation_scenario(
            status=ProviderRunStatus.SUCCESS, called_provider=False, cache_hit=True
        )
    )
    evaluation = _evaluation(result, CAPABILITY)

    assert evaluation.completion is CheckCompletion.COMPLETE
    assert evaluation.status is RequirementStatus.SATISFIED
    assert evaluation.checks[0].served_without_call is True


def test_a_local_source_covers_without_any_remote_cost() -> None:
    """Zero network cost is not zero coverage.

    A credential-free local dataset answers a real question. Requiring a remote
    call before crediting coverage would make the cheapest source the only one
    that never counted.
    """
    root = file_object(sha256="a" * 64)
    result = assess(
        scenario(root)
        .with_claim("malware_sample_identity", provider="alpha", source_family="fam_a")
        .with_attempt(
            attempt(
                ProviderCapability.FALSE_POSITIVE_CONTEXT,
                provider="local",
                locality=ProviderLocality.LOCAL,
                called_provider=False,
            )
        )
    )
    evaluation = _evaluation(result, ProviderCapability.FALSE_POSITIVE_CONTEXT)

    assert evaluation.completion is CheckCompletion.COMPLETE
    assert evaluation.checks[0].local_source is True


# --------------------------------------------------------------------------- #
# Partial: the envelope is not the capability
# --------------------------------------------------------------------------- #


def test_a_capability_reported_partial_is_limited_not_satisfied() -> None:
    """The planner's own per-capability statement, believed.

    A bounded search horizon or an unmet family target means the absence of a
    finding covers less than it appears to. That is a limitation on the
    requirement, never an inference about the observable.
    """
    root = file_object(sha256="a" * 64)
    result = assess(
        scenario(root)
        .with_claim("malware_sample_identity", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(CAPABILITY, status=ProviderRunStatus.NO_DATA))
        .with_coverage(coverage_item(CAPABILITY, status=CoverageStatus.PARTIAL))
    )
    evaluation = _evaluation(result, CAPABILITY)

    assert evaluation.completion is CheckCompletion.COMPLETE
    assert evaluation.information_yield is InformationYield.NO_DATA
    assert evaluation.status is RequirementStatus.LIMITED
    assert evaluation.limitations


def test_a_partial_envelope_does_not_make_every_capability_partial() -> None:
    """The Task 17 lesson, applied where it belongs.

    A provider whose optional enrichment failed while its verdict-bearing answer
    arrived intact has told us nothing less about the capability we asked for.
    Only the capability actually reported partial is limited.
    """
    root = file_object(sha256="a" * 64)
    result = assess(
        scenario(root)
        .with_claim("malware_sample_identity", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(ProviderCapability.MALWARE_INTELLIGENCE, provider="alpha"))
        .with_attempt(attempt(CAPABILITY, provider="beta", status=ProviderRunStatus.PARTIAL))
        .with_coverage(coverage_item(ProviderCapability.MALWARE_INTELLIGENCE))
    )

    intelligence = _evaluation(result, ProviderCapability.MALWARE_INTELLIGENCE)
    reputation = _evaluation(result, CAPABILITY)

    assert intelligence.status is RequirementStatus.SATISFIED
    assert intelligence.limitations == ()
    assert reputation.status is RequirementStatus.LIMITED


# --------------------------------------------------------------------------- #
# Capability-level aggregation
# --------------------------------------------------------------------------- #


def test_one_source_answering_covers_the_capability() -> None:
    """A requirement asks for information, not for a quorum.

    Two of three sources failed here. The capability is covered, and both
    failures stay in the trace so nobody has to guess what happened.
    """
    root = file_object(sha256="a" * 64)
    result = assess(
        scenario(root)
        .with_claim("malware_sample_identity", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(CAPABILITY, provider="one", status=ProviderRunStatus.NOT_CONFIGURED))
        .with_attempt(attempt(CAPABILITY, provider="two", status=ProviderRunStatus.QUOTA_EXCEEDED))
        .with_attempt(attempt(CAPABILITY, provider="three", source_family="fam_c"))
    )
    evaluation = _evaluation(result, CAPABILITY)

    assert evaluation.status is RequirementStatus.SATISFIED
    assert len(evaluation.checks) == 3
    assert {check.raw_status for check in evaluation.checks} == {
        "not_configured",
        "quota_exceeded",
        "success",
    }
    assert not [gap for gap in result.gaps if gap.capability is CAPABILITY]


def test_independent_families_are_counted_as_families_not_providers() -> None:
    """Three datasets from one organisation answer once.

    Grouping follows Task 17 for the same reason it does there: a number going
    up is not information arriving.
    """
    root = file_object(sha256="a" * 64)
    result = assess(
        scenario(root)
        .with_claim("malware_sample_identity", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(CAPABILITY, provider="one", source_family="shared"))
        .with_attempt(attempt(CAPABILITY, provider="two", source_family="shared"))
        .with_attempt(attempt(CAPABILITY, provider="three", source_family="shared"))
    )
    evaluation = _evaluation(result, CAPABILITY)

    assert evaluation.independent_families == ("shared",)
