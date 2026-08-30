"""Bundled calls, challenge relevance, and mixed gaps (Task 18).

Three interactions that only appear where layers meet, and that leave every
single-layer test green while producing a wrong answer.

**Bundling.** Task 13 answers several goals with one request wherever a provider
declares that one read returns its whole document, and it records a single
``ProviderAttempt`` carrying the call's *primary* capability. The capabilities
that call actually answered live in the coverage items instead. A readiness
ledger built from attempts alone therefore reports a covered capability as never
attempted, and demands a second call the planner deliberately avoided.

**Relevance.** Independence is necessary for a benign challenge and is not
sufficient. A separate origin that only looked at infrastructure exposure has not
searched for anything adverse, however independent it is.

**Mixed gaps.** When material gaps disagree about what can be done next, the
useful answer for an orchestrator is the cheapest honest one: something is still
addressable.
"""

from __future__ import annotations

import pytest

from fixtures.readiness import (
    assess,
    attempt,
    coverage_item,
    file_object,
    scenario,
    skipped,
)
from ti_recon.enums import (
    CoverageStatus,
    EvidenceEffect,
    InvestigationDepth,
    ProviderCapability,
    ProviderRunStatus,
    Verdict,
)
from ti_recon.planning.models import SkipReason
from ti_recon.reasoning.readiness import (
    CheckCompletion,
    ContinuationState,
    GapType,
    ReadinessStatus,
    RequirementStatus,
    continuation_for,
)
from ti_recon.reasoning.readiness.policy import DIRECTIONAL_SEARCH_CAPABILITIES

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
THREAT = ProviderCapability.THREAT_ASSOCIATIONS
BEHAVIOUR = ProviderCapability.FILE_BEHAVIOR


def _evaluation(result, capability):
    for item in result.requirement_evaluations:
        if item.requirement.capability is capability:
            return item
    raise AssertionError(f"no evaluation for {capability.value}")


# --------------------------------------------------------------------------- #
# One call, several capabilities
# --------------------------------------------------------------------------- #


def _bundled(intelligence_status: CoverageStatus, *, weak_basis: bool = True):
    """One execution recorded under REPUTATION, coverage crediting both.

    This is the exact shape Task 13 produces for a bundled call: the attempt
    names the primary capability, and every capability the response answered is
    credited in the coverage items.
    """
    root = file_object(sha256="b" * 64)
    semantic = "aggregated_reputation" if weak_basis else "malware_sample_identity"
    return (
        scenario(root)
        .with_claim(semantic, provider="alpha", source_family="fam_a")
        .with_attempt(attempt(REPUTATION, provider="alpha", source_family="fam_a"))
        .with_coverage(coverage_item(REPUTATION, status=CoverageStatus.COVERED))
        .with_coverage(coverage_item(INTELLIGENCE, status=intelligence_status))
    )


def test_a_bundled_call_covers_every_capability_it_answered() -> None:
    """One physical request is enough when the planner says it answered both.

    Requiring a second execution would contradict Task 13's whole reason for
    bundling — and would report a gap that no additional call could close,
    because the information is already in hand.
    """
    result = assess(_bundled(CoverageStatus.COVERED))
    evaluation = _evaluation(result, INTELLIGENCE)

    assert evaluation.completion is CheckCompletion.COMPLETE
    assert evaluation.status is RequirementStatus.SATISFIED
    assert not [gap for gap in result.gaps if gap.capability is INTELLIGENCE]


def test_a_partly_answered_bundle_credits_only_what_it_covered() -> None:
    """Evidence for one capability does not establish another.

    The same envelope answered the primary capability fully and the bundled one
    only partly. Crediting the second from the first — because the response
    "contained evidence" — is exactly the inference this layer must not make.
    """
    result = assess(_bundled(CoverageStatus.PARTIAL))

    assert _evaluation(result, REPUTATION).status is RequirementStatus.SATISFIED
    assert _evaluation(result, INTELLIGENCE).status is RequirementStatus.LIMITED
    assert _evaluation(result, INTELLIGENCE).completion is CheckCompletion.PARTIAL


def test_a_capability_the_bundle_did_not_answer_stays_unmet() -> None:
    """The capability-dependent provider case, in generic terms.

    Where one endpoint answers A and a separate one is needed for B, Task 13
    credits only A. Completion of A must not satisfy B, and no provider is named
    anywhere in reaching that conclusion.
    """
    result = assess(_bundled(CoverageStatus.NOT_COVERED))
    evaluation = _evaluation(result, INTELLIGENCE)

    assert evaluation.status is RequirementStatus.UNSATISFIED
    assert evaluation.completion is CheckCompletion.NOT_ATTEMPTED
    assert [gap.gap_type for gap in result.gaps if gap.capability is INTELLIGENCE] == [
        GapType.NOT_ATTEMPTED
    ]


def test_a_bundled_goal_recorded_as_already_attempted_is_not_a_gap() -> None:
    """Task 13 skips a goal a previous bundled call already answered.

    The skip reason says the work was done, not declined. Reading it as an
    unattempted capability would turn the planner's duplicate-call optimisation
    into a reported deficiency.
    """
    result = assess(
        _bundled(CoverageStatus.COVERED).with_skip(
            skipped(INTELLIGENCE, SkipReason.ALREADY_ATTEMPTED)
        )
    )
    evaluation = _evaluation(result, INTELLIGENCE)

    assert evaluation.status is RequirementStatus.SATISFIED
    assert not [gap for gap in result.gaps if gap.capability is INTELLIGENCE]


def test_a_blocked_execution_is_still_visible_under_a_covered_capability() -> None:
    """Consulting the coverage record must not hide a failed execution.

    Coverage says what was answered; the attempts say what happened. An operator
    asking why a source is missing from the picture still gets the answer.
    """
    result = assess(
        _bundled(CoverageStatus.COVERED).with_attempt(
            attempt(INTELLIGENCE, provider="other", status=ProviderRunStatus.NOT_CONFIGURED)
        )
    )
    evaluation = _evaluation(result, INTELLIGENCE)

    assert evaluation.status is RequirementStatus.SATISFIED
    assert "not_configured" in {check.raw_status for check in evaluation.checks}


def test_bundling_and_separate_calls_reach_the_same_readiness() -> None:
    """Physical request count must not change the answer.

    Two executions and one bundled execution that answered the same two
    capabilities describe the same state of knowledge. If readiness could tell
    them apart it would be measuring provider traffic rather than coverage.
    """
    root = file_object(sha256="c" * 64)

    def scene(bundled: bool):
        base = (
            scenario(root)
            .with_claim("aggregated_reputation", provider="alpha", source_family="fam_a")
            .with_attempt(attempt(REPUTATION, provider="alpha", source_family="fam_a"))
            .with_coverage(coverage_item(REPUTATION, status=CoverageStatus.COVERED))
            .with_coverage(coverage_item(INTELLIGENCE, status=CoverageStatus.COVERED))
        )
        if not bundled:
            base = base.with_attempt(
                attempt(INTELLIGENCE, provider="alpha", source_family="fam_a", sequence=2)
            )
        return base

    separate = assess(scene(bundled=False))
    together = assess(scene(bundled=True))

    assert together.readiness_status is separate.readiness_status
    assert together.coverage_adequacy is separate.coverage_adequacy
    assert together.continuation_state is separate.continuation_state
    assert [
        (item.requirement.capability, item.status) for item in together.requirement_evaluations
    ] == [(item.requirement.capability, item.status) for item in separate.requirement_evaluations]


# --------------------------------------------------------------------------- #
# Independence is necessary, not sufficient
# --------------------------------------------------------------------------- #


def _single_benign():
    root = file_object(sha256="d" * 64)
    return (
        scenario(root)
        .with_claim(
            semantic="benign_reputation",
            provider="alpha",
            source_family="fam_a",
            effect=EvidenceEffect.SUPPORTS_BENIGN,
        )
        .with_attempt(attempt(REPUTATION, provider="alpha", source_family="fam_a"))
        .with_attempt(attempt(INTELLIGENCE, provider="alpha_i", source_family="fam_a"))
        .with_coverage(coverage_item(REPUTATION))
        .with_coverage(coverage_item(INTELLIGENCE))
    )


def _challenge_missing(result) -> bool:
    return GapType.INDEPENDENT_CHALLENGE_MISSING in {gap.gap_type for gap in result.gaps}


def test_the_adverse_search_set_is_explicit_and_provider_neutral() -> None:
    """A small controlled set of capabilities, not a name or a substring.

    Behavioural analysis is deliberately outside it: watching a sample run is a
    different question from searching for what is known about it, and treating
    them as interchangeable would let one stand in for the other.
    """
    assert DIRECTIONAL_SEARCH_CAPABILITIES == frozenset({REPUTATION, INTELLIGENCE, THREAT})
    assert BEHAVIOUR not in DIRECTIONAL_SEARCH_CAPABILITIES


@pytest.mark.parametrize(
    "capability",
    sorted(DIRECTIONAL_SEARCH_CAPABILITIES, key=lambda item: item.value),
    ids=lambda item: item.value,
)
def test_an_independent_adverse_search_satisfies_the_challenge(
    capability: ProviderCapability,
) -> None:
    """Any of the three, from an unrelated origin, returning nothing.

    The requirement is that a search capable of contradicting the benign
    conclusion actually ran. Its empty answer creates no benign evidence.
    """
    result = assess(
        _single_benign().with_attempt(
            attempt(
                capability,
                provider="gamma",
                source_family="fam_gamma",
                status=ProviderRunStatus.NO_DATA,
            )
        )
    )

    assert result.verdict is Verdict.LIKELY_BENIGN
    assert not _challenge_missing(result)


CONTEXT_CAPABILITIES = [
    ProviderCapability.FALSE_POSITIVE_CONTEXT,
    ProviderCapability.SCANNER_CONTEXT,
    ProviderCapability.CERTIFICATE_CONTEXT,
    ProviderCapability.CURRENT_INFRASTRUCTURE,
    ProviderCapability.NETWORK_OWNERSHIP,
    ProviderCapability.RELATIONSHIPS,
    ProviderCapability.FILE_BEHAVIOR,
]


@pytest.mark.parametrize("capability", CONTEXT_CAPABILITIES, ids=lambda item: item.value)
def test_an_independent_but_irrelevant_check_does_not_challenge_anything(
    capability: ProviderCapability,
) -> None:
    """Independence is necessary and nowhere near sufficient.

    A separate origin that looked only at infrastructure exposure, certificate
    context or business-service membership has searched for nothing adverse. It
    is real coverage of its own requirement and it leaves the benign conclusion
    exactly as unchallenged as it was.
    """
    result = assess(
        _single_benign().with_attempt(
            attempt(
                capability,
                provider="gamma",
                source_family="fam_gamma",
                status=ProviderRunStatus.NO_DATA,
            )
        )
    )

    assert result.verdict is Verdict.LIKELY_BENIGN
    assert _challenge_missing(result)
    assert result.readiness_status is ReadinessStatus.NEEDS_MORE_DATA


def test_an_irrelevant_check_cannot_improve_readiness_but_a_relevant_one_may() -> None:
    """The property, with its counterpart, and the assessment untouched by both.

    One investigation that accumulates checks, rather than three built
    separately: the evidence — and therefore the run-scoped assessment id — is
    literally the same object throughout, so the comparison is about the checks
    and nothing else.
    """
    scene = _single_benign()
    baseline = assess(scene)

    irrelevant = assess(
        scene.with_attempt(
            attempt(
                ProviderCapability.SCANNER_CONTEXT,
                provider="gamma",
                source_family="fam_gamma",
                status=ProviderRunStatus.NO_DATA,
            )
        )
    )
    relevant = assess(
        scene.with_attempt(
            attempt(
                THREAT,
                provider="delta",
                source_family="fam_delta",
                status=ProviderRunStatus.NO_DATA,
            )
        )
    )

    assert baseline.readiness_status is ReadinessStatus.NEEDS_MORE_DATA
    assert irrelevant.readiness_status is ReadinessStatus.NEEDS_MORE_DATA
    assert relevant.readiness_status is not ReadinessStatus.NEEDS_MORE_DATA

    for result in (irrelevant, relevant):
        assert result.verdict is baseline.verdict
        assert result.confidence is baseline.confidence
        assert result.verdict_rule_id == baseline.verdict_rule_id
        assert result.assessment_id == baseline.assessment_id


def test_a_limited_adverse_search_leaves_the_challenge_limited() -> None:
    """A bounded search is not a completed one.

    A source that answered partly has not established the absence it appears to;
    the challenge is recorded as limited rather than met.
    """
    result = assess(
        _single_benign().with_attempt(
            attempt(
                THREAT,
                provider="gamma",
                source_family="fam_gamma",
                status=ProviderRunStatus.PARTIAL,
            )
        )
    )
    challenge = next(
        item for item in result.requirement_evaluations if item.requirement.capability is THREAT
    )

    assert challenge.status is RequirementStatus.LIMITED
    assert not _challenge_missing(result)


# --------------------------------------------------------------------------- #
# Mixed material gaps
# --------------------------------------------------------------------------- #

MIXED_GAPS = {
    "addressable_and_blocked": (
        frozenset({GapType.NOT_ATTEMPTED, GapType.NOT_CONFIGURED}),
        ContinuationState.MORE_DATA_AVAILABLE,
    ),
    "addressable_and_exhausted": (
        frozenset({GapType.BUDGET_LIMITED, GapType.CAPABILITY_UNAVAILABLE}),
        ContinuationState.MORE_DATA_AVAILABLE,
    ),
    "blocked_and_exhausted": (
        frozenset({GapType.NOT_CONFIGURED, GapType.CAPABILITY_UNAVAILABLE}),
        ContinuationState.BLOCKED,
    ),
    "two_addressable": (
        frozenset({GapType.NOT_ATTEMPTED, GapType.BUDGET_LIMITED}),
        ContinuationState.MORE_DATA_AVAILABLE,
    ),
    "none": (frozenset(), ContinuationState.COMPLETE),
}


@pytest.mark.parametrize("case", sorted(MIXED_GAPS))
def test_the_cheapest_honest_next_step_wins(case: str) -> None:
    """Precedence: addressable, then blocked, then exhausted.

    An orchestrator's question is "can anything still be attempted now?", so a
    run with one addressable gap and one blocker reports that something is
    addressable. The blocker does not disappear — it stays in ``gaps`` — and
    once the addressable work is done a later evaluation will surface it as the
    remaining obstacle. Reporting BLOCKED first would stop a run that still had
    useful work in front of it.
    """
    gap_types, expected = MIXED_GAPS[case]

    assert continuation_for(material_gap_types=gap_types) is expected


def test_a_blocked_gap_survives_alongside_an_addressable_one() -> None:
    """Both are reported; only the continuation state picks a headline."""
    root = file_object(sha256="e" * 64)
    result = assess(
        scenario(root, depth=InvestigationDepth.DEEP)
        .with_claim("aggregated_reputation", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(REPUTATION, provider="rep", status=ProviderRunStatus.NOT_CONFIGURED))
        .with_skip(skipped(INTELLIGENCE, SkipReason.BUDGET_EXHAUSTED))
    )

    gap_types = {gap.gap_type for gap in result.gaps}
    assert GapType.NOT_CONFIGURED in gap_types
    assert GapType.BUDGET_LIMITED in gap_types
    assert result.continuation_state is ContinuationState.MORE_DATA_AVAILABLE
    assert result.readiness_status is ReadinessStatus.NEEDS_MORE_DATA
