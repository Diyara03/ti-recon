"""When a failure matters, and when it is just a failure (Task 18).

Most things that go wrong during an investigation do not affect whether its
assessment is usable. A provider without credentials, a source out of quota, an
optional capability nobody implements — each is a real fact worth keeping in the
trace, and none of them is a gap unless it actually prevented a *material*
requirement from being met.

The same goes for scope. A QUICK run is not incomplete for skipping DEEP work
nobody asked for, and a conditional goal whose trigger never fired was never a
requirement at all.
"""

from __future__ import annotations

import inspect

import pytest

from fixtures.readiness import (
    assess,
    attempt,
    coverage_item,
    file_object,
    finding_stale,
    observable,
    scenario,
    signal,
    skipped,
)
from ti_recon.enums import (
    CoverageStatus,
    InvestigationDepth,
    ProviderCapability,
    ProviderRunStatus,
    Verdict,
)
from ti_recon.planning.models import SkipReason
from ti_recon.reasoning.models import ContextSignalType
from ti_recon.reasoning.readiness import (
    ContinuationState,
    GapType,
    ReadinessStatus,
    RequirementActivation,
    RequirementStatus,
)

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
BEHAVIOUR = ProviderCapability.FILE_BEHAVIOR


def _evaluation(result, capability):
    for item in result.requirement_evaluations:
        if item.requirement.capability is capability:
            return item
    raise AssertionError(f"no evaluation for {capability.value}")


def _covered_malicious_file(depth=InvestigationDepth.STANDARD):
    """A decisive file assessment whose material checks all ran."""
    root = file_object(sha256="a" * 64)
    return (
        scenario(root, depth=depth)
        .with_claim("malware_sample_identity", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(REPUTATION, provider="rep", source_family="fam_rep"))
        .with_attempt(attempt(INTELLIGENCE, provider="alpha", source_family="fam_a"))
        .with_coverage(coverage_item(REPUTATION))
        .with_coverage(coverage_item(INTELLIGENCE))
    )


# --------------------------------------------------------------------------- #
# A failure is only a gap when it blocks something material
# --------------------------------------------------------------------------- #

UNRELATED_FAILURES = {
    "not_configured": ProviderRunStatus.NOT_CONFIGURED,
    "quota_exceeded": ProviderRunStatus.QUOTA_EXCEEDED,
    "temporarily_unavailable": ProviderRunStatus.TEMPORARILY_UNAVAILABLE,
    "error": ProviderRunStatus.ERROR,
    "not_supported": ProviderRunStatus.NOT_SUPPORTED,
}


@pytest.mark.parametrize("case", sorted(UNRELATED_FAILURES))
def test_an_unrelated_failure_cannot_move_readiness(case: str) -> None:
    """Same status, same adequacy, same continuation, same gaps.

    The failed capability here is already covered by another source. Downgrading
    on it would mean any investigation touching a misconfigured provider looked
    worse than one that never tried, which rewards asking fewer questions.
    """
    baseline = assess(_covered_malicious_file())
    with_failure = assess(
        _covered_malicious_file().with_attempt(
            attempt(REPUTATION, provider="broken", status=UNRELATED_FAILURES[case])
        )
    )

    assert with_failure.readiness_status is baseline.readiness_status
    assert with_failure.coverage_adequacy is baseline.coverage_adequacy
    assert with_failure.continuation_state is baseline.continuation_state
    assert {gap.gap_type for gap in with_failure.gaps} == {gap.gap_type for gap in baseline.gaps}


@pytest.mark.parametrize("case", sorted(UNRELATED_FAILURES))
def test_an_unrelated_failure_stays_in_the_trace(case: str) -> None:
    """Not a gap, and not hidden either.

    An analyst asking why a source is missing from the picture deserves the
    answer, even when the requirement was met elsewhere.
    """
    result = assess(
        _covered_malicious_file().with_attempt(
            attempt(REPUTATION, provider="broken", status=UNRELATED_FAILURES[case])
        )
    )
    statuses = {check.raw_status for check in _evaluation(result, REPUTATION).checks}

    assert UNRELATED_FAILURES[case].value in statuses


def test_all_paths_blocked_for_a_material_capability_blocks_continuation() -> None:
    """Every eligible source unusable, and the trace keeps each cause."""
    root = file_object(sha256="c" * 64)
    result = assess(
        scenario(root)
        .with_attempt(attempt(REPUTATION, provider="one", status=ProviderRunStatus.NOT_CONFIGURED))
        .with_attempt(attempt(REPUTATION, provider="two", status=ProviderRunStatus.QUOTA_EXCEEDED))
        # Every material capability is blocked. Leaving one merely unattempted
        # would make the run honestly report "more data available" about that
        # one instead, which is a different situation.
        .with_attempt(
            attempt(INTELLIGENCE, provider="three", status=ProviderRunStatus.NOT_CONFIGURED)
        )
    )
    evaluation = _evaluation(result, REPUTATION)

    assert evaluation.status is RequirementStatus.UNSATISFIED
    assert result.continuation_state is ContinuationState.BLOCKED
    assert {check.raw_status for check in evaluation.checks} == {
        "not_configured",
        "quota_exceeded",
    }


def test_a_capability_no_source_offers_has_no_remaining_path() -> None:
    """A catalogue blind spot, not a run that went wrong.

    Structural: the planner recorded that it considered nobody. Reporting this
    as continuable would promise an enrichment path that does not exist.
    """
    root = file_object(sha256="c" * 64)
    # The unavailable capability is the only material one outstanding, so the
    # continuation state describes it rather than a different, continuable gap.
    result = assess(
        scenario(root)
        .with_attempt(attempt(INTELLIGENCE, provider="intel", status=ProviderRunStatus.NO_DATA))
        .with_coverage(
            coverage_item(REPUTATION, status=CoverageStatus.NOT_COVERED, providers_considered=())
        )
        .with_coverage(coverage_item(INTELLIGENCE))
    )

    assert GapType.CAPABILITY_UNAVAILABLE in {gap.gap_type for gap in result.gaps}
    assert result.continuation_state is ContinuationState.EXHAUSTED
    assert result.readiness_status is ReadinessStatus.UNRESOLVED


# --------------------------------------------------------------------------- #
# Depth bounds expectation
# --------------------------------------------------------------------------- #


def test_a_quick_run_is_not_missing_deeper_capabilities() -> None:
    """Nobody asked for them, so their absence is not a deficiency.

    Behavioural analysis is not part of a QUICK file investigation at all, and a
    readiness layer that demanded it would make the shallow depth permanently
    unusable.
    """
    result = assess(_covered_malicious_file(depth=InvestigationDepth.QUICK))
    capabilities = {item.requirement.capability for item in result.requirement_evaluations}

    assert BEHAVIOUR not in capabilities
    assert not [gap for gap in result.gaps if gap.capability is BEHAVIOUR]


def test_the_same_capability_becomes_material_only_at_the_depth_that_wants_it() -> None:
    """One skipped goal, two depths, two different answers.

    At STANDARD behavioural analysis is optional and its absence is a
    limitation; at DEEP it is a relevant goal and a thin basis makes it matter.
    Depth is the requested scope, so it decides what counts as missing.
    """
    root = file_object(sha256="b" * 64)

    def run(depth):
        return assess(
            scenario(root, depth=depth)
            .with_claim("aggregated_reputation", provider="alpha", source_family="fam_a")
            .with_attempt(attempt(REPUTATION, provider="alpha", source_family="fam_a"))
            .with_attempt(attempt(INTELLIGENCE, provider="intel", source_family="fam_i"))
            .with_coverage(coverage_item(REPUTATION))
            .with_coverage(coverage_item(INTELLIGENCE))
            .with_skip(skipped(BEHAVIOUR, SkipReason.BUDGET_EXHAUSTED))
        )

    shallow = run(InvestigationDepth.STANDARD)
    deep = run(InvestigationDepth.DEEP)

    assert not [gap for gap in shallow.gaps if gap.capability is BEHAVIOUR]
    assert [gap.gap_type for gap in deep.gaps if gap.capability is BEHAVIOUR] == [
        GapType.BUDGET_LIMITED
    ]


def test_a_goal_that_never_activated_is_not_a_gap() -> None:
    """The planner already decided, with information this layer does not have.

    A conditional follow-up whose trigger never fired was never a requirement.
    Overriding that would make everything the system could theoretically do
    mandatory for every investigation.
    """
    result = assess(
        _covered_malicious_file(depth=InvestigationDepth.DEEP).with_skip(
            skipped(BEHAVIOUR, SkipReason.GOAL_NOT_ACTIVE)
        )
    )
    evaluation = _evaluation(result, BEHAVIOUR)

    assert evaluation.requirement.activation is RequirementActivation.NOT_ACTIVATED
    assert evaluation.status is RequirementStatus.NOT_APPLICABLE
    assert not [gap for gap in result.gaps if gap.capability is BEHAVIOUR]


# --------------------------------------------------------------------------- #
# Sandbox quality, and scoped staleness
# --------------------------------------------------------------------------- #


def test_a_sandbox_that_watched_nothing_gives_limited_behavioural_coverage() -> None:
    """Completed is not informative.

    Task 12 established that a run which observed no execution has not produced
    behavioural coverage — the sample may have wanted a click, noticed the
    watcher, or found its C2 down. That is a limitation on the coverage and, as
    ever, evidence of nothing in either direction.
    """
    root = file_object(sha256="b" * 64)
    scene = (
        scenario(root, depth=InvestigationDepth.DEEP)
        .with_claim("aggregated_reputation", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(REPUTATION, provider="alpha", source_family="fam_a"))
        .with_attempt(attempt(INTELLIGENCE, provider="intel", source_family="fam_i"))
        .with_attempt(attempt(BEHAVIOUR, provider="sandbox", source_family="fam_s"))
        .with_coverage(coverage_item(REPUTATION))
        .with_coverage(coverage_item(INTELLIGENCE))
    )
    meaningful = assess(
        scene.with_signal(signal(ContextSignalType.SANDBOX_MEANINGFUL_EXECUTION, root))
    )

    quiet_scene = (
        scenario(root, depth=InvestigationDepth.DEEP)
        .with_claim("aggregated_reputation", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(REPUTATION, provider="alpha", source_family="fam_a"))
        .with_attempt(attempt(INTELLIGENCE, provider="intel", source_family="fam_i"))
        .with_attempt(attempt(BEHAVIOUR, provider="sandbox", source_family="fam_s"))
        .with_coverage(coverage_item(REPUTATION))
        .with_coverage(coverage_item(INTELLIGENCE))
        .with_signal(signal(ContextSignalType.SANDBOX_LOW_EXECUTION, root))
    )
    quiet = assess(quiet_scene)

    assert _evaluation(meaningful, BEHAVIOUR).status is RequirementStatus.SATISFIED
    assert _evaluation(quiet, BEHAVIOUR).status is RequirementStatus.LIMITED
    assert GapType.LOW_INFORMATION_YIELD in {
        limitation.gap_type for limitation in _evaluation(quiet, BEHAVIOUR).limitations
    }
    # And neither says anything about what the file is.
    assert meaningful.verdict is quiet.verdict


def test_stale_context_limits_only_the_requirement_that_used_it() -> None:
    """Task 16's scoping lesson, carried forward.

    An out-of-date local dataset says nothing whatsoever about an exact
    malware-sample identification. It limits the false-positive context that
    came from it, and stops there.
    """
    root = file_object(sha256="a" * 64)
    scene = _covered_malicious_file().with_attempt(
        attempt(ProviderCapability.FALSE_POSITIVE_CONTEXT, provider="local")
    )
    baseline = assess(scene)

    stale_scene = _covered_malicious_file().with_attempt(
        attempt(ProviderCapability.FALSE_POSITIVE_CONTEXT, provider="local")
    )
    stale_scene = stale_scene.with_finding(finding_stale(root, "evidence-1"))
    stale = assess(stale_scene)

    assert stale.verdict is baseline.verdict is Verdict.MALICIOUS
    assert (
        _evaluation(stale, ProviderCapability.FALSE_POSITIVE_CONTEXT).status
        is RequirementStatus.LIMITED
    )
    assert _evaluation(stale, INTELLIGENCE).status is RequirementStatus.SATISFIED
    assert _evaluation(stale, REPUTATION).status is RequirementStatus.SATISFIED
    assert stale.readiness_status is not ReadinessStatus.NEEDS_MORE_DATA


# --------------------------------------------------------------------------- #
# Integrity
# --------------------------------------------------------------------------- #


def test_an_unresolved_claim_subject_prevents_full_readiness() -> None:
    """Evidence exists that nobody can attribute to the target or away from it.

    Task 17 keeps such a claim out of the verdict, which is right. Readiness
    must not then report a clean bill of coverage over it: something relevant
    may have been said, and its applicability is undetermined.
    """
    root = file_object(sha256="a" * 64)
    stray = observable("203.0.113.99")
    scene = (
        scenario(root)
        .with_claim("malware_sample_identity", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(REPUTATION, provider="rep", source_family="fam_rep"))
        .with_attempt(attempt(INTELLIGENCE, provider="alpha", source_family="fam_a"))
        .with_coverage(coverage_item(REPUTATION))
        .with_coverage(coverage_item(INTELLIGENCE))
    )
    # An orphan claim: its subject object appears in no envelope and no graph.
    orphan = scene.with_claim(
        "c2_association", provider="stray", source_family="fam_stray", subject=stray
    )
    orphan._envelopes[-1] = orphan._envelopes[-1].model_copy(update={"objects": ()})
    result = assess(orphan)

    assert result.verdict is Verdict.MALICIOUS
    assert GapType.UNRESOLVED_INPUT in {gap.gap_type for gap in result.gaps}
    assert result.readiness_status is not ReadinessStatus.READY


# --------------------------------------------------------------------------- #
# Capability availability: catalogue fact vs execution history
# --------------------------------------------------------------------------- #


def test_a_budget_skip_outranks_an_empty_considered_list() -> None:
    """Observed execution beats catalogue inference when the two disagree.

    An empty ``providers_considered`` is an *inference* that nothing could have
    served the capability. A recorded budget skip is direct evidence that a
    candidate existed and was declined for allowance. Letting the inference win
    told an operator the question was unanswerable when a larger budget would
    answer it — and closed the continuation state from MORE_DATA_AVAILABLE to
    EXHAUSTED on the strength of the weaker fact.

    Real planner output cannot produce this contradiction, because a candidate
    it skipped for budget is a candidate it considered. The precedence still has
    to be the right way round for a caller assembling a result by hand, and for
    whatever the planner records next.
    """
    root = file_object(sha256="a" * 63 + "b")
    result = assess(
        scenario(root)
        .with_claim("aggregated_reputation", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(REPUTATION, provider="alpha", source_family="fam_a"))
        .with_coverage(coverage_item(REPUTATION))
        .with_skip(skipped(INTELLIGENCE, SkipReason.BUDGET_EXHAUSTED))
        .with_coverage(
            coverage_item(INTELLIGENCE, status=CoverageStatus.NOT_COVERED, providers_considered=())
        )
    )

    assert [gap.gap_type for gap in result.gaps if gap.capability is INTELLIGENCE] == [
        GapType.BUDGET_LIMITED
    ]
    assert result.continuation_state is ContinuationState.MORE_DATA_AVAILABLE


def test_capability_availability_comes_from_the_catalogue_not_the_run() -> None:
    """``providers_considered`` records candidacy, not what was attempted.

    Task 13 builds it by walking the registry and asking each descriptor whether
    it supports the capability for this object type — before budget, credentials,
    activation, depth or ranking touch anything. That is what makes an empty set
    a statement about the catalogue rather than about this particular run, and it
    is the only reason inferring CAPABILITY_UNAVAILABLE from it is defensible.
    """
    from ti_recon.planning.planner import AdaptiveEnrichmentPlanner

    source = inspect.getsource(AdaptiveEnrichmentPlanner.providers_considered)

    # Candidacy is decided by the descriptor, not by execution outcomes.
    assert "descriptor.supports(object_type, capability)" in source
    for execution_concept in ("budget", "credential", "attempt", "status"):
        assert execution_concept not in source


def test_a_never_activated_goal_is_not_unavailable_whatever_coverage_says() -> None:
    """Activation is settled before availability is ever consulted."""
    result = assess(
        _covered_malicious_file(depth=InvestigationDepth.DEEP)
        .with_skip(skipped(BEHAVIOUR, SkipReason.GOAL_NOT_ACTIVE))
        .with_coverage(
            coverage_item(BEHAVIOUR, status=CoverageStatus.NOT_COVERED, providers_considered=())
        )
    )
    evaluation = _evaluation(result, BEHAVIOUR)

    assert evaluation.status is RequirementStatus.NOT_APPLICABLE
    assert not [gap for gap in result.gaps if gap.capability is BEHAVIOUR]


def test_a_deeper_capability_is_absent_rather_than_unavailable() -> None:
    """Out of scope for the requested depth, so never evaluated at all."""
    result = assess(
        _covered_malicious_file(depth=InvestigationDepth.QUICK).with_coverage(
            coverage_item(BEHAVIOUR, status=CoverageStatus.NOT_COVERED, providers_considered=())
        )
    )

    assert BEHAVIOUR not in {item.requirement.capability for item in result.requirement_evaluations}
    assert not [gap for gap in result.gaps if gap.capability is BEHAVIOUR]
