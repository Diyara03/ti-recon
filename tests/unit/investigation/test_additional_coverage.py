"""Obtaining a second source for a capability that already has one (Task 19).

Task 13's goal says how much coverage is worth buying by default. Task 18 can
have a requirement that default satisfies numerically and not in substance: a
benign assessment resting on one origin is not ready until somebody
*independent* has looked, and "one family answered" is exactly what the base
goal was satisfied by.

So the two questions are separated. **Which** capabilities may be queried is
frozen at the first round and can never grow. **How much** source coverage is
enough for an admissible, active capability is something a readiness
requirement may raise, for one capability, for one round.

Nothing here is provider voting. Task 17 still decides what the second answer
means, whether it is independent, and whether it changes anything at all — and
it may return nothing, context, agreement or contradiction. Task 18 asked for a
*check*, not for a result.
"""

from __future__ import annotations

import pytest

from fixtures.investigation import (
    InvestigationStack,
    claim_evidence,
    file_root,
    spec,
)
from fixtures.investigation.stack import ScriptedProvider
from ti_recon.enums import (
    EvidenceEffect,
    InvestigationDepth,
    ProviderCapability,
    ProviderRunStatus,
    Verdict,
)
from ti_recon.investigation import (
    InvestigationRequest,
    RoundTrigger,
    WorkflowStopReason,
)
from ti_recon.investigation.models import ContinuationNeed
from ti_recon.planning.models import CallCostClass, ProviderLocality, SkipReason
from ti_recon.reasoning.claims.models import ClaimSemantic

REPUTATION = ProviderCapability.REPUTATION
DIGEST = "f" * 64


def _benign(provider_id: str, family: str, *, priority: int = 50) -> ScriptedProvider:
    return ScriptedProvider(
        spec(provider_id, family=family, capabilities=frozenset({REPUTATION}), priority=priority),
        {
            DIGEST: claim_evidence(
                ClaimSemantic.BENIGN_REPUTATION, effect=EvidenceEffect.SUPPORTS_BENIGN
            )
        },
    )


def _silent(
    provider_id: str, family: str, *, priority: int = 50, **kwargs: object
) -> ScriptedProvider:
    return ScriptedProvider(
        spec(
            provider_id,
            family=family,
            capabilities=frozenset({REPUTATION}),
            priority=priority,
            **kwargs,  # type: ignore[arg-type]
        ),
        {},
    )


def _quick(**overrides: object) -> InvestigationRequest:
    """QUICK: one good answer is the base goal, so a second source is spare."""
    return InvestigationRequest(
        root=file_root(DIGEST),
        depth=InvestigationDepth.QUICK,
        **overrides,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# The acceptance case
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_benign_assessment_gets_a_second_source_in_a_second_round() -> None:
    """The whole mechanism, end to end, with nothing faked.

    QUICK's reputation goal wants one family and gets it, so Task 13 finishes
    with ``asleep`` never considered — its base goal was met. Task 17 reaches
    LIKELY_BENIGN on one origin; Task 18 says nothing independent has looked and
    a path remains; Task 19 asks Task 13 for another eligible source of the same
    capability, and Task 13 — not the workflow — picks the one from a family the
    benign basis does not already account for.
    """
    answered, asleep = (
        _benign("answered", "fam_a", priority=99),
        _silent("asleep", "fam_b", priority=1),
    )
    stack = InvestigationStack(providers=[answered, asleep])
    await stack.add_credentials()

    result = await stack.investigate(_quick())

    # Round one bought exactly what the base goal asked for.
    assert stack.requests_for("answered")
    assert result.rounds[0].trigger is RoundTrigger.INITIAL
    # Round two is real: a new provider, a new call, new coverage.
    assert len(result.rounds) >= 2
    assert result.rounds[1].trigger is RoundTrigger.READINESS_CONTINUATION
    assert stack.requests_for("asleep"), "the second source was never asked"
    assert result.rounds[1].new_attempt_sequences
    assert [item.need for item in result.rounds[1].directives] == [
        ContinuationNeed.ADDITIONAL_COVERAGE
    ]

    # Both families are in the accumulated coverage; neither replaced the other.
    families = {
        attempt.source_family
        for attempt in result.enrichment.attempts
        if attempt.capability is REPUTATION
    }
    assert families == {"fam_a", "fam_b"}
    # Task 17 decided what it meant. The check ran; nothing was assumed of it.
    assert result.assessment.assessment.verdict is Verdict.LIKELY_BENIGN
    assert result.stop_reason is not WorkflowStopReason.NO_ACTIONABLE_CONTINUATION


@pytest.mark.asyncio
async def test_the_first_call_is_not_made_twice() -> None:
    """Reopening raises the bar; it does not forget what was asked.

    Call identity is still ``(provider_id, capability)`` and still carried, so
    the source that answered in round one is not a candidate in round two.
    """
    answered, asleep = (
        _benign("answered", "fam_a", priority=99),
        _silent("asleep", "fam_b", priority=1),
    )
    stack = InvestigationStack(providers=[answered, asleep])
    await stack.add_credentials()

    result = await stack.investigate(_quick())

    assert len(stack.requests_for("answered")) == 1
    reasons = {
        candidate.reason
        for decision in result.enrichment.decisions
        for candidate in decision.skipped
        if candidate.provider_id == "answered"
    }
    # Excluded twice over here — its family cannot supply the independence, and
    # the call was made. Either is disqualifying; neither is a re-ask.
    assert reasons
    assert reasons <= {SkipReason.ALREADY_ATTEMPTED, SkipReason.SOURCE_FAMILY_EXCLUDED}


@pytest.mark.asyncio
async def test_a_same_family_candidate_does_not_get_the_remaining_call() -> None:
    """Independence is the requirement; a sibling dataset cannot supply it.

    ``a_two`` is unattempted, eligible and ranks first. It belongs to the family
    the benign basis already accounts for, so the per-capability exclusion takes
    it out before the ranking runs — and the one remaining call goes to the
    family that could actually satisfy the requirement.
    """
    stack = InvestigationStack(
        providers=[
            _benign("answered", "fam_a", priority=99),
            _silent("a_two", "fam_a", priority=98),
            _silent("independent", "fam_b", priority=1),
        ]
    )
    await stack.add_credentials()

    result = await stack.investigate(_quick(max_remote_provider_runs=2))

    assert stack.requests_for("a_two") == []
    assert stack.requests_for("independent")
    assert any(
        candidate.reason is SkipReason.SOURCE_FAMILY_EXCLUDED
        for decision in result.enrichment.decisions
        for candidate in decision.skipped
    )


@pytest.mark.asyncio
async def test_no_remaining_budget_means_no_reopened_call() -> None:
    """Reopening changes sufficiency, never the allowance.

    One remote unit, spent on the first answer. The requirement is real and
    unmet, the candidate is eligible, and the investigation still stops — with
    the reason a caller can act on.
    """
    stack = InvestigationStack(
        providers=[_benign("answered", "fam_a", priority=99), _silent("asleep", "fam_b")]
    )
    await stack.add_credentials()

    result = await stack.investigate(_quick(max_remote_provider_runs=1))

    assert stack.requests_for("asleep") == []
    assert result.enrichment.budget.remote_runs_used <= 1
    assert result.stop_reason in {
        WorkflowStopReason.CURRENT_BUDGET_EXHAUSTED,
        WorkflowStopReason.NO_PROGRESS,
    }


@pytest.mark.asyncio
async def test_a_local_source_answers_a_reopened_capability_for_free() -> None:
    """Zero remote allowance is not zero capability, here too."""
    stack = InvestigationStack(
        providers=[
            _benign("answered", "fam_a", priority=99),
            _silent(
                "free",
                "fam_b",
                priority=1,
                locality=ProviderLocality.LOCAL,
                cost=CallCostClass.ZERO,
            ),
        ]
    )
    await stack.add_credentials()

    result = await stack.investigate(_quick(max_remote_provider_runs=1))

    assert stack.requests_for("free")
    assert result.enrichment.budget.remote_runs_used <= 1


@pytest.mark.asyncio
async def test_nothing_eligible_remains_and_the_run_stops() -> None:
    """The requirement stands and cannot be met, so the loop ends.

    Every other source is in the family that already answered. No call, no loop,
    and a recorded reason rather than a silent success.
    """
    stack = InvestigationStack(
        providers=[_benign("answered", "fam_a", priority=99), _silent("sibling", "fam_a")]
    )
    await stack.add_credentials()

    result = await stack.investigate(_quick())

    assert stack.requests_for("sibling") == []
    assert result.readiness.readiness_status.value == "needs_more_data"
    assert result.stop_reason in {
        WorkflowStopReason.NO_PROGRESS,
        WorkflowStopReason.CURRENT_BUDGET_EXHAUSTED,
        WorkflowStopReason.NO_ACTIONABLE_CONTINUATION,
    }
    assert len(result.rounds) <= 2


@pytest.mark.asyncio
async def test_a_reopened_capability_keeps_its_earlier_coverage() -> None:
    """The first family's answer stays true and stays visible.

    Reopening raises a target; it never clears ``covered_families``. Task 17's
    independence grouping and Task 18's challenge both read the accumulated
    view, so erasing the first answer would break the very requirement that
    asked for the second one.
    """
    answered, asleep = (
        _benign("answered", "fam_a", priority=99),
        _silent("asleep", "fam_b", priority=1),
    )
    stack = InvestigationStack(providers=[answered, asleep])
    await stack.add_credentials()

    result = await stack.investigate(_quick())

    by_provider = {
        attempt.provider_id: attempt
        for attempt in result.enrichment.attempts
        if attempt.capability is REPUTATION
    }
    assert by_provider["answered"].status is ProviderRunStatus.SUCCESS
    assert by_provider["asleep"].status is ProviderRunStatus.NO_DATA
    assert by_provider["answered"].sequence < by_provider["asleep"].sequence


def test_task_13_is_unchanged_without_an_additional_coverage_request() -> None:
    """Opt-in, and used only by a readiness continuation.

    An ordinary Task 13 caller must not suddenly get more providers, more calls
    or more families. With no request the effective target is the goal's own.
    """
    from ti_recon.planning.models import EnrichmentBudget
    from ti_recon.planning.state import PlanningState

    state = PlanningState(budget=EnrichmentBudget(max_remote_provider_runs=4, max_high_cost_runs=1))
    state.covered_families[REPUTATION] = {"fam_a"}

    assert state.effective_target(REPUTATION, 1) == 1
    assert state.effective_target(REPUTATION, 2) == 2

    raised = state.continuation(additional_coverage=frozenset({REPUTATION}))
    assert raised.effective_target(REPUTATION, 1) == 2
    # The earlier coverage is intact, and every other capability is untouched.
    assert raised.covered_families[REPUTATION] == {"fam_a"}
    assert raised.effective_target(ProviderCapability.MALWARE_INTELLIGENCE, 1) == 1


@pytest.mark.asyncio
async def test_a_relaying_second_source_leaves_the_requirement_open() -> None:
    """A different family is *potentially* independent, and no more than that.

    ``relay`` belongs to its own family and names the first source's origin, so
    Task 17 groups the two into one component and Task 18 says the independent
    check is still missing. The pre-call family constraint did what it could;
    the returned provenance is what settles it, and the run continues to a third
    family rather than declaring the job done because the id was different.
    """
    answered = _benign("answered", "fam_a", priority=99)
    relay = ScriptedProvider(
        spec("relay", family="fam_b", capabilities=frozenset({REPUTATION}), priority=50),
        {
            DIGEST: claim_evidence(
                ClaimSemantic.BENIGN_REPUTATION,
                effect=EvidenceEffect.SUPPORTS_BENIGN,
                origin_provider="answered",
            )
        },
    )
    third = _silent("third", "fam_c", priority=1)
    stack = InvestigationStack(providers=[answered, relay, third])
    await stack.add_credentials()

    # STANDARD, where the base goal already wants two families: both are bought
    # in the first round, and two families is still one origin.
    result = await stack.investigate(
        InvestigationRequest(root=file_root(DIGEST), depth=InvestigationDepth.STANDARD)
    )

    assert stack.requests_for("answered") and stack.requests_for("relay")
    # Two families answered and Task 13's own goal was met, yet the requirement
    # is unmet: the second answer named the first one's origin.
    assert len(result.rounds) >= 2
    assert [item.need for item in result.rounds[1].directives] == [
        ContinuationNeed.ADDITIONAL_COVERAGE
    ]
    # Both known-dependent families are excluded, from Task 17's grouping rather
    # than from a comparison of provider ids.
    assert sorted(result.rounds[1].directives[0].avoid_source_families) == ["fam_a", "fam_b"]
    # And the genuinely unrelated family was reached.
    assert stack.requests_for("third")
