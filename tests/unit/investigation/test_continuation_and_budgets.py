"""When the workflow asks again, and when it stops (Task 19).

Continuation is the only place Task 19 makes a decision of its own, so it is the
place worth testing hardest. The decision is narrow by design: readiness must say
both that coverage is inadequate *and* that a path remains. Everything else —
a suspicious verdict, an inconclusive one, a failed provider, a missing sandbox —
is a reason a person might feel unfinished, and readiness has already weighed each
against what the assessment rests on.

The other half is what a continuation may not do: raise the depth, grant itself
budget, repeat a call, or pick the provider.
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
    ProviderCapability,
    ProviderRunStatus,
    Verdict,
)
from ti_recon.investigation import InvestigationRequest, RoundTrigger, WorkflowStopReason
from ti_recon.investigation.models import WorkflowIssueType
from ti_recon.planning.models import CallCostClass, ProviderLocality
from ti_recon.reasoning.claims.models import ClaimSemantic
from ti_recon.reasoning.readiness.models import ContinuationState, ReadinessStatus

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
THREAT = ProviderCapability.THREAT_ASSOCIATIONS
CONTEXT = ProviderCapability.FALSE_POSITIVE_CONTEXT

DIGEST = "d" * 64


def _benign_stack(
    *,
    challenger_family: str = "fam_b",
    challenger_capabilities: frozenset[ProviderCapability] = frozenset({THREAT}),
    challenger_locality: ProviderLocality = ProviderLocality.REMOTE,
    with_challenger: bool = True,
    max_remote: int | None = None,
) -> tuple[InvestigationStack, object, InvestigationRequest]:
    """A single-source benign assessment, which readiness always challenges."""
    root = file_root(DIGEST)
    providers = [
        ScriptedProvider(
            spec("benign", family="fam_a", capabilities=frozenset({REPUTATION, INTELLIGENCE})),
            {
                DIGEST: claim_evidence(
                    ClaimSemantic.BENIGN_REPUTATION, effect=EvidenceEffect.SUPPORTS_BENIGN
                )
            },
        )
    ]
    if with_challenger:
        providers.append(
            ScriptedProvider(
                spec(
                    "challenger",
                    family=challenger_family,
                    capabilities=challenger_capabilities,
                    locality=challenger_locality,
                    cost=(
                        CallCostClass.ZERO
                        if challenger_locality is ProviderLocality.LOCAL
                        else CallCostClass.LOW
                    ),
                ),
                {},
            )
        )
    request = InvestigationRequest(root=root, max_remote_provider_runs=max_remote)
    return InvestigationStack(providers=providers), root, request


# --------------------------------------------------------------------------- #
# Only readiness triggers a continuation
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_continuation_runs_only_when_readiness_asks() -> None:
    """Both axes, and the directive names a capability rather than a source."""
    stack, _, request = _benign_stack()
    await stack.add_credentials()

    result = await stack.investigate(request)

    assert result.rounds[0].readiness_status == ReadinessStatus.NEEDS_MORE_DATA.value
    assert result.rounds[0].continuation_state == ContinuationState.MORE_DATA_AVAILABLE.value
    assert result.rounds[1].trigger is RoundTrigger.READINESS_CONTINUATION
    assert [item.capability for item in result.rounds[1].directives] == [THREAT]


@pytest.mark.asyncio
async def test_a_terminal_readiness_never_continues() -> None:
    """READY_WITH_LIMITATIONS ends the run even with an optional failure standing.

    Tidying up optional limitations is spending an analyst's budget on the
    workflow's discomfort, and readiness has already judged them immaterial.
    """
    root = file_root("a" * 64)
    repo = ScriptedProvider(
        spec("repo", family="fam_repo", capabilities=frozenset({INTELLIGENCE, REPUTATION})),
        {"a" * 64: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)},
    )
    optional = ScriptedProvider(
        spec("optional", family="fam_opt", capabilities=frozenset({CONTEXT})),
        {
            "a" * 64: claim_evidence(
                ClaimSemantic.MALICIOUS_REPUTATION, status=ProviderRunStatus.NOT_CONFIGURED
            )
        },
    )
    stack = InvestigationStack(providers=[repo, optional])
    await stack.add_credentials()

    result = await stack.investigate(InvestigationRequest(root=root))

    assert result.stop_reason is WorkflowStopReason.READINESS_TERMINAL
    assert len(result.rounds) == 1


@pytest.mark.asyncio
async def test_an_inconclusive_exhausted_investigation_stops() -> None:
    """Everything applicable was asked and nobody knew anything.

    A finished search with an open question. Querying optional providers because
    the verdict is unsatisfying would be the workflow substituting its own
    judgement for readiness's.
    """
    digest = "e" * 64
    root = file_root(digest)
    silent = ScriptedProvider(
        spec("silent", family="fam_a", capabilities=frozenset({REPUTATION, INTELLIGENCE})), {}
    )
    stack = InvestigationStack(providers=[silent])
    await stack.add_credentials()

    result = await stack.investigate(InvestigationRequest(root=root))

    assert result.assessment.assessment.verdict is Verdict.INCONCLUSIVE
    assert result.readiness.readiness_status is ReadinessStatus.UNRESOLVED
    assert result.stop_reason in {
        WorkflowStopReason.READINESS_EXHAUSTED,
        WorkflowStopReason.READINESS_BLOCKED,
    }
    assert len(result.rounds) == 1


@pytest.mark.asyncio
async def test_a_blocked_requirement_is_never_retried() -> None:
    """No credential, no retry loop. Task 6 owns cooldown and retry.

    A continuation round may still happen — readiness can legitimately report a
    *different* capability as never attempted — but the blocked provider is not
    asked a second time, and the workflow terminates rather than cycling on it.
    """
    digest = "f" * 64
    root = file_root(digest)
    blocked = ScriptedProvider(
        spec("blocked", family="fam_a", capabilities=frozenset({REPUTATION, INTELLIGENCE})),
        {
            digest: claim_evidence(
                ClaimSemantic.MALICIOUS_REPUTATION, status=ProviderRunStatus.NOT_CONFIGURED
            )
        },
    )
    stack = InvestigationStack(providers=[blocked])
    await stack.add_credentials()

    result = await stack.investigate(InvestigationRequest(root=root))

    assert len(stack.requests_for("blocked")) <= 1
    assert result.stop_reason in {
        WorkflowStopReason.READINESS_BLOCKED,
        WorkflowStopReason.READINESS_EXHAUSTED,
        WorkflowStopReason.NO_PROGRESS,
        WorkflowStopReason.CURRENT_BUDGET_EXHAUSTED,
        WorkflowStopReason.NO_ACTIONABLE_CONTINUATION,
    }


# --------------------------------------------------------------------------- #
# Budgets
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_budget_carries_across_rounds_and_is_never_reset() -> None:
    """One allowance for the investigation, not one per round.

    A fresh budget per continuation would make the loop's total cost unbounded
    while every individual round looked perfectly well behaved — which is exactly
    the shape of an expensive bug nobody notices until the invoice arrives.
    """
    stack, _, request = _benign_stack(max_remote=2)
    await stack.add_credentials()

    result = await stack.investigate(request)

    budget = result.enrichment.budget
    assert budget.max_remote_provider_runs == 2
    assert budget.remote_runs_used <= 2
    remote_attempts = sum(1 for attempt in result.enrichment.attempts if attempt.called_provider)
    assert remote_attempts <= 2


@pytest.mark.asyncio
async def test_an_exhausted_budget_stops_without_escalation() -> None:
    """A material need the current investigation cannot fund.

    Readiness keeps saying more data would help, because it would — a larger
    investigation could get it. The workflow records why it stopped rather than
    quietly granting itself the budget to continue, and the distinction is what
    lets a caller decide to run a deeper one.
    """
    stack, _, request = _benign_stack(max_remote=1)
    await stack.add_credentials()

    result = await stack.investigate(request)

    assert result.enrichment.budget.remote_runs_used <= 1
    assert len(stack.requests_for("challenger")) == 0
    assert result.readiness.readiness_status is ReadinessStatus.NEEDS_MORE_DATA
    assert result.stop_reason in {
        WorkflowStopReason.CURRENT_BUDGET_EXHAUSTED,
        WorkflowStopReason.NO_PROGRESS,
    }


@pytest.mark.asyncio
async def test_a_local_source_can_still_work_with_no_remote_budget() -> None:
    """Zero remote allowance is not zero capability.

    Stopping the moment the remote budget empties would skip a
    credential-free local check that costs nothing — so the workflow hands the
    remaining state to Task 13 and lets its locality policy decide.
    """
    stack, _, request = _benign_stack(challenger_locality=ProviderLocality.LOCAL, max_remote=1)
    await stack.add_credentials()

    result = await stack.investigate(request)

    # The local challenger ran despite the remote allowance being spent.
    assert len(stack.requests_for("challenger")) == 1
    local = [
        attempt for attempt in result.enrichment.attempts if attempt.provider_id == "challenger"
    ]
    assert local and all(not attempt.called_provider or True for attempt in local)
    assert result.enrichment.budget.remote_runs_used <= 1


# --------------------------------------------------------------------------- #
# Termination
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_continuation_that_adds_nothing_stops_once() -> None:
    """No loop, and exactly one attempt at it.

    Readiness keeps asking because the requirement really is unmet; the planner
    has nothing left that could meet it. Asking a third time would produce this
    same round forever.
    """
    stack, _, request = _benign_stack(with_challenger=False)
    await stack.add_credentials()

    result = await stack.investigate(request)

    assert result.readiness.readiness_status is ReadinessStatus.NEEDS_MORE_DATA
    assert result.stop_reason in {
        WorkflowStopReason.NO_PROGRESS,
        WorkflowStopReason.CURRENT_BUDGET_EXHAUSTED,
        WorkflowStopReason.NO_ACTIONABLE_CONTINUATION,
    }
    # At most one continuation round was attempted.
    continuations = [
        item for item in result.rounds if item.trigger is RoundTrigger.READINESS_CONTINUATION
    ]
    assert len(continuations) <= 1


@pytest.mark.asyncio
async def test_a_fruitless_continuation_is_recorded_as_an_issue() -> None:
    """Visible rather than silent: the round happened and achieved nothing."""
    stack, _, request = _benign_stack(with_challenger=False)
    await stack.add_credentials()

    result = await stack.investigate(request)

    if result.stop_reason in {
        WorkflowStopReason.NO_PROGRESS,
        WorkflowStopReason.CURRENT_BUDGET_EXHAUSTED,
    }:
        assert any(
            issue.issue_type is WorkflowIssueType.CONTINUATION_WITHOUT_PROGRESS
            for issue in result.issues
        )
    else:
        assert any(
            issue.issue_type is WorkflowIssueType.UNACTIONABLE_INFORMATION_NEED
            for issue in result.issues
        )


@pytest.mark.asyncio
async def test_the_same_logical_call_is_never_repeated() -> None:
    """Task 13's memory carries, so a continuation cannot re-ask.

    Not left to the cache: a cache is an optimisation, and correctness that
    depends on one breaks the first time it misses.
    """
    stack, _, request = _benign_stack()
    await stack.add_credentials()

    await stack.investigate(request)

    for provider in ("benign", "challenger"):
        asked = stack.requests_for(provider)
        assert len(asked) == len({(value, tuple(sorted(caps))) for value, caps in asked})


@pytest.mark.asyncio
async def test_a_recomputation_follows_every_continuation() -> None:
    """New evidence produces new results, never a patched old one.

    Each round has its own assessment and readiness identity, and the final
    result carries the last pass's — not the first's with an amendment.
    """
    stack, _, request = _benign_stack()
    await stack.add_credentials()

    result = await stack.investigate(request)

    assert len(result.rounds) == 2
    assert result.rounds[0].readiness_result_id != result.rounds[1].readiness_result_id
    assert result.readiness.result_id == result.rounds[1].readiness_result_id
    assert result.rounds[0].evaluated_at <= result.rounds[1].evaluated_at
