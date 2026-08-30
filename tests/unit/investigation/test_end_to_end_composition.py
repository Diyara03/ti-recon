"""One observable, all the way through (Task 19).

Every layer in these tests is real: the Task 13 planner, the Task 6 executor with
its cache and cooldown stores, the Task 14 correlation engine and all four
reasoning engines. Only the providers are fake, and they are scripted per
observable.

That distinction carries the weight here. A Task 19 test that stubbed the
assessment would prove the workflow can copy a value between two objects; what
needs proving is that a scripted provider answer travels through qualification,
explanation, fusion and readiness and arrives as a verdict nobody wrote down in
advance.
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
    INVESTIGATION_WORKFLOW_VERSION,
    InvestigationRequest,
    RoundTrigger,
    WorkflowStopReason,
)
from ti_recon.reasoning.claims.models import ClaimSemantic
from ti_recon.reasoning.readiness.models import ReadinessStatus

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
THREAT = ProviderCapability.THREAT_ASSOCIATIONS

MALWARE_DIGEST = "a" * 64


def _known_malware_stack() -> tuple[InvestigationStack, object]:
    """A curated repository holding this exact sample, and nothing else."""
    root = file_root(MALWARE_DIGEST)
    repo = ScriptedProvider(
        spec("repo", family="fam_repo", capabilities=frozenset({INTELLIGENCE, REPUTATION})),
        {MALWARE_DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)},
    )
    return InvestigationStack(providers=[repo]), root


@pytest.mark.asyncio
async def test_a_known_malware_sample_finishes_in_one_pass() -> None:
    """The whole chain, and the workflow stops because readiness says so.

    A decisive exact identification needs nothing further, and the workflow's
    only job at that point is to notice. Terminal readiness ends the run whether
    or not other providers exist and whether or not any of them failed.
    """
    stack, root = _known_malware_stack()
    await stack.add_credentials()

    result = await stack.investigate(InvestigationRequest(root=root))

    assert result.assessment.assessment.verdict is Verdict.MALICIOUS
    assert result.readiness.readiness_status in {
        ReadinessStatus.READY,
        ReadinessStatus.READY_WITH_LIMITATIONS,
    }
    assert result.stop_reason is WorkflowStopReason.READINESS_TERMINAL
    assert len(result.rounds) == 1
    assert result.rounds[0].trigger is RoundTrigger.INITIAL


@pytest.mark.asyncio
async def test_every_stage_contributed_to_the_result() -> None:
    """Each layer's real output is present, not a placeholder.

    If any stage had been skipped or stubbed the chain would still produce a
    verdict — it would simply be a verdict formed without qualification, without
    alternative explanations, or without a coverage judgement.
    """
    stack, root = _known_malware_stack()
    await stack.add_credentials()

    result = await stack.investigate(InvestigationRequest(root=root))

    assert result.enrichment.attempts, "Task 13 executed nothing"
    assert result.correlation.graph_nodes, "Task 14 built no graph"
    assert result.qualification.evaluated_at == result.evaluated_at, "Task 15 absent"
    assert result.reasoning.policy_version, "Task 16 absent"
    assert result.assessment.normalized_claims, "Task 17 built no claims"
    assert result.readiness.requirement_evaluations, "Task 18 evaluated nothing"
    assert result.workflow_version == INVESTIGATION_WORKFLOW_VERSION


@pytest.mark.asyncio
async def test_the_final_results_all_come_from_one_pass() -> None:
    """No stale mixing across rounds.

    Pairing a Task 16 result from one round with a Task 17 result from another
    would be an assessment nobody actually reached. The four final outputs share
    one instant and one accumulated state.
    """
    stack, root = _known_malware_stack()
    await stack.add_credentials()

    result = await stack.investigate(InvestigationRequest(root=root))

    assert result.readiness.assessment_id == result.assessment.assessment.assessment_id
    assert result.qualification.evaluated_at == result.evaluated_at
    assert result.readiness.evaluated_at == result.evaluated_at
    assert result.rounds[-1].assessment_id == result.assessment.assessment.assessment_id
    assert result.rounds[-1].readiness_result_id == result.readiness.result_id


@pytest.mark.asyncio
async def test_the_root_is_the_same_observable_at_every_stage() -> None:
    """Planning, fusion and readiness all describe what the caller asked about."""
    stack, root = _known_malware_stack()
    await stack.add_credentials()

    result = await stack.investigate(InvestigationRequest(root=root))

    assert result.root.canonical_key == root.canonical_key
    assert result.enrichment.target.canonical_key == root.canonical_key
    assert result.assessment.target_key == root.canonical_key
    assert result.readiness.target_key == root.canonical_key
    assert result.correlation.root_node_key == root.canonical_key


@pytest.mark.asyncio
async def test_a_provider_failure_does_not_abort_the_investigation() -> None:
    """An unusable source is an analytical input, not an exception.

    One provider is unavailable and another answers. The run completes, the
    failure is on the record, and readiness decides whether the gap mattered —
    which is exactly the division of labour that lets an investigation survive a
    misconfigured integration.
    """
    root = file_root(MALWARE_DIGEST)
    broken = ScriptedProvider(
        spec("broken", family="fam_broken", capabilities=frozenset({REPUTATION})),
        {
            MALWARE_DIGEST: claim_evidence(
                ClaimSemantic.MALICIOUS_REPUTATION,
                status=ProviderRunStatus.TEMPORARILY_UNAVAILABLE,
            )
        },
    )
    working = ScriptedProvider(
        spec("working", family="fam_work", capabilities=frozenset({INTELLIGENCE})),
        {MALWARE_DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)},
    )
    stack = InvestigationStack(providers=[broken, working])
    await stack.add_credentials()

    result = await stack.investigate(InvestigationRequest(root=root))

    statuses = {attempt.status for attempt in result.enrichment.attempts}
    assert ProviderRunStatus.TEMPORARILY_UNAVAILABLE in statuses
    assert result.assessment.assessment.verdict is Verdict.MALICIOUS
    assert result.readiness.requirement_evaluations


@pytest.mark.asyncio
async def test_the_depth_the_caller_asked_for_is_the_depth_that_runs() -> None:
    """No escalation anywhere in the workflow.

    A QUICK investigation that would have benefited from DEEP work wanted a
    different investigation, and that is the caller's decision to make.
    """
    stack, root = _known_malware_stack()
    await stack.add_credentials()

    result = await stack.investigate(
        InvestigationRequest(root=root, depth=InvestigationDepth.QUICK)
    )

    assert result.requested_depth is InvestigationDepth.QUICK
    assert result.enrichment.depth is InvestigationDepth.QUICK
    for evaluation in result.readiness.requirement_evaluations:
        assert evaluation.requirement.requested_depth is InvestigationDepth.QUICK


@pytest.mark.asyncio
async def test_a_result_survives_serialization() -> None:
    """Round-trips byte-identically, with no reliance on object identity."""
    stack, root = _known_malware_stack()
    await stack.add_credentials()

    result = await stack.investigate(InvestigationRequest(root=root))
    dumped = result.model_dump_json()
    restored = type(result).model_validate_json(dumped)

    assert restored.model_dump_json() == dumped
    assert restored.result_id == result.result_id
    assert restored.root.canonical_key == result.root.canonical_key
    assert restored.assessment.assessment.verdict is result.assessment.assessment.verdict
    assert restored.readiness.readiness_status is result.readiness.readiness_status
    assert restored.stop_reason is result.stop_reason
    assert len(restored.rounds) == len(result.rounds)


@pytest.mark.asyncio
async def test_no_credential_reaches_the_result() -> None:
    """The fake keys are unmistakable, and none of them appears.

    Serialized whole, because a secret that leaks into a nested provider trace is
    just as exposed as one on the top-level object.
    """
    stack, root = _known_malware_stack()
    await stack.add_credentials()

    result = await stack.investigate(InvestigationRequest(root=root))
    dumped = result.model_dump_json()

    assert "SHOULD-NOT-LEAK" not in dumped
    for token in ("Authorization", "Auth-Key", "x-apikey", "api_key", "secret"):
        assert token.lower() not in dumped.lower()


@pytest.mark.asyncio
async def test_a_benign_assessment_is_challenged_before_it_is_ready() -> None:
    """The workflow's whole purpose, in one case.

    One source asserts the file is benign. An absence is only as good as the
    search behind it, so readiness requires an independent adverse search before
    calling the assessment ready. The search is a *capability*; Task 13 picks who
    can serve it, and the answer is nothing at all — which satisfies "somebody
    looked" and creates no benign evidence whatsoever.

    Run at DEEP, because that is the depth at which Task 13 admits threat-
    association hunting for a file. At STANDARD the same requirement is real and
    unbuyable, which is a different test.

    Note what the workflow never did: choose a provider, raise the depth, grant
    itself budget, or touch the verdict.
    """
    digest = "c" * 64
    root = file_root(digest)
    benign = ScriptedProvider(
        spec("benign", family="fam_a", capabilities=frozenset({REPUTATION, INTELLIGENCE})),
        {
            digest: claim_evidence(
                ClaimSemantic.BENIGN_REPUTATION, effect=EvidenceEffect.SUPPORTS_BENIGN
            )
        },
    )
    # An independent family that can run an adverse search, and knows nothing.
    challenger = ScriptedProvider(
        spec("challenger", family="fam_b", capabilities=frozenset({THREAT})), {}
    )
    stack = InvestigationStack(providers=[benign, challenger])
    await stack.add_credentials()

    result = await stack.investigate(InvestigationRequest(root=root, depth=InvestigationDepth.DEEP))

    # The challenge ran, returned nothing, and moved coverage rather than verdict.
    assert len(stack.requests_for("challenger")) == 1
    assert THREAT in {item.capability for item in result.enrichment.coverage}
    assert result.assessment.assessment.verdict is Verdict.LIKELY_BENIGN
    # Nobody named the challenger: the workflow asked for a capability.
    for round_ in result.rounds:
        for directive in round_.directives:
            assert "challenger" not in directive.reason
    assert result.requested_depth is InvestigationDepth.DEEP
