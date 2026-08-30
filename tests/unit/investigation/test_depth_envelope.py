"""What a continuation may ask for (Task 19).

The depth a caller asked for is a ceiling on the *questions*, not only on the
budget. Task 13 decides which capabilities a root of this type is worth
investigating at this depth; a continuation may narrow that set and may never
widen it. Otherwise readiness — which quite correctly says what would help —
would be able to turn a QUICK investigation into a DEEP one, one capability at
a time, without anyone deciding to pay for it.

Three categories, deliberately not collapsed into two:

* admissible and active -- a continuation may target it;
* admissible but not yet activated by Task 13 -- left to Task 13's own
  activation rule, never forced by a workflow that mentioned the capability;
* outside the requested depth -- never planned at all.
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
    EvidenceClass,
    EvidenceEffect,
    InvestigationDepth,
    ProviderCapability,
)
from ti_recon.investigation import (
    InvestigationRequest,
    RoundTrigger,
    WorkflowStopReason,
)
from ti_recon.planning.models import CallCostClass, ProviderLocality, SkipReason
from ti_recon.reasoning.claims.models import ClaimSemantic

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
THREAT = ProviderCapability.THREAT_ASSOCIATIONS
BEHAVIOUR = ProviderCapability.FILE_BEHAVIOR
DIGEST = "e" * 64


def _stack(*, deep_only: ProviderCapability = THREAT) -> InvestigationStack:
    """A benign assertion plus a source serving a capability DEEP admits."""
    return InvestigationStack(
        providers=[
            ScriptedProvider(
                spec("benign", family="fam_a", capabilities=frozenset({REPUTATION})),
                {
                    DIGEST: claim_evidence(
                        ClaimSemantic.BENIGN_REPUTATION, effect=EvidenceEffect.SUPPORTS_BENIGN
                    )
                },
            ),
            ScriptedProvider(
                spec("deeper", family="fam_b", capabilities=frozenset({deep_only})), {}
            ),
        ]
    )


@pytest.mark.parametrize("depth", [InvestigationDepth.QUICK, InvestigationDepth.STANDARD])
@pytest.mark.asyncio
async def test_a_shallower_depth_never_acquires_a_deeper_capability(
    depth: InvestigationDepth,
) -> None:
    """QUICK stays QUICK and STANDARD stays STANDARD.

    Threat-association hunting is admissible for a file at DEEP and at neither of
    these. Readiness still reports the need — it is a real one — and the
    workflow declines to buy it, because deciding that the investigation should
    have been deeper is the caller's decision and nobody else's.
    """
    stack = _stack()
    await stack.add_credentials()

    result = await stack.investigate(InvestigationRequest(root=file_root(DIGEST), depth=depth))

    assert stack.requests_for("deeper") == []
    assert THREAT not in {item.capability for item in result.enrichment.coverage}
    assert result.requested_depth is depth
    # And no round was spent pretending otherwise.
    assert [item.trigger for item in result.rounds] == [RoundTrigger.INITIAL]
    assert result.stop_reason in {
        WorkflowStopReason.NO_ACTIONABLE_CONTINUATION,
        WorkflowStopReason.READINESS_TERMINAL,
    }


@pytest.mark.asyncio
async def test_an_elevated_capability_is_out_of_scope_at_a_shallower_depth() -> None:
    """The same rule for the expensive one.

    ``FILE_BEHAVIOR`` at STANDARD is conditional and at QUICK is absent
    altogether. A QUICK investigation that would have benefited from watching the
    sample run wanted a different investigation.
    """
    stack = _stack(deep_only=BEHAVIOUR)
    await stack.add_credentials()

    result = await stack.investigate(
        InvestigationRequest(root=file_root(DIGEST), depth=InvestigationDepth.QUICK)
    )

    assert stack.requests_for("deeper") == []
    assert BEHAVIOUR not in {item.capability for item in result.enrichment.coverage}
    assert result.requested_depth is InvestigationDepth.QUICK


@pytest.mark.asyncio
async def test_a_conditional_goal_is_not_activated_by_a_continuation() -> None:
    """Activation stays Task 13's, even for a capability the depth admits.

    ``FILE_BEHAVIOR`` is in the STANDARD template, so it is inside the envelope —
    but it is a conditional follow-up, and its trigger did not fire. Task 19 must
    not force it merely because it is allowed to talk about it, or the activation
    rule would apply to the first round only.
    """
    # Nothing directional and a covered baseline, so the follow-up's trigger
    # never fires. A benign or malicious assertion would have fired it
    # legitimately, in the first round, which is a different situation.
    stack = InvestigationStack(
        providers=[
            ScriptedProvider(
                spec("context_only", family="fam_a", capabilities=frozenset({REPUTATION})),
                {
                    DIGEST: claim_evidence(
                        ClaimSemantic.UNCLASSIFIED_DIRECTIONAL,
                        effect=EvidenceEffect.CONTEXT_ONLY,
                        evidence_class=EvidenceClass.CONTEXT,
                    )
                },
            ),
            ScriptedProvider(
                spec("deeper", family="fam_b", capabilities=frozenset({BEHAVIOUR})), {}
            ),
        ]
    )
    await stack.add_credentials()

    result = await stack.investigate(
        InvestigationRequest(root=file_root(DIGEST), depth=InvestigationDepth.STANDARD)
    )

    assert stack.requests_for("deeper") == []
    inactive = [
        candidate
        for decision in result.enrichment.decisions
        for candidate in decision.skipped
        if candidate.capability is BEHAVIOUR
    ]
    # Reported as not yet eligible, never as forced or as never existing.
    assert inactive
    assert {item.reason for item in inactive} == {SkipReason.GOAL_NOT_ACTIVE}


@pytest.mark.asyncio
async def test_the_benign_challenge_does_not_reach_for_a_deeper_source() -> None:
    """A real requirement the current invocation cannot legitimately satisfy.

    Readiness wants an independent adverse search. The only source that could run
    one serves a capability this depth does not admit. Escalating would satisfy
    the requirement by changing the question the caller asked, so the workflow
    records that no allowed continuation addresses the need and stops. Starting a
    deeper investigation remains the caller's to do.
    """
    stack = _stack()
    await stack.add_credentials()

    result = await stack.investigate(
        InvestigationRequest(root=file_root(DIGEST), depth=InvestigationDepth.STANDARD)
    )

    assert THREAT in {item.capability for item in result.readiness.information_needs}
    assert stack.requests_for("deeper") == []
    assert result.stop_reason is WorkflowStopReason.NO_ACTIONABLE_CONTINUATION
    assert result.issues
    # The verdict readiness was unhappy with is untouched by any of this.
    assert result.assessment.assessment.verdict.value == "likely_benign"


@pytest.mark.asyncio
async def test_every_continuation_stays_inside_the_first_rounds_envelope() -> None:
    """The property, over a run that genuinely continues.

    Whatever a continuation asks for, it is something the first round was already
    allowed to ask for. Never a union, never a superset — a continuation can only
    ever subtract from the space Task 13 opened.
    """
    providers = [
        ScriptedProvider(
            spec(
                "local_benign",
                family="fam_a",
                capabilities=frozenset({REPUTATION}),
                locality=ProviderLocality.LOCAL,
                cost=CallCostClass.ZERO,
            ),
            {
                DIGEST: claim_evidence(
                    ClaimSemantic.BENIGN_REPUTATION, effect=EvidenceEffect.SUPPORTS_BENIGN
                )
            },
        ),
        ScriptedProvider(spec("gated", family="fam_b", capabilities=frozenset({INTELLIGENCE})), {}),
    ]
    stack = InvestigationStack(providers=providers)
    await stack.add_credentials()

    result = await stack.investigate(
        InvestigationRequest(root=file_root(DIGEST), max_remote_provider_runs=0)
    )

    envelope = {item.capability for item in result.enrichment.coverage}
    continuations = [
        item for item in result.rounds if item.trigger is RoundTrigger.READINESS_CONTINUATION
    ]
    assert continuations
    for round_ in continuations:
        asked = {item.capability for item in round_.directives}
        assert asked
        assert asked <= envelope
