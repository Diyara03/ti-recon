"""What identifies a call, and what a call costs (Task 19).

Four things the workflow gets to be wrong about quietly, each of which looks
fine from the outside until somebody reads the numbers:

* **call identity.** "This provider was already asked" is true of a question,
  not of a provider. A source that answered a reputation lookup has said nothing
  about what a sample did when it ran, and refusing to ask it would turn one
  answered question into a permanently unanswerable one.
* **attempt identity across rounds.** Composing rounds is a keyed merge, so the
  key has to be unique across the whole investigation rather than within one
  round of it.
* **budget accounting.** Root enrichment and pivot enrichment spend two
  different allowances. One physical call must reduce the allowance it was
  charged to and no other.
* **progress.** A round that added information made progress, whether or not the
  information cost a request.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from fixtures.investigation import (
    InvestigationStack,
    claim_evidence,
    file_root,
    observable_root,
    spec,
)
from fixtures.investigation.stack import ScriptedProvider
from ti_recon.correlation import PivotMode
from ti_recon.correlation.policy import PivotPolicy
from ti_recon.correlation.session import CorrelationSession
from ti_recon.enums import (
    CoverageRelevance,
    CoverageStatus,
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    ProviderRunStatus,
    RelationshipType,
    Verdict,
)
from ti_recon.investigation import InvestigationRequest
from ti_recon.investigation.continuation import directives_for
from ti_recon.investigation.engine import _RunState
from ti_recon.investigation.merge import MergeConflictError, merge_enrichment_results
from ti_recon.investigation.models import WorkflowIssue, WorkflowIssueType
from ti_recon.models.evidence import Evidence
from ti_recon.planning.models import (
    AdaptiveEnrichmentResult,
    CallCostClass,
    EnrichmentBudget,
    EnrichmentPlanningRequest,
    NoveltyClass,
    ProviderAttempt,
    ProviderLocality,
    SelectionReason,
    SkipReason,
    StopReason,
)
from ti_recon.reasoning.claims.models import ClaimSemantic, claim_from
from ti_recon.reasoning.claims.policy import CLAIM_SEMANTICS_POLICY_VERSION
from ti_recon.reasoning.fusion.models import AssessmentConfidence, FusionAssessment
from ti_recon.reasoning.fusion.results import FusionResult
from ti_recon.reasoning.readiness.models import (
    ContinuationState,
    CoverageAdequacy,
    GapOutlook,
    GapType,
    InformationNeed,
    ReadinessCoverageSummary,
    ReadinessGap,
    ReadinessPurpose,
    ReadinessStatus,
)
from ti_recon.reasoning.readiness.results import (
    AssessmentReadinessResult,
    ReadinessPolicyVersions,
)

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
THREAT = ProviderCapability.THREAT_ASSOCIATIONS
#: Deliberately not an adverse search. ``wide`` has to be asked something in the
#: first round that does *not* already answer readiness's independent-challenge
#: question, or there is no second round to observe.
CONTEXT = ProviderCapability.FALSE_POSITIVE_CONTEXT

DIGEST = "d" * 64
SAMPLE = "a" * 64
CONTACTED = "evil.example"


def _benign_and_wide(*, invariant: bool) -> InvestigationStack:
    """A benign assertion, and one other source that answers two questions.

    ``wide`` is asked for false-positive context immediately, and threat
    associations only once the baseline has run — two goals that become
    candidates at different moments, so they are never bundled into one
    decision. Whether the second question costs a second call is the whole
    point: a provider whose response depends on what was requested has genuinely
    not answered it yet, and one that returns its whole document already has.

    Run at DEEP, the depth at which Task 13 admits both capabilities for a file.
    """
    providers = [
        ScriptedProvider(
            spec("benign", family="fam_a", capabilities=frozenset({REPUTATION, INTELLIGENCE})),
            {
                DIGEST: claim_evidence(
                    ClaimSemantic.BENIGN_REPUTATION, effect=EvidenceEffect.SUPPORTS_BENIGN
                )
            },
        ),
        ScriptedProvider(
            spec(
                "wide",
                family="fam_b",
                capabilities=frozenset({CONTEXT, THREAT}),
                locality=ProviderLocality.LOCAL,
                cost=CallCostClass.ZERO,
                invariant=invariant,
            ),
            {},
        ),
    ]
    return InvestigationStack(providers=providers)


def _deep_request() -> InvestigationRequest:
    return InvestigationRequest(root=file_root(DIGEST), depth=InvestigationDepth.DEEP)


def _continuing_stack() -> tuple[InvestigationStack, InvestigationRequest]:
    """An admissible capability the first round could not afford to ask.

    The shape that genuinely produces a second round: a local source answers
    whatever the remote allowance is, and a remote one serving an admissible,
    material capability is never affordable — so readiness finds a real gap with
    a real path, and Task 13 is asked again.
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
    request = InvestigationRequest(root=file_root(DIGEST), max_remote_provider_runs=0)
    return InvestigationStack(providers=providers), request


# --------------------------------------------------------------------------- #
# 1. A logical call is a provider and a question, not a provider
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_used_provider_may_still_answer_a_different_capability() -> None:
    """Incremental work is not a repeated call.

    ``wide`` answered false-positive context. Its profile says a response is
    shaped by what was asked, so threat associations are genuinely unasked, and
    the provider that already helped must remain eligible to answer them.
    Excluding it by provider id would leave the investigation demanding a
    capability from a catalogue that has it.
    """
    stack = _benign_and_wide(invariant=False)
    await stack.add_credentials()

    await stack.investigate(_deep_request())

    asked = [tuple(sorted(item.value for item in caps)) for _, caps in stack.requests_for("wide")]
    assert (CONTEXT.value,) in asked
    assert (THREAT.value,) in asked
    # The same question, never twice.
    assert len(asked) == len(set(asked))


@pytest.mark.asyncio
async def test_a_capability_invariant_response_is_never_bought_twice() -> None:
    """One read that answered everything is not asked again.

    The same providers and the same scripts as above, with one flag changed. The
    provider now declares that a single response carries its whole document, so
    Task 13 credits the threat search from the first call and never buys the
    document twice.
    """
    stack = _benign_and_wide(invariant=True)
    await stack.add_credentials()

    result = await stack.investigate(_deep_request())

    assert len(stack.requests_for("wide")) == 1
    assert THREAT in {item.capability for item in result.enrichment.coverage}


@pytest.mark.asyncio
async def test_answering_nothing_does_not_block_a_provider_for_everything() -> None:
    """``NO_DATA`` closes one question, not a source.

    Task 13 blocks a whole provider only for the failures that are genuinely
    provider-wide — a refused credential, a spent quota, an unreachable endpoint.
    A source that simply held nothing has answered, and remains available for a
    different question.
    """
    stack = _benign_and_wide(invariant=False)
    await stack.add_credentials()

    result = await stack.investigate(_deep_request())

    empty = [item for item in result.enrichment.attempts if item.provider_id == "wide"]
    assert {item.status for item in empty} == {ProviderRunStatus.NO_DATA}
    assert {item.capability for item in empty} == {CONTEXT, THREAT}


# --------------------------------------------------------------------------- #
# 2. Attempt identity spans the investigation
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_attempt_sequences_continue_across_rounds() -> None:
    """Unique and monotonic over the whole investigation, not per round.

    The continuation state carries the planner's counter, which is what makes the
    sequence an identity rather than a position. If a round restarted it, two
    unrelated attempts would collide on the merge key.
    """
    stack, request = _continuing_stack()
    await stack.add_credentials()

    result = await stack.investigate(request)

    per_round = [set(item.new_attempt_sequences) for item in result.rounds]
    assert len(per_round) == 2
    assert not per_round[0] & per_round[1]

    merged = [item.sequence for item in result.enrichment.attempts]
    assert merged == sorted(merged)
    assert len(merged) == len(set(merged)) == sum(len(item) for item in per_round)


def _attempt(sequence: int, provider_id: str, **overrides: object) -> ProviderAttempt:
    return ProviderAttempt(
        sequence=sequence,
        provider_id=provider_id,
        capability=REPUTATION,
        source_family=f"fam_{provider_id}",
        locality=ProviderLocality.REMOTE,
        cost_class=CallCostClass.LOW,
        reason=SelectionReason.MISSING_CAPABILITY,
        novelty=NoveltyClass.NEW_CAPABILITY,
        status=ProviderRunStatus.SUCCESS,
        **overrides,
    )


def _round(*attempts: ProviderAttempt) -> AdaptiveEnrichmentResult:
    return AdaptiveEnrichmentResult(
        target=file_root(SAMPLE),
        depth=InvestigationDepth.STANDARD,
        attempts=attempts,
        budget=EnrichmentBudget(max_remote_provider_runs=4, max_high_cost_runs=1),
        stop_reason=StopReason.GOALS_SATISFIED,
    )


def test_an_identical_attempt_seen_twice_is_one_attempt() -> None:
    """A keyed merge, so a round reporting what an earlier one did is harmless.

    The same record, not a similar one: ``ProviderAttempt`` compares every field
    it carries, including when it was recorded, so anything that is not literally
    the same execution is a conflict rather than a duplicate. That asymmetry is
    the safe one.
    """
    attempt = _attempt(0, "alpha")
    merged = merge_enrichment_results([_round(attempt), _round(attempt)])

    assert [item.sequence for item in merged.attempts] == [0]


def test_merging_no_rounds_at_all_is_a_structural_error() -> None:
    """An investigation has at least one collection round.

    Reachable only from a caller that composed nothing, so it is a fault in the
    workflow rather than an empty result to hand onward.
    """
    with pytest.raises(MergeConflictError, match="at least one"):
        merge_enrichment_results([])


def test_rounds_describing_different_observables_are_refused() -> None:
    """The target describes the investigation, not the round.

    Two rounds about different objects is not something to reconcile: whichever
    one won, the merged view would attribute one observable's coverage to
    another, and every stage above reads that view.
    """
    other = _round().model_copy(update={"target": observable_root(CONTACTED)})
    with pytest.raises(MergeConflictError, match="different observables"):
        merge_enrichment_results([_round(_attempt(0, "alpha")), other])


def test_rounds_disagreeing_about_depth_are_refused() -> None:
    """Depth is a ceiling the caller set, identical every round.

    A disagreement means a continuation escalated or reduced it, which is the one
    thing the workflow promises never to do — so it is raised rather than merged
    away under whichever value happened to be last.
    """
    deeper = _round().model_copy(update={"depth": InvestigationDepth.DEEP})
    with pytest.raises(MergeConflictError, match="depth"):
        merge_enrichment_results([_round(_attempt(0, "alpha")), deeper])


def test_two_different_attempts_sharing_a_sequence_are_refused() -> None:
    """Never silently overwritten.

    Reachable only if the state carried between rounds was wrong, which means
    every conclusion drawn from the merged view would come from a picture that
    never existed. Louder is better than plausible.
    """
    with pytest.raises(MergeConflictError, match="attempt 0"):
        merge_enrichment_results([_round(_attempt(0, "alpha")), _round(_attempt(0, "beta"))])


# --------------------------------------------------------------------------- #
# 3. Coverage accumulates
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_the_first_rounds_coverage_survives_the_second() -> None:
    """The later round's coverage is the cumulative one, not the newer one.

    Task 13's state carries covered families forward, so the last round already
    describes the whole investigation. A round that replaced coverage rather than
    extending it would report the first round's work as never done — and the
    second round here asks about a different capability entirely, so a
    replacement would show up as reputation coverage vanishing.
    """
    stack, request = _continuing_stack()
    await stack.add_credentials()

    result = await stack.investigate(request)

    assert len(result.rounds) == 2
    by_capability = {item.capability: item for item in result.enrichment.coverage}
    # Covered in round one, by a provider round two never asked again.
    assert by_capability[REPUTATION].status is not CoverageStatus.NOT_COVERED
    assert [item.capability for item in result.rounds[1].directives] == [INTELLIGENCE]


# --------------------------------------------------------------------------- #
# 4. Two budgets, one call each
# --------------------------------------------------------------------------- #


def _pivot_stack() -> InvestigationStack:
    """A sample that contacted a domain, and a source that can answer about both."""
    return InvestigationStack(
        providers=[
            ScriptedProvider(
                spec(
                    "repo",
                    family="fam_repo",
                    capabilities=frozenset({INTELLIGENCE, REPUTATION}),
                    object_types=frozenset({IntelObjectType.FILE, IntelObjectType.DOMAIN_NAME}),
                ),
                {
                    SAMPLE: claim_evidence(
                        ClaimSemantic.MALWARE_SAMPLE_IDENTITY,
                        relations=((RelationshipType.CONTACTS, CONTACTED, "contacted"),),
                    ),
                    CONTACTED: claim_evidence(ClaimSemantic.MALICIOUS_REPUTATION),
                },
            )
        ]
    )


@pytest.mark.asyncio
async def test_a_pivot_result_reaches_every_reasoning_stage() -> None:
    """What a pivot learned is part of the investigation, not just of the graph.

    The graph already held the pivot's node, so the omission was invisible: the
    picture looked complete while the evidence behind half of it had never been
    qualified, explained, assessed or counted. A claim that reaches fusion is
    also the only way the rule that a pivot may not decide the root's verdict has
    anything to act on.
    """
    stack = _pivot_stack()
    await stack.add_credentials()

    result = await stack.investigate(
        InvestigationRequest(root=file_root(SAMPLE)),
        pivot_policy=PivotPolicy(mode=PivotMode.ENRICH, allow_remote_pivot_lookup=True),
    )

    pivot_key = observable_root(CONTACTED).canonical_key
    subjects = {claim.subject_key for claim in result.assessment.normalized_claims}
    assert result.correlation.pivot_runs
    assert pivot_key in subjects
    # Present, and still not a vote: the verdict is about what the analyst typed.
    assert result.assessment.assessment.target_key == file_root(SAMPLE).canonical_key
    assert result.assessment.assessment.verdict is Verdict.MALICIOUS


@pytest.mark.asyncio
async def test_a_pivot_spends_the_pivot_allowance_and_not_the_roots() -> None:
    """Two constraints, one unit each — never two units of one.

    Task 14 hands each pivot the *remaining pivot* allowance as a Task 13
    reduction, so a pivot call is charged once, to the budget that exists to
    bound disclosure beyond what the analyst asked about. The root's allowance is
    what remains for the observable itself, and a pivot must not quietly eat it.
    """
    stack = _pivot_stack()
    await stack.add_credentials()

    result = await stack.investigate(
        InvestigationRequest(root=file_root(SAMPLE)),
        pivot_policy=PivotPolicy(mode=PivotMode.ENRICH, allow_remote_pivot_lookup=True),
    )

    root_calls = sum(1 for item in result.enrichment.attempts if item.called_provider)
    pivot_calls = sum(item.remote_runs_used for item in result.correlation.pivot_runs)
    assert pivot_calls == 1
    assert result.correlation.pivot_budget.remote_runs_used == pivot_calls
    # Charged once each: the root budget records the root's calls alone.
    assert result.enrichment.budget.remote_runs_used == root_calls
    assert all(
        attempt.provider_id == "repo" and attempt.capability in {INTELLIGENCE, REPUTATION}
        for attempt in result.enrichment.attempts
    )


@pytest.mark.asyncio
async def test_a_cached_pivot_costs_no_remote_allowance() -> None:
    """A second investigation asks the same pivot and pays nothing.

    Both budgets are charged on whether a provider was actually contacted, so a
    result Task 6 already had discloses nothing and costs nothing. Identical
    stack, identical analyst, identical cache.
    """
    stack = _pivot_stack()
    await stack.add_credentials()
    policy = PivotPolicy(mode=PivotMode.ENRICH, allow_remote_pivot_lookup=True)

    first = await stack.investigate(
        InvestigationRequest(root=file_root(SAMPLE)), pivot_policy=policy
    )
    second = await stack.investigate(
        InvestigationRequest(root=file_root(SAMPLE)), pivot_policy=policy
    )

    assert first.correlation.pivot_budget.remote_runs_used == 1
    assert second.correlation.pivot_runs
    assert second.correlation.pivot_budget.remote_runs_used == 0
    assert second.enrichment.budget.remote_runs_used == 0


@pytest.mark.asyncio
async def test_a_local_pivot_costs_no_remote_allowance() -> None:
    """Locality, not luck: a local source discloses nothing to anyone."""
    local = ScriptedProvider(
        spec(
            "local_repo",
            family="fam_local",
            capabilities=frozenset({INTELLIGENCE, REPUTATION}),
            locality=ProviderLocality.LOCAL,
            cost=CallCostClass.ZERO,
            object_types=frozenset({IntelObjectType.FILE, IntelObjectType.DOMAIN_NAME}),
        ),
        {
            SAMPLE: claim_evidence(
                ClaimSemantic.MALWARE_SAMPLE_IDENTITY,
                relations=((RelationshipType.CONTACTS, CONTACTED, "contacted"),),
            ),
            CONTACTED: claim_evidence(ClaimSemantic.MALICIOUS_REPUTATION),
        },
    )
    stack = InvestigationStack(providers=[local])
    await stack.add_credentials()

    result = await stack.investigate(
        InvestigationRequest(root=file_root(SAMPLE)),
        pivot_policy=PivotPolicy(mode=PivotMode.ENRICH, allow_remote_pivot_lookup=True),
    )

    assert result.correlation.pivot_runs
    assert result.correlation.pivot_budget.remote_runs_used == 0
    assert result.enrichment.budget.remote_runs_used == 0


# --------------------------------------------------------------------------- #
# 5. Progress is collection, not bookkeeping
# --------------------------------------------------------------------------- #


def test_progress_is_measured_from_what_was_collected() -> None:
    """A cache hit that answered something new is progress.

    Progress and remote cost are different questions, and conflating them would
    end an investigation the moment its allowance emptied even though a free
    source had just answered the thing it was missing. Round bookkeeping is not
    progress either — an index, an instant and a fresh result id all change on
    their own.
    """
    state = _RunState(investigation_id="inv-1", session=CorrelationSession())
    empty = state.progress_key()

    cached = _attempt(0, "alpha", called_provider=False, cache_hit=True, coverage_gained=True)
    state.enrichments.append(_round(cached))
    state.attempted_capabilities.add(REPUTATION.value)
    assert state.progress_key() != empty

    # Bookkeeping alone is not progress: a workflow issue is a record of
    # something that did *not* work.
    moved = state.progress_key()
    state.issues.append(
        WorkflowIssue(
            issue_type=WorkflowIssueType.CONTINUATION_WITHOUT_PROGRESS,
            detail="nothing new",
            round_index=1,
        )
    )
    assert state.progress_key() == moved


# --------------------------------------------------------------------------- #
# 6. A directive asks for information; only one of them asks for independence
# --------------------------------------------------------------------------- #


def _benign_fusion() -> FusionResult:
    """One benign claim from one family, so a dependence component exists."""
    evidence = Evidence(
        investigation_id="inv-1",
        subject_object_id="obj-1",
        evidence_class=EvidenceClass.CURATED_THREAT_ASSERTION,
        claim_type="scripted_benign",
        effect=EvidenceEffect.SUPPORTS_BENIGN,
        transport_provider="benign",
        origin_provider="benign",
        source_family="fam_a",
    )
    claim = claim_from(
        evidence,
        policy_version=CLAIM_SEMANTICS_POLICY_VERSION,
        semantic=ClaimSemantic.BENIGN_REPUTATION,
        subject_key="file:sha256:" + DIGEST,
    )
    assessment = FusionAssessment(
        assessment_id="assess-1",
        target_key="file:sha256:" + DIGEST,
        verdict=Verdict.LIKELY_BENIGN,
        confidence=AssessmentConfidence.LOW,
        verdict_rule_id="likely_benign.directional.v1",
        confidence_rule_id="confidence.low.v1",
        as_of=datetime(2026, 8, 1, tzinfo=UTC),
        fusion_policy_version="1.0.0",
        claim_semantics_policy_version=CLAIM_SEMANTICS_POLICY_VERSION,
        qualification_policy_version="1.0.0",
        false_positive_policy_version="1.0.0",
        engine_version="1.0.0",
    )
    return FusionResult(
        target_key=assessment.target_key, assessment=assessment, normalized_claims=(claim,)
    )


def _need(capability: ProviderCapability) -> InformationNeed:
    return InformationNeed(
        capability=capability,
        criticality=CoverageRelevance.REQUIRED,
        reason="material gap",
        outlook=GapOutlook.MAY_ADDRESS_MATERIAL_GAP,
    )


def _gap(capability: ProviderCapability, gap_type: GapType) -> ReadinessGap:
    return ReadinessGap(
        gap_id=f"gap-{capability.value}",
        requirement_id=f"req-{capability.value}",
        gap_type=gap_type,
        capability=capability,
        criticality=CoverageRelevance.REQUIRED,
        outlook=GapOutlook.MAY_ADDRESS_MATERIAL_GAP,
        detail="not met",
    )


def _readiness_wanting(*pairs: tuple[ProviderCapability, GapType]) -> AssessmentReadinessResult:
    return AssessmentReadinessResult(
        result_id="readiness-1",
        purpose=ReadinessPurpose.ANALYST_TRIAGE,
        target_key="file:sha256:" + DIGEST,
        requested_depth=InvestigationDepth.STANDARD,
        readiness_status=ReadinessStatus.NEEDS_MORE_DATA,
        coverage_adequacy=CoverageAdequacy.INADEQUATE,
        continuation_state=ContinuationState.MORE_DATA_AVAILABLE,
        gaps=tuple(_gap(capability, gap_type) for capability, gap_type in pairs),
        information_needs=tuple(_need(capability) for capability, _ in pairs),
        assessment_id="assess-1",
        verdict=Verdict.LIKELY_BENIGN,
        confidence=AssessmentConfidence.LOW,
        verdict_rule_id="likely_benign.directional.v1",
        coverage_summary=ReadinessCoverageSummary(),
        policy_versions=ReadinessPolicyVersions(
            readiness_policy_version="1.0.0",
            fusion_policy_version="1.0.0",
            claim_semantics_policy_version=CLAIM_SEMANTICS_POLICY_VERSION,
            false_positive_policy_version="1.0.0",
            qualification_policy_version="1.0.0",
        ),
        evaluated_at=datetime(2026, 8, 1, tzinfo=UTC),
    )


def test_only_the_need_that_asked_for_independence_carries_a_family_hint() -> None:
    """A source-family hint belongs to the challenge and to nothing else.

    Whether a sandbox shares an origin with something that called the file benign
    has no bearing on what the sandbox watched it do. Attaching the families to
    every directive records a constraint nobody asked for — and would be the
    first thing a future planner seam mistook for one, quietly excluding a whole
    family from a capability where independence was never the question.
    """
    directives = directives_for(
        _readiness_wanting(
            (THREAT, GapType.INDEPENDENT_CHALLENGE_MISSING),
            (ProviderCapability.FILE_BEHAVIOR, GapType.NOT_ATTEMPTED),
        ),
        _benign_fusion(),
    )

    by_capability = {item.capability: item for item in directives}
    assert by_capability[THREAT].avoid_source_families == frozenset({"fam_a"})
    assert by_capability[ProviderCapability.FILE_BEHAVIOR].avoid_source_families == frozenset()


def test_every_actionable_need_becomes_a_directive() -> None:
    """No hidden "first gap wins".

    Task 18 may name several material needs, and dropping the rest would leave
    the investigation permanently short of one of them while reporting that it
    had continued. All of them go to Task 13, in a stable order, and Task 13
    decides what the remaining allowance can actually buy.
    """
    directives = directives_for(
        _readiness_wanting(
            (THREAT, GapType.INDEPENDENT_CHALLENGE_MISSING),
            (ProviderCapability.FILE_BEHAVIOR, GapType.NOT_ATTEMPTED),
            (INTELLIGENCE, GapType.BUDGET_LIMITED),
        ),
        _benign_fusion(),
    )

    assert [item.capability for item in directives] == sorted(
        (THREAT, ProviderCapability.FILE_BEHAVIOR, INTELLIGENCE), key=lambda item: item.value
    )


@pytest.mark.asyncio
async def test_a_session_exclusion_reaches_the_planner_and_stops_a_call() -> None:
    """The seam, proven where the two layers actually meet.

    A directive's ``avoid_source_families`` is worth nothing if it stops at the
    record. The correlation session is what carries it into Task 13, so a
    session that excludes a family must produce a round in which that family's
    provider is not asked — and in which the capability it was excluded from is
    the only thing affected.
    """
    excluded = ScriptedProvider(
        spec("shared_family", family="fam_a", capabilities=frozenset({REPUTATION})), {}
    )
    stack = InvestigationStack(providers=[excluded])
    await stack.add_credentials()
    planning_request = EnrichmentPlanningRequest(
        intel_object=file_root(DIGEST), depth=InvestigationDepth.STANDARD
    )

    # Round one: no exclusion, so the provider is asked.
    session = CorrelationSession()
    await stack.correlation.run(
        planning_request, stack.context(), investigation_id="inv-1", session=session
    )
    assert len(stack.requests_for("shared_family")) == 1

    # Round two, same session: its family may no longer answer reputation.
    session.focus = frozenset({REPUTATION})
    session.excluded_families = {REPUTATION: frozenset({"fam_a"})}
    result = await stack.correlation.run(
        planning_request, stack.context(), investigation_id="inv-1", session=session
    )

    assert len(stack.requests_for("shared_family")) == 1
    assert any(
        candidate.reason is SkipReason.SOURCE_FAMILY_EXCLUDED
        for decision in result.root_enrichment.decisions
        for candidate in decision.skipped
    )
