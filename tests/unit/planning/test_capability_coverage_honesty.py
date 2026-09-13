"""Coverage is credited only for a question a provider was actually asked (Task 24).

Two halves.

The generic rule: the planner asks a provider only for capabilities its planning
profile offers, credits a request-shaped provider with exactly what it asked, and
credits a capability-invariant provider with everything it plans. So a
capability the profile does not offer is never bundled and never credited, and a
SUCCESS answering some other question cannot cover it. That is where honesty
lives -- in the declaration -- because Task 13 records outcomes per call and no
evidence record names a capability, so there is no generic evidence-based check
to add without inventing one.

The concrete regression: the DEEP address run that produced CS-02, replayed over
the real catalogue with fabricated outcomes matching the live statuses. Before
the fix GTI's bundle carried ``current_infrastructure`` and closed it with a
SUCCESS that carried nothing for it, and the one provider that answers it was
never asked. After the fix the goal stays open past GTI and the planner reaches
that provider on its own ranking. Nothing here names a provider as a preference;
the assertions read the trace the planner wrote.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fixtures.planning import (
    FakeProviderSpec,
    build_registry,
    fake_outcome,
    file_object,
)
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    InvestigationDepth,
    ProviderCapability,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution.models import ProviderExecutionOutcome
from ti_recon.models.evidence import Evidence
from ti_recon.normalization import normalize_observable
from ti_recon.planning import AdaptiveEnrichmentPlanner, EnrichmentPlanningRequest
from ti_recon.planning.catalog import build_default_planning_registry
from ti_recon.planning.models import SkipReason
from ti_recon.providers import ProviderRegistry
from ti_recon.providers.catalog import build_default_adapters
from ti_recon.providers.result import ProviderResultEnvelope

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
INFRASTRUCTURE = ProviderCapability.CURRENT_INFRASTRUCTURE
OWNERSHIP = ProviderCapability.NETWORK_OWNERSHIP


# --------------------------------------------------------------------------- #
# Generic: the declaration is the boundary
# --------------------------------------------------------------------------- #


def _plan_one(spec: FakeProviderSpec, *, status: ProviderRunStatus = ProviderRunStatus.SUCCESS):
    registry, profiles = build_registry((spec,))
    planner = AdaptiveEnrichmentPlanner(registry=registry, profiles=profiles)
    request = EnrichmentPlanningRequest(
        intel_object=file_object(), depth=InvestigationDepth.STANDARD
    )
    state = planner.initial_state(request)
    decision = planner.next(request, state)
    assert decision.call is not None
    state.observe(
        decision.call,
        fake_outcome(spec.provider_id, status=status, effect=EvidenceEffect.CONTEXT_ONLY),
    )
    return decision.call, state


def test_a_capability_the_profile_does_not_offer_is_never_bundled_or_credited() -> None:
    """Descriptor says A and B; the planning profile offers A alone. The call
    carries A, answers A, and a SUCCESS covers A and nothing else."""
    spec = FakeProviderSpec(
        provider_id="repo",
        source_family="fam_repo",
        capabilities=frozenset({REPUTATION, INTELLIGENCE}),
        planning_capabilities=frozenset({REPUTATION}),
    )
    call, state = _plan_one(spec)
    assert call.capabilities == frozenset({REPUTATION})
    assert call.answered_capabilities == frozenset({REPUTATION})
    assert state.answered_families(REPUTATION) == frozenset({"fam_repo"})
    assert state.answered_families(INTELLIGENCE) == frozenset()
    assert ("repo", INTELLIGENCE) not in state.answered


def test_a_request_shaped_provider_is_credited_exactly_what_it_was_asked() -> None:
    """Both offered, both current goals, so both are asked and both credited:
    the provider declared it answers both, and that declaration is the promise
    CS-02 holds a provider to."""
    spec = FakeProviderSpec(
        provider_id="repo",
        source_family="fam_repo",
        capabilities=frozenset({REPUTATION, INTELLIGENCE}),
    )
    call, state = _plan_one(spec)
    assert call.capabilities == frozenset({REPUTATION, INTELLIGENCE})
    assert call.answered_capabilities == call.capabilities
    assert state.answered_families(INTELLIGENCE) == frozenset({"fam_repo"})


def test_an_unplanned_capability_is_skipped_as_unsupported_not_credited() -> None:
    """With another provider keeping the goal alive, the one whose profile does
    not offer it is skipped by name and never becomes its candidate."""
    repo = FakeProviderSpec(
        provider_id="repo",
        source_family="fam_repo",
        capabilities=frozenset({REPUTATION, INTELLIGENCE}),
        planning_capabilities=frozenset({REPUTATION}),
    )
    archive = FakeProviderSpec(
        provider_id="archive",
        source_family="fam_archive",
        capabilities=frozenset({INTELLIGENCE}),
    )
    registry, profiles = build_registry((repo, archive))
    planner = AdaptiveEnrichmentPlanner(registry=registry, profiles=profiles)
    request = EnrichmentPlanningRequest(
        intel_object=file_object(), depth=InvestigationDepth.STANDARD
    )
    decision = planner.next(request, planner.initial_state(request))
    reasons = {
        (item.provider_id, item.capability, item.reason)
        for item in decision.skipped
        if item.capability is INTELLIGENCE
    }
    assert ("repo", INTELLIGENCE, SkipReason.UNSUPPORTED_CAPABILITY) in reasons


def test_a_goal_no_profile_offers_is_dropped_rather_than_credited() -> None:
    """The declaration decides candidacy before anything is asked: a goal no
    planning profile serves does not exist for the run, so no answer can be
    credited to it."""
    repo = FakeProviderSpec(
        provider_id="repo",
        source_family="fam_repo",
        capabilities=frozenset({REPUTATION, INTELLIGENCE}),
        planning_capabilities=frozenset({REPUTATION}),
    )
    registry, profiles = build_registry((repo,))
    planner = AdaptiveEnrichmentPlanner(registry=registry, profiles=profiles)
    request = EnrichmentPlanningRequest(
        intel_object=file_object(), depth=InvestigationDepth.STANDARD
    )
    state = planner.initial_state(request)
    assert INTELLIGENCE not in {goal.capability for goal in state.goals}


# --------------------------------------------------------------------------- #
# The live address run, replayed over the real catalogue
# --------------------------------------------------------------------------- #

#: What each provider answered live for the address, as the trace recorded it.
#: A provider absent from the workstation's configuration is NOT_CONFIGURED.
LIVE_STATUSES: dict[str, ProviderRunStatus] = {
    "misp_warninglists": ProviderRunStatus.SUCCESS,
    "greynoise": ProviderRunStatus.NO_DATA,
    "urlhaus": ProviderRunStatus.NO_DATA,
    "threatfox": ProviderRunStatus.NO_DATA,
    "gti": ProviderRunStatus.SUCCESS,
    "urlscan": ProviderRunStatus.NOT_CONFIGURED,
    "censys": ProviderRunStatus.SUCCESS,
}


def _replay(statuses: dict[str, ProviderRunStatus]) -> tuple[list[Any], Any]:
    adapters = build_default_adapters()
    planner = AdaptiveEnrichmentPlanner(
        registry=ProviderRegistry(adapters), profiles=build_default_planning_registry()
    )
    root = normalize_observable("203.0.113.9").intel_object
    request = EnrichmentPlanningRequest(intel_object=root, depth=InvestigationDepth.DEEP)
    state = planner.initial_state(request)
    now = datetime.now(UTC)
    calls: list[Any] = []
    for _ in range(20):
        decision = planner.next(request, state)
        if decision.stop is not None:
            calls.append(decision.stop)
            break
        call = decision.call
        assert call is not None
        calls.append(call)
        status = statuses[call.provider_id]
        adapter = next(a for a in adapters if a.descriptor.provider_id == call.provider_id)
        called = status is not ProviderRunStatus.NOT_CONFIGURED
        evidence: tuple[Evidence, ...] = ()
        if called:
            evidence = (
                Evidence(
                    investigation_id="inv",
                    subject_object_id=root.id,
                    evidence_class=EvidenceClass.CONTEXT,
                    claim_type=f"{call.provider_id}_context",
                    effect=EvidenceEffect.CONTEXT_ONLY,
                    transport_provider=call.provider_id,
                    origin_provider=call.provider_id,
                    source_family=adapter.descriptor.source_family,
                ),
            )
        envelope = ProviderResultEnvelope(
            provider=call.provider_id,
            operation=ProviderOperation.LOOKUP,
            status=status,
            adapter_version="0",
            api_version="v",
            evidence=evidence,
            objects=(root,),
        )
        state.observe(
            call,
            ProviderExecutionOutcome(
                provider_id=call.provider_id,
                operation=ProviderOperation.LOOKUP,
                status=status,
                request_id="r",
                scope_identity="s",
                result=envelope if called else None,
                attempts=1 if called else 0,
                started_at=now,
                completed_at=now,
                duration_ms=1.0,
            ),
        )
    return calls, state


def test_the_live_address_run_no_longer_closes_infrastructure_on_a_reputation_answer() -> None:
    calls, state = _replay(LIVE_STATUSES)
    by_provider = {call.provider_id: call for call in calls if not isinstance(call, str)}
    # The reputation family that used to carry the infrastructure question no
    # longer does: its bundle is exactly what it answers.
    assert INFRASTRUCTURE not in by_provider["gti"].capabilities
    assert INFRASTRUCTURE not in by_provider["gti"].answered_capabilities
    # The goal stayed open past that answer and was asked of the providers that
    # declare it, in the planner's own order, until one answered.
    asked = [
        call.provider_id
        for call in calls
        if not isinstance(call, str) and INFRASTRUCTURE in call.capabilities
    ]
    assert asked, "the infrastructure goal must reach a provider that declares it"
    assert "gti" not in asked
    assert state.answered_families(INFRASTRUCTURE) == frozenset({"censys"})
    assert calls[-1].value == "goals_satisfied"


def test_an_unconfigured_first_choice_does_not_close_the_goal() -> None:
    """The workstation had no urlscan key: NOT_CONFIGURED blocks that provider and
    the next declared provider is asked, so the goal is answered rather than
    reported unattempted."""
    calls, state = _replay(LIVE_STATUSES)
    infrastructure_calls = [
        call for call in calls if not isinstance(call, str) and INFRASTRUCTURE in call.capabilities
    ]
    statuses = [LIVE_STATUSES[call.provider_id] for call in infrastructure_calls]
    assert ProviderRunStatus.NOT_CONFIGURED in statuses
    assert statuses[-1] is ProviderRunStatus.SUCCESS
    assert state.answered_families(INFRASTRUCTURE)


def test_the_replay_names_no_preferred_provider() -> None:
    """The ranking chose; this file only reads the trace. A provider that happens
    to declare the capability and be configured is what gets asked -- change the
    configuration and a different declared provider is asked instead."""
    everything_configured = {**LIVE_STATUSES, "urlscan": ProviderRunStatus.SUCCESS}
    calls, state = _replay(everything_configured)
    asked = [
        call.provider_id
        for call in calls
        if not isinstance(call, str) and INFRASTRUCTURE in call.capabilities
    ]
    assert len(asked) == 1
    assert state.answered_families(INFRASTRUCTURE)


def test_the_policy_boundary_is_unchanged_for_network_ownership() -> None:
    """CS-POLICY-01, recorded and deliberately not changed here: one
    capability-invariant family's empty answer still satisfies the one-family
    ownership target, so no provider is asked for it by name."""
    calls, state = _replay(LIVE_STATUSES)
    # The scanner family's empty whole-document answer closed the target ...
    assert "greynoise" in state.answered_families(OWNERSHIP)
    # ... so no call ever carried the question, by name or in a bundle. Any
    # further family credited here answered it inside a document fetched for a
    # different question, exactly as invariant 45 describes.
    assert not [
        call for call in calls if not isinstance(call, str) and OWNERSHIP in call.capabilities
    ]
