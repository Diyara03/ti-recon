"""An explicit corroboration objective, and the default that stops when adequate.

Two things that must not be conflated. By default the workflow stops when
readiness says coverage is adequate for triage -- an eligible extra source is
not a reason to spend more of somebody's quota. A caller who asks to
corroborate gets at most one bounded round past that point: an adverse search
from a family independent of the assessment's basis, if one is eligible and
affordable. Never inferred from a verdict, never a second planner, never a
guarantee that a second source exists.
"""

from __future__ import annotations

import pytest

from fixtures.investigation import InvestigationStack, observable_root, spec
from fixtures.investigation.stack import ScriptedProvider, claim_evidence
from ti_recon.credentials import AuthType, CredentialStatus
from ti_recon.enums import IntelObjectType, InvestigationDepth, ProviderCapability
from ti_recon.investigation import (
    InvestigationObjective,
    InvestigationRequest,
    RoundTrigger,
    WorkflowStopReason,
)
from ti_recon.investigation.models import ContinuationNeed, WorkflowIssueType
from ti_recon.planning.models import CallCostClass, ProviderLocality
from ti_recon.reasoning.claims.models import ClaimSemantic
from ti_recon.reasoning.readiness.models import ReadinessStatus

ADDRESS = "203.0.113.90"
REPUTATION = ProviderCapability.REPUTATION
SCANNER = ProviderCapability.SCANNER_CONTEXT
OWNERSHIP = ProviderCapability.NETWORK_OWNERSHIP
CONTEXT = ProviderCapability.FALSE_POSITIVE_CONTEXT
IPV4 = frozenset({IntelObjectType.IPV4_ADDR})
USER = "analyst-corroborate"


def _stack(*, with_extra: bool = True, max_remote: int | None = None):
    """Adequate on the first round: a decisive family plus a second family.

    ``extra`` is a third, independent family that only serves reputation and
    ranks last, so the base two-family target never reaches it. It is exactly
    what a corroboration objective is for -- and exactly what triage must not
    spend on.
    """
    providers = [
        ScriptedProvider(
            spec(
                "decisive",
                family="fam_a",
                capabilities=frozenset({REPUTATION, OWNERSHIP, SCANNER}),
                priority=70,
                object_types=IPV4,
            ),
            {ADDRESS: claim_evidence(ClaimSemantic.MALWARE_DISTRIBUTION)},
        ),
        ScriptedProvider(
            spec(
                "second",
                family="fam_b",
                capabilities=frozenset({REPUTATION}),
                priority=55,
                object_types=IPV4,
            ),
            {ADDRESS: claim_evidence(ClaimSemantic.MALICIOUS_REPUTATION)},
        ),
        ScriptedProvider(
            spec(
                "local_ctx",
                family="fam_local",
                capabilities=frozenset({CONTEXT}),
                locality=ProviderLocality.LOCAL,
                cost=CallCostClass.ZERO,
                priority=90,
                object_types=IPV4,
            ),
            {},
        ),
    ]
    if with_extra:
        providers.append(
            ScriptedProvider(
                spec(
                    "extra",
                    family="fam_c",
                    capabilities=frozenset({REPUTATION}),
                    priority=10,
                    object_types=IPV4,
                ),
                {ADDRESS: claim_evidence(ClaimSemantic.MALICIOUS_REPUTATION)},
            )
        )
    return InvestigationStack(providers=providers), max_remote


async def _credentials(stack: InvestigationStack) -> None:
    for provider in stack.providers:
        descriptor = provider.descriptor
        if descriptor.requires_credentials:
            await stack.manager.create_connection(
                user_id=USER,
                provider_id=descriptor.provider_id,
                secret=f"{descriptor.provider_id}-key",
                auth_type=AuthType.API_KEY,
                status=CredentialStatus.ACTIVE,
                credential_group=descriptor.provider_id,
            )


def _request(
    objective: InvestigationObjective, max_remote: int | None = None
) -> InvestigationRequest:
    return InvestigationRequest(
        root=observable_root(ADDRESS),
        depth=InvestigationDepth.STANDARD,
        objective=objective,
        max_remote_provider_runs=max_remote,
    )


def _triggers(result) -> list[RoundTrigger]:
    return [item.trigger for item in result.rounds]


@pytest.mark.asyncio
async def test_triage_stops_when_adequate_and_leaves_the_extra_source_unasked() -> None:
    """Case C: the default does not spend on an eligible extra source."""
    stack, _ = _stack()
    await _credentials(stack)

    result = await stack.investigate(_request(InvestigationObjective.TRIAGE), user_id=USER)

    assert result.readiness.readiness_status in {
        ReadinessStatus.READY,
        ReadinessStatus.READY_WITH_LIMITATIONS,
    }
    assert result.stop_reason is WorkflowStopReason.READINESS_TERMINAL
    assert _triggers(result) == [RoundTrigger.INITIAL]
    assert stack.requests_for("extra") == []
    assert result.objective == "triage"


@pytest.mark.asyncio
async def test_corroborate_spends_one_round_on_an_independent_source() -> None:
    """Case D: the explicit objective buys the independent search, once."""
    stack, _ = _stack()
    await _credentials(stack)

    result = await stack.investigate(_request(InvestigationObjective.CORROBORATE), user_id=USER)

    assert _triggers(result) == [RoundTrigger.INITIAL, RoundTrigger.CORROBORATION]
    corroboration = result.rounds[1]
    assert {item.need for item in corroboration.directives} == {
        ContinuationNeed.ADDITIONAL_COVERAGE
    }
    assert {item.capability for item in corroboration.directives} == {REPUTATION}
    assert all(
        {"fam_a", "fam_b"} <= item.avoid_source_families for item in corroboration.directives
    )
    assert len(stack.requests_for("extra")) == 1
    # Nothing already asked is asked the same question again, and the verdict
    # is recomputed rather than patched: the extra source appears in the
    # coverage record.
    for provider_id in ("decisive", "second"):
        reputation_calls = [
            item for item in stack.requests_for(provider_id) if REPUTATION in item[1]
        ]
        assert len(reputation_calls) == 1, provider_id
    assert "extra" in {item.provider_id for item in result.enrichment.attempts}
    assert result.stop_reason is WorkflowStopReason.READINESS_TERMINAL
    assert result.objective == "corroborate"
    assert not any(
        issue.issue_type is WorkflowIssueType.CORROBORATION_NOT_OBTAINED for issue in result.issues
    )


@pytest.mark.asyncio
async def test_corroborate_with_nothing_independent_records_an_issue_and_changes_nothing() -> None:
    stack, _ = _stack(with_extra=False)
    await _credentials(stack)
    baseline = await stack.investigate(_request(InvestigationObjective.TRIAGE), user_id=USER)

    stack, _ = _stack(with_extra=False)
    await _credentials(stack)
    result = await stack.investigate(_request(InvestigationObjective.CORROBORATE), user_id=USER)

    assert any(
        issue.issue_type is WorkflowIssueType.CORROBORATION_NOT_OBTAINED for issue in result.issues
    )
    assert _triggers(result).count(RoundTrigger.CORROBORATION) <= 1
    assert result.stop_reason is WorkflowStopReason.READINESS_TERMINAL
    assert result.assessment.assessment.verdict is baseline.assessment.assessment.verdict
    assert result.assessment.assessment.confidence is baseline.assessment.assessment.confidence


@pytest.mark.asyncio
async def test_corroborate_never_exceeds_the_remote_allowance() -> None:
    """Two remote calls are the allowance; the objective cannot grant a third."""
    stack, _ = _stack()
    await _credentials(stack)

    result = await stack.investigate(
        _request(InvestigationObjective.CORROBORATE, max_remote=2), user_id=USER
    )

    remote = [
        item
        for item in result.enrichment.attempts
        if item.called_provider and item.locality is ProviderLocality.REMOTE
    ]
    assert len(remote) <= 2
    assert stack.requests_for("extra") == []
    assert any(
        issue.issue_type is WorkflowIssueType.CORROBORATION_NOT_OBTAINED for issue in result.issues
    )


@pytest.mark.asyncio
async def test_corroborate_is_never_inferred_and_runs_only_past_adequate_readiness() -> None:
    """A run that never reached adequate readiness has no corroboration round."""
    providers = [
        ScriptedProvider(
            spec(
                "weak",
                family="fam_a",
                capabilities=frozenset({REPUTATION}),
                priority=70,
                object_types=IPV4,
            ),
            {ADDRESS: claim_evidence(ClaimSemantic.AGGREGATED_REPUTATION)},
        ),
        ScriptedProvider(
            spec(
                "scanner",
                family="fam_scan",
                capabilities=frozenset({SCANNER, REPUTATION}),
                priority=60,
                object_types=IPV4,
            ),
            {},
        ),
    ]
    stack = InvestigationStack(providers=providers)
    await stack.manager.create_connection(
        user_id=USER,
        provider_id="weak",
        secret="weak-key",
        auth_type=AuthType.API_KEY,
        status=CredentialStatus.ACTIVE,
        credential_group="weak",
    )

    result = await stack.investigate(_request(InvestigationObjective.CORROBORATE), user_id=USER)

    assert result.stop_reason is not WorkflowStopReason.READINESS_TERMINAL
    assert RoundTrigger.CORROBORATION not in _triggers(result)


@pytest.mark.asyncio
async def test_the_report_records_the_objective_that_was_asked_for() -> None:
    from ti_recon.reporting.builder import build_analyst_report

    stack, _ = _stack()
    await _credentials(stack)

    result = await stack.investigate(_request(InvestigationObjective.CORROBORATE), user_id=USER)

    report = build_analyst_report(result)
    assert report.request.objective == "corroborate"
    assert report.request.depth is InvestigationDepth.STANDARD


@pytest.mark.asyncio
async def test_a_corroboration_round_that_reaches_only_an_unconfigured_source_is_not_obtained() -> (
    None
):
    """An attempt that could not be made is not a second source (Task 24 Phase 3).

    Live, the corroboration round reached one unconfigured provider, the attempt
    count moved, and the report showed two rounds and no issue -- as if a
    second opinion had been sought and found. Obtained means answered.
    """
    stack, _ = _stack(with_extra=True)
    # Credentials for everything except the only independent family.
    for provider in stack.providers:
        descriptor = provider.descriptor
        if descriptor.requires_credentials and descriptor.provider_id != "extra":
            await stack.manager.create_connection(
                user_id=USER,
                provider_id=descriptor.provider_id,
                secret=f"{descriptor.provider_id}-key",
                auth_type=AuthType.API_KEY,
                status=CredentialStatus.ACTIVE,
                credential_group=descriptor.provider_id,
            )

    result = await stack.investigate(_request(InvestigationObjective.CORROBORATE), user_id=USER)

    assert RoundTrigger.CORROBORATION in _triggers(result)
    assert any(
        issue.issue_type is WorkflowIssueType.CORROBORATION_NOT_OBTAINED for issue in result.issues
    )
    extra = [item for item in result.enrichment.attempts if item.provider_id == "extra"]
    assert extra and not any(item.coverage_gained for item in extra)
