"""A refused, unconfigured or errored check never borrows a yield (Task 24 1B).

Yield is derived per provider because a claim does not record which call
produced it. Before this fix a ``NOT_SUPPORTED`` behaviour query inherited
``DIRECTIONAL`` from the same provider's reputation answer, so a refusal read
as a finding. Only an attempt that completed and produced evidence can have
yielded anything; every other status yields ``NONE``, whatever else the
provider returned in another call.
"""

from __future__ import annotations

import pytest

from fixtures.readiness import assess, attempt, file_object, scenario
from ti_recon.enums import ProviderCapability, ProviderRunStatus
from ti_recon.reasoning.readiness import (
    CheckCompletion,
    InformationYield,
    completion_for,
    yield_for,
)

DIRECTIONAL = frozenset({"alpha"})


@pytest.mark.parametrize(
    "status",
    [
        ProviderRunStatus.NOT_SUPPORTED,
        ProviderRunStatus.NOT_CONFIGURED,
        ProviderRunStatus.ERROR,
        ProviderRunStatus.QUOTA_EXCEEDED,
        ProviderRunStatus.TEMPORARILY_UNAVAILABLE,
    ],
)
def test_a_check_that_did_not_complete_yields_nothing_even_for_a_directional_provider(
    status: ProviderRunStatus,
) -> None:
    item = attempt(
        ProviderCapability.FILE_BEHAVIOR,
        provider="alpha",
        status=status,
        called_provider=False,
        produced_evidence=False,
    )
    assert completion_for(item) not in {CheckCompletion.COMPLETE, CheckCompletion.PARTIAL}
    assert yield_for(item, directional_providers=DIRECTIONAL) is InformationYield.NONE


def test_a_completed_check_that_produced_nothing_yields_nothing() -> None:
    item = attempt(
        ProviderCapability.FILE_BEHAVIOR,
        provider="alpha",
        status=ProviderRunStatus.SUCCESS,
        produced_evidence=False,
    )
    assert yield_for(item, directional_providers=DIRECTIONAL) is InformationYield.NONE


def test_the_five_states_stay_distinct() -> None:
    def state(
        status: ProviderRunStatus, *, produced: bool
    ) -> tuple[CheckCompletion, InformationYield]:
        item = attempt(
            ProviderCapability.REPUTATION,
            provider="alpha",
            status=status,
            called_provider=status is not ProviderRunStatus.NOT_CONFIGURED,
            produced_evidence=produced,
        )
        return completion_for(item), yield_for(item, directional_providers=DIRECTIONAL)

    assert state(ProviderRunStatus.SUCCESS, produced=True) == (
        CheckCompletion.COMPLETE,
        InformationYield.DIRECTIONAL,
    )
    assert state(ProviderRunStatus.NO_DATA, produced=True) == (
        CheckCompletion.COMPLETE,
        InformationYield.NO_DATA,
    )
    assert state(ProviderRunStatus.NOT_CONFIGURED, produced=False) == (
        CheckCompletion.BLOCKED,
        InformationYield.NONE,
    )
    assert state(ProviderRunStatus.NOT_SUPPORTED, produced=False) == (
        CheckCompletion.OUT_OF_SCOPE,
        InformationYield.NONE,
    )
    assert state(ProviderRunStatus.ERROR, produced=False) == (
        CheckCompletion.BLOCKED,
        InformationYield.NONE,
    )


def test_a_refused_behaviour_query_does_not_inherit_the_reputation_answer() -> None:
    """The live shape: one provider answered reputation directionally and
    refused behaviour below DEEP. The behaviour requirement must not read as
    a directional finding."""
    root = file_object(sha256="a" * 64)
    scene = (
        scenario(root)
        .with_claim("malicious_reputation", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(ProviderCapability.REPUTATION, provider="alpha", sequence=1))
        .with_attempt(
            attempt(
                ProviderCapability.FILE_BEHAVIOR,
                provider="alpha",
                status=ProviderRunStatus.NOT_SUPPORTED,
                called_provider=False,
                produced_evidence=False,
                sequence=2,
            )
        )
    )

    result = assess(scene)

    yields = {
        item.requirement.capability: item.information_yield
        for item in result.requirement_evaluations
    }
    assert yields[ProviderCapability.REPUTATION] is InformationYield.DIRECTIONAL
    if ProviderCapability.FILE_BEHAVIOR in yields:
        assert yields[ProviderCapability.FILE_BEHAVIOR] is InformationYield.NONE
    checks = [
        check
        for item in result.requirement_evaluations
        for check in item.checks
        if check.capability is ProviderCapability.FILE_BEHAVIOR
    ]
    assert checks and all(check.information_yield is InformationYield.NONE for check in checks)
