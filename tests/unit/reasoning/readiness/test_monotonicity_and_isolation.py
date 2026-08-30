"""What may and may not move readiness (Task 18).

The acceptance rule for the layer, as invariants rather than cases: closing a
material gap can only help, and adding something irrelevant can only be recorded.
Both directions matter. A readiness answer that degrades when an unrelated
provider fails would punish investigations for asking more questions; one that
improves when a dependent duplicate arrives would count the same source twice.
"""

from __future__ import annotations

import pytest

from fixtures.readiness import (
    assess,
    attempt,
    coverage_item,
    file_object,
    observable,
    scenario,
    skipped,
)
from ti_recon.enums import InvestigationDepth, ProviderCapability, ProviderRunStatus
from ti_recon.planning.models import SkipReason
from ti_recon.reasoning.readiness import ReadinessStatus

REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
BEHAVIOUR = ProviderCapability.FILE_BEHAVIOR

#: Worst to best, so "cannot get worse" is a comparison rather than a feeling.
STATUS_ORDER = {
    ReadinessStatus.UNRESOLVED: 0,
    ReadinessStatus.NEEDS_MORE_DATA: 1,
    ReadinessStatus.READY_WITH_LIMITATIONS: 2,
    ReadinessStatus.READY: 3,
}

#: One shared pivot instance. A second object built from the same value would be
#: a different IntelObject, and its claims would not resolve -- which would make
#: these tests pass for the wrong reason.
PIVOT = observable("203.0.113.77")


def _suspicious_with_gap():
    """A thin basis at DEEP, with behavioural analysis left unrun."""
    root = file_object(sha256="b" * 64)
    return (
        scenario(root, depth=InvestigationDepth.DEEP)
        .with_claim("aggregated_reputation", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(REPUTATION, provider="alpha", source_family="fam_a"))
        .with_attempt(attempt(INTELLIGENCE, provider="intel", source_family="fam_i"))
        .with_coverage(coverage_item(REPUTATION))
        .with_coverage(coverage_item(INTELLIGENCE))
        .with_skip(skipped(BEHAVIOUR, SkipReason.BUDGET_EXHAUSTED))
    )


def test_closing_the_material_gap_cannot_make_readiness_worse() -> None:
    """The property that makes the layer useful to act on.

    An analyst who obtains the missing capability must never be told the
    investigation got worse for it.
    """
    scene = _suspicious_with_gap()
    before = assess(scene)
    after = assess(scene.with_attempt(attempt(BEHAVIOUR, provider="sbx", source_family="fam_s")))

    assert before.readiness_status is ReadinessStatus.NEEDS_MORE_DATA
    assert STATUS_ORDER[after.readiness_status] >= STATUS_ORDER[before.readiness_status]


def test_completing_a_check_that_returns_nothing_still_improves_coverage() -> None:
    """The distinction this layer exists for, stated as movement.

    The source answered and held nothing. Coverage advances; the assessment does
    not budge, because an empty answer is not evidence.
    """
    scene = _suspicious_with_gap()
    before = assess(scene)
    after = assess(
        scene.with_attempt(
            attempt(
                BEHAVIOUR,
                provider="sbx",
                source_family="fam_s",
                status=ProviderRunStatus.NO_DATA,
            )
        )
    )

    assert after.coverage_summary.checks_no_data > before.coverage_summary.checks_no_data
    assert STATUS_ORDER[after.readiness_status] >= STATUS_ORDER[before.readiness_status]
    assert after.verdict is before.verdict
    assert after.confidence is before.confidence


IRRELEVANT_ADDITIONS = {
    "unrelated_provider_failure": lambda scene: scene.with_attempt(
        attempt(REPUTATION, provider="broken", status=ProviderRunStatus.ERROR)
    ),
    "unsupported_capability": lambda scene: scene.with_attempt(
        attempt(
            ProviderCapability.CERTIFICATE_CONTEXT,
            provider="certs",
            status=ProviderRunStatus.NOT_SUPPORTED,
        )
    ),
    "pivot_missing_credentials": lambda scene: scene.with_attempt(
        attempt(
            ProviderCapability.NETWORK_OWNERSHIP,
            provider="pivot",
            status=ProviderRunStatus.NOT_CONFIGURED,
        )
    ),
    "pivot_quota_failure": lambda scene: scene.with_attempt(
        attempt(
            ProviderCapability.CURRENT_INFRASTRUCTURE,
            provider="pivot2",
            status=ProviderRunStatus.QUOTA_EXCEEDED,
        )
    ),
    "pivot_directional_claim": lambda scene: scene.with_claim(
        "c2_association", provider="pivotprov", source_family="fam_pivot", subject=PIVOT
    ),
}


@pytest.mark.parametrize("case", sorted(IRRELEVANT_ADDITIONS))
def test_adding_something_irrelevant_cannot_make_readiness_worse(case: str) -> None:
    """Failures elsewhere are recorded, not charged to this assessment.

    None of these blocks a material requirement for this observable. A layer
    that downgraded on them would make every investigation that touched a
    misconfigured provider look worse than one that never tried.
    """
    scene = _suspicious_with_gap()
    before = assess(scene)
    after = assess(IRRELEVANT_ADDITIONS[case](scene))

    assert STATUS_ORDER[after.readiness_status] >= STATUS_ORDER[before.readiness_status]
    assert after.verdict is before.verdict
    assert after.confidence is before.confidence


def test_a_dependent_duplicate_does_not_widen_independent_coverage() -> None:
    """Same family answering twice is one origin, exactly as in Task 17.

    Execution is recorded -- two checks really did run -- but the breadth of
    information has not changed, and readiness must not pretend otherwise.
    """
    root = file_object(sha256="a" * 64)
    scene = (
        scenario(root)
        .with_claim("malware_sample_identity", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(REPUTATION, provider="one", source_family="shared"))
        .with_coverage(coverage_item(REPUTATION))
    )
    before = assess(scene)
    after = assess(scene.with_attempt(attempt(REPUTATION, provider="two", source_family="shared")))

    evaluation = next(
        item for item in after.requirement_evaluations if item.requirement.capability is REPUTATION
    )
    assert evaluation.independent_families == ("shared",)
    assert len(evaluation.checks) == 2
    assert after.readiness_status is before.readiness_status
