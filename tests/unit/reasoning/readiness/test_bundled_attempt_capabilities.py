"""A bundled attempt is one check under every capability it carried (Task 24 Phase 3).

One call bundling several questions is one attempt in the trace. The provider
was asked all of them, and a refusal, an outage or an unconfigured credential
refused all of them -- so the ledger must not type the secondary capability
"not attempted". A completed bundle's secondary is UNATTRIBUTED: the call
completed, and what that capability got back is not retained per capability.
Never DIRECTIONAL, CONTEXT_ONLY or NO_DATA for a secondary.
"""

from __future__ import annotations

from fixtures.readiness import assess, attempt, coverage_item, scenario
from ti_recon.enums import CoverageStatus, ProviderCapability, ProviderRunStatus
from ti_recon.normalization import normalize_observable
from ti_recon.reasoning.readiness import (
    CheckCompletion,
    ContinuationState,
    GapType,
    InformationYield,
    RequirementStatus,
    capability_checks,
)

REPUTATION = ProviderCapability.REPUTATION
SCANNER = ProviderCapability.SCANNER_CONTEXT
BUNDLE = frozenset({REPUTATION, SCANNER})


def _evaluation(result, capability):
    for item in result.requirement_evaluations:
        if item.requirement.capability is capability:
            return item
    raise AssertionError(f"no evaluation for {capability.value}")


def test_a_refused_bundle_is_blocked_under_every_capability_it_carried() -> None:
    item = attempt(
        REPUTATION,
        provider="alpha",
        status=ProviderRunStatus.NOT_CONFIGURED,
        called_provider=False,
        produced_evidence=False,
        capabilities=BUNDLE,
    )
    checks = capability_checks([item], directional_providers=frozenset())
    assert set(checks) == BUNDLE
    for capability in BUNDLE:
        (check,) = checks[capability]
        assert check.capability is capability
        assert check.completion is CheckCompletion.BLOCKED
        assert check.information_yield is InformationYield.NONE


def test_a_completed_bundles_secondary_is_unattributed_never_directional() -> None:
    item = attempt(REPUTATION, provider="alpha", capabilities=BUNDLE)
    checks = capability_checks([item], directional_providers=frozenset({"alpha"}))
    (primary,) = checks[REPUTATION]
    (secondary,) = checks[SCANNER]
    assert primary.information_yield is InformationYield.DIRECTIONAL
    assert secondary.completion is CheckCompletion.COMPLETE
    assert secondary.information_yield is InformationYield.UNATTRIBUTED


def test_a_no_data_bundles_secondary_does_not_inherit_no_data() -> None:
    item = attempt(
        REPUTATION, provider="alpha", status=ProviderRunStatus.NO_DATA, capabilities=BUNDLE
    )
    checks = capability_checks([item], directional_providers=frozenset())
    (secondary,) = checks[SCANNER]
    assert secondary.information_yield is InformationYield.UNATTRIBUTED


def test_the_secondary_gap_is_typed_by_what_happened() -> None:
    """The live shape: an unconfigured provider bundling reputation and scanner
    context for an address. Before this change the scanner gap read
    ``not_attempted``; the provider had been asked and said NOT_CONFIGURED."""
    root = normalize_observable("203.0.113.9").intel_object
    scene = (
        scenario(root)
        .with_claim("aggregated_reputation", provider="beta", source_family="fam_b")
        .with_attempt(attempt(REPUTATION, provider="beta", source_family="fam_b", sequence=1))
        .with_attempt(
            attempt(
                REPUTATION,
                provider="alpha",
                source_family="fam_a",
                status=ProviderRunStatus.NOT_CONFIGURED,
                called_provider=False,
                produced_evidence=False,
                capabilities=BUNDLE,
                sequence=2,
            )
        )
        .with_coverage(coverage_item(REPUTATION, status=CoverageStatus.COVERED))
        .with_coverage(coverage_item(SCANNER, status=CoverageStatus.NOT_COVERED))
    )

    result = assess(scene)

    scanner = _evaluation(result, SCANNER)
    assert scanner.status is not RequirementStatus.NOT_APPLICABLE
    assert scanner.completion is CheckCompletion.BLOCKED
    assert scanner.gap_type is GapType.NOT_CONFIGURED
    if scanner.material:
        assert result.continuation_state is not ContinuationState.MORE_DATA_AVAILABLE or any(
            gap.capability is not SCANNER for gap in result.gaps
        )
