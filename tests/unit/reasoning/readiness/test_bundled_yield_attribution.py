"""A bundled secondary's yield is attributed where a claim's semantic names it (Task 24).

Live shape (GN-FINDING-03): one call keyed on ``REPUTATION`` also carried
``SCANNER_CONTEXT``; the source's only directional claim was a scanner
classification -- ``SCANNER_ACTIVITY`` -- and the ledger still reported the
scanner requirement's yield as ``UNATTRIBUTED``, because Task 13 retains
outcomes per call. The claim's own proposition names the question it answers,
so the yield is now ``DIRECTIONAL`` there, and only there.

``UNATTRIBUTED`` stays the answer for everything the record genuinely cannot
attribute: a claim whose semantic names the primary and not the secondary, a
semantic served by several capabilities, an unclassified claim, and a call that
produced nothing. A call that did not complete still yields ``NONE``.
"""

from __future__ import annotations

from fixtures.fusion import evidence, file_object
from fixtures.readiness import assess, attempt, coverage_item, scenario
from ti_recon.enums import CoverageStatus, ProviderCapability, ProviderRunStatus
from ti_recon.normalization import normalize_observable
from ti_recon.reasoning.claims import CLAIM_SEMANTICS_POLICY_VERSION, ClaimSemantic, claim_from
from ti_recon.reasoning.readiness import (
    CheckCompletion,
    InformationYield,
    RequirementStatus,
    capability_checks,
)
from ti_recon.reasoning.readiness.coverage import (
    directional_capabilities_by_provider,
    secondary_yield_for,
)
from ti_recon.reasoning.readiness.policy import CAPABILITY_ANSWERED_BY_SEMANTIC

REPUTATION = ProviderCapability.REPUTATION
SCANNER = ProviderCapability.SCANNER_CONTEXT
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE
BUNDLE = frozenset({REPUTATION, SCANNER})


def _claim(semantic: ClaimSemantic, *, provider: str = "alpha"):
    subject = normalize_observable("203.0.113.9").intel_object
    record = evidence(subject, provider=provider, claim_type=f"{provider}_finding")
    return claim_from(
        record,
        policy_version=CLAIM_SEMANTICS_POLICY_VERSION,
        semantic=semantic,
        subject_key=subject.canonical_key,
    )


def _evaluation(result, capability):
    for item in result.requirement_evaluations:
        if item.requirement.capability is capability:
            return item
    raise AssertionError(f"no evaluation for {capability.value}")


# --------------------------------------------------------------------------- #
# The table
# --------------------------------------------------------------------------- #


def test_every_attributed_semantic_names_exactly_one_capability() -> None:
    for semantic, capability in CAPABILITY_ANSWERED_BY_SEMANTIC.items():
        assert isinstance(semantic, ClaimSemantic)
        assert isinstance(capability, ProviderCapability)
    assert CAPABILITY_ANSWERED_BY_SEMANTIC[ClaimSemantic.SCANNER_ACTIVITY] is SCANNER


def test_an_ambiguous_or_unclassified_semantic_is_never_attributed() -> None:
    """A guess would be worse than the retention limit it replaced."""
    for semantic in (
        ClaimSemantic.UNCLASSIFIED_DIRECTIONAL,
        ClaimSemantic.MALWARE_DISTRIBUTION,
        ClaimSemantic.C2_ASSOCIATION,
        ClaimSemantic.THREAT_INFRASTRUCTURE_ASSOCIATION,
    ):
        assert semantic not in CAPABILITY_ANSWERED_BY_SEMANTIC


def test_attribution_is_keyed_by_the_transport_that_produced_the_claim() -> None:
    attributed = directional_capabilities_by_provider(
        [
            _claim(ClaimSemantic.SCANNER_ACTIVITY, provider="alpha"),
            _claim(ClaimSemantic.AGGREGATED_REPUTATION, provider="beta"),
            _claim(ClaimSemantic.UNCLASSIFIED_DIRECTIONAL, provider="gamma"),
        ]
    )
    assert attributed == {"alpha": frozenset({SCANNER}), "beta": frozenset({REPUTATION})}


# --------------------------------------------------------------------------- #
# J -- deterministically attributable
# --------------------------------------------------------------------------- #


def test_j_a_scanner_claim_attributes_the_secondary_scanner_bucket() -> None:
    item = attempt(REPUTATION, provider="alpha", capabilities=BUNDLE)
    attributed = directional_capabilities_by_provider([_claim(ClaimSemantic.SCANNER_ACTIVITY)])
    checks = capability_checks(
        [item], directional_providers=frozenset({"alpha"}), attributed_capabilities=attributed
    )
    (primary,) = checks[REPUTATION]
    (secondary,) = checks[SCANNER]
    assert primary.information_yield is InformationYield.DIRECTIONAL
    assert secondary.completion is CheckCompletion.COMPLETE
    assert secondary.information_yield is InformationYield.DIRECTIONAL


def test_j_the_live_shape_through_the_whole_readiness_engine() -> None:
    """One call keyed on reputation, carrying scanner context, answered by a
    scanner classification: the scanner requirement is satisfied *and*
    directionally informed, and the reputation requirement reads as before."""
    root = normalize_observable("203.0.113.9").intel_object
    scene = (
        scenario(root)
        .with_claim("scanner_activity", provider="alpha", source_family="fam_a")
        .with_attempt(
            attempt(REPUTATION, provider="alpha", source_family="fam_a", capabilities=BUNDLE)
        )
        .with_coverage(coverage_item(REPUTATION, status=CoverageStatus.COVERED))
        .with_coverage(coverage_item(SCANNER, status=CoverageStatus.COVERED))
    )
    result = assess(scene)
    scanner = _evaluation(result, SCANNER)
    assert scanner.status is RequirementStatus.SATISFIED
    assert scanner.completion is CheckCompletion.COMPLETE
    assert scanner.information_yield is InformationYield.DIRECTIONAL
    assert _evaluation(result, REPUTATION).information_yield is InformationYield.DIRECTIONAL


# --------------------------------------------------------------------------- #
# K -- genuinely unattributable
# --------------------------------------------------------------------------- #


def test_k_a_claim_naming_the_primary_leaves_the_secondary_unattributed() -> None:
    """A reputation claim answers the reputation question, and says nothing
    about what the same call returned for scanner context."""
    item = attempt(REPUTATION, provider="alpha", capabilities=BUNDLE)
    attributed = directional_capabilities_by_provider([_claim(ClaimSemantic.AGGREGATED_REPUTATION)])
    checks = capability_checks(
        [item], directional_providers=frozenset({"alpha"}), attributed_capabilities=attributed
    )
    (secondary,) = checks[SCANNER]
    assert secondary.completion is CheckCompletion.COMPLETE
    assert secondary.information_yield is InformationYield.UNATTRIBUTED


def test_k_an_ambiguous_semantic_leaves_every_secondary_unattributed() -> None:
    item = attempt(REPUTATION, provider="alpha", capabilities=frozenset({REPUTATION, INTELLIGENCE}))
    attributed = directional_capabilities_by_provider([_claim(ClaimSemantic.MALWARE_DISTRIBUTION)])
    checks = capability_checks(
        [item], directional_providers=frozenset({"alpha"}), attributed_capabilities=attributed
    )
    (secondary,) = checks[INTELLIGENCE]
    assert secondary.information_yield is InformationYield.UNATTRIBUTED


def test_k_the_live_shape_with_an_unrelated_claim_stays_unattributed() -> None:
    root = normalize_observable("203.0.113.9").intel_object
    scene = (
        scenario(root)
        .with_claim("aggregated_reputation", provider="alpha", source_family="fam_a")
        .with_attempt(
            attempt(REPUTATION, provider="alpha", source_family="fam_a", capabilities=BUNDLE)
        )
        .with_coverage(coverage_item(REPUTATION, status=CoverageStatus.COVERED))
        .with_coverage(coverage_item(SCANNER, status=CoverageStatus.COVERED))
    )
    scanner = _evaluation(assess(scene), SCANNER)
    assert scanner.completion is CheckCompletion.COMPLETE
    assert scanner.information_yield is InformationYield.UNATTRIBUTED


def test_another_providers_scanner_claim_attributes_nothing_here() -> None:
    """Attribution is per transport: beta's claim says nothing about alpha's call."""
    item = attempt(REPUTATION, provider="alpha", capabilities=BUNDLE)
    attributed = directional_capabilities_by_provider(
        [_claim(ClaimSemantic.SCANNER_ACTIVITY, provider="beta")]
    )
    checks = capability_checks(
        [item], directional_providers=frozenset({"beta"}), attributed_capabilities=attributed
    )
    (secondary,) = checks[SCANNER]
    assert secondary.information_yield is InformationYield.UNATTRIBUTED


# --------------------------------------------------------------------------- #
# Completion still gates everything
# --------------------------------------------------------------------------- #


def test_a_call_that_did_not_complete_yields_none_whatever_the_claims_say() -> None:
    refused = attempt(
        REPUTATION,
        provider="alpha",
        status=ProviderRunStatus.NOT_CONFIGURED,
        called_provider=False,
        produced_evidence=False,
        capabilities=BUNDLE,
    )
    attributed = {"alpha": frozenset({SCANNER})}
    assert (
        secondary_yield_for(refused, SCANNER, attributed_capabilities=attributed)
        is InformationYield.NONE
    )


def test_a_call_that_produced_nothing_is_not_attributed_a_claim() -> None:
    empty = attempt(REPUTATION, provider="alpha", produced_evidence=False, capabilities=BUNDLE)
    attributed = {"alpha": frozenset({SCANNER})}
    assert (
        secondary_yield_for(empty, SCANNER, attributed_capabilities=attributed)
        is InformationYield.UNATTRIBUTED
    )


def test_a_no_data_bundle_stays_unattributed_for_its_secondary() -> None:
    """No claim exists to attribute, and a bundled NO_DATA is not retained per question."""
    item = attempt(
        REPUTATION, provider="alpha", status=ProviderRunStatus.NO_DATA, capabilities=BUNDLE
    )
    checks = capability_checks(
        [item], directional_providers=frozenset(), attributed_capabilities={}
    )
    (secondary,) = checks[SCANNER]
    assert secondary.information_yield is InformationYield.UNATTRIBUTED


def test_attribution_never_reaches_a_capability_the_call_did_not_carry() -> None:
    """A scanner claim from a call that carried only reputation creates no scanner check."""
    item = attempt(REPUTATION, provider="alpha")
    attributed = {"alpha": frozenset({SCANNER})}
    checks = capability_checks(
        [item], directional_providers=frozenset({"alpha"}), attributed_capabilities=attributed
    )
    assert set(checks) == {REPUTATION}


def test_the_default_keeps_the_previous_behaviour() -> None:
    """Callers that pass no attribution get the retention limit exactly as before."""
    item = attempt(REPUTATION, provider="alpha", capabilities=BUNDLE)
    checks = capability_checks([item], directional_providers=frozenset({"alpha"}))
    (secondary,) = checks[SCANNER]
    assert secondary.information_yield is InformationYield.UNATTRIBUTED


def test_the_file_shape_is_unchanged_where_nothing_names_the_secondary() -> None:
    sample = file_object(sha256="b" * 64)
    scene = (
        scenario(sample)
        .with_claim("aggregated_reputation", provider="alpha", source_family="fam_a")
        .with_attempt(
            attempt(
                REPUTATION,
                provider="alpha",
                source_family="fam_a",
                capabilities=frozenset({REPUTATION, INTELLIGENCE}),
            )
        )
        .with_coverage(coverage_item(REPUTATION, status=CoverageStatus.COVERED))
        .with_coverage(coverage_item(INTELLIGENCE, status=CoverageStatus.COVERED))
    )
    assert (
        _evaluation(assess(scene), INTELLIGENCE).information_yield is InformationYield.UNATTRIBUTED
    )
