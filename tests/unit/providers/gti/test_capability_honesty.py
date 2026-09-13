"""A provider advertises only what its adapter answers (Task 24, CS-02).

Live shape: a DEEP address lookup bundled ``current_infrastructure`` beside
``reputation`` because GTI declared it, returned SUCCESS, and the planner
credited the capability as covered -- although the adapter fetched no
relationship for it and emitted no infrastructure evidence. That closed the goal
before a provider that does answer it was asked.

The rule: a capability is declared only where the adapter answers it with
normalized evidence, or with a capability-specific empty answer. These tests pin
the three GTI omissions and prove, over the real adapter and the real fixtures,
that nothing GTI emits at any depth is filed under any of them.
"""

from __future__ import annotations

from fixtures.reasoning import gti_file_deep_envelope, gti_file_envelope
from ti_recon.enums import IntelObjectType, InvestigationDepth, ProviderCapability
from ti_recon.providers.gti import GTI_CAPABILITIES, build_gti_descriptor
from ti_recon.providers.gti.descriptor import (
    GTI_UNDECLARED_INFRASTRUCTURE_CAPABILITIES,
    build_gti_planning_profile,
)
from ti_recon.providers.gti.relationships import (
    RELATIONSHIP_PLANS,
    RELATIONSHIP_SPECS,
    GTIRelationshipDepth,
    relationship_plan,
)

UNDECLARED = GTI_UNDECLARED_INFRASTRUCTURE_CAPABILITIES


def test_the_three_infrastructure_capabilities_are_deliberately_undeclared() -> None:
    assert UNDECLARED == {
        ProviderCapability.CURRENT_INFRASTRUCTURE,
        ProviderCapability.HISTORICAL_INFRASTRUCTURE,
        ProviderCapability.NETWORK_OWNERSHIP,
    }
    assert not (UNDECLARED & GTI_CAPABILITIES)
    assert not (UNDECLARED & build_gti_descriptor().capabilities)
    assert not (UNDECLARED & build_gti_planning_profile().planning_capabilities)


def test_what_stays_declared_is_what_the_adapter_answers() -> None:
    assert GTI_CAPABILITIES == {
        ProviderCapability.REPUTATION,
        ProviderCapability.MALWARE_INTELLIGENCE,
        ProviderCapability.THREAT_ASSOCIATIONS,
        ProviderCapability.RELATIONSHIPS,
        ProviderCapability.FILE_BEHAVIOR,
    }


def test_no_relationship_spec_serves_an_undeclared_capability() -> None:
    """Every relationship GTI can fetch is filed under a declared capability, so
    the declaration and the fetch plan cannot disagree."""
    for name, spec in RELATIONSHIP_SPECS.items():
        assert spec.capability in GTI_CAPABILITIES, name
        assert spec.capability not in UNDECLARED, name


def test_a_request_naming_only_an_undeclared_capability_fetches_nothing() -> None:
    """The live call's shape: nothing in the plan answers it, so the plan is empty."""
    for object_type in (IntelObjectType.IPV4_ADDR, IntelObjectType.DOMAIN_NAME):
        for capability in UNDECLARED:
            assert (
                relationship_plan(
                    object_type, GTIRelationshipDepth.DEEP, capabilities=frozenset({capability})
                )
                == ()
            )


def test_the_deep_address_plan_is_all_relationships_and_associations() -> None:
    names = RELATIONSHIP_PLANS[IntelObjectType.IPV4_ADDR][GTIRelationshipDepth.DEEP]
    served = {RELATIONSHIP_SPECS[name].capability for name in names}
    assert served <= {ProviderCapability.RELATIONSHIPS, ProviderCapability.THREAT_ASSOCIATIONS}


def test_no_evidence_gti_emits_is_an_infrastructure_or_ownership_record() -> None:
    """Over the real adapter at STANDARD and DEEP: every claim type GTI produces
    is an assessment, a statistic, a sandbox record, an association or a
    relationship -- never an ownership or hosting record."""
    for builder in (gti_file_envelope, gti_file_deep_envelope):
        for record in builder().evidence:
            lowered = record.claim_type.lower()
            assert "ownership" not in lowered, record.claim_type
            assert "infrastructure" not in lowered, record.claim_type
            assert "resolution" not in lowered, record.claim_type


def test_the_address_attributes_are_kept_as_properties_not_removed() -> None:
    """The raw fields stay: honesty about capability is not deletion of data."""
    from ti_recon.providers.gti.normalizer import GTI_METADATA_FIELDS

    kept = GTI_METADATA_FIELDS[IntelObjectType.IPV4_ADDR]
    for name in ("asn", "as_owner", "network", "country"):
        assert name in kept


def test_the_planning_profile_still_plans_every_declared_capability() -> None:
    profile = build_gti_planning_profile()
    assert profile.planning_capabilities == GTI_CAPABILITIES
    assert profile.minimum_depth is InvestigationDepth.QUICK
    assert profile.capability_invariant_response is False
