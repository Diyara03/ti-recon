"""The urlscan provider descriptor (Task 8).

The descriptor is what the registry and the future planner read. What it claims
— and what it refuses to claim — is the whole contract.
"""

from __future__ import annotations

from ti_recon.enums import IntelObjectType, ProviderCapability
from ti_recon.providers.urlscan import (
    URLSCAN_CREDENTIAL_GROUP,
    URLSCAN_ORIGIN_PROVIDER,
    URLSCAN_PROVIDER_ID,
    URLSCAN_SOURCE_FAMILY,
    build_urlscan_descriptor,
)


def test_identity_fields() -> None:
    descriptor = build_urlscan_descriptor()
    assert descriptor.provider_id == URLSCAN_PROVIDER_ID == "urlscan"
    assert descriptor.display_name == "urlscan.io"
    assert descriptor.source_family == URLSCAN_SOURCE_FAMILY
    assert descriptor.credential_group == URLSCAN_CREDENTIAL_GROUP
    assert descriptor.requires_credentials is True


def test_first_hand_observations_are_not_marked_relayed() -> None:
    """urlscan visits pages itself, so its own observations are first-hand.

    ``Evidence.is_relayed`` is ``transport != origin``. Spelling the origin
    differently would mark urlscan's own browser observations as second-hand.
    """
    assert URLSCAN_ORIGIN_PROVIDER == URLSCAN_PROVIDER_ID


def test_supported_object_types() -> None:
    descriptor = build_urlscan_descriptor()
    assert descriptor.supported_object_types == frozenset(
        {
            IntelObjectType.IPV4_ADDR,
            IntelObjectType.IPV6_ADDR,
            IntelObjectType.DOMAIN_NAME,
            IntelObjectType.URL,
            IntelObjectType.FILE,
        }
    )


def test_web_forensics_is_declared_and_generic() -> None:
    descriptor = build_urlscan_descriptor()
    assert ProviderCapability.WEB_FORENSICS in descriptor.capabilities
    # Generic, so a future web-analysis provider can serve the same capability.
    assert ProviderCapability.WEB_FORENSICS.value == "web_forensics"
    assert not any(capability.value.startswith("urlscan") for capability in ProviderCapability)


def test_no_active_capability_is_claimed() -> None:
    """urlscan can submit and rescan URLs. This integration cannot."""
    descriptor = build_urlscan_descriptor()
    assert descriptor.supports_passive is True
    assert descriptor.supports_active is False
    assert descriptor.supports_batch is False


def test_capabilities_are_enrichment_shaped() -> None:
    """Everything declared is something urlscan can answer from stored data."""
    descriptor = build_urlscan_descriptor()
    assert descriptor.capabilities == frozenset(
        {
            ProviderCapability.REPUTATION,
            ProviderCapability.WEB_BEHAVIOR,
            ProviderCapability.HISTORICAL_INFRASTRUCTURE,
            ProviderCapability.CURRENT_INFRASTRUCTURE,
            ProviderCapability.RELATIONSHIPS,
            ProviderCapability.WEB_FORENSICS,
        }
    )
