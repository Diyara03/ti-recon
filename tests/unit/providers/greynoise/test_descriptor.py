"""The GreyNoise descriptor (Task 9).

The descriptor is how the engine finds this provider without naming it, and how
it learns what GreyNoise cannot answer. Both matter: an over-broad descriptor
turns a blind spot into a silent empty result.
"""

from __future__ import annotations

from ti_recon.enums import IntelObjectType, ProviderCapability
from ti_recon.providers import ProviderRegistry
from ti_recon.providers.greynoise import (
    GREYNOISE_ADAPTER_VERSION,
    GREYNOISE_API_VERSION,
    GREYNOISE_LINEAGE_GROUP,
    GREYNOISE_ORIGIN_PROVIDER,
    GREYNOISE_PROVIDER_ID,
    GREYNOISE_SOURCE_FAMILY,
    GreyNoiseAdapter,
    build_greynoise_descriptor,
)


def test_the_descriptor_identifies_greynoise() -> None:
    descriptor = build_greynoise_descriptor()
    assert descriptor.provider_id == "greynoise"
    assert descriptor.source_family == "greynoise"
    assert descriptor.credential_group == "greynoise"
    assert descriptor.requires_credentials is True


def test_only_version_three_is_declared() -> None:
    """The v2 IP context, RIOT and GNQL endpoints are deprecated and absent."""
    assert GREYNOISE_API_VERSION == "v3"
    assert GREYNOISE_ADAPTER_VERSION == "0.1.0"


def test_ipv4_is_the_only_supported_observable() -> None:
    descriptor = build_greynoise_descriptor()
    assert descriptor.supported_object_types == frozenset({IntelObjectType.IPV4_ADDR})


def test_every_other_observable_type_is_unsupported() -> None:
    """Explicitly, so a coverage gap can never read as an empty answer."""
    descriptor = build_greynoise_descriptor()
    for object_type in (
        IntelObjectType.IPV6_ADDR,
        IntelObjectType.DOMAIN_NAME,
        IntelObjectType.URL,
        IntelObjectType.FILE,
    ):
        assert object_type not in descriptor.supported_object_types


def test_the_declared_capabilities_are_what_greynoise_answers() -> None:
    descriptor = build_greynoise_descriptor()
    assert ProviderCapability.SCANNER_CONTEXT in descriptor.capabilities
    assert ProviderCapability.REPUTATION in descriptor.capabilities
    assert ProviderCapability.NETWORK_OWNERSHIP in descriptor.capabilities
    assert ProviderCapability.FALSE_POSITIVE_CONTEXT in descriptor.capabilities


def test_nothing_active_is_declared() -> None:
    """GreyNoise has hunting and feed APIs; this integration has none of them."""
    descriptor = build_greynoise_descriptor()
    assert descriptor.supports_active is False
    assert descriptor.supports_batch is False
    assert ProviderCapability.ACTIVE_SCAN not in descriptor.capabilities
    assert ProviderCapability.BATCH_LOOKUP not in descriptor.capabilities
    assert descriptor.passive_capabilities == descriptor.capabilities


def test_greynoise_is_its_own_origin() -> None:
    """It runs the sensors; it relays nobody."""
    assert GREYNOISE_ORIGIN_PROVIDER == GREYNOISE_PROVIDER_ID
    assert GREYNOISE_LINEAGE_GROUP == f"{GREYNOISE_SOURCE_FAMILY}:{GREYNOISE_ORIGIN_PROVIDER}"


def test_the_provider_is_discoverable_by_capability_not_by_name() -> None:
    registry = ProviderRegistry([GreyNoiseAdapter()])
    matches = registry.find_compatible(
        IntelObjectType.IPV4_ADDR, ProviderCapability.SCANNER_CONTEXT
    )
    assert [adapter.descriptor.provider_id for adapter in matches] == ["greynoise"]


def test_no_provider_answers_scanner_context_for_a_domain() -> None:
    registry = ProviderRegistry([GreyNoiseAdapter()])
    assert (
        registry.find_compatible(IntelObjectType.DOMAIN_NAME, ProviderCapability.SCANNER_CONTEXT)
        == ()
    )
