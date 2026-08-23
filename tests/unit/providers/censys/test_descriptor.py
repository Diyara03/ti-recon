"""The Censys descriptor (Task 9).

What is declared here decides what the engine will ask Censys for. The absences
matter as much as the presences: Censys answers "what is exposed", never "is
this malicious", and a descriptor claiming otherwise would route reputation
questions to a provider that cannot answer them.
"""

from __future__ import annotations

from ti_recon.enums import IntelObjectType, ProviderCapability
from ti_recon.providers import ProviderRegistry
from ti_recon.providers.censys import (
    CENSYS_ADAPTER_VERSION,
    CENSYS_API_VERSION,
    CENSYS_LINEAGE_GROUP,
    CENSYS_ORIGIN_PROVIDER,
    CENSYS_PROVIDER_ID,
    CENSYS_SOURCE_FAMILY,
    CensysAdapter,
    build_censys_descriptor,
)


def test_the_descriptor_identifies_censys() -> None:
    descriptor = build_censys_descriptor()
    assert descriptor.provider_id == "censys"
    assert descriptor.source_family == "censys"
    assert descriptor.credential_group == "censys"
    assert descriptor.requires_credentials is True


def test_the_platform_api_version_is_declared() -> None:
    assert CENSYS_API_VERSION == "v3"
    assert CENSYS_ADAPTER_VERSION == "0.1.0"


def test_addresses_and_urls_are_supported() -> None:
    descriptor = build_censys_descriptor()
    assert descriptor.supported_object_types == frozenset(
        {IntelObjectType.IPV4_ADDR, IntelObjectType.IPV6_ADDR, IntelObjectType.URL}
    )


def test_a_bare_domain_is_not_declared() -> None:
    """A web property needs a port; a domain names none."""
    assert IntelObjectType.DOMAIN_NAME not in build_censys_descriptor().supported_object_types


def test_a_file_is_not_declared() -> None:
    """Censys indexes certificates by fingerprint, not files by file hash."""
    assert IntelObjectType.FILE not in build_censys_descriptor().supported_object_types


def test_the_declared_capabilities_are_infrastructure_and_pivots() -> None:
    capabilities = build_censys_descriptor().capabilities
    assert ProviderCapability.CURRENT_INFRASTRUCTURE in capabilities
    assert ProviderCapability.NETWORK_OWNERSHIP in capabilities
    assert ProviderCapability.CERTIFICATE_CONTEXT in capabilities
    assert ProviderCapability.RELATIONSHIPS in capabilities


def test_censys_is_not_declared_as_a_reputation_source() -> None:
    """It sees what is exposed; it does not judge it, and neither do we."""
    capabilities = build_censys_descriptor().capabilities
    assert ProviderCapability.REPUTATION not in capabilities
    assert ProviderCapability.THREAT_ASSOCIATIONS not in capabilities
    assert ProviderCapability.SCANNER_CONTEXT not in capabilities


def test_nothing_active_is_declared() -> None:
    """Censys can rescan an asset on request; this integration cannot."""
    descriptor = build_censys_descriptor()
    assert descriptor.supports_active is False
    assert descriptor.supports_batch is False
    assert ProviderCapability.ACTIVE_SCAN not in descriptor.capabilities
    assert descriptor.passive_capabilities == descriptor.capabilities


def test_web_forensics_is_not_declared() -> None:
    """urlscan is the web-forensics provider; nothing here retrieves a body."""
    assert ProviderCapability.WEB_FORENSICS not in build_censys_descriptor().capabilities


def test_censys_is_its_own_origin() -> None:
    """It scans the internet itself; it relays nobody."""
    assert CENSYS_ORIGIN_PROVIDER == CENSYS_PROVIDER_ID
    assert CENSYS_LINEAGE_GROUP == f"{CENSYS_SOURCE_FAMILY}:{CENSYS_ORIGIN_PROVIDER}"


def test_the_provider_is_discoverable_by_capability_not_by_name() -> None:
    registry = ProviderRegistry([CensysAdapter()])
    matches = registry.find_compatible(
        IntelObjectType.IPV4_ADDR, ProviderCapability.CURRENT_INFRASTRUCTURE
    )
    assert [adapter.descriptor.provider_id for adapter in matches] == ["censys"]


def test_no_provider_answers_infrastructure_for_a_bare_domain() -> None:
    registry = ProviderRegistry([CensysAdapter()])
    assert (
        registry.find_compatible(
            IntelObjectType.DOMAIN_NAME, ProviderCapability.CURRENT_INFRASTRUCTURE
        )
        == ()
    )


def test_censys_is_never_returned_for_a_reputation_question() -> None:
    registry = ProviderRegistry([CensysAdapter()])
    assert registry.find_compatible(IntelObjectType.IPV4_ADDR, ProviderCapability.REPUTATION) == ()
