"""Capability-based provider registry (Task 5)."""

from __future__ import annotations

import inspect
import json

import pytest

from fixtures.fake_providers import (
    FakeAggregatorProvider,
    FakeMinimalProvider,
    FakeScannerProvider,
    FakeWarningListProvider,
    all_fake_adapters,
)
from ti_recon.enums import ActivityMode, IntelObjectType, ProviderCapability
from ti_recon.providers import (
    DuplicateProviderId,
    ProviderDescriptor,
    ProviderRegistry,
    UnknownProvider,
)
from ti_recon.providers import (
    ProviderCapability as ExportedCapability,
)
from ti_recon.providers.adapter import ProviderAdapter
from ti_recon.security import SENSITIVE_KEY_PATTERN


@pytest.fixture
def registry() -> ProviderRegistry:
    return ProviderRegistry(all_fake_adapters())


# --------------------------------------------------------------------------- #
# Membership
# --------------------------------------------------------------------------- #


def test_register_and_get() -> None:
    registry = ProviderRegistry()
    adapter = FakeScannerProvider()
    registry.register(adapter)
    assert registry.get("fake_scanner") is adapter
    assert "fake_scanner" in registry
    assert len(registry) == 1


def test_duplicate_provider_id_is_rejected() -> None:
    registry = ProviderRegistry([FakeScannerProvider()])
    with pytest.raises(DuplicateProviderId, match="already registered"):
        registry.register(FakeScannerProvider())


def test_duplicate_rejection_does_not_replace_the_original() -> None:
    original = FakeScannerProvider()
    registry = ProviderRegistry([original])
    replacement = FakeScannerProvider()
    with pytest.raises(DuplicateProviderId):
        registry.register(replacement)
    assert registry.get("fake_scanner") is original


def test_unregister_removes_the_adapter(registry: ProviderRegistry) -> None:
    registry.unregister("fake_scanner")
    assert "fake_scanner" not in registry
    with pytest.raises(UnknownProvider):
        registry.get("fake_scanner")


def test_unregister_unknown_provider_raises(registry: ProviderRegistry) -> None:
    with pytest.raises(UnknownProvider, match="not registered"):
        registry.unregister("nope")


def test_get_unknown_provider_raises(registry: ProviderRegistry) -> None:
    with pytest.raises(UnknownProvider):
        registry.get("nope")


def test_constructor_registers_the_given_adapters(registry: ProviderRegistry) -> None:
    assert len(registry) == 4


# --------------------------------------------------------------------------- #
# Deterministic ordering
# --------------------------------------------------------------------------- #


def test_list_all_is_ordered_by_provider_id(registry: ProviderRegistry) -> None:
    ids = [adapter.descriptor.provider_id for adapter in registry.list_all()]
    assert ids == sorted(ids)


def test_ordering_is_independent_of_registration_order() -> None:
    forward = ProviderRegistry(
        [FakeAggregatorProvider(), FakeScannerProvider(), FakeWarningListProvider()]
    )
    backward = ProviderRegistry(
        [FakeWarningListProvider(), FakeScannerProvider(), FakeAggregatorProvider()]
    )
    assert [a.descriptor.provider_id for a in forward.list_all()] == [
        a.descriptor.provider_id for a in backward.list_all()
    ]


def test_iteration_matches_list_all(registry: ProviderRegistry) -> None:
    assert list(registry) == list(registry.list_all())


def test_find_results_are_deterministic(registry: ProviderRegistry) -> None:
    first = registry.find_by_capability(ProviderCapability.REPUTATION)
    second = registry.find_by_capability(ProviderCapability.REPUTATION)
    assert [a.descriptor.provider_id for a in first] == [a.descriptor.provider_id for a in second]


# --------------------------------------------------------------------------- #
# Capability matching
# --------------------------------------------------------------------------- #


def test_find_compatible_matches_the_scanner_for_ip_scanner_context(
    registry: ProviderRegistry,
) -> None:
    """The canonical case: ipv4-addr + SCANNER_CONTEXT."""
    matches = registry.find_compatible(
        IntelObjectType.IPV4_ADDR, ProviderCapability.SCANNER_CONTEXT
    )
    ids = [adapter.descriptor.provider_id for adapter in matches]
    assert ids == ["fake_scanner"]
    assert "fake_aggregator" not in ids


def test_aggregator_does_not_match_scanner_context(registry: ProviderRegistry) -> None:
    matches = registry.find_compatible(
        IntelObjectType.IPV4_ADDR, ProviderCapability.SCANNER_CONTEXT
    )
    assert FakeAggregatorProvider().descriptor.provider_id not in [
        adapter.descriptor.provider_id for adapter in matches
    ]


def test_scanner_does_not_match_reputation(registry: ProviderRegistry) -> None:
    matches = registry.find_compatible(IntelObjectType.IPV4_ADDR, ProviderCapability.REPUTATION)
    ids = [adapter.descriptor.provider_id for adapter in matches]
    assert ids == ["fake_aggregator"]


def test_capability_match_respects_object_type(registry: ProviderRegistry) -> None:
    """The scanner has SCANNER_CONTEXT but not for URLs."""
    assert registry.find_by_capability(ProviderCapability.SCANNER_CONTEXT)
    assert registry.find_compatible(IntelObjectType.URL, ProviderCapability.SCANNER_CONTEXT) == ()


def test_multiple_providers_may_serve_one_capability() -> None:
    registry = ProviderRegistry([FakeScannerProvider(), FakeWarningListProvider()])
    matches = registry.find_compatible(
        IntelObjectType.IPV4_ADDR, ProviderCapability.FALSE_POSITIVE_CONTEXT
    )
    assert [adapter.descriptor.provider_id for adapter in matches] == [
        "fake_scanner",
        "fake_warninglist",
    ]


def test_find_by_object_type(registry: ProviderRegistry) -> None:
    ids = [
        adapter.descriptor.provider_id
        for adapter in registry.find_by_object_type(IntelObjectType.FILE)
    ]
    assert ids == ["fake_aggregator", "fake_minimal"]


def test_find_by_capability_ignores_object_type(registry: ProviderRegistry) -> None:
    ids = [
        adapter.descriptor.provider_id
        for adapter in registry.find_by_capability(ProviderCapability.MALWARE_INTELLIGENCE)
    ]
    assert ids == ["fake_aggregator", "fake_minimal"]


def test_unmatched_capability_returns_empty(registry: ProviderRegistry) -> None:
    assert (
        registry.find_compatible(IntelObjectType.URL, ProviderCapability.CERTIFICATE_CONTEXT) == ()
    )


def test_capabilities_for_object_type(registry: ProviderRegistry) -> None:
    capabilities = registry.capabilities_for_object_type(IntelObjectType.IPV6_ADDR)
    assert ProviderCapability.SCANNER_CONTEXT in capabilities
    assert ProviderCapability.REPUTATION in capabilities
    assert ProviderCapability.CERTIFICATE_CONTEXT not in capabilities


def test_empty_registry_matches_nothing() -> None:
    registry = ProviderRegistry()
    assert registry.list_all() == ()
    assert (
        registry.find_compatible(IntelObjectType.IPV4_ADDR, ProviderCapability.SCANNER_CONTEXT)
        == ()
    )
    assert registry.capabilities_for_object_type(IntelObjectType.IPV4_ADDR) == frozenset()


# --------------------------------------------------------------------------- #
# Credential and activity filters
# --------------------------------------------------------------------------- #


def test_providers_may_require_no_credentials(registry: ProviderRegistry) -> None:
    matches = registry.find_compatible(
        IntelObjectType.IPV4_ADDR,
        ProviderCapability.FALSE_POSITIVE_CONTEXT,
        requires_credentials=False,
    )
    assert [adapter.descriptor.provider_id for adapter in matches] == ["fake_warninglist"]


def test_credential_filter_can_select_only_keyed_providers(
    registry: ProviderRegistry,
) -> None:
    matches = registry.find_compatible(
        IntelObjectType.IPV4_ADDR,
        ProviderCapability.FALSE_POSITIVE_CONTEXT,
        requires_credentials=True,
    )
    assert [adapter.descriptor.provider_id for adapter in matches] == ["fake_scanner"]


def test_passive_mode_excludes_active_only_providers() -> None:
    class ActiveOnlyProvider(FakeMinimalProvider):
        _descriptor = ProviderDescriptor(
            provider_id="fake_active_only",
            display_name="Fake Active Only",
            adapter_version="0.1.0",
            source_family="sandbox",
            supported_object_types=frozenset({IntelObjectType.URL}),
            capabilities=frozenset({ProviderCapability.ACTIVE_SCAN}),
            supports_passive=False,
            supports_active=True,
        )

    registry = ProviderRegistry([ActiveOnlyProvider()])
    assert (
        registry.find_compatible(
            IntelObjectType.URL,
            ProviderCapability.ACTIVE_SCAN,
            activity_mode=ActivityMode.PASSIVE,
        )
        == ()
    )
    active = registry.find_compatible(
        IntelObjectType.URL,
        ProviderCapability.ACTIVE_SCAN,
        activity_mode=ActivityMode.ACTIVE,
    )
    assert [adapter.descriptor.provider_id for adapter in active] == ["fake_active_only"]


def test_active_mode_excludes_passive_only_providers(registry: ProviderRegistry) -> None:
    assert (
        registry.find_compatible(
            IntelObjectType.IPV4_ADDR,
            ProviderCapability.SCANNER_CONTEXT,
            activity_mode=ActivityMode.ACTIVE,
        )
        == ()
    )


# --------------------------------------------------------------------------- #
# No credentials, no vendor branching
# --------------------------------------------------------------------------- #


def test_registry_exposes_no_credential_surface() -> None:
    for name, _ in inspect.getmembers(ProviderRegistry, inspect.isfunction):
        assert SENSITIVE_KEY_PATTERN.search(name) is None, name


def test_descriptors_serialize_without_credential_state(
    registry: ProviderRegistry,
) -> None:
    payload = json.dumps(
        [descriptor.model_dump(mode="json") for descriptor in registry.descriptors()]
    )
    lowered = payload.lower()
    for token in ("api_key", "apikey", "auth-key", "authorization", "bearer ", "secret"):
        assert token not in lowered


def test_registry_source_contains_no_vendor_branching() -> None:
    """Capability matching must not need to know any vendor's name."""
    import ti_recon.providers.registry as registry_module

    source = inspect.getsource(registry_module)
    for vendor in (
        "virustotal",
        "urlscan",
        "greynoise",
        "censys",
        "threatfox",
        "urlhaus",
        "malwarebazaar",
        "shodan",
        "abuseipdb",
        "securitytrails",
        "ipinfo",
    ):
        assert vendor not in source.lower()


def test_registry_does_not_score_or_prioritize() -> None:
    """Provider selection is a later task; matching must not imply a ranking."""
    method_names = {name for name, _ in inspect.getmembers(ProviderRegistry, inspect.isfunction)}
    assert method_names.isdisjoint({"rank", "score", "prioritize", "best", "select"})


def test_registry_accepts_any_conforming_adapter() -> None:
    """Registration depends only on the contract, never on a known id list."""

    class BrandNewProvider(FakeMinimalProvider):
        _descriptor = ProviderDescriptor(
            provider_id="totally_new_provider",
            display_name="Totally New",
            adapter_version="9.9.9",
            source_family="new_family",
            supported_object_types=frozenset({IntelObjectType.DOMAIN_NAME}),
            capabilities=frozenset({ProviderCapability.HISTORICAL_INFRASTRUCTURE}),
        )

    registry = ProviderRegistry([BrandNewProvider()])
    matches = registry.find_compatible(
        IntelObjectType.DOMAIN_NAME, ProviderCapability.HISTORICAL_INFRASTRUCTURE
    )
    assert len(matches) == 1


def test_registered_objects_are_provider_adapters(registry: ProviderRegistry) -> None:
    for adapter in registry:
        assert isinstance(adapter, ProviderAdapter)


def test_capability_enum_is_re_exported_from_providers() -> None:
    assert ExportedCapability is ProviderCapability


def test_repr_lists_provider_ids_only(registry: ProviderRegistry) -> None:
    text = repr(registry)
    assert "fake_scanner" in text
    assert SENSITIVE_KEY_PATTERN.search(text) is None
