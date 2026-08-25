"""All four integrated providers, in one registry (Task 9).

Provider independence is the invariant this file exists for. The engine asks for
an object type and a capability; the registry answers with whichever providers
can serve it, and no engine code ever names a vendor. With four real adapters
registered together, that claim is testable rather than aspirational.

It also checks the thing that only becomes visible once several providers
coexist: that they answer *different* questions, and that none of them has
quietly claimed a capability it cannot serve.
"""

from __future__ import annotations

import pytest

from fixtures.censys.contract import contract_censys_adapter
from fixtures.greynoise.contract import contract_greynoise_adapter
from fixtures.gti.contract import contract_gti_adapter
from fixtures.urlscan.contract import contract_urlscan_adapter
from ti_recon.enums import IntelObjectType, ProviderCapability
from ti_recon.execution.policy import ProviderPolicyRegistry
from ti_recon.providers import ProviderAdapter, ProviderRegistry
from ti_recon.providers.censys import build_censys_execution_policy
from ti_recon.providers.greynoise import build_greynoise_execution_policy
from ti_recon.providers.gti import build_gti_execution_policy
from ti_recon.providers.urlscan import build_urlscan_execution_policy

ALL_PROVIDERS = ("censys", "greynoise", "gti", "urlscan")


@pytest.fixture
def adapters() -> list[ProviderAdapter]:
    return [
        contract_gti_adapter(),
        contract_urlscan_adapter(),
        contract_greynoise_adapter(),
        contract_censys_adapter(),
    ]


@pytest.fixture
def registry(adapters: list[ProviderAdapter]) -> ProviderRegistry:
    return ProviderRegistry(adapters)


# --------------------------------------------------------------------------- #
# They coexist
# --------------------------------------------------------------------------- #


def test_all_four_providers_register_without_collision(registry: ProviderRegistry) -> None:
    assert tuple(sorted(adapter.descriptor.provider_id for adapter in registry.list_all())) == (
        ALL_PROVIDERS
    )


def test_every_provider_has_its_own_identity(adapters: list[ProviderAdapter]) -> None:
    """``transport_provider`` is the provider id, so a collision would make
    evidence provenance ambiguous."""
    ids = [adapter.descriptor.provider_id for adapter in adapters]
    assert len(set(ids)) == len(ids)


def test_every_provider_has_its_own_source_family(adapters: list[ProviderAdapter]) -> None:
    """Four independent families: none of them relays another's data."""
    families = [adapter.descriptor.source_family for adapter in adapters]
    assert len(set(families)) == len(families)


def test_every_provider_has_its_own_credential_group(adapters: list[ProviderAdapter]) -> None:
    """One key per provider here — nothing in this set shares a credential."""
    groups = [adapter.descriptor.credential_group for adapter in adapters]
    assert len(set(groups)) == len(groups)


def test_every_provider_has_its_own_execution_policy() -> None:
    policies = ProviderPolicyRegistry(
        policies=[
            build_gti_execution_policy(),
            build_urlscan_execution_policy(),
            build_greynoise_execution_policy(),
            build_censys_execution_policy(),
        ]
    )
    assert len(policies) == 4
    for provider_id in ALL_PROVIDERS:
        assert provider_id in policies


# --------------------------------------------------------------------------- #
# They answer different questions
# --------------------------------------------------------------------------- #


def test_a_scanner_context_question_reaches_only_greynoise(
    registry: ProviderRegistry,
) -> None:
    matches = registry.find_compatible(
        IntelObjectType.IPV4_ADDR, ProviderCapability.SCANNER_CONTEXT
    )
    assert [adapter.descriptor.provider_id for adapter in matches] == ["greynoise"]


def test_a_web_forensics_question_reaches_only_urlscan(registry: ProviderRegistry) -> None:
    matches = registry.find_compatible(IntelObjectType.URL, ProviderCapability.WEB_FORENSICS)
    assert [adapter.descriptor.provider_id for adapter in matches] == ["urlscan"]


def test_a_file_behaviour_question_reaches_only_gti(registry: ProviderRegistry) -> None:
    matches = registry.find_compatible(IntelObjectType.FILE, ProviderCapability.FILE_BEHAVIOR)
    assert [adapter.descriptor.provider_id for adapter in matches] == ["gti"]


def test_an_exposure_question_reaches_censys(registry: ProviderRegistry) -> None:
    matches = registry.find_compatible(
        IntelObjectType.IPV4_ADDR, ProviderCapability.CURRENT_INFRASTRUCTURE
    )
    provider_ids = {adapter.descriptor.provider_id for adapter in matches}
    assert "censys" in provider_ids


def test_a_reputation_question_never_reaches_censys(registry: ProviderRegistry) -> None:
    """Censys answers what is exposed, not whether it is hostile."""
    matches = registry.find_compatible(IntelObjectType.IPV4_ADDR, ProviderCapability.REPUTATION)
    provider_ids = {adapter.descriptor.provider_id for adapter in matches}
    assert "censys" not in provider_ids
    assert provider_ids


def test_a_bare_domain_reaches_neither_new_provider(registry: ProviderRegistry) -> None:
    """GreyNoise is IPv4-only and a Censys web property needs a port."""
    for capability in ProviderCapability:
        matches = registry.find_compatible(IntelObjectType.DOMAIN_NAME, capability)
        provider_ids = {adapter.descriptor.provider_id for adapter in matches}
        assert "greynoise" not in provider_ids
        assert "censys" not in provider_ids


def test_a_file_hash_reaches_neither_new_provider(registry: ProviderRegistry) -> None:
    """Neither answers for a file — and a hash is never a certificate."""
    for capability in ProviderCapability:
        matches = registry.find_compatible(IntelObjectType.FILE, capability)
        provider_ids = {adapter.descriptor.provider_id for adapter in matches}
        assert "greynoise" not in provider_ids
        assert "censys" not in provider_ids


# --------------------------------------------------------------------------- #
# Nothing in the set is active
# --------------------------------------------------------------------------- #


def test_no_integrated_provider_declares_an_active_capability(
    adapters: list[ProviderAdapter],
) -> None:
    for adapter in adapters:
        descriptor = adapter.descriptor
        assert descriptor.supports_active is False
        assert ProviderCapability.ACTIVE_SCAN not in descriptor.capabilities
        assert descriptor.passive_capabilities == descriptor.capabilities


def test_no_integrated_provider_declares_batch_support(
    adapters: list[ProviderAdapter],
) -> None:
    for adapter in adapters:
        assert adapter.descriptor.supports_batch is False


def test_every_integrated_provider_requires_a_credential(
    adapters: list[ProviderAdapter],
) -> None:
    """Each is a per-analyst key; none reads a public feed."""
    for adapter in adapters:
        assert adapter.descriptor.requires_credentials is True


def test_no_execution_policy_shares_results_between_analysts() -> None:
    """Every one of these providers is entitlement- or credit-sensitive."""
    for policy in (
        build_gti_execution_policy(),
        build_urlscan_execution_policy(),
        build_greynoise_execution_policy(),
        build_censys_execution_policy(),
    ):
        assert policy.cache.scope.value == "user"
        assert policy.cache.partial_ttl_seconds is None
        assert policy.cache.no_data_ttl_seconds < policy.cache.success_ttl_seconds
