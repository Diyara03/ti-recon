"""The GTI descriptor and its registry integration (Task 7).

The adapter itself arrives in the next commit; what matters here is that GTI's
identity is declared correctly and is discoverable through the generic Task 5
registry with no engine change and no vendor branching.
"""

from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from ti_recon.credentials import VIRUSTOTAL_GROUP, credential_group_for, providers_in_group
from ti_recon.enums import ActivityMode, IntelObjectType, ProviderCapability
from ti_recon.providers import ProviderRegistry
from ti_recon.providers.gti import (
    GTI_ADAPTER_VERSION,
    GTI_API_VERSION,
    GTI_CREDENTIAL_GROUP,
    GTI_ORIGIN_PROVIDER,
    GTI_PROVIDER_ID,
    GTI_SOURCE_FAMILY,
    build_gti_descriptor,
)


def test_identity_matches_the_documented_naming() -> None:
    descriptor = build_gti_descriptor()
    assert descriptor.provider_id == "gti"
    assert descriptor.display_name == "Google Threat Intelligence"
    assert descriptor.api_version == "v3"
    assert descriptor.source_family == "google_ti"
    assert descriptor.credential_group == "virustotal"
    assert descriptor.adapter_version == GTI_ADAPTER_VERSION


def test_gti_evidence_is_its_own_data_not_relayed() -> None:
    """GTI both produces and serves its assessments, so origin equals transport.

    ``Evidence.is_relayed`` is ``transport != origin``. Spelling the origin
    differently would mark GTI's own judgement as second-hand and let a future
    fusion layer discount it as relayed corroboration.
    """
    assert GTI_PROVIDER_ID == "gti"
    assert GTI_ORIGIN_PROVIDER == GTI_PROVIDER_ID


def test_the_human_readable_name_lives_on_the_descriptor() -> None:
    """ "Google Threat Intelligence" is a display name, not a lineage key."""
    assert build_gti_descriptor().display_name == "Google Threat Intelligence"


def test_the_source_family_groups_every_gti_signal() -> None:
    """Mandiant-curated components are parts of one source, not extra sources."""
    assert GTI_SOURCE_FAMILY == "google_ti"
    assert GTI_API_VERSION == "v3"


def test_every_v1_observable_type_is_supported() -> None:
    supported = build_gti_descriptor().supported_object_types
    assert supported == {
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.IPV6_ADDR,
        IntelObjectType.DOMAIN_NAME,
        IntelObjectType.URL,
        IntelObjectType.FILE,
    }


def test_hashes_are_covered_by_the_file_object_type() -> None:
    """MD5, SHA-1 and SHA-256 all resolve to one `file` object."""
    supported = build_gti_descriptor().supported_object_types
    assert IntelObjectType.FILE in supported
    assert not {t for t in supported if t.value in {"md5", "sha1", "sha256"}}


def test_declared_capabilities_are_common_vocabulary_only() -> None:
    """No GTI-specific data field becomes a global capability."""
    capabilities = build_gti_descriptor().capabilities
    assert capabilities <= set(ProviderCapability)
    assert ProviderCapability.REPUTATION in capabilities
    assert ProviderCapability.THREAT_ASSOCIATIONS in capabilities
    assert ProviderCapability.FILE_BEHAVIOR in capabilities
    assert ProviderCapability.RELATIONSHIPS in capabilities


def test_intelligence_search_is_not_declared() -> None:
    """Deferred on purpose: search is a pivot capability, not IOC enrichment."""
    assert not [c for c in ProviderCapability if "search" in c.value]


def test_gti_is_passive_only() -> None:
    descriptor = build_gti_descriptor()
    assert descriptor.supports_passive is True
    assert descriptor.supports_active is False
    assert ProviderCapability.ACTIVE_SCAN not in descriptor.capabilities
    assert descriptor.passive_capabilities == descriptor.capabilities


def test_gti_requires_a_credential() -> None:
    assert build_gti_descriptor().requires_credentials is True


def test_batch_is_not_claimed() -> None:
    descriptor = build_gti_descriptor()
    assert descriptor.supports_batch is False
    assert ProviderCapability.BATCH_LOOKUP not in descriptor.capabilities


def test_the_descriptor_is_immutable() -> None:
    with pytest.raises(ValidationError, match="frozen"):
        build_gti_descriptor().provider_id = "other"


def test_the_descriptor_names_a_credential_group_but_holds_no_credential() -> None:
    """`credential_group` is the name of a stored secret, never the secret."""
    descriptor = build_gti_descriptor()
    assert set(type(descriptor).model_fields) == {
        "provider_id",
        "display_name",
        "adapter_version",
        "api_version",
        "source_family",
        "credential_group",
        "supported_object_types",
        "capabilities",
        "supports_passive",
        "supports_active",
        "supports_batch",
        "requires_credentials",
        # A local dataset fingerprint, for providers that have one. Non-secret
        # by construction: it is a digest of public data, and a remote provider
        # leaves it unset.
        "dataset_version",
    }
    assert descriptor.dataset_version is None
    serialized = descriptor.model_dump_json()
    assert "vt-key" not in serialized
    assert descriptor.credential_group == "virustotal"


# --------------------------------------------------------------------------- #
# Credential grouping
# --------------------------------------------------------------------------- #


def test_the_credential_is_a_virustotal_key_not_a_new_secret_type() -> None:
    """One stored VirusTotal key serves the GTI-branded product."""
    assert GTI_CREDENTIAL_GROUP == VIRUSTOTAL_GROUP == "virustotal"
    assert credential_group_for("gti") == VIRUSTOTAL_GROUP


def test_the_group_agrees_with_the_descriptor() -> None:
    assert build_gti_descriptor().credential_group == credential_group_for("gti")


def test_a_future_virustotal_adapter_would_share_the_same_key() -> None:
    assert providers_in_group(VIRUSTOTAL_GROUP) == frozenset({"gti", "virustotal"})


def test_no_separate_gti_api_key_concept_exists() -> None:
    """The secret is the analyst's VirusTotal key; no second secret type."""
    import ti_recon.credentials.groups as groups
    import ti_recon.providers.gti.config as config

    for module in (groups, config):
        assert "GTI_API_KEY" not in inspect.getsource(module)


# --------------------------------------------------------------------------- #
# Registry integration
# --------------------------------------------------------------------------- #


def test_the_descriptor_is_discoverable_through_the_generic_registry() -> None:
    """No engine change and no vendor branching is needed to find GTI."""
    from fixtures.gti.shell_adapter import DescriptorOnlyAdapter

    registry = ProviderRegistry([DescriptorOnlyAdapter(build_gti_descriptor())])

    assert "gti" in registry
    assert registry.get("gti").descriptor.provider_id == "gti"

    for object_type in build_gti_descriptor().supported_object_types:
        matches = registry.find_compatible(object_type, ProviderCapability.REPUTATION)
        assert [a.descriptor.provider_id for a in matches] == ["gti"]


def test_gti_is_not_offered_for_an_active_investigation() -> None:
    from fixtures.gti.shell_adapter import DescriptorOnlyAdapter

    registry = ProviderRegistry([DescriptorOnlyAdapter(build_gti_descriptor())])
    assert (
        registry.find_compatible(
            IntelObjectType.URL,
            ProviderCapability.REPUTATION,
            activity_mode=ActivityMode.ACTIVE,
        )
        == ()
    )


def test_the_registry_source_still_names_no_vendor() -> None:
    """Registering a real provider must not have introduced branching."""
    import ti_recon.providers.registry as registry_module

    source = inspect.getsource(registry_module).lower()
    for vendor in ("gti", "virustotal", "google"):
        assert vendor not in source
