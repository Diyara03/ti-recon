"""What the three abuse.ch providers share, and must keep sharing (Task 10).

ThreatFox, URLhaus and MalwareBazaar are three adapters over one ecosystem. The
tests here are about the seams between them: one credential for all three, one
source family so agreement between them is never read as corroboration, distinct
lineage groups so their claims stay distinguishable, and relayed findings keeping
the origin — and the family — of whoever actually produced them.
"""

from __future__ import annotations

import pytest

from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.groups import (
    ABUSE_CH_GROUP,
    credential_group_for,
    providers_in_group,
)
from ti_recon.enums import IntelObjectType, ProviderCapability
from ti_recon.providers import ProviderRegistry
from ti_recon.providers.abusech import (
    ABUSE_CH_AUTH_HEADER,
    ABUSE_CH_AUTH_TYPE,
    ABUSE_CH_CREDENTIAL_GROUP,
    ABUSE_CH_PROVIDER_IDS,
    ABUSE_CH_SOURCE_FAMILY,
    BLOCKLIST_RELAY_FAMILY,
    BLOCKLIST_RELAY_ORIGIN,
    VENDOR_INTEL_RELAY_FAMILY,
    VENDOR_INTEL_RELAY_ORIGIN,
    VIRUSTOTAL_RELAY_FAMILY,
    VIRUSTOTAL_RELAY_ORIGIN,
    lineage_group_for,
)
from ti_recon.providers.gti import GTI_SOURCE_FAMILY
from ti_recon.providers.malwarebazaar import MalwareBazaarAdapter, build_malwarebazaar_descriptor
from ti_recon.providers.threatfox import ThreatFoxAdapter, build_threatfox_descriptor
from ti_recon.providers.urlhaus import UrlhausAdapter, build_urlhaus_descriptor

DESCRIPTORS = {
    "threatfox": build_threatfox_descriptor(),
    "urlhaus": build_urlhaus_descriptor(),
    "malwarebazaar": build_malwarebazaar_descriptor(),
}


def registry() -> ProviderRegistry:
    return ProviderRegistry([ThreatFoxAdapter(), UrlhausAdapter(), MalwareBazaarAdapter()])


# --------------------------------------------------------------------------- #
# One credential, three providers
# --------------------------------------------------------------------------- #


def test_the_three_providers_are_the_abusech_group() -> None:
    assert ABUSE_CH_PROVIDER_IDS == frozenset({"threatfox", "urlhaus", "malwarebazaar"})
    assert providers_in_group(ABUSE_CH_GROUP) == ABUSE_CH_PROVIDER_IDS
    assert ABUSE_CH_CREDENTIAL_GROUP == ABUSE_CH_GROUP


@pytest.mark.parametrize("provider_id", sorted(DESCRIPTORS))
def test_every_provider_resolves_its_credential_from_the_shared_group(provider_id: str) -> None:
    """An analyst stores one Auth-Key, not three."""
    assert credential_group_for(provider_id) == ABUSE_CH_GROUP
    assert DESCRIPTORS[provider_id].credential_group == ABUSE_CH_GROUP
    assert DESCRIPTORS[provider_id].requires_credentials is True


def test_the_shared_credential_is_an_auth_key_header() -> None:
    assert ABUSE_CH_AUTH_TYPE is AuthType.AUTH_KEY
    assert ABUSE_CH_AUTH_HEADER == "Auth-Key"


# --------------------------------------------------------------------------- #
# One family, three lineages
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("provider_id", sorted(DESCRIPTORS))
def test_every_provider_declares_the_shared_family(provider_id: str) -> None:
    """Three of them agreeing is one ecosystem agreeing with itself."""
    assert DESCRIPTORS[provider_id].source_family == ABUSE_CH_SOURCE_FAMILY


def test_each_platform_keeps_its_own_lineage_group() -> None:
    """Same house, distinguishable claims."""
    groups = {lineage_group_for(provider_id) for provider_id in ABUSE_CH_PROVIDER_IDS}
    assert len(groups) == 3
    for group in groups:
        assert group.startswith(f"{ABUSE_CH_SOURCE_FAMILY}:")


def test_a_lineage_group_is_never_the_bare_family() -> None:
    """Otherwise two platforms' claims would merge into one lineage."""
    for provider_id in ABUSE_CH_PROVIDER_IDS:
        assert lineage_group_for(provider_id) != ABUSE_CH_SOURCE_FAMILY


# --------------------------------------------------------------------------- #
# Relayed findings keep their real provenance
# --------------------------------------------------------------------------- #


def test_a_relayed_virustotal_count_shares_the_family_a_direct_gti_result_carries() -> None:
    """The point of the whole relay design: relayed VT and direct GTI are one source.

    If these two strings ever diverge, a URLhaus-relayed VirusTotal ratio and a
    direct Google Threat Intelligence lookup become two independent
    corroborations of each other, which is exactly the inflation the lineage
    rules exist to prevent.
    """
    assert VIRUSTOTAL_RELAY_FAMILY == GTI_SOURCE_FAMILY


def test_no_relay_is_attributed_to_abusech() -> None:
    relays = (
        (VIRUSTOTAL_RELAY_ORIGIN, VIRUSTOTAL_RELAY_FAMILY),
        (BLOCKLIST_RELAY_ORIGIN, BLOCKLIST_RELAY_FAMILY),
        (VENDOR_INTEL_RELAY_ORIGIN, VENDOR_INTEL_RELAY_FAMILY),
    )
    for origin, family in relays:
        assert origin not in ABUSE_CH_PROVIDER_IDS
        assert family != ABUSE_CH_SOURCE_FAMILY


def test_the_three_relay_kinds_stay_distinct() -> None:
    """A vendor sandbox, a URL blocklist and VirusTotal are not one source."""
    families = {VIRUSTOTAL_RELAY_FAMILY, BLOCKLIST_RELAY_FAMILY, VENDOR_INTEL_RELAY_FAMILY}
    assert len(families) == 3


# --------------------------------------------------------------------------- #
# The observable matrix
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("object_type", "capability", "expected"),
    [
        (IntelObjectType.IPV4_ADDR, ProviderCapability.REPUTATION, ["threatfox", "urlhaus"]),
        (IntelObjectType.DOMAIN_NAME, ProviderCapability.REPUTATION, ["threatfox", "urlhaus"]),
        (IntelObjectType.URL, ProviderCapability.REPUTATION, ["threatfox", "urlhaus"]),
        (
            IntelObjectType.FILE,
            ProviderCapability.REPUTATION,
            ["malwarebazaar", "threatfox", "urlhaus"],
        ),
        (
            IntelObjectType.FILE,
            ProviderCapability.MALWARE_INTELLIGENCE,
            ["malwarebazaar"],
        ),
        (IntelObjectType.IPV6_ADDR, ProviderCapability.REPUTATION, []),
    ],
)
def test_which_provider_answers_which_observable(
    object_type: IntelObjectType, capability: ProviderCapability, expected: list[str]
) -> None:
    matches = registry().find_compatible(object_type, capability)
    assert sorted(adapter.descriptor.provider_id for adapter in matches) == expected


def test_no_abusech_provider_claims_an_active_or_batch_operation() -> None:
    for descriptor in DESCRIPTORS.values():
        assert descriptor.supports_passive is True
        assert descriptor.supports_active is False
        assert descriptor.supports_batch is False
        assert ProviderCapability.ACTIVE_SCAN not in descriptor.capabilities


def test_no_abusech_provider_claims_dynamic_analysis() -> None:
    """All three relay sandbox output; relaying is not observing."""
    for descriptor in DESCRIPTORS.values():
        assert ProviderCapability.FILE_BEHAVIOR not in descriptor.capabilities


def test_the_three_providers_have_distinct_ids_and_registry_slots() -> None:
    assert sorted(descriptor.provider_id for descriptor in registry().descriptors()) == [
        "malwarebazaar",
        "threatfox",
        "urlhaus",
    ]
