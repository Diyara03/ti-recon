"""The GreyNoise provider descriptor (Task 9).

Separate from the adapter so the identity of the provider — its id, credential
group, supported object types and declared capabilities — can be imported and
registered without pulling in the client or the normalizer.

Naming choices worth stating:

* ``provider_id = "greynoise"`` is what appears as ``transport_provider`` on
  every piece of evidence: whose API we actually called.
* ``source_family = "greynoise"`` groups everything that comes out of
  GreyNoise's own sensor network. GreyNoise *observes* scanning traffic itself,
  so its classification, its tags and its Business Services Intelligence are all
  first-hand — origin equals transport for every one of them, and they are all
  one source. A classification and a BSI record agreeing is not two providers
  agreeing.
* ``credential_group = "greynoise"`` because the credential is a GreyNoise API
  key and nothing else consumes it.

Only IPv4 is declared. GreyNoise's sensor network reports on addresses, and this
integration answers for the one address family it can answer for; every other
observable type is reported as ``NOT_SUPPORTED`` by the execution layer rather
than as a lookup that found nothing. That distinction is the whole point — see
:mod:`ti_recon.providers.greynoise.adapter`.
"""

from __future__ import annotations

from typing import Final

from ti_recon.enums import IntelObjectType, ProviderCapability
from ti_recon.providers.descriptor import ProviderDescriptor

__all__ = [
    "GREYNOISE_ADAPTER_VERSION",
    "GREYNOISE_API_VERSION",
    "GREYNOISE_CAPABILITIES",
    "GREYNOISE_CREDENTIAL_GROUP",
    "GREYNOISE_ORIGIN_PROVIDER",
    "GREYNOISE_PROVIDER_ID",
    "GREYNOISE_SOURCE_FAMILY",
    "GREYNOISE_SUPPORTED_OBJECT_TYPES",
    "build_greynoise_descriptor",
]

GREYNOISE_PROVIDER_ID: Final[str] = "greynoise"

#: Who produced the observation, as opposed to whose API carried it. Equal to
#: :data:`GREYNOISE_PROVIDER_ID` for everything this integration normalizes:
#: GreyNoise runs its own sensors and curates its own service inventory, so it
#: relays nobody. Nothing here ever sets a different origin, and if a future
#: GreyNoise field turns out to repeat a third party's opinion, that field must
#: get its own origin before it becomes evidence.
GREYNOISE_ORIGIN_PROVIDER: Final[str] = GREYNOISE_PROVIDER_ID

GREYNOISE_SOURCE_FAMILY: Final[str] = "greynoise"
GREYNOISE_CREDENTIAL_GROUP: Final[str] = "greynoise"

#: Only v3 is implemented. The v2 IP context, RIOT and GNQL endpoints are
#: deprecated and deliberately absent.
GREYNOISE_API_VERSION: Final[str] = "v3"
GREYNOISE_ADAPTER_VERSION: Final[str] = "0.1.0"

#: IPv4 only.
#:
#: GreyNoise's sensor fleet is addressed by IP, and its v3 IP endpoints are the
#: only ones this integration calls. IPv6 is not declared — not because the
#: address family is uninteresting, but because declaring coverage we have not
#: implemented would turn a blind spot into a silent empty answer.
GREYNOISE_SUPPORTED_OBJECT_TYPES: Final[frozenset[IntelObjectType]] = frozenset(
    {IntelObjectType.IPV4_ADDR}
)

#: What the *integration* can technically answer.
#:
#: ``SCANNER_CONTEXT`` is the reason GreyNoise exists in TI Recon: it is the one
#: provider that can say "this address scans the whole internet all day".
#: ``REPUTATION`` covers the classification, which is GreyNoise's own assessment.
#: ``NETWORK_OWNERSHIP`` covers the ASN, organization and geography that travel
#: with a sensor observation. ``FALSE_POSITIVE_CONTEXT`` covers Business
#: Services Intelligence — the inventory of known business services, whose
#: entire purpose is telling an analyst that an alert is probably about a
#: mail server rather than an attacker.
#:
#: No active capability is declared, and there is no code path to turn one on.
GREYNOISE_CAPABILITIES: Final[frozenset[ProviderCapability]] = frozenset(
    {
        ProviderCapability.SCANNER_CONTEXT,
        ProviderCapability.REPUTATION,
        ProviderCapability.NETWORK_OWNERSHIP,
        ProviderCapability.FALSE_POSITIVE_CONTEXT,
        ProviderCapability.RELATIONSHIPS,
    }
)


def build_greynoise_descriptor() -> ProviderDescriptor:
    """The static declaration registered with the provider registry."""
    return ProviderDescriptor(
        provider_id=GREYNOISE_PROVIDER_ID,
        display_name="GreyNoise",
        adapter_version=GREYNOISE_ADAPTER_VERSION,
        api_version=GREYNOISE_API_VERSION,
        source_family=GREYNOISE_SOURCE_FAMILY,
        credential_group=GREYNOISE_CREDENTIAL_GROUP,
        supported_object_types=GREYNOISE_SUPPORTED_OBJECT_TYPES,
        capabilities=GREYNOISE_CAPABILITIES,
        supports_passive=True,
        supports_active=False,
        supports_batch=False,
        requires_credentials=True,
    )
