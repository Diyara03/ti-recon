"""The ThreatFox provider descriptor (Task 10).

Separate from the adapter so the identity of the provider — its id, credential
group, supported object types and declared capabilities — can be imported and
registered without pulling in the client or the normalizer.

Naming choices worth stating:

* ``provider_id = "threatfox"`` is what appears as ``transport_provider`` on
  every piece of evidence: whose API we actually called.
* ``source_family = "abuse_ch"`` — shared with URLhaus and MalwareBazaar. They
  are three datasets in one ecosystem that cross-reference each other, and a
  fusion layer must never read two of them agreeing as two independent sources.
  Each still keeps its own lineage group; see
  :mod:`ti_recon.providers.abusech.family`.
* ``credential_group = "abuse_ch"`` because one Auth-Key serves all three.

``FILE`` is declared, but ThreatFox searches by MD5 or SHA-256 only. A file
identified by SHA-1 alone is reported ``NOT_SUPPORTED`` by the adapter rather
than answered with a guess — see
:mod:`ti_recon.providers.threatfox.adapter`.

IPv6 is deliberately absent. ThreatFox stores address intelligence as
``ip:port``, and the current public API documentation does not establish how an
IPv6 literal is represented or matched there. Declaring support we cannot
validate would turn a blind spot into a silent empty answer.
"""

from __future__ import annotations

from typing import Final

from ti_recon.enums import IntelObjectType, ProviderCapability
from ti_recon.providers.abusech.family import (
    ABUSE_CH_CREDENTIAL_GROUP,
    ABUSE_CH_SOURCE_FAMILY,
)
from ti_recon.providers.descriptor import ProviderDescriptor

__all__ = [
    "THREATFOX_ADAPTER_VERSION",
    "THREATFOX_API_VERSION",
    "THREATFOX_CAPABILITIES",
    "THREATFOX_CREDENTIAL_GROUP",
    "THREATFOX_ORIGIN_PROVIDER",
    "THREATFOX_PROVIDER_ID",
    "THREATFOX_SOURCE_FAMILY",
    "THREATFOX_SUPPORTED_OBJECT_TYPES",
    "build_threatfox_descriptor",
]

THREATFOX_PROVIDER_ID: Final[str] = "threatfox"

#: Who produced the observation, as opposed to whose API carried it. Equal to
#: :data:`THREATFOX_PROVIDER_ID` for ThreatFox's own curated IOC records.
#: Anything ThreatFox merely repeats from elsewhere gets its own origin at
#: normalization time so it is never mistaken for a ThreatFox finding.
THREATFOX_ORIGIN_PROVIDER: Final[str] = THREATFOX_PROVIDER_ID

THREATFOX_SOURCE_FAMILY: Final[str] = ABUSE_CH_SOURCE_FAMILY
THREATFOX_CREDENTIAL_GROUP: Final[str] = ABUSE_CH_CREDENTIAL_GROUP

THREATFOX_API_VERSION: Final[str] = "v1"
THREATFOX_ADAPTER_VERSION: Final[str] = "0.1.0"

#: Every observable type ThreatFox can be asked about.
THREATFOX_SUPPORTED_OBJECT_TYPES: Final[frozenset[IntelObjectType]] = frozenset(
    {
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.DOMAIN_NAME,
        IntelObjectType.URL,
        IntelObjectType.FILE,
    }
)

#: What the *integration* can answer.
#:
#: ``REPUTATION`` because a current ThreatFox record is that platform's own
#: assessment of an indicator. ``THREAT_ASSOCIATIONS`` because the malware
#: family, its aliases and its Malpedia reference are the most useful thing
#: ThreatFox returns. ``RELATIONSHIPS`` because a hash search yields the
#: infrastructure a sample is tied to.
#:
#: No active capability is declared, and there is no code path to turn one on:
#: ThreatFox accepts IOC submissions and this integration cannot make one.
THREATFOX_CAPABILITIES: Final[frozenset[ProviderCapability]] = frozenset(
    {
        ProviderCapability.REPUTATION,
        ProviderCapability.THREAT_ASSOCIATIONS,
        ProviderCapability.RELATIONSHIPS,
    }
)


def build_threatfox_descriptor() -> ProviderDescriptor:
    """The static declaration registered with the provider registry."""
    return ProviderDescriptor(
        provider_id=THREATFOX_PROVIDER_ID,
        display_name="ThreatFox (abuse.ch)",
        adapter_version=THREATFOX_ADAPTER_VERSION,
        api_version=THREATFOX_API_VERSION,
        source_family=THREATFOX_SOURCE_FAMILY,
        credential_group=THREATFOX_CREDENTIAL_GROUP,
        supported_object_types=THREATFOX_SUPPORTED_OBJECT_TYPES,
        capabilities=THREATFOX_CAPABILITIES,
        supports_passive=True,
        supports_active=False,
        supports_batch=False,
        requires_credentials=True,
    )
