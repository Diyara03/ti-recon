"""The URLhaus provider descriptor (Task 10).

Separate from the adapter so the identity of the provider can be imported and
registered without pulling in the client or the normalizer.

* ``provider_id = "urlhaus"`` is what appears as ``transport_provider`` on every
  piece of evidence.
* ``source_family = "abuse_ch"`` — shared with ThreatFox and MalwareBazaar, so a
  fusion layer can never read two of them agreeing as two independent sources.
* ``credential_group = "abuse_ch"`` because one Auth-Key serves all three.

URLhaus answers three different questions, and the descriptor deliberately does
not distinguish them: a URL is looked up exactly, a domain or address is looked
up as a *host*, and a file hash is looked up as a *payload*. Those are very
different claims, and the difference is carried by match scope and evidence
effect rather than by capability — see
:mod:`ti_recon.providers.urlhaus.normalizer`.

IPv6 is absent: the current API documents host lookup for IPv4, hostnames and
domains, and inferring IPv6 support would turn a blind spot into a silent empty
answer. SHA-1 is absent for the same reason — URLhaus indexes payloads by MD5
and SHA-256.
"""

from __future__ import annotations

from typing import Final

from ti_recon.enums import IntelObjectType, InvestigationDepth, ProviderCapability
from ti_recon.planning.models import (
    CallCostClass,
    ProviderLocality,
    ProviderPlanningProfile,
)
from ti_recon.providers.abusech.family import (
    ABUSE_CH_CREDENTIAL_GROUP,
    ABUSE_CH_SOURCE_FAMILY,
)
from ti_recon.providers.descriptor import ProviderDescriptor

__all__ = [
    "URLHAUS_ADAPTER_VERSION",
    "URLHAUS_API_VERSION",
    "URLHAUS_CAPABILITIES",
    "URLHAUS_CREDENTIAL_GROUP",
    "URLHAUS_ORIGIN_PROVIDER",
    "URLHAUS_PROVIDER_ID",
    "URLHAUS_SOURCE_FAMILY",
    "URLHAUS_SUPPORTED_OBJECT_TYPES",
    "build_urlhaus_descriptor",
    "build_urlhaus_planning_profile",
]

URLHAUS_PROVIDER_ID: Final[str] = "urlhaus"

#: Who produced the observation. URLhaus tracks malware-distribution URLs
#: itself, so origin equals transport for its own records. The VirusTotal
#: results and blocklist statuses it repeats get their own origin at
#: normalization time so they are never mistaken for URLhaus findings.
URLHAUS_ORIGIN_PROVIDER: Final[str] = URLHAUS_PROVIDER_ID

URLHAUS_SOURCE_FAMILY: Final[str] = ABUSE_CH_SOURCE_FAMILY
URLHAUS_CREDENTIAL_GROUP: Final[str] = ABUSE_CH_CREDENTIAL_GROUP

URLHAUS_API_VERSION: Final[str] = "v1"
URLHAUS_ADAPTER_VERSION: Final[str] = "0.1.0"

#: Every observable type URLhaus can be asked about.
URLHAUS_SUPPORTED_OBJECT_TYPES: Final[frozenset[IntelObjectType]] = frozenset(
    {
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.DOMAIN_NAME,
        IntelObjectType.URL,
        IntelObjectType.FILE,
    }
)

#: What the *integration* can answer.
#:
#: ``REPUTATION`` because a tracked URL is URLhaus's own assessment that the URL
#: served malware. ``THREAT_ASSOCIATIONS`` because a payload carries a family
#: signature. ``RELATIONSHIPS`` because the URL/host/payload triangle is the most
#: useful thing URLhaus returns — a URL points at a host and at the file it
#: served, and a file points back at every URL that served it.
#:
#: ``WEB_BEHAVIOR`` is deliberately absent: URLhaus records *that* a URL served
#: malware, not what a browser saw. urlscan answers that question.
URLHAUS_CAPABILITIES: Final[frozenset[ProviderCapability]] = frozenset(
    {
        ProviderCapability.REPUTATION,
        ProviderCapability.THREAT_ASSOCIATIONS,
        ProviderCapability.RELATIONSHIPS,
    }
)


def build_urlhaus_descriptor() -> ProviderDescriptor:
    """The static declaration registered with the provider registry.

    ``supports_active`` is ``False`` and stays that way. URLhaus accepts URL
    submissions and serves payload downloads; this integration can do neither,
    and there is no code path to turn either on.
    """
    return ProviderDescriptor(
        provider_id=URLHAUS_PROVIDER_ID,
        display_name="URLhaus (abuse.ch)",
        adapter_version=URLHAUS_ADAPTER_VERSION,
        api_version=URLHAUS_API_VERSION,
        source_family=URLHAUS_SOURCE_FAMILY,
        credential_group=URLHAUS_CREDENTIAL_GROUP,
        supported_object_types=URLHAUS_SUPPORTED_OBJECT_TYPES,
        capabilities=URLHAUS_CAPABILITIES,
        supports_passive=True,
        supports_active=False,
        supports_batch=False,
        requires_credentials=True,
    )


#: How the planner may use this provider (Task 13).
#:
#: One read per lookup, so ``LOW``. Priority slightly above its abuse.ch
#: siblings for URL work, where exact malware-distribution records are the most
#: directly relevant thing the family holds — a tie-break, not a quality claim.
def build_urlhaus_planning_profile() -> ProviderPlanningProfile:
    """The Task 13 planning profile for this provider."""
    return ProviderPlanningProfile(
        provider_id=URLHAUS_PROVIDER_ID,
        source_family=URLHAUS_SOURCE_FAMILY,
        locality=ProviderLocality.REMOTE,
        cost_class=CallCostClass.LOW,
        planning_capabilities=URLHAUS_CAPABILITIES,
        minimum_depth=InvestigationDepth.QUICK,
        priority=55,
        # One path-routed read returns the URL or host record whole.
        capability_invariant_response=True,
    )
