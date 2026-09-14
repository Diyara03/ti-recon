"""The urlscan.io provider descriptor (Task 8).

Separate from the adapter so the identity of the provider — its id, credential
group, supported object types and declared capabilities — can be imported and
registered without pulling in the client or the normalizer.

Naming choices worth stating:

* ``provider_id = "urlscan"`` is what appears as ``transport_provider`` on every
  piece of evidence: whose API we actually called.
* ``source_family = "urlscan"`` groups every signal that comes out of urlscan's
  own crawling infrastructure. urlscan *observes* pages itself, so its browser
  observations are first-hand and origin equals transport for them. Relayed
  third-party opinions surfaced inside a scan result (a blocklist hit, a
  brand-detection engine) get their own origin at normalization time and are
  therefore correctly marked ``is_relayed``.
* ``credential_group = "urlscan"`` because the credential is an urlscan API key
  and nothing else consumes it.

What is deliberately *not* declared: any active capability. urlscan can submit
and rescan URLs; TI Recon's integration cannot. ``supports_active`` is ``False``
and no submission path exists to turn on.
"""

from __future__ import annotations

from typing import Final

from ti_recon.enums import IntelObjectType, InvestigationDepth, ProviderCapability
from ti_recon.planning.models import (
    CallCostClass,
    ProviderLocality,
    ProviderPlanningProfile,
)
from ti_recon.providers.descriptor import ProviderDescriptor

__all__ = [
    "URLSCAN_ADAPTER_VERSION",
    "URLSCAN_API_VERSION",
    "URLSCAN_CAPABILITIES",
    "URLSCAN_CREDENTIAL_GROUP",
    "URLSCAN_ORIGIN_PROVIDER",
    "URLSCAN_PROVIDER_ID",
    "URLSCAN_SOURCE_FAMILY",
    "URLSCAN_SUPPORTED_OBJECT_TYPES",
    "URLSCAN_UNDECLARED_CAPABILITIES",
    "build_urlscan_descriptor",
    "build_urlscan_planning_profile",
]

URLSCAN_PROVIDER_ID: Final[str] = "urlscan"

#: Who produced the observation, as opposed to whose API carried it. Equal to
#: :data:`URLSCAN_PROVIDER_ID` for urlscan's own browser observations, which are
#: first-hand. Evidence derived from a third party that urlscan merely repeats
#: overrides this at normalization time so it is never mistaken for independent
#: confirmation.
URLSCAN_ORIGIN_PROVIDER: Final[str] = URLSCAN_PROVIDER_ID

URLSCAN_SOURCE_FAMILY: Final[str] = "urlscan"
URLSCAN_CREDENTIAL_GROUP: Final[str] = "urlscan"
URLSCAN_API_VERSION: Final[str] = "v1"
URLSCAN_ADAPTER_VERSION: Final[str] = "0.1.0"

#: Every observable type an analyst may submit. A ``file`` is supported because
#: urlscan indexes the hashes of the resources a page served, so a hash can be
#: pivoted back to the pages that delivered it — not because urlscan analyses
#: files the way a sandbox does.
URLSCAN_SUPPORTED_OBJECT_TYPES: Final[frozenset[IntelObjectType]] = frozenset(
    {
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.IPV6_ADDR,
        IntelObjectType.DOMAIN_NAME,
        IntelObjectType.URL,
        IntelObjectType.FILE,
    }
)

#: What the *integration* can technically do. ``WEB_FORENSICS`` is declared but
#: gated: it is only exercised when a caller explicitly asks for it at DEEP
#: depth, because retrieving stored page artifacts is far more expensive than
#: reading a scan summary. Declaring it here says "this provider can serve that
#: request", not "this provider does that on every lookup".
#:
#: ``CURRENT_INFRASTRUCTURE`` is deliberately absent. A search hit is a
#: historical scan record: the page's address, network, server and
#: certificate are what a browser saw at ``task.time``, which at DEEP may be
#: years ago, and nothing in the integration establishes that any of it is
#: observable now. That is ``HISTORICAL_INFRASTRUCTURE``, declared below.
#: Declaring the current one let a scan-time snapshot close a goal that a
#: provider observing the present would otherwise answer (Task 24, US-02).
URLSCAN_CAPABILITIES: Final[frozenset[ProviderCapability]] = frozenset(
    {
        ProviderCapability.REPUTATION,
        ProviderCapability.WEB_BEHAVIOR,
        ProviderCapability.HISTORICAL_INFRASTRUCTURE,
        ProviderCapability.RELATIONSHIPS,
        ProviderCapability.WEB_FORENSICS,
    }
)

#: Capabilities urlscan's data looks like it could serve and deliberately does
#: not declare, so the omission is visible and tested rather than accidental.
URLSCAN_UNDECLARED_CAPABILITIES: Final[frozenset[ProviderCapability]] = frozenset(
    {ProviderCapability.CURRENT_INFRASTRUCTURE}
)


def build_urlscan_descriptor() -> ProviderDescriptor:
    """The static declaration registered with the provider registry.

    ``supports_active`` is ``False`` and stays that way. Submitting a URL to
    urlscan causes urlscan's crawler to visit it, which is an active operation
    against the target and — for a public scan — a disclosure of what is being
    investigated. That path is out of scope for this task and unimplemented.
    """
    return ProviderDescriptor(
        provider_id=URLSCAN_PROVIDER_ID,
        display_name="urlscan.io",
        adapter_version=URLSCAN_ADAPTER_VERSION,
        api_version=URLSCAN_API_VERSION,
        source_family=URLSCAN_SOURCE_FAMILY,
        credential_group=URLSCAN_CREDENTIAL_GROUP,
        supported_object_types=URLSCAN_SUPPORTED_OBJECT_TYPES,
        capabilities=URLSCAN_CAPABILITIES,
        supports_passive=True,
        supports_active=False,
        supports_batch=False,
        requires_credentials=True,
    )


#: How the planner may use this provider (Task 13).
#:
#: ``MEDIUM`` for ordinary reads, and ``WEB_FORENSICS`` elevated to the
#: high-cost budget: retrieving and statically analysing stored screenshots, DOM
#: snapshots and response bodies is a different order of work from reading a
#: scan summary, and one per-provider cost class cannot say so.
#:
#: That elevation is also what keeps forensics out of a QUICK run, since QUICK
#: allows no high-cost runs at all.
def build_urlscan_planning_profile() -> ProviderPlanningProfile:
    """The Task 13 planning profile for this provider."""
    return ProviderPlanningProfile(
        provider_id=URLSCAN_PROVIDER_ID,
        source_family=URLSCAN_SOURCE_FAMILY,
        locality=ProviderLocality.REMOTE,
        cost_class=CallCostClass.MEDIUM,
        planning_capabilities=URLSCAN_CAPABILITIES,
        elevated_cost_capabilities=frozenset({ProviderCapability.WEB_FORENSICS}),
        minimum_depth=InvestigationDepth.QUICK,
        priority=40,
        # The response is shaped by the request: retrieving and statically analysing
        # stored page artifacts happens only when WEB_FORENSICS was asked for.
        capability_invariant_response=False,
    )
