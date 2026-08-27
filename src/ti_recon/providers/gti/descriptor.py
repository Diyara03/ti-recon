"""The GTI provider descriptor (Task 7).

Kept in its own module so the identity of the provider — its id, credential
group, supported object types and declared capabilities — can be read, imported
and registered without pulling in the adapter, the client or vt-py.

Naming choices worth stating:

* ``provider_id = "gti"`` is what appears as ``transport_provider`` on every
  piece of evidence: whose API we actually called.
* ``source_family = "google_ti"`` groups every signal that ultimately comes out
  of Google Threat Intelligence, including the Mandiant-curated components
  inside a GTI assessment. Those are *parts of one source*, and giving them
  their own family would let internal GTI signals masquerade as independent
  corroboration.
* ``credential_group = "virustotal"`` because the credential an analyst supplies
  *is* their VirusTotal API key. Naming the group after the key rather than the
  product means a future VirusTotal-branded integration reuses the same stored
  secret instead of asking for it twice.
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
    "GTI_ADAPTER_VERSION",
    "GTI_API_VERSION",
    "GTI_CAPABILITIES",
    "GTI_CREDENTIAL_GROUP",
    "GTI_ORIGIN_PROVIDER",
    "GTI_PROVIDER_ID",
    "GTI_SOURCE_FAMILY",
    "GTI_SUPPORTED_OBJECT_TYPES",
    "build_gti_descriptor",
    "build_gti_planning_profile",
]

GTI_PROVIDER_ID: Final[str] = "gti"

#: Who produced the intelligence, as opposed to whose API carried it.
#:
#: Equal to :data:`GTI_PROVIDER_ID` on purpose. GTI both produces and serves its
#: assessments, so ``Evidence.is_relayed`` — which is ``transport != origin`` —
#: must be false for them. Giving the origin a different spelling of the same
#: source would mark GTI's own judgement as second-hand and let a future fusion
#: layer discount it as relayed corroboration, which is the opposite of the
#: truth.
#:
#: It is still a separate constant because the two fields are genuinely
#: different, and a sibling adapter reading the same API under a different
#: provider id (a VirusTotal-branded integration, say) would set transport to
#: itself and origin to this — correctly marking that evidence as relayed.
GTI_ORIGIN_PROVIDER: Final[str] = GTI_PROVIDER_ID

GTI_SOURCE_FAMILY: Final[str] = "google_ti"
GTI_CREDENTIAL_GROUP: Final[str] = "virustotal"
GTI_API_VERSION: Final[str] = "v3"
GTI_ADAPTER_VERSION: Final[str] = "0.1.0"

#: Every observable type an analyst may submit. File hashes (MD5/SHA-1/SHA-256)
#: all resolve to the ``file`` object type, as the Task 3 model requires.
GTI_SUPPORTED_OBJECT_TYPES: Final[frozenset[IntelObjectType]] = frozenset(
    {
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.IPV6_ADDR,
        IntelObjectType.DOMAIN_NAME,
        IntelObjectType.URL,
        IntelObjectType.FILE,
    }
)

#: What the *integration* can technically do. Not a claim about any particular
#: account: whether a given key is entitled to a given relationship is only
#: knowable at request time, and is reported per operation rather than guessed
#: at up front.
GTI_CAPABILITIES: Final[frozenset[ProviderCapability]] = frozenset(
    {
        ProviderCapability.REPUTATION,
        ProviderCapability.MALWARE_INTELLIGENCE,
        ProviderCapability.THREAT_ASSOCIATIONS,
        ProviderCapability.RELATIONSHIPS,
        ProviderCapability.CURRENT_INFRASTRUCTURE,
        ProviderCapability.HISTORICAL_INFRASTRUCTURE,
        ProviderCapability.NETWORK_OWNERSHIP,
        ProviderCapability.FILE_BEHAVIOR,
    }
)


def build_gti_descriptor() -> ProviderDescriptor:
    """The static declaration registered with the provider registry.

    ``supports_active`` is ``False`` and stays that way: Task 7 is passive
    enrichment. Submission, rescanning and sandbox detonation are separate
    operations behind an explicit consent path that nothing here implements.
    """
    return ProviderDescriptor(
        provider_id=GTI_PROVIDER_ID,
        display_name="Google Threat Intelligence",
        adapter_version=GTI_ADAPTER_VERSION,
        api_version=GTI_API_VERSION,
        source_family=GTI_SOURCE_FAMILY,
        credential_group=GTI_CREDENTIAL_GROUP,
        supported_object_types=GTI_SUPPORTED_OBJECT_TYPES,
        capabilities=GTI_CAPABILITIES,
        supports_passive=True,
        supports_active=False,
        supports_batch=False,
        requires_credentials=True,
    )


#: How the planner may use this provider (Task 13).
#:
#: ``MEDIUM`` because the allowance is metered per lookup and shared across an
#: analyst's whole use of the key. Highest remote priority for broad reputation:
#: it covers every observable type and is usually the most informative single
#: remote question for triage — a tie-break among equals, not a quality score.
#:
#: ``FILE_BEHAVIOR`` is elevated to the high-cost budget. The descriptor does
#: declare it, so GTI is a genuine second source family for sandbox behaviour —
#: which matters, because it means behaviour coverage does not depend on one
#: provider being configured. But asking for it pulls a deep file report, so it
#: is priced accordingly rather than treated as another cheap read.
def build_gti_planning_profile() -> ProviderPlanningProfile:
    """The Task 13 planning profile for this provider."""
    return ProviderPlanningProfile(
        provider_id=GTI_PROVIDER_ID,
        source_family=GTI_SOURCE_FAMILY,
        locality=ProviderLocality.REMOTE,
        cost_class=CallCostClass.MEDIUM,
        planning_capabilities=GTI_CAPABILITIES,
        elevated_cost_capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
        minimum_depth=InvestigationDepth.QUICK,
        priority=70,
        # The response is shaped by the request: `relationship_plan` is filtered by
        # exactly the capabilities asked for, and the behaviour summary is fetched
        # only when FILE_BEHAVIOR is among them. So a capability nobody asked for
        # was not answered, and a later call for it is real incremental work.
        capability_invariant_response=False,
    )
