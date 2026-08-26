"""The MISP Warning Lists provider descriptor (Task 11).

Three declarations do the interesting work here.

``requires_credentials = False``. There is no key, so there is nothing to
resolve, validate, cool down or leak. Task 6 already supports this generically —
it skips the credential gate, never touches the secret store, and permits a
shared cache scope only for providers in exactly this position — so no execution
change was needed to add a local provider.

``FALSE_POSITIVE_CONTEXT`` and nothing else. The capability already existed in
the Task 3 vocabulary, waiting for a provider that answers "why might this look
worse than it is?". Declaring ``REPUTATION`` instead would be a category error
with real consequences: a planner asking for reputation wants an opinion about
whether something is malicious, and this provider does not have one. It would
also make a warninglist hit look substitutable for a GTI or ThreatFox verdict.

``dataset_version`` carries the snapshot and profile fingerprint. It is a generic
descriptor field, used by the Task 6 cache key exactly as ``api_version`` and
``adapter_version`` are, so a refreshed dataset cannot serve answers computed
from the old one — with no provider-specific branch anywhere in the executor.
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
    "MISP_WARNINGLISTS_ADAPTER_VERSION",
    "MISP_WARNINGLISTS_CAPABILITIES",
    "MISP_WARNINGLISTS_DATASET_VERSION",
    "MISP_WARNINGLISTS_ORIGIN_PROVIDER",
    "MISP_WARNINGLISTS_PROVIDER_ID",
    "MISP_WARNINGLISTS_SOURCE_FAMILY",
    "MISP_WARNINGLISTS_SUPPORTED_OBJECT_TYPES",
    "build_misp_warninglists_descriptor",
    "build_misp_warninglists_planning_profile",
    "lineage_group_for_dataset",
]

MISP_WARNINGLISTS_PROVIDER_ID: Final[str] = "misp_warninglists"

#: Origin equals transport: the dataset is curated by the MISP community and read
#: directly, with nobody relaying it. What the lists *contain* is often somebody
#: else's data — a cloud provider's published ranges, a popularity ranking — but
#: the curation is MISP's, and that is what an origin names.
MISP_WARNINGLISTS_ORIGIN_PROVIDER: Final[str] = MISP_WARNINGLISTS_PROVIDER_ID

#: One family for the whole MISP ecosystem, so a future MISP-instance integration
#: cannot read as an independent second source.
MISP_WARNINGLISTS_SOURCE_FAMILY: Final[str] = "misp"

MISP_WARNINGLISTS_ADAPTER_VERSION: Final[str] = "0.1.0"

#: Not an API version — there is no API. It identifies the *dataset contract*:
#: the upstream schema this package models. A snapshot's own fingerprint is far
#: more specific and travels in ``dataset_version``.
MISP_WARNINGLISTS_DATASET_VERSION: Final[str] = "misp-warninglists-schema-1"

#: Everything TI Recon can build MISP candidates for.
MISP_WARNINGLISTS_SUPPORTED_OBJECT_TYPES: Final[frozenset[IntelObjectType]] = frozenset(
    {
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.IPV6_ADDR,
        IntelObjectType.DOMAIN_NAME,
        IntelObjectType.URL,
        IntelObjectType.FILE,
    }
)

#: One capability. See the module docstring for why it is not ``REPUTATION``.
MISP_WARNINGLISTS_CAPABILITIES: Final[frozenset[ProviderCapability]] = frozenset(
    {ProviderCapability.FALSE_POSITIVE_CONTEXT}
)


def lineage_group_for_dataset(dataset_fingerprint: str) -> str:
    """The lineage group every warninglist finding shares.

    One group for the whole dataset, on purpose. ``public-dns-v4``,
    ``censys-scanning``, ``rfc1918`` and ``cloudflare`` are not four providers
    agreeing — they are four records from one curated source, and a fusion layer
    that counted them separately would let a single dataset outvote genuinely
    independent intelligence.

    The snapshot fingerprint is part of the group so context from two different
    dataset versions is distinguishable rather than silently merged.
    """
    return f"{MISP_WARNINGLISTS_SOURCE_FAMILY}:warninglists:{dataset_fingerprint[:16]}"


def build_misp_warninglists_descriptor(dataset_version: str | None = None) -> ProviderDescriptor:
    """The static declaration registered with the provider registry.

    ``dataset_version`` should be the active snapshot-and-profile identity. It is
    passed in rather than read here because a descriptor must stay a pure value:
    the adapter knows which snapshot it loaded, this function does not.
    """
    return ProviderDescriptor(
        provider_id=MISP_WARNINGLISTS_PROVIDER_ID,
        display_name="MISP Warning Lists",
        adapter_version=MISP_WARNINGLISTS_ADAPTER_VERSION,
        api_version=MISP_WARNINGLISTS_DATASET_VERSION,
        source_family=MISP_WARNINGLISTS_SOURCE_FAMILY,
        supported_object_types=MISP_WARNINGLISTS_SUPPORTED_OBJECT_TYPES,
        capabilities=MISP_WARNINGLISTS_CAPABILITIES,
        supports_passive=True,
        supports_active=False,
        supports_batch=False,
        # No key, no connection, no secret store access. See the module docstring.
        requires_credentials=False,
        dataset_version=dataset_version,
    )


#: How the planner may use this provider (Task 13).
#:
#: Local and free, so it is ranked ahead of every remote provider: collecting
#: cheap context first cannot delay anything, and it may explain whatever the
#: remote providers go on to report.
#:
#: ``LOCAL`` is declared here rather than inferred from ``requires_credentials``,
#: which happens to be ``False`` for this provider and would be the wrong test
#: for the next one — a credential-free HTTP provider still discloses the
#: observable.
#:
#: ``FALSE_POSITIVE_CONTEXT`` and nothing else. It must never look like a
#: substitute for reputation: a warninglist match explains evidence, it does not
#: replace the need for any.
def build_misp_warninglists_planning_profile() -> ProviderPlanningProfile:
    """The Task 13 planning profile for this provider."""
    return ProviderPlanningProfile(
        provider_id=MISP_WARNINGLISTS_PROVIDER_ID,
        source_family=MISP_WARNINGLISTS_SOURCE_FAMILY,
        locality=ProviderLocality.LOCAL,
        cost_class=CallCostClass.ZERO,
        planning_capabilities=MISP_WARNINGLISTS_CAPABILITIES,
        minimum_depth=InvestigationDepth.QUICK,
        priority=90,
    )
