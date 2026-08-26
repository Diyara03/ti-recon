"""The Hybrid Analysis provider descriptor (Task 12).

``FILE_BEHAVIOR`` and nothing else. The capability already existed in the Task 3
vocabulary, documented as "sandbox/dynamic-analysis observations of what a file
did when run", and Task 10 deliberately declined it for MalwareBazaar on the
grounds that relaying somebody else's sandbox output is not observing behaviour.
Hybrid Analysis is the direct sandbox integration it was reserved for.

Declaring ``REPUTATION`` instead would tell the planner a sandbox is
interchangeable with GTI, which is wrong in both directions: GTI cannot say what
a sample did when executed, and a sandbox cannot say what the industry thinks of
it. It would also make a sandbox non-detection look substitutable for a
reputation verdict, which is the exact confusion this provider must not create.

Files only. Hybrid Analysis has host, domain and URL search, and those are
database *hunting* semantics rather than per-observable enrichment — a future
query planner's business, and urlscan already covers web intelligence.

``supports_active`` is ``False`` and stays that way. The API can submit and
detonate; this integration searches for runs that already happened. Active
sandboxing needs explicit analyst approval, a privacy warning about a community
platform that may retain and redistribute what it receives, an entitlement check
and environment selection — design work in its own right, and none of it is
implemented or stubbed here.
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
    "HYBRID_ANALYSIS_ADAPTER_VERSION",
    "HYBRID_ANALYSIS_API_VERSION",
    "HYBRID_ANALYSIS_CAPABILITIES",
    "HYBRID_ANALYSIS_ORIGIN_PROVIDER",
    "HYBRID_ANALYSIS_PROVIDER_ID",
    "HYBRID_ANALYSIS_SOURCE_FAMILY",
    "HYBRID_ANALYSIS_SUPPORTED_OBJECT_TYPES",
    "build_hybrid_analysis_descriptor",
    "build_hybrid_analysis_planning_profile",
    "lineage_group_for_sample",
]

HYBRID_ANALYSIS_PROVIDER_ID: Final[str] = "hybrid_analysis"

#: Origin equals transport: Falcon Sandbox ran the sample itself. The AV and
#: machine-learning material a report also carries belongs to other parties and
#: is summarized rather than adopted — see the normalizer.
HYBRID_ANALYSIS_ORIGIN_PROVIDER: Final[str] = HYBRID_ANALYSIS_PROVIDER_ID

#: Deliberately *not* a generic ``"sandbox"`` family. Two independent sandboxes
#: agreeing is genuine corroboration, and a shared family would suppress it —
#: the opposite of the abuse.ch case, where one organization's three datasets
#: must not read as three sources.
HYBRID_ANALYSIS_SOURCE_FAMILY: Final[str] = "hybrid_analysis"

#: The API version this integration was written against.
HYBRID_ANALYSIS_API_VERSION: Final[str] = "v2"
HYBRID_ANALYSIS_ADAPTER_VERSION: Final[str] = "0.1.0"

#: Files only. See the module docstring.
HYBRID_ANALYSIS_SUPPORTED_OBJECT_TYPES: Final[frozenset[IntelObjectType]] = frozenset(
    {IntelObjectType.FILE}
)

HYBRID_ANALYSIS_CAPABILITIES: Final[frozenset[ProviderCapability]] = frozenset(
    {ProviderCapability.FILE_BEHAVIOR}
)


def lineage_group_for_sample(sha256: str | None) -> str:
    """The lineage group every finding about one sample shares.

    Sample-level on purpose. A hash with a Windows 11 run, a Windows 7 run and a
    Windows 10 run has three observations from **one** provider of **one**
    sample, and a fusion layer that counted them separately would let a
    thoroughly-detonated file outvote genuinely independent intelligence by
    having been run more often.

    Keyed by the canonical digest so two different samples stay distinguishable
    within the family.
    """
    identity = (sha256 or "unknown")[:64]
    return f"{HYBRID_ANALYSIS_SOURCE_FAMILY}:sample:{identity}"


def build_hybrid_analysis_descriptor() -> ProviderDescriptor:
    """The static declaration registered with the provider registry."""
    return ProviderDescriptor(
        provider_id=HYBRID_ANALYSIS_PROVIDER_ID,
        display_name="Hybrid Analysis (Falcon Sandbox)",
        adapter_version=HYBRID_ANALYSIS_ADAPTER_VERSION,
        api_version=HYBRID_ANALYSIS_API_VERSION,
        source_family=HYBRID_ANALYSIS_SOURCE_FAMILY,
        supported_object_types=HYBRID_ANALYSIS_SUPPORTED_OBJECT_TYPES,
        capabilities=HYBRID_ANALYSIS_CAPABILITIES,
        supports_passive=True,
        supports_active=False,
        supports_batch=False,
        requires_credentials=True,
    )


#: How the planner may use this provider (Task 13).
#:
#: ``HIGH`` and ``STANDARD``-minimum, for one measured reason: a lookup can
#: spend up to three physical requests against a restricted key documented at
#: roughly five per minute. That is the scarcest allowance of any provider here,
#: so a QUICK triage must not spend it — and QUICK allows no high-cost runs, so
#: it cannot.
#:
#: Its several sandbox reports are one provider contribution and one source
#: family. The planner never sees the report count, and could not treat it as
#: corroboration if it did.
def build_hybrid_analysis_planning_profile() -> ProviderPlanningProfile:
    """The Task 13 planning profile for this provider."""
    return ProviderPlanningProfile(
        provider_id=HYBRID_ANALYSIS_PROVIDER_ID,
        source_family=HYBRID_ANALYSIS_SOURCE_FAMILY,
        locality=ProviderLocality.REMOTE,
        cost_class=CallCostClass.HIGH,
        planning_capabilities=HYBRID_ANALYSIS_CAPABILITIES,
        minimum_depth=InvestigationDepth.STANDARD,
        priority=50,
        # One hash search plus its bounded report reads. Only one capability is
        # declared, so this is a statement about shape rather than a saving.
        capability_invariant_response=True,
    )
