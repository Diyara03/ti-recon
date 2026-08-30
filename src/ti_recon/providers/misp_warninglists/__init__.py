"""MISP Warning Lists provider (Task 11).

TI Recon's source of **local false-positive and infrastructure context**. It
answers a question none of the remote providers do:

    *Does this observable have characteristics — shared hosting, a public
    resolver, a special-use range, a scanner, a popular domain, a known-good
    hash, a test artifact — that should change how I read the other evidence?*

It is emphatically **not** a reputation source. Every finding it produces is
``EvidenceClass.CONTEXT`` with ``EvidenceEffect.CONTEXT_ONLY``, and a clean
lookup means "nothing in the configured lists matched" and nothing else. A cloud
range hosts attacks, a CDN serves malware, a popular domain has a malicious path
on it right now, and a warninglist can be stale. Deciding what a malicious
ThreatFox record plus an Azure-range hit adds up to is false-positive reasoning
and belongs to the future fusion layer.

What makes it unusual
---------------------

**No server, no key, no network.** No MISP instance, no API token, no PyMISP, no
HTTP, no DNS, no Redis, no daemon. A lookup reads an in-memory index compiled
from a pinned local snapshot at construction time. That is what keeps the
capability available during offline triage, and it is enforced structurally: this
package contains no client and no transport.

**The dataset is pinned and its provenance is recorded.**
``ti_recon/data/misp_warninglists``
carries the upstream commit, a schema fingerprint, a dataset fingerprint, per-list
checksums and every list the build omitted. Refreshing it is an operator running
``tools/update_misp_warninglists.py`` against a local checkout — never something
a lookup can trigger.

**``matching_attributes`` is authoritative.** An observable is turned into the
MISP attribute values it legitimately *is*, and a list is offered only the
candidates whose attribute type it declares. A hostname list is never asked about
an MD5.

**A URL's host is not the URL.** ``https://github.com/attacker/payload.exe``
matching a popular-domain list is a fact about ``github.com``, reported at
``SAME_HOST`` scope and flagged ``host_component_only``. Losing that distinction
is how a living-off-trusted-sites payload gets waved through.

Measured, not assumed
---------------------

The pinned upstream snapshot holds 143 lists and 5,214,898 entries; twenty lists
hold 4,910,632 of them, and the popularity rankings among those are nested
subsets of each other. Loading everything costs ~510 MB of retained heap to learn
one fact sixteen times. The default ``core`` profile bounds that to 123 lists and
304,266 entries for ~34 MB, and every exclusion is recorded so no result can
imply it checked lists it never had.
"""

from ti_recon.providers.misp_warninglists.adapter import (
    MISP_WARNINGLISTS_NOT_SUPPORTED,
    SNAPSHOT_UNAVAILABLE,
    UNSUPPORTED_REASONS,
    MispWarningListsAdapter,
)
from ti_recon.providers.misp_warninglists.candidates import (
    HASH_ATTRIBUTE_BY_ALGORITHM,
    SUPPORTED_OBJECT_TYPES,
    CandidateComponent,
    WarningListCandidate,
    build_candidates,
    candidate_attribute_types,
)
from ti_recon.providers.misp_warninglists.config import (
    DEFAULT_SNAPSHOT_ROOT,
    DEFAULT_STALE_AFTER_DAYS,
    MispWarningListsConfig,
)
from ti_recon.providers.misp_warninglists.descriptor import (
    MISP_WARNINGLISTS_ADAPTER_VERSION,
    MISP_WARNINGLISTS_CAPABILITIES,
    MISP_WARNINGLISTS_DATASET_VERSION,
    MISP_WARNINGLISTS_ORIGIN_PROVIDER,
    MISP_WARNINGLISTS_PROVIDER_ID,
    MISP_WARNINGLISTS_SOURCE_FAMILY,
    MISP_WARNINGLISTS_SUPPORTED_OBJECT_TYPES,
    build_misp_warninglists_descriptor,
    build_misp_warninglists_planning_profile,
    lineage_group_for_dataset,
)
from ti_recon.providers.misp_warninglists.loader import (
    UnusableList,
    WarningListIndex,
    build_index,
)
from ti_recon.providers.misp_warninglists.matchers import (
    MATCHER_SUPPORT,
    CidrList,
    CompiledList,
    HostnameList,
    ListMatch,
    RegexList,
    StringList,
    SubstringList,
    compile_list,
)
from ti_recon.providers.misp_warninglists.models import (
    ALL_ATTRIBUTES,
    RAW_MATCHER_TYPES,
    ListOmissionReason,
    LoadDiagnostics,
    RawWarningList,
    SnapshotListRecord,
    SnapshotManifest,
)
from ti_recon.providers.misp_warninglists.normalizer import (
    COVERAGE_CLAIM_TYPE,
    MATCHES_CLAIM_TYPE,
    NO_MATCH_CLAIM_TYPE,
    NormalizationContext,
    normalize_coverage,
    normalize_matches,
    normalize_no_match,
)
from ti_recon.providers.misp_warninglists.policy import (
    DEPTH_MATCH_LIMITS,
    MISP_WARNINGLISTS_MAX_CONCURRENCY,
    MispWarningListsLookupPolicy,
    build_misp_warninglists_execution_policy,
)
from ti_recon.providers.misp_warninglists.profile import (
    CORE_PROFILE_ID,
    DEFAULT_MAX_LIST_ENTRIES,
    FULL_PROFILE_ID,
    REDUNDANT_POPULARITY_TIERS,
    RETAINED_POPULARITY_TIERS,
    ProfileSelection,
    WarningListProfile,
    core_profile,
    full_profile,
)
from ti_recon.providers.misp_warninglists.snapshot import (
    LISTS_DIRNAME,
    MANIFEST_FILENAME,
    SnapshotError,
    WarningListSnapshot,
    load_snapshot,
    slug_is_safe,
)

__all__ = [
    "ALL_ATTRIBUTES",
    "CORE_PROFILE_ID",
    "COVERAGE_CLAIM_TYPE",
    "DEFAULT_MAX_LIST_ENTRIES",
    "DEFAULT_SNAPSHOT_ROOT",
    "DEFAULT_STALE_AFTER_DAYS",
    "DEPTH_MATCH_LIMITS",
    "FULL_PROFILE_ID",
    "HASH_ATTRIBUTE_BY_ALGORITHM",
    "LISTS_DIRNAME",
    "MANIFEST_FILENAME",
    "MATCHER_SUPPORT",
    "MATCHES_CLAIM_TYPE",
    "MISP_WARNINGLISTS_ADAPTER_VERSION",
    "MISP_WARNINGLISTS_CAPABILITIES",
    "MISP_WARNINGLISTS_DATASET_VERSION",
    "MISP_WARNINGLISTS_MAX_CONCURRENCY",
    "MISP_WARNINGLISTS_NOT_SUPPORTED",
    "MISP_WARNINGLISTS_ORIGIN_PROVIDER",
    "MISP_WARNINGLISTS_PROVIDER_ID",
    "MISP_WARNINGLISTS_SOURCE_FAMILY",
    "MISP_WARNINGLISTS_SUPPORTED_OBJECT_TYPES",
    "NO_MATCH_CLAIM_TYPE",
    "RAW_MATCHER_TYPES",
    "REDUNDANT_POPULARITY_TIERS",
    "RETAINED_POPULARITY_TIERS",
    "SNAPSHOT_UNAVAILABLE",
    "SUPPORTED_OBJECT_TYPES",
    "UNSUPPORTED_REASONS",
    "CandidateComponent",
    "CidrList",
    "CompiledList",
    "HostnameList",
    "ListMatch",
    "ListOmissionReason",
    "LoadDiagnostics",
    "MispWarningListsAdapter",
    "MispWarningListsConfig",
    "MispWarningListsLookupPolicy",
    "NormalizationContext",
    "ProfileSelection",
    "RawWarningList",
    "RegexList",
    "SnapshotError",
    "SnapshotListRecord",
    "SnapshotManifest",
    "StringList",
    "SubstringList",
    "UnusableList",
    "WarningListCandidate",
    "WarningListIndex",
    "WarningListProfile",
    "WarningListSnapshot",
    "build_candidates",
    "build_index",
    "build_misp_warninglists_descriptor",
    "build_misp_warninglists_execution_policy",
    "build_misp_warninglists_planning_profile",
    "candidate_attribute_types",
    "compile_list",
    "core_profile",
    "full_profile",
    "lineage_group_for_dataset",
    "load_snapshot",
    "normalize_coverage",
    "normalize_matches",
    "normalize_no_match",
    "slug_is_safe",
]
