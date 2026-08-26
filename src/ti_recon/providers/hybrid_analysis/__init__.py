"""Hybrid Analysis / Falcon Sandbox provider (Task 12).

TI Recon's first **dynamic-analysis** source, and the first provider to answer a
question about what a sample *did* rather than what anyone thinks of it:

    What happened when this sample was previously analysed in a sandbox, in which
    environment, and how informative was that run?

Passive only. It searches for detonations that already happened; it never starts
one. There is no submission path and no download path to disable — the client
cannot express either.

Why active submission is deferred
---------------------------------

The public service is a community platform, and its own terms allow submitted
content to be retained, used and redistributed, with screenshots and metadata
able to expose it. Uploading a customer's file to that is a decision a human
makes with a warning in front of them, not a side effect of enrichment. A future
active path needs explicit approval, a privacy notice, an entitlement check and
environment selection — so none of it is implemented, and nothing is stubbed
"for later".

What it will not conclude
-------------------------

**A sandbox that saw nothing did not see safety.** No verdict maps to
``SUPPORTS_BENIGN``: ``malicious`` and ``suspicious`` point at malicious, and
``no specific threat``, ``no verdict`` and ``whitelisted`` are context. A sample
may sit still because the OS was wrong, it wanted a click, its C2 was down, it
was geofenced, or it noticed it was being watched — so the useful output in that
case is the *quality* record, which says whether anything ran at all.

**Several reports are not several sources.** A hash detonated on Windows 7, 10
and 11 has three observations from one sandbox of one sample. They become one
sample-level finding sharing one lineage group, because a fusion layer that
counted them separately would let a well-studied file outvote genuinely
independent intelligence by having been run more often.

**Disagreement is preserved, not resolved.** Malicious on Windows 11 and nothing
on Windows 7 is environment-dependent malware describing itself, and
``divergent_verdicts`` keeps it legible.

Cost
----

One hash search plus at most two report summaries: 1, 2 or 3 physical requests at
QUICK, STANDARD and DEEP. A restricted key allows roughly five requests a minute
and two hundred an hour, so which reports are read — strongest completed verdict,
then a contrasting one — is a deliberate policy rather than an accident of
iteration order.
"""

from ti_recon.providers.hybrid_analysis.adapter import (
    HYBRID_ANALYSIS_NOT_SUPPORTED,
    UNSUPPORTED_REASONS,
    HybridAnalysisAdapter,
    HybridAnalysisClientFactory,
)
from ti_recon.providers.hybrid_analysis.client import (
    ALLOWED_PATHS,
    HASH_LENGTHS,
    ContainerReport,
    HybridAnalysisClient,
    HybridAnalysisHttpClient,
    HybridAnalysisOperation,
    HybridAnalysisResponse,
)
from ti_recon.providers.hybrid_analysis.config import (
    HYBRID_ANALYSIS_AUTH_HEADER,
    HYBRID_ANALYSIS_HOST,
    HYBRID_ANALYSIS_USER_AGENT,
    HybridAnalysisConfig,
)
from ti_recon.providers.hybrid_analysis.descriptor import (
    HYBRID_ANALYSIS_ADAPTER_VERSION,
    HYBRID_ANALYSIS_API_VERSION,
    HYBRID_ANALYSIS_CAPABILITIES,
    HYBRID_ANALYSIS_ORIGIN_PROVIDER,
    HYBRID_ANALYSIS_PROVIDER_ID,
    HYBRID_ANALYSIS_SOURCE_FAMILY,
    HYBRID_ANALYSIS_SUPPORTED_OBJECT_TYPES,
    build_hybrid_analysis_descriptor,
    lineage_group_for_sample,
)
from ti_recon.providers.hybrid_analysis.errors import (
    CONTAINER_REPORT_STATUS,
    HYBRID_ANALYSIS_STATUS_CATEGORIES,
    QUOTA_MESSAGE_PATTERNS,
    category_for_status,
    credential_validation_for,
)
from ti_recon.providers.hybrid_analysis.models import (
    EXCLUDED_DETONATION_FIELDS,
    SAFE_DETONATION_FIELDS,
    VERDICT_BY_PROVIDER_WORD,
    read_key_info,
    read_report_summary,
    read_search_result,
)
from ti_recon.providers.hybrid_analysis.normalizer import (
    ASSESSMENT_CLAIM_TYPE,
    BEHAVIOUR_CLAIM_TYPE,
    COVERAGE_CLAIM_TYPE,
    NO_REPORT_CLAIM_TYPE,
    NormalizationContext,
    ObjectRegistry,
    normalize_behaviour,
    normalize_coverage,
    normalize_no_report,
    normalize_sample_assessment,
)
from ti_recon.providers.hybrid_analysis.policy import (
    HYBRID_ANALYSIS_MAX_CONCURRENCY,
    HYBRID_ANALYSIS_NO_DATA_TTL_SECONDS,
    HYBRID_ANALYSIS_SUCCESS_TTL_SECONDS,
    MAX_REQUESTS_PER_LOOKUP,
    HybridAnalysisLookupPolicy,
    build_hybrid_analysis_execution_policy,
)

__all__ = [
    "ALLOWED_PATHS",
    "ASSESSMENT_CLAIM_TYPE",
    "BEHAVIOUR_CLAIM_TYPE",
    "CONTAINER_REPORT_STATUS",
    "COVERAGE_CLAIM_TYPE",
    "EXCLUDED_DETONATION_FIELDS",
    "HASH_LENGTHS",
    "HYBRID_ANALYSIS_ADAPTER_VERSION",
    "HYBRID_ANALYSIS_API_VERSION",
    "HYBRID_ANALYSIS_AUTH_HEADER",
    "HYBRID_ANALYSIS_CAPABILITIES",
    "HYBRID_ANALYSIS_HOST",
    "HYBRID_ANALYSIS_MAX_CONCURRENCY",
    "HYBRID_ANALYSIS_NOT_SUPPORTED",
    "HYBRID_ANALYSIS_NO_DATA_TTL_SECONDS",
    "HYBRID_ANALYSIS_ORIGIN_PROVIDER",
    "HYBRID_ANALYSIS_PROVIDER_ID",
    "HYBRID_ANALYSIS_SOURCE_FAMILY",
    "HYBRID_ANALYSIS_STATUS_CATEGORIES",
    "HYBRID_ANALYSIS_SUCCESS_TTL_SECONDS",
    "HYBRID_ANALYSIS_SUPPORTED_OBJECT_TYPES",
    "HYBRID_ANALYSIS_USER_AGENT",
    "MAX_REQUESTS_PER_LOOKUP",
    "NO_REPORT_CLAIM_TYPE",
    "QUOTA_MESSAGE_PATTERNS",
    "SAFE_DETONATION_FIELDS",
    "UNSUPPORTED_REASONS",
    "VERDICT_BY_PROVIDER_WORD",
    "ContainerReport",
    "HybridAnalysisAdapter",
    "HybridAnalysisClient",
    "HybridAnalysisClientFactory",
    "HybridAnalysisConfig",
    "HybridAnalysisHttpClient",
    "HybridAnalysisLookupPolicy",
    "HybridAnalysisOperation",
    "HybridAnalysisResponse",
    "NormalizationContext",
    "ObjectRegistry",
    "build_hybrid_analysis_descriptor",
    "build_hybrid_analysis_execution_policy",
    "category_for_status",
    "credential_validation_for",
    "lineage_group_for_sample",
    "normalize_behaviour",
    "normalize_coverage",
    "normalize_no_report",
    "normalize_sample_assessment",
    "read_key_info",
    "read_report_summary",
    "read_search_result",
]
