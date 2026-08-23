"""GreyNoise provider (Task 9).

TI Recon's source of **internet-scanning context**. GreyNoise runs a sensor
network that records who is spraying the internet, and answers one question
nobody else answers as well: is this address background noise, and if so, whose?

What that buys an investigation:

* **Scanner classification** — GreyNoise's own assessment of an address that
  scans, with the raw word preserved so ``suspicious`` is never rendered as
  ``malicious``.
* **Business Services Intelligence** — the inventory of common business services
  (a public resolver, a mail relay, a CDN edge). Always context: it is triage
  material, not an allow-list, and the classification already carries
  GreyNoise's opinion.
* **Tags, CVE associations and sensor detail** — what the traffic looked like.
  Observations, aggregated and bounded, pointing nowhere on their own.

Two access levels, resolved per credential. The full v3 IP context needs an
entitled subscription; the Community endpoint does not. An ``AUTO`` lookup finds
out which one a key has — once — and remembers it. A rejected key is never
mistaken for a free-tier one.

Passive throughout, and IPv4 only. Nothing here runs a GNQL query, walks a
timeline, downloads a feed, retrieves a PCAP or submits anything — GreyNoise
offers all of those, and this integration deliberately cannot. Every other
observable type is reported as ``NOT_SUPPORTED``, never as an empty answer.
"""

from ti_recon.providers.greynoise.access import (
    DEFAULT_ACCESS_TTL_SECONDS,
    AccessLevelStore,
    GreyNoiseAccessLevel,
    GreyNoiseAccessMode,
    InMemoryAccessLevelStore,
)
from ti_recon.providers.greynoise.adapter import (
    CREDENTIAL_PROBE_ADDRESS,
    GREYNOISE_COMMUNITY_ACCESS_ONLY,
    GREYNOISE_DOCUMENT_UNREADABLE,
    GREYNOISE_NOT_SUPPORTED,
    GREYNOISE_PARTIAL_CONTEXT,
    GreyNoiseAdapter,
    GreyNoiseClientFactory,
)
from ti_recon.providers.greynoise.client import (
    GreyNoiseClient,
    GreyNoiseHttpClient,
    GreyNoiseJsonResult,
    GreyNoiseOperation,
)
from ti_recon.providers.greynoise.config import (
    GREYNOISE_API_KEY_HEADER,
    GREYNOISE_AUTH_TYPE,
    GREYNOISE_HOST,
    GreyNoiseConfig,
    build_transport_config,
)
from ti_recon.providers.greynoise.descriptor import (
    GREYNOISE_ADAPTER_VERSION,
    GREYNOISE_API_VERSION,
    GREYNOISE_CAPABILITIES,
    GREYNOISE_CREDENTIAL_GROUP,
    GREYNOISE_ORIGIN_PROVIDER,
    GREYNOISE_PROVIDER_ID,
    GREYNOISE_SOURCE_FAMILY,
    GREYNOISE_SUPPORTED_OBJECT_TYPES,
    build_greynoise_descriptor,
)
from ti_recon.providers.greynoise.errors import (
    CREDENTIAL_STATUS_BY_CATEGORY,
    GREYNOISE_STATUS_CATEGORIES,
    QUOTA_RETRY_AFTER_THRESHOLD_SECONDS,
    category_for_status,
    credential_status_for,
    credential_validation_for,
    parse_retry_after,
    parse_utc_timestamp,
    scrub_detail,
    translate_status_error,
)
from ti_recon.providers.greynoise.metering import parse_rate_limit_headers
from ti_recon.providers.greynoise.normalizer import (
    CLASSIFICATION_EFFECTS,
    GREYNOISE_LINEAGE_GROUP,
    GREYNOISE_NOT_OBSERVED,
    GREYNOISE_PROPERTY_NAMESPACE,
    MAX_CVES,
    MAX_FINGERPRINTS,
    MAX_PATHS,
    MAX_PORTS,
    MAX_TAGS,
    SCANNER_METADATA_FIELDS,
    TRUST_LEVEL_MEANINGS,
    GreyNoiseDocument,
    GreyNoiseNormalization,
    NormalizationContext,
    enrich_primary_object,
    normalize_business_service,
    normalize_classification,
    normalize_cve_activity,
    normalize_network_context,
    normalize_not_observed,
    normalize_scanner_observation,
    normalize_tags,
)
from ti_recon.providers.greynoise.policy import (
    DEPTH_DETAIL,
    GreyNoiseDetail,
    GreyNoiseLookupPolicy,
    build_greynoise_execution_policy,
    detail_for_depth,
)

__all__ = [
    "CLASSIFICATION_EFFECTS",
    "CREDENTIAL_PROBE_ADDRESS",
    "CREDENTIAL_STATUS_BY_CATEGORY",
    "DEFAULT_ACCESS_TTL_SECONDS",
    "DEPTH_DETAIL",
    "GREYNOISE_ADAPTER_VERSION",
    "GREYNOISE_API_KEY_HEADER",
    "GREYNOISE_API_VERSION",
    "GREYNOISE_AUTH_TYPE",
    "GREYNOISE_CAPABILITIES",
    "GREYNOISE_COMMUNITY_ACCESS_ONLY",
    "GREYNOISE_CREDENTIAL_GROUP",
    "GREYNOISE_DOCUMENT_UNREADABLE",
    "GREYNOISE_HOST",
    "GREYNOISE_LINEAGE_GROUP",
    "GREYNOISE_NOT_OBSERVED",
    "GREYNOISE_NOT_SUPPORTED",
    "GREYNOISE_ORIGIN_PROVIDER",
    "GREYNOISE_PARTIAL_CONTEXT",
    "GREYNOISE_PROPERTY_NAMESPACE",
    "GREYNOISE_PROVIDER_ID",
    "GREYNOISE_SOURCE_FAMILY",
    "GREYNOISE_STATUS_CATEGORIES",
    "GREYNOISE_SUPPORTED_OBJECT_TYPES",
    "MAX_CVES",
    "MAX_FINGERPRINTS",
    "MAX_PATHS",
    "MAX_PORTS",
    "MAX_TAGS",
    "QUOTA_RETRY_AFTER_THRESHOLD_SECONDS",
    "SCANNER_METADATA_FIELDS",
    "TRUST_LEVEL_MEANINGS",
    "AccessLevelStore",
    "GreyNoiseAccessLevel",
    "GreyNoiseAccessMode",
    "GreyNoiseAdapter",
    "GreyNoiseClient",
    "GreyNoiseClientFactory",
    "GreyNoiseConfig",
    "GreyNoiseDetail",
    "GreyNoiseDocument",
    "GreyNoiseHttpClient",
    "GreyNoiseJsonResult",
    "GreyNoiseLookupPolicy",
    "GreyNoiseNormalization",
    "GreyNoiseOperation",
    "InMemoryAccessLevelStore",
    "NormalizationContext",
    "build_greynoise_descriptor",
    "build_greynoise_execution_policy",
    "build_transport_config",
    "category_for_status",
    "credential_status_for",
    "credential_validation_for",
    "detail_for_depth",
    "enrich_primary_object",
    "normalize_business_service",
    "normalize_classification",
    "normalize_cve_activity",
    "normalize_network_context",
    "normalize_not_observed",
    "normalize_scanner_observation",
    "normalize_tags",
    "parse_rate_limit_headers",
    "parse_retry_after",
    "parse_utc_timestamp",
    "scrub_detail",
    "translate_status_error",
]
