"""Censys provider (Task 9).

TI Recon's source of **internet exposure and infrastructure context**. Censys
scans the internet and records what answered: which ports respond, what software
is visible behind them, which certificate is served, which names point at the
asset.

What that buys an investigation:

* **Exposure** — the responding ports, transports and application protocols, and
  the vendor/product/version Censys could see. Bounded, and never a banner.
* **Ownership** — the autonomous system that announces the address, and roughly
  where it sits.
* **Certificates** — served leaf certificates as ``x509-certificate`` objects,
  which are among the strongest pivots available between two hosts that
  otherwise look unrelated.
* **Names and exposures** — DNS and reverse DNS, Censys labels, and reported
  vulnerabilities.

All of it is context. Censys answers "what is exposed here", not "is this
malicious", and nothing in this package can produce a direction: an open RDP
port is a risk to its owner, an outdated web server is not malware, and a
reported CVE is an inference from a version string rather than a compromise.

One deterministic request per lookup. An observable maps onto exactly one asset
identity — an address, or a ``hostname:port`` derived from a URL — so a lookup
costs one predictable credit. Depth changes how much of that already-paid-for
document is normalized, never how many requests are made.

Deliberately absent: CenQL and the general search endpoint, historical
timelines and ``at_time`` enumeration, collections, live rescan and live
discovery. Censys is also not the web-forensics provider — nothing here
retrieves a response body. A bare domain and a file hash are reported as
``NOT_SUPPORTED``, never as empty answers.
"""

from ti_recon.providers.censys.adapter import (
    CENSYS_DOCUMENT_UNREADABLE,
    CENSYS_NOT_SUPPORTED,
    UNSUPPORTED_REASONS,
    CensysAdapter,
    CensysClientFactory,
)
from ti_recon.providers.censys.assets import (
    DEFAULT_PORT_FOR_SCHEME,
    WEB_PROPERTY_SCHEMES,
    CensysAsset,
    CensysAssetKind,
    asset_for,
    unsupported_reason_for,
)
from ti_recon.providers.censys.client import (
    CensysClient,
    CensysHttpClient,
    CensysJsonResult,
    CensysOperation,
)
from ti_recon.providers.censys.config import (
    CENSYS_AUTH_TYPE,
    CENSYS_HOST,
    CENSYS_HOST_ACCEPT,
    CENSYS_JSON_ACCEPT,
    CENSYS_WEB_PROPERTY_ACCEPT,
    CensysConfig,
    build_transport_config,
)
from ti_recon.providers.censys.credits import (
    CREDIT_BUCKET_NAME,
    CensysCreditReading,
    CensysCreditScope,
    parse_credits,
)
from ti_recon.providers.censys.descriptor import (
    CENSYS_ADAPTER_VERSION,
    CENSYS_API_VERSION,
    CENSYS_CAPABILITIES,
    CENSYS_CREDENTIAL_GROUP,
    CENSYS_ORIGIN_PROVIDER,
    CENSYS_PROVIDER_ID,
    CENSYS_SOURCE_FAMILY,
    CENSYS_SUPPORTED_OBJECT_TYPES,
    build_censys_descriptor,
)
from ti_recon.providers.censys.errors import (
    CENSYS_STATUS_CATEGORIES,
    CREDENTIAL_STATUS_BY_CATEGORY,
    category_for_status,
    credential_status_for,
    credential_validation_for,
    parse_retry_after,
    parse_utc_timestamp,
    scrub_detail,
    translate_status_error,
)
from ti_recon.providers.censys.normalizer import (
    AUTONOMOUS_SYSTEM_FIELDS,
    CENSYS_LINEAGE_GROUP,
    CENSYS_PROPERTY_NAMESPACE,
    LOCATION_FIELDS,
    MAX_CERTIFICATES,
    MAX_DNS_NAMES,
    MAX_ENDPOINTS,
    MAX_LABELS,
    MAX_PORTS,
    MAX_SERVICES,
    MAX_VULNERABILITIES,
    SERVICE_FIELDS,
    CensysDocument,
    CensysNormalization,
    NormalizationContext,
    enrich_host_object,
    enrich_web_property_object,
    normalize_dns_names,
    normalize_host_observation,
    normalize_labels,
    normalize_network_ownership,
    normalize_not_observed,
    normalize_services,
    normalize_tls_certificates,
    normalize_vulnerabilities,
    normalize_web_property_observation,
)
from ti_recon.providers.censys.organizations import (
    ORGANIZATION_ID_PATTERN,
    ORGANIZATION_METADATA_KEY,
    ConnectionOrganizationDirectory,
    OrganizationDirectory,
    StaticOrganizationDirectory,
    normalize_organization_id,
)
from ti_recon.providers.censys.policy import (
    DEFAULT_MAX_CONCURRENCY,
    DEPTH_DETAIL,
    CensysDetail,
    CensysLookupPolicy,
    build_censys_execution_policy,
    detail_for_depth,
)

__all__ = [
    "AUTONOMOUS_SYSTEM_FIELDS",
    "CENSYS_ADAPTER_VERSION",
    "CENSYS_API_VERSION",
    "CENSYS_AUTH_TYPE",
    "CENSYS_CAPABILITIES",
    "CENSYS_CREDENTIAL_GROUP",
    "CENSYS_DOCUMENT_UNREADABLE",
    "CENSYS_HOST",
    "CENSYS_HOST_ACCEPT",
    "CENSYS_JSON_ACCEPT",
    "CENSYS_LINEAGE_GROUP",
    "CENSYS_NOT_SUPPORTED",
    "CENSYS_ORIGIN_PROVIDER",
    "CENSYS_PROPERTY_NAMESPACE",
    "CENSYS_PROVIDER_ID",
    "CENSYS_SOURCE_FAMILY",
    "CENSYS_STATUS_CATEGORIES",
    "CENSYS_SUPPORTED_OBJECT_TYPES",
    "CENSYS_WEB_PROPERTY_ACCEPT",
    "CREDENTIAL_STATUS_BY_CATEGORY",
    "CREDIT_BUCKET_NAME",
    "DEFAULT_MAX_CONCURRENCY",
    "DEFAULT_PORT_FOR_SCHEME",
    "DEPTH_DETAIL",
    "LOCATION_FIELDS",
    "MAX_CERTIFICATES",
    "MAX_DNS_NAMES",
    "MAX_ENDPOINTS",
    "MAX_LABELS",
    "MAX_PORTS",
    "MAX_SERVICES",
    "MAX_VULNERABILITIES",
    "ORGANIZATION_ID_PATTERN",
    "ORGANIZATION_METADATA_KEY",
    "SERVICE_FIELDS",
    "UNSUPPORTED_REASONS",
    "WEB_PROPERTY_SCHEMES",
    "CensysAdapter",
    "CensysAsset",
    "CensysAssetKind",
    "CensysClient",
    "CensysClientFactory",
    "CensysConfig",
    "CensysCreditReading",
    "CensysCreditScope",
    "CensysDetail",
    "CensysDocument",
    "CensysHttpClient",
    "CensysJsonResult",
    "CensysLookupPolicy",
    "CensysNormalization",
    "CensysOperation",
    "ConnectionOrganizationDirectory",
    "NormalizationContext",
    "OrganizationDirectory",
    "StaticOrganizationDirectory",
    "asset_for",
    "build_censys_descriptor",
    "build_censys_execution_policy",
    "build_transport_config",
    "category_for_status",
    "credential_status_for",
    "credential_validation_for",
    "detail_for_depth",
    "enrich_host_object",
    "enrich_web_property_object",
    "normalize_dns_names",
    "normalize_host_observation",
    "normalize_labels",
    "normalize_network_ownership",
    "normalize_not_observed",
    "normalize_organization_id",
    "normalize_services",
    "normalize_tls_certificates",
    "normalize_vulnerabilities",
    "normalize_web_property_observation",
    "parse_credits",
    "parse_retry_after",
    "parse_utc_timestamp",
    "scrub_detail",
    "translate_status_error",
    "unsupported_reason_for",
]
