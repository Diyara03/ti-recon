"""Shared abuse.ch foundation (Task 10).

Not a provider. This package holds what ThreatFox, URLhaus and MalwareBazaar
genuinely share, so that the rules which must not drift between them are written
once:

* **one credential** — a single ``Auth-Key`` in the ``abuse_ch`` credential
  group, so an analyst stores it once and all three providers can use it;
* **one source family** — three datasets in one ecosystem, so a fusion layer can
  never read them as three independent corroborations, while per-platform
  lineage groups keep their claims distinguishable;
* **one request shape** — a form POST to a fixed origin whose real outcome
  arrives in the body's ``query_status`` rather than in the HTTP status;
* **one relay rule** — third-party findings these APIs repeat are attributed to
  whoever produced them and can never carry a direction;
* **one fair-use posture** — no published budget to code against, so
  conservative by construction.

The three provider packages depend on this one. It depends on no provider.
"""

from ti_recon.providers.abusech.client import AbuseChHttpClient, AbuseChJsonResult
from ti_recon.providers.abusech.config import (
    MALWAREBAZAAR_HOST,
    THREATFOX_HOST,
    URLHAUS_HOST,
    AbuseChConfig,
    build_transport_config,
)
from ti_recon.providers.abusech.errors import (
    ABUSE_CH_STATUS_CATEGORIES,
    NO_DATA_QUERY_STATUSES,
    QUERY_STATUS_CATEGORIES,
    SUCCESS_QUERY_STATUSES,
    category_for_query_status,
    category_for_status,
    credential_status_for,
    credential_validation_for,
    parse_retry_after,
    parse_utc_timestamp,
    query_status_of,
    scrub_detail,
    translate_query_status,
    translate_status_error,
)
from ti_recon.providers.abusech.evidence import (
    MAX_RELAYED_SOURCES,
    AbuseChNormalization,
    NormalizationContext,
    build_evidence,
    relayed_summary,
)
from ti_recon.providers.abusech.family import (
    ABUSE_CH_AUTH_HEADER,
    ABUSE_CH_AUTH_TYPE,
    ABUSE_CH_CREDENTIAL_GROUP,
    ABUSE_CH_PROVIDER_IDS,
    ABUSE_CH_SOURCE_FAMILY,
    BLOCKLIST_RELAY_FAMILY,
    BLOCKLIST_RELAY_ORIGIN,
    VENDOR_INTEL_RELAY_FAMILY,
    VENDOR_INTEL_RELAY_ORIGIN,
    VIRUSTOTAL_RELAY_FAMILY,
    VIRUSTOTAL_RELAY_ORIGIN,
    lineage_group_for,
)
from ti_recon.providers.abusech.policy import (
    ABUSE_CH_MAX_CONCURRENCY,
    DEPTH_BOUNDS,
    MAX_RELATED_CEILING,
    AbuseChBounds,
    bounds_for_depth,
    build_abusech_execution_policy,
)
from ti_recon.providers.abusech.values import (
    MAX_LABEL,
    MAX_TEXT,
    count,
    flag,
    hex_digest,
    mapping,
    number,
    scalar,
    string_list,
    text,
)

__all__ = [
    "ABUSE_CH_AUTH_HEADER",
    "ABUSE_CH_AUTH_TYPE",
    "ABUSE_CH_CREDENTIAL_GROUP",
    "ABUSE_CH_MAX_CONCURRENCY",
    "ABUSE_CH_PROVIDER_IDS",
    "ABUSE_CH_SOURCE_FAMILY",
    "ABUSE_CH_STATUS_CATEGORIES",
    "BLOCKLIST_RELAY_FAMILY",
    "BLOCKLIST_RELAY_ORIGIN",
    "DEPTH_BOUNDS",
    "MALWAREBAZAAR_HOST",
    "MAX_LABEL",
    "MAX_RELATED_CEILING",
    "MAX_RELAYED_SOURCES",
    "MAX_TEXT",
    "NO_DATA_QUERY_STATUSES",
    "QUERY_STATUS_CATEGORIES",
    "SUCCESS_QUERY_STATUSES",
    "THREATFOX_HOST",
    "URLHAUS_HOST",
    "VENDOR_INTEL_RELAY_FAMILY",
    "VENDOR_INTEL_RELAY_ORIGIN",
    "VIRUSTOTAL_RELAY_FAMILY",
    "VIRUSTOTAL_RELAY_ORIGIN",
    "AbuseChBounds",
    "AbuseChConfig",
    "AbuseChHttpClient",
    "AbuseChJsonResult",
    "AbuseChNormalization",
    "NormalizationContext",
    "bounds_for_depth",
    "build_abusech_execution_policy",
    "build_evidence",
    "build_transport_config",
    "category_for_query_status",
    "category_for_status",
    "count",
    "credential_status_for",
    "credential_validation_for",
    "flag",
    "hex_digest",
    "lineage_group_for",
    "mapping",
    "number",
    "parse_retry_after",
    "parse_utc_timestamp",
    "query_status_of",
    "relayed_summary",
    "scalar",
    "scrub_detail",
    "string_list",
    "text",
    "translate_query_status",
    "translate_status_error",
]
