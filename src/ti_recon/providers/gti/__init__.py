"""Google Threat Intelligence provider (Task 7).

The first real provider integration. It reads GTI / VirusTotal API v3 with each
analyst's own VirusTotal API key and returns normalized Task 3 models.

GTI is **one evidence provider**, not TI Recon's authority. It supplies
high-quality evidence; weighing that against other providers and reaching a
verdict is the future fusion layer's job, and nothing here computes a verdict,
risk score or confidence.

Passive only. No submission, no rescanning, no downloads, no sandbox detonation.
"""

from ti_recon.providers.gti.adapter import GTIAdapter
from ti_recon.providers.gti.client import (
    FORBIDDEN_VT_METHODS,
    GTI_COLLECTIONS,
    GTIClient,
    GTIClientFactory,
    GTIObject,
    GTIPathError,
    GTIRelationshipDescriptor,
    VtPyGTIClient,
    VtPyGTIClientFactory,
    url_identifier,
)
from ti_recon.providers.gti.config import (
    DEFAULT_GTI_HOST,
    DEFAULT_X_TOOL,
    GTI_X_TOOL_ENV_VAR,
    GTIConfig,
    gti_config_from_env,
)
from ti_recon.providers.gti.descriptor import (
    GTI_ADAPTER_VERSION,
    GTI_API_VERSION,
    GTI_CAPABILITIES,
    GTI_CREDENTIAL_GROUP,
    GTI_ORIGIN_PROVIDER,
    GTI_PROVIDER_ID,
    GTI_SOURCE_FAMILY,
    GTI_SUPPORTED_OBJECT_TYPES,
    build_gti_descriptor,
    build_gti_planning_profile,
)
from ti_recon.providers.gti.errors import (
    GTI_ERROR_CATEGORIES,
    category_for_gti_code,
    translate_gti_error,
)
from ti_recon.providers.gti.normalizer import (
    GTI_THREAT_SEVERITY_UNREADABLE,
    THREAT_SEVERITY_DATA_FIELDS,
    normalize_threat_severity,
)
from ti_recon.providers.gti.policy import (
    DEFAULT_EXCLUDED_ATTRIBUTES,
    GTILookupPolicy,
    build_gti_execution_policy,
    collection_for_object_type,
)
from ti_recon.providers.gti.quota import (
    GATING_QUOTA_PREFIX,
    GTIQuotaReading,
    parse_overall_quotas,
)
from ti_recon.providers.gti.relationships import (
    LIMITS_BY_DEPTH,
    RELATIONSHIP_PLANS,
    RELATIONSHIP_SPECS,
    GTIRelationshipDepth,
    GTIRelationshipLimits,
    GTIRelationshipSpec,
    depth_for_investigation,
    relationship_plan,
)

__all__ = [
    "DEFAULT_EXCLUDED_ATTRIBUTES",
    "DEFAULT_GTI_HOST",
    "DEFAULT_X_TOOL",
    "FORBIDDEN_VT_METHODS",
    "GATING_QUOTA_PREFIX",
    "GTI_ADAPTER_VERSION",
    "GTI_API_VERSION",
    "GTI_CAPABILITIES",
    "GTI_COLLECTIONS",
    "GTI_CREDENTIAL_GROUP",
    "GTI_ERROR_CATEGORIES",
    "GTI_ORIGIN_PROVIDER",
    "GTI_PROVIDER_ID",
    "GTI_SOURCE_FAMILY",
    "GTI_SUPPORTED_OBJECT_TYPES",
    "GTI_THREAT_SEVERITY_UNREADABLE",
    "GTI_X_TOOL_ENV_VAR",
    "LIMITS_BY_DEPTH",
    "RELATIONSHIP_PLANS",
    "RELATIONSHIP_SPECS",
    "THREAT_SEVERITY_DATA_FIELDS",
    "GTIAdapter",
    "GTIClient",
    "GTIClientFactory",
    "GTIConfig",
    "GTILookupPolicy",
    "GTIObject",
    "GTIPathError",
    "GTIQuotaReading",
    "GTIRelationshipDepth",
    "GTIRelationshipDescriptor",
    "GTIRelationshipLimits",
    "GTIRelationshipSpec",
    "VtPyGTIClient",
    "VtPyGTIClientFactory",
    "build_gti_descriptor",
    "build_gti_execution_policy",
    "build_gti_planning_profile",
    "category_for_gti_code",
    "collection_for_object_type",
    "depth_for_investigation",
    "gti_config_from_env",
    "normalize_threat_severity",
    "parse_overall_quotas",
    "relationship_plan",
    "translate_gti_error",
    "url_identifier",
]
