"""Google Threat Intelligence provider (Task 7).

The first real provider integration. It reads GTI / VirusTotal API v3 with each
analyst's own VirusTotal API key and returns normalized Task 3 models.

GTI is **one evidence provider**, not TI Recon's authority. It supplies
high-quality evidence; weighing that against other providers and reaching a
verdict is the future fusion layer's job, and nothing here computes a verdict,
risk score or confidence.

Passive only. No submission, no rescanning, no downloads, no sandbox detonation.
"""

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
)
from ti_recon.providers.gti.errors import (
    GTI_ERROR_CATEGORIES,
    category_for_gti_code,
    translate_gti_error,
)

__all__ = [
    "DEFAULT_GTI_HOST",
    "DEFAULT_X_TOOL",
    "FORBIDDEN_VT_METHODS",
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
    "GTI_X_TOOL_ENV_VAR",
    "GTIClient",
    "GTIClientFactory",
    "GTIConfig",
    "GTIObject",
    "GTIPathError",
    "GTIRelationshipDescriptor",
    "VtPyGTIClient",
    "VtPyGTIClientFactory",
    "build_gti_descriptor",
    "category_for_gti_code",
    "gti_config_from_env",
    "translate_gti_error",
    "url_identifier",
]
