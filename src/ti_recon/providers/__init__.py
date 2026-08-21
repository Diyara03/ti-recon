"""Provider integration framework (Task 5).

Provider-neutral contracts only. No real provider integration lives here, and
none may: an adapter for a specific vendor belongs in its own module and must
depend on these contracts rather than the other way round.
"""

from ti_recon.enums import ProviderCapability, ProviderErrorCategory, ProviderOperation
from ti_recon.providers.adapter import (
    CapabilityDiscovery,
    CredentialValidation,
    ProviderAdapter,
    ProviderHealthReport,
)
from ti_recon.providers.capabilities import ACTIVE_CAPABILITIES, ProviderHealth
from ti_recon.providers.descriptor import ProviderDescriptor
from ti_recon.providers.errors import (
    PROVIDER_ERROR_RUN_STATUS,
    RETRYABLE_ERROR_CATEGORIES,
    ProviderAuthenticationError,
    ProviderError,
    ProviderInvalidRequestError,
    ProviderNotFoundError,
    ProviderPartialResultError,
    ProviderPermissionError,
    ProviderPlanLimitedError,
    ProviderQuotaExceededError,
    ProviderRateLimitedError,
    ProviderSchemaError,
    ProviderTransientError,
    ProviderUnavailableError,
    ProviderUnknownError,
    UnsupportedProviderOperation,
)
from ti_recon.providers.registry import (
    DuplicateProviderId,
    ProviderRegistry,
    ProviderRegistryError,
    UnknownProvider,
)
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import (
    CacheabilityHint,
    NormalizedPayload,
    ProviderResultEnvelope,
    RateLimitSnapshot,
)

__all__ = [
    "ACTIVE_CAPABILITIES",
    "PROVIDER_ERROR_RUN_STATUS",
    "RETRYABLE_ERROR_CATEGORIES",
    "CacheabilityHint",
    "CapabilityDiscovery",
    "CredentialValidation",
    "DuplicateProviderId",
    "NormalizedPayload",
    "ProviderAdapter",
    "ProviderAuthenticationError",
    "ProviderCapability",
    "ProviderDescriptor",
    "ProviderError",
    "ProviderErrorCategory",
    "ProviderHealth",
    "ProviderHealthReport",
    "ProviderInvalidRequestError",
    "ProviderNotFoundError",
    "ProviderOperation",
    "ProviderPartialResultError",
    "ProviderPermissionError",
    "ProviderPlanLimitedError",
    "ProviderQuotaExceededError",
    "ProviderRateLimitedError",
    "ProviderRegistry",
    "ProviderRegistryError",
    "ProviderRequest",
    "ProviderResultEnvelope",
    "ProviderSchemaError",
    "ProviderTransientError",
    "ProviderUnavailableError",
    "ProviderUnknownError",
    "RateLimitSnapshot",
    "UnknownProvider",
    "UnsupportedProviderOperation",
]
