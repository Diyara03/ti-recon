"""A descriptor-only adapter, used to exercise registry integration.

Exists so the GTI descriptor can be registered and matched through the generic
Task 5 registry before the real adapter is written. It answers nothing: every
operation is explicitly unsupported.
"""

from __future__ import annotations

from collections.abc import Mapping

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import ProviderErrorCategory
from ti_recon.models.evidence import RawEvidenceReference
from ti_recon.providers import (
    CapabilityDiscovery,
    CredentialValidation,
    NormalizedPayload,
    ProviderAdapter,
    ProviderDescriptor,
    ProviderRequest,
    ProviderResultEnvelope,
    UnsupportedProviderOperation,
)

__all__ = ["DescriptorOnlyAdapter"]


class DescriptorOnlyAdapter(ProviderAdapter):
    """Carries a descriptor and refuses every operation."""

    def __init__(self, descriptor: ProviderDescriptor) -> None:
        self._descriptor = descriptor

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    async def validate_credentials(
        self, credential: CredentialMaterial | None
    ) -> CredentialValidation:
        return CredentialValidation(
            provider_id=self._descriptor.provider_id, status=CredentialStatus.UNKNOWN
        )

    async def discover_capabilities(
        self, credential: CredentialMaterial | None
    ) -> CapabilityDiscovery:
        return CapabilityDiscovery(provider_id=self._descriptor.provider_id)

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        raise UnsupportedProviderOperation(self._descriptor.provider_id, operation="lookup")

    def normalize(
        self,
        request: ProviderRequest,
        payload: Mapping[str, object],
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizedPayload:
        return NormalizedPayload()

    def classify_error(self, error: Exception) -> ProviderErrorCategory:
        return ProviderErrorCategory.UNKNOWN_ERROR
