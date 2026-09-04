"""Provider descriptor (Task 5).

A descriptor is a provider's self-declaration: what it can answer, for which
object types, whether it needs a credential. The registry matches on this, which
is what keeps vendor names out of engine code.
"""

from __future__ import annotations

from pydantic import Field, model_validator

from ti_recon.enums import IntelObjectType, ProviderCapability
from ti_recon.models.base import FrozenTiReconModel

__all__ = ["ProviderDescriptor"]


class ProviderDescriptor(FrozenTiReconModel):
    """Static declaration of one provider integration.

    ``source_family`` groups providers whose data shares an upstream origin. It
    feeds evidence lineage: two providers in the same family confirming each
    other is much weaker than two independent families agreeing.

    ``credential_group`` lets several providers share one credential (the
    abuse.ch family). It defaults to ``provider_id``.
    """

    provider_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    display_name: str = Field(min_length=1, max_length=120)
    adapter_version: str = Field(min_length=1, max_length=32)
    # Explicit rather than optional: a stored assessment must remain explainable,
    # and "which API version produced this?" is part of that. A provider with an
    # unversioned API says so out loud.
    api_version: str = Field(default="unversioned", min_length=1, max_length=32)
    source_family: str = Field(min_length=1, max_length=64)
    credential_group: str = Field(default="", max_length=64)
    supported_object_types: frozenset[IntelObjectType] = Field(min_length=1)
    capabilities: frozenset[ProviderCapability] = Field(min_length=1)
    supports_passive: bool = True
    supports_active: bool = False
    supports_batch: bool = False
    requires_credentials: bool = True

    #: Identity of the local dataset this adapter answers from, when it has one.
    #:
    #: ``None`` for every provider that answers from a remote API — their data
    #: version is whatever the API returned, and there is nothing local to
    #: version. A provider that reads a pinned local dataset sets it to that
    #: dataset's fingerprint, and the cache key includes it for exactly the
    #: reason it already includes ``api_version`` and ``adapter_version``:
    #: results parsed from one version of something must not be served after it
    #: changes. Refreshing a dataset therefore invalidates its cached answers
    #: with no provider-specific handling anywhere in the execution layer.
    dataset_version: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def _validate_descriptor(self) -> ProviderDescriptor:
        if not self.credential_group:
            object.__setattr__(self, "credential_group", self.provider_id)

        has_active_capability = ProviderCapability.ACTIVE_SCAN in self.capabilities
        if has_active_capability and not self.supports_active:
            msg = "a provider declaring ACTIVE_SCAN must set supports_active"
            raise ValueError(msg)
        if self.supports_active and not has_active_capability:
            msg = "a provider setting supports_active must declare an active capability"
            raise ValueError(msg)

        has_batch_capability = ProviderCapability.BATCH_LOOKUP in self.capabilities
        if has_batch_capability != self.supports_batch:
            msg = "supports_batch must agree with the BATCH_LOOKUP capability"
            raise ValueError(msg)

        if not self.supports_passive and not self.supports_active:
            msg = "a provider must support passive or active operations"
            raise ValueError(msg)
        return self

    @property
    def passive_capabilities(self) -> frozenset[ProviderCapability]:
        """Capabilities usable without interacting with the target."""
        return frozenset(
            capability
            for capability in self.capabilities
            if capability is not ProviderCapability.ACTIVE_SCAN
        )

    def supports(self, object_type: IntelObjectType, capability: ProviderCapability) -> bool:
        """Whether this provider can serve ``capability`` for ``object_type``."""
        return object_type in self.supported_object_types and capability in self.capabilities
