"""Provider adapter contract (Task 5).

Every provider integration implements :class:`ProviderAdapter`. The contract is
narrow on purpose — an adapter fetches, normalizes and classifies. It does not
decide anything about maliciousness.

Contract invariants (enforced by tests in ``tests/unit/test_provider_contract.py``):

* all provider I/O is ``async``;
* no credential appears in a :class:`ProviderRequest`;
* no secret appears in a :class:`ProviderResultEnvelope`;
* provenance is mandatory on every piece of evidence, and
  ``transport_provider`` may differ from ``origin_provider``;
* adapters return normalized Task 3 models, not provider payloads;
* unsupported operations raise :class:`UnsupportedProviderOperation`;
* an adapter never decides a verdict, risk score or confidence.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence

from pydantic import Field

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import IntelObjectType, ProviderCapability, ProviderErrorCategory
from ti_recon.models.base import FrozenTiReconModel, UtcDatetime, utc_now
from ti_recon.models.evidence import RawEvidenceReference
from ti_recon.providers.capabilities import ProviderHealth
from ti_recon.providers.descriptor import ProviderDescriptor
from ti_recon.providers.errors import UnsupportedProviderOperation
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import (
    NormalizedPayload,
    ProviderResultEnvelope,
    RateLimitSnapshot,
)

__all__ = [
    "CapabilityDiscovery",
    "CredentialValidation",
    "ProviderAdapter",
    "ProviderHealthReport",
]


class CredentialValidation(FrozenTiReconModel):
    """Outcome of checking a credential against a provider.

    Reports a :class:`CredentialStatus` — the same vocabulary the credential
    layer stores — so a validation result can be recorded directly without
    translation. ``detail`` is free text and must never quote the credential.
    """

    provider_id: str = Field(min_length=1, max_length=64)
    status: CredentialStatus
    detail: str | None = Field(default=None, max_length=300)
    checked_at: UtcDatetime = Field(default_factory=utc_now)

    @property
    def is_usable(self) -> bool:
        return self.status in {CredentialStatus.ACTIVE, CredentialStatus.UNKNOWN}


class CapabilityDiscovery(FrozenTiReconModel):
    """Capabilities actually available to a specific credential.

    A descriptor states what the *integration* can do; discovery states what
    *this account's plan* can do. The difference is why a free-tier key produces
    coverage gaps rather than silent empty results.
    """

    provider_id: str = Field(min_length=1, max_length=64)
    capabilities: frozenset[ProviderCapability] = frozenset()
    plan_hint: str | None = Field(default=None, max_length=120)
    discovered_at: UtcDatetime = Field(default_factory=utc_now)


class ProviderHealthReport(FrozenTiReconModel):
    """A provider's current availability, independent of any credential."""

    provider_id: str = Field(min_length=1, max_length=64)
    health: ProviderHealth = ProviderHealth.UNKNOWN
    detail: str | None = Field(default=None, max_length=300)
    checked_at: UtcDatetime = Field(default_factory=utc_now)


class ProviderAdapter(ABC):
    """Base class for all provider integrations."""

    # --------------------------------------------------------------------- #
    # Declaration
    # --------------------------------------------------------------------- #

    @property
    @abstractmethod
    def descriptor(self) -> ProviderDescriptor:
        """Static declaration of this provider's identity and abilities."""

    def supports(self, object_type: IntelObjectType, capability: ProviderCapability) -> bool:
        """Whether this adapter can serve ``capability`` for ``object_type``."""
        return self.descriptor.supports(object_type, capability)

    def assert_supports(self, object_type: IntelObjectType, capability: ProviderCapability) -> None:
        """Raise :class:`UnsupportedProviderOperation` if the pair is unsupported."""
        if not self.supports(object_type, capability):
            raise UnsupportedProviderOperation(
                self.descriptor.provider_id,
                operation=f"{capability.value} for {object_type.value}",
            )

    # --------------------------------------------------------------------- #
    # Required operations
    # --------------------------------------------------------------------- #

    @abstractmethod
    async def validate_credentials(
        self, credential: CredentialMaterial | None
    ) -> CredentialValidation:
        """Check whether ``credential`` works against this provider.

        ``credential`` is ``None`` for providers with
        ``requires_credentials=False``.
        """

    @abstractmethod
    async def discover_capabilities(
        self, credential: CredentialMaterial | None
    ) -> CapabilityDiscovery:
        """Report which capabilities this credential's plan actually allows."""

    @abstractmethod
    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        """Perform a single passive lookup and return normalized results."""

    # --------------------------------------------------------------------- #
    # Optional operations
    #
    # These raise a typed UnsupportedProviderOperation rather than
    # NotImplementedError: a provider not offering batch lookup is an ordinary
    # runtime fact the engine must route around, not a bug to crash on.
    # --------------------------------------------------------------------- #

    async def batch_lookup(
        self,
        requests: Sequence[ProviderRequest],
        credential: CredentialMaterial | None,
    ) -> Sequence[ProviderResultEnvelope]:
        """Look up several objects in one call, if the provider supports it."""
        raise UnsupportedProviderOperation(self.descriptor.provider_id, operation="batch_lookup")

    async def pivot(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        """Follow relationships from an object, if the provider supports it."""
        raise UnsupportedProviderOperation(self.descriptor.provider_id, operation="pivot")

    async def active_action(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        """Perform an action that interacts with the target.

        Not implemented by anything in this codebase. Any future implementation
        must be gated on ``descriptor.supports_active`` *and* on explicit user
        approval carried by ``request.activity_mode``.
        """
        raise UnsupportedProviderOperation(self.descriptor.provider_id, operation="active_action")

    # --------------------------------------------------------------------- #
    # Pure helpers
    # --------------------------------------------------------------------- #

    @abstractmethod
    def normalize(
        self,
        request: ProviderRequest,
        payload: Mapping[str, object],
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizedPayload:
        """Turn a provider payload into Task 3 models.

        Synchronous and pure: normalization must be testable against a stored
        response fixture with no I/O.
        """

    @abstractmethod
    def classify_error(self, error: Exception) -> ProviderErrorCategory:
        """Map a provider or transport failure onto a normalized category."""

    def parse_rate_limits(self, headers: Mapping[str, str]) -> RateLimitSnapshot | None:
        """Extract rate-limit state from response headers, if the provider sends any.

        Defaults to ``None``. Most providers expose only part of this, and some
        expose none; guessing would give a scheduler numbers it should not trust.
        """
        return None

    async def health(self, credential: CredentialMaterial | None = None) -> ProviderHealthReport:
        """Report provider availability.

        Defaults to ``UNKNOWN`` rather than ``AVAILABLE``: an adapter that has
        not checked should not claim its provider is up.
        """
        return ProviderHealthReport(
            provider_id=self.descriptor.provider_id,
            health=ProviderHealth.UNKNOWN,
        )

    def __repr__(self) -> str:
        descriptor = self.descriptor
        return (
            f"<{type(self).__name__} provider={descriptor.provider_id} "
            f"adapter_version={descriptor.adapter_version}>"
        )
