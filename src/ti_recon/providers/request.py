"""Provider request (Task 5).

A :class:`ProviderRequest` says *what* to ask a provider. It deliberately
carries no credential: authentication is applied by the transport from the
credential resolved for the authenticated user. A request object therefore
crosses layers, gets logged and gets attached to errors without any risk of
carrying a secret with it.
"""

from __future__ import annotations

from pydantic import Field, model_validator

from ti_recon.enums import (
    ActivityMode,
    InvestigationDepth,
    ProviderCapability,
    ProviderOperation,
)
from ti_recon.models.base import FrozenTiReconModel, Identifier
from ti_recon.models.intel_object import IntelObject

__all__ = ["ProviderRequest"]


class ProviderRequest(FrozenTiReconModel):
    """One provider operation to perform for one object."""

    investigation_id: Identifier
    intel_object: IntelObject
    operation: ProviderOperation = ProviderOperation.LOOKUP
    requested_capabilities: frozenset[ProviderCapability] = Field(min_length=1)
    depth: InvestigationDepth = InvestigationDepth.STANDARD
    activity_mode: ActivityMode = ActivityMode.PASSIVE
    max_results: int | None = Field(default=None, ge=1, le=10_000)
    max_pages: int | None = Field(default=None, ge=1, le=1_000)

    @model_validator(mode="after")
    def _validate_request(self) -> ProviderRequest:
        """Keep passive requests passive.

        The activity mode is the user's consent boundary. If a passive request
        could carry an active operation or capability, that consent would be
        bypassable by whoever constructed the request.
        """
        if self.activity_mode is ActivityMode.PASSIVE:
            if self.operation is ProviderOperation.ACTIVE_ACTION:
                msg = "an active action requires activity_mode=active"
                raise ValueError(msg)
            if ProviderCapability.ACTIVE_SCAN in self.requested_capabilities:
                msg = "requesting ACTIVE_SCAN requires activity_mode=active"
                raise ValueError(msg)
        return self
