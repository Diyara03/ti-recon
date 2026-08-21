"""Provider capabilities and health (Task 5).

``ProviderCapability`` itself lives in :mod:`ti_recon.enums` because the data
model refers to it; it is re-exported here so provider code has one obvious
import.
"""

from __future__ import annotations

from enum import StrEnum

from ti_recon.enums import ACTIVE_CAPABILITIES, ProviderCapability

__all__ = ["ACTIVE_CAPABILITIES", "ProviderCapability", "ProviderHealth"]


class ProviderHealth(StrEnum):
    """Whether a provider integration is currently working.

    A fourth axis, independent of credential status, policy status and the
    status of any single run. A provider can be ``AVAILABLE`` while a user's key
    is revoked, and ``UNAVAILABLE`` while every key is perfectly valid.
    """

    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"
