"""Shared helpers for execution-layer tests.

Everything here is deterministic: a manual clock, a sleeper that records
instead of waiting, and envelope/request builders. No test in this package
touches a network or a wall clock.
"""

from __future__ import annotations

from typing import Any

from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    MatchScope,
    ObjectClass,
    ProviderCapability,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution import ExecutionScope, ManualClock, RecordingSleeper
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers import (
    CacheabilityHint,
    NormalizedPayload,
    ProviderRequest,
    ProviderResultEnvelope,
)

__all__ = [
    "SHA256_SAMPLE",
    "deterministic_time",
    "make_envelope",
    "make_evidence",
    "make_object",
    "make_request",
    "make_scope",
]

SHA256_SAMPLE = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def deterministic_time() -> tuple[ManualClock, RecordingSleeper]:
    """A clock that only moves when told, and a sleeper that moves it."""
    clock = ManualClock()
    return clock, RecordingSleeper(clock)


def make_object(
    object_type: IntelObjectType = IntelObjectType.DOMAIN_NAME,
    value: str = "evil.example",
) -> IntelObject:
    if object_type is IntelObjectType.FILE:
        return IntelObject(
            object_class=ObjectClass.OBSERVABLE,
            object_type=object_type,
            canonical_value=SHA256_SAMPLE,
            display_value=SHA256_SAMPLE,
            properties={"hashes": {"SHA-256": SHA256_SAMPLE}},
        )
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=object_type,
        canonical_value=value,
        display_value=value,
    )


def make_request(**overrides: Any) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": make_object(),
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.REPUTATION}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


def make_scope(
    *,
    provider_id: str = "fake_provider",
    user_id: str = "user-a",
    connection_id: str | None = "conn-a",
) -> ExecutionScope:
    return ExecutionScope.for_user(
        provider_id=provider_id,
        user_id=user_id,
        provider_connection_id=connection_id,
    )


def make_evidence(
    *,
    provider: str = "fake_provider",
    investigation_id: str = "inv-1",
    subject_object_id: str = "obj-1",
    claim_type: str = "multi-vendor.detection-count",
    attributes: dict[str, Any] | None = None,
) -> Evidence:
    return Evidence(
        investigation_id=investigation_id,
        subject_object_id=subject_object_id,
        evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
        claim_type=claim_type,
        effect=EvidenceEffect.SUPPORTS_MALICIOUS,
        transport_provider=provider,
        origin_provider=provider,
        source_family="aggregator",
        match_scope=MatchScope.EXACT_OBSERVABLE,
        attributes=attributes if attributes is not None else {"malicious_vendors": 7},
    )


def make_envelope(
    *,
    provider: str = "fake_provider",
    status: ProviderRunStatus = ProviderRunStatus.SUCCESS,
    operation: ProviderOperation = ProviderOperation.LOOKUP,
    with_evidence: bool = True,
    cacheability: CacheabilityHint | None = None,
    **overrides: Any,
) -> ProviderResultEnvelope:
    payload = NormalizedPayload(
        evidence=(make_evidence(provider=provider),) if with_evidence else ()
    )
    return ProviderResultEnvelope.from_payload(
        provider=provider,
        operation=operation,
        status=status,
        adapter_version="0.1.0",
        api_version="v1",
        payload=payload,
        cacheability=cacheability,
        **overrides,
    )
