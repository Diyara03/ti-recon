"""Scriptable fake adapters for execution-layer tests.

These are **not** provider integrations. They contain no vendor API details — no
hosts, endpoints, payload schemas or header names — and perform no I/O. Each is
shaped after a *category* of real provider behaviour that the execution layer
has to handle correctly, so the controls can be tested against realistic shapes
without naming or contacting a vendor.

Every adapter counts its calls and can be scripted with a sequence of scripted
outcomes, which is what makes retry, coalescing and cache behaviour observable.
"""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    MatchScope,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.models.evidence import Evidence, RawEvidenceReference
from ti_recon.providers import (
    CapabilityDiscovery,
    CredentialValidation,
    NormalizedPayload,
    ProviderAdapter,
    ProviderDescriptor,
    ProviderError,
    ProviderQuotaSnapshot,
    ProviderRequest,
    ProviderResultEnvelope,
    RateLimitSnapshot,
)

__all__ = [
    "GreyNoiseLikeAdapter",
    "PartialResultAdapter",
    "ScriptedAdapter",
    "ScriptedStep",
    "UrlscanLikeAdapter",
    "credential_free_descriptor",
    "gti_like_descriptor",
    "urlscan_like_descriptor",
]


def gti_like_descriptor(provider_id: str = "fake_aggregator") -> ProviderDescriptor:
    """A broad, credentialed aggregator: every submittable type, quota-metered."""
    return ProviderDescriptor(
        provider_id=provider_id,
        display_name="Fake Aggregator",
        adapter_version="0.3.0",
        api_version="v3",
        source_family="aggregator",
        supported_object_types=frozenset(
            {
                IntelObjectType.IPV4_ADDR,
                IntelObjectType.IPV6_ADDR,
                IntelObjectType.DOMAIN_NAME,
                IntelObjectType.URL,
                IntelObjectType.FILE,
            }
        ),
        capabilities=frozenset(
            {
                ProviderCapability.REPUTATION,
                ProviderCapability.MALWARE_INTELLIGENCE,
                ProviderCapability.RELATIONSHIPS,
            }
        ),
    )


def urlscan_like_descriptor() -> ProviderDescriptor:
    """A provider whose limits differ per action."""
    return ProviderDescriptor(
        provider_id="fake_websurface",
        display_name="Fake Web Surface",
        adapter_version="0.1.0",
        api_version="v1",
        source_family="web_surface",
        supported_object_types=frozenset({IntelObjectType.URL, IntelObjectType.DOMAIN_NAME}),
        capabilities=frozenset({ProviderCapability.WEB_BEHAVIOR, ProviderCapability.RELATIONSHIPS}),
    )


def credential_free_descriptor() -> ProviderDescriptor:
    """A local list that needs no key and whose answer cannot vary by caller."""
    return ProviderDescriptor(
        provider_id="fake_localwarninglist",
        display_name="Fake Local Warning List",
        adapter_version="0.1.0",
        api_version="unversioned",
        source_family="warning_list",
        supported_object_types=frozenset({IntelObjectType.DOMAIN_NAME, IntelObjectType.IPV4_ADDR}),
        capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
        requires_credentials=False,
    )


@dataclass
class ScriptedStep:
    """One scripted provider response.

    Exactly one of ``error`` or a result description applies. ``hold`` makes the
    call observably slow so concurrency and coalescing can be exercised.
    """

    error: ProviderError | None = None
    status: ProviderRunStatus = ProviderRunStatus.SUCCESS
    with_evidence: bool = True
    rate_limit: RateLimitSnapshot | None = None
    quota: ProviderQuotaSnapshot | None = None
    hold: bool = False


@dataclass
class ScriptedAdapter(ProviderAdapter):
    """An adapter that replays a script and records what it was asked to do.

    The last step repeats once the script runs out, so a test can script "fail
    once, then succeed forever" without counting calls.
    """

    _descriptor: ProviderDescriptor = field(default_factory=gti_like_descriptor)
    script: deque[ScriptedStep] = field(default_factory=deque)
    calls: int = 0
    active_calls: int = 0
    peak_concurrency: int = 0
    seen_credentials: list[str | None] = field(default_factory=list)
    seen_operations: list[ProviderOperation] = field(default_factory=list)
    release: asyncio.Event | None = None

    @classmethod
    def with_steps(
        cls, *steps: ScriptedStep, descriptor: ProviderDescriptor | None = None
    ) -> ScriptedAdapter:
        return cls(_descriptor=descriptor or gti_like_descriptor(), script=deque(steps))

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    # -- required contract -------------------------------------------------

    async def validate_credentials(
        self, credential: CredentialMaterial | None
    ) -> CredentialValidation:
        return CredentialValidation(
            provider_id=self._descriptor.provider_id, status=CredentialStatus.ACTIVE
        )

    async def discover_capabilities(
        self, credential: CredentialMaterial | None
    ) -> CapabilityDiscovery:
        return CapabilityDiscovery(
            provider_id=self._descriptor.provider_id,
            capabilities=self._descriptor.capabilities,
        )

    def normalize(
        self,
        request: ProviderRequest,
        payload: Mapping[str, object],
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizedPayload:
        if not payload.get("with_evidence", True):
            return NormalizedPayload()
        evidence = Evidence(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
            claim_type="multi-vendor.detection-count",
            effect=EvidenceEffect.SUPPORTS_MALICIOUS,
            transport_provider=self._descriptor.provider_id,
            origin_provider=self._descriptor.provider_id,
            source_family=self._descriptor.source_family,
            match_scope=MatchScope.EXACT_OBSERVABLE,
            attributes={"malicious_vendors": 7},
            raw_reference_id=raw_reference.id if raw_reference else None,
        )
        return NormalizedPayload(evidence=(evidence,))

    def classify_error(self, error: Exception) -> ProviderErrorCategory:
        if isinstance(error, ProviderError):
            return error.category
        if isinstance(error, TimeoutError):
            return ProviderErrorCategory.TRANSIENT_ERROR
        if isinstance(error, ValueError):
            return ProviderErrorCategory.SCHEMA_ERROR
        return ProviderErrorCategory.UNKNOWN_ERROR

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        return await self._perform(request, credential)

    async def pivot(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        return await self._perform(request, credential)

    async def active_action(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        return await self._perform(request, credential)

    # -- scripting ---------------------------------------------------------

    async def _perform(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        self.calls += 1
        self.active_calls += 1
        self.peak_concurrency = max(self.peak_concurrency, self.active_calls)
        self.seen_credentials.append(credential.reveal() if credential else None)
        self.seen_operations.append(request.operation)
        try:
            step = self._next_step()
            if step.hold:
                if self.release is not None:
                    await self.release.wait()
                else:
                    for _ in range(5):
                        await asyncio.sleep(0)
            if step.error is not None:
                raise step.error
            return self._envelope(request, step)
        finally:
            self.active_calls -= 1

    def _next_step(self) -> ScriptedStep:
        if not self.script:
            return ScriptedStep()
        if len(self.script) == 1:
            return self.script[0]
        return self.script.popleft()

    def _envelope(self, request: ProviderRequest, step: ScriptedStep) -> ProviderResultEnvelope:
        raw_reference = RawEvidenceReference(
            investigation_id=request.investigation_id,
            provider=self._descriptor.provider_id,
            operation=request.operation,
            storage_key=f"raw/{self._descriptor.provider_id}/{self.calls}",
        )
        payload = self.normalize(
            request, {"with_evidence": step.with_evidence}, raw_reference=raw_reference
        )
        return ProviderResultEnvelope.from_payload(
            provider=self._descriptor.provider_id,
            operation=request.operation,
            status=step.status,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            payload=payload,
            raw_reference=raw_reference,
            rate_limit=step.rate_limit,
            quota=step.quota,
        )


class UrlscanLikeAdapter(ScriptedAdapter):
    """Shaped after a provider whose actions are limited independently.

    Its lookup reports healthy limits while its pivot reports an exhausted
    minute window, so a cooldown on one action must not silence the other.
    """

    def __init__(self, *, exhausted_reset_at: datetime | None = None) -> None:
        super().__init__(_descriptor=urlscan_like_descriptor())
        self._exhausted_reset_at = exhausted_reset_at

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        from ti_recon.providers import RateLimitWindow

        self.script = deque(
            [
                ScriptedStep(
                    rate_limit=RateLimitSnapshot(
                        operation=ProviderOperation.LOOKUP.value,
                        windows=(
                            RateLimitWindow(window_name="minute", limit=60, remaining=59),
                            RateLimitWindow(window_name="hour", limit=1000, remaining=990),
                        ),
                    )
                )
            ]
        )
        return await self._perform(request, credential)

    async def pivot(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        from ti_recon.providers import RateLimitWindow

        self.script = deque(
            [
                ScriptedStep(
                    rate_limit=RateLimitSnapshot(
                        operation=ProviderOperation.PIVOT.value,
                        windows=(
                            RateLimitWindow(
                                window_name="minute",
                                limit=5,
                                remaining=0,
                                reset_at=self._exhausted_reset_at,
                                reset_after_seconds=(None if self._exhausted_reset_at else 600.0),
                            ),
                            RateLimitWindow(window_name="day", limit=100, remaining=90),
                        ),
                    )
                )
            ]
        )
        return await self._perform(request, credential)


class PartialResultAdapter(ScriptedAdapter):
    """Shaped after a provider that returns a subset under some subscriptions.

    Returns a completed ``PARTIAL`` result carrying real evidence, which must
    survive and must not be retried.
    """

    def __init__(self) -> None:
        super().__init__(
            _descriptor=ProviderDescriptor(
                provider_id="fake_scannoise",
                display_name="Fake Scanner Noise",
                adapter_version="0.1.0",
                api_version="v2",
                source_family="scanner_noise",
                supported_object_types=frozenset({IntelObjectType.IPV4_ADDR}),
                capabilities=frozenset(
                    {
                        ProviderCapability.SCANNER_CONTEXT,
                        ProviderCapability.FALSE_POSITIVE_CONTEXT,
                    }
                ),
            ),
            script=deque([ScriptedStep(status=ProviderRunStatus.PARTIAL)]),
        )

    def normalize(
        self,
        request: ProviderRequest,
        payload: Mapping[str, object],
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizedPayload:
        evidence = Evidence(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            evidence_class=EvidenceClass.CONTEXT,
            claim_type="scanner.classification",
            effect=EvidenceEffect.CONTEXT_ONLY,
            transport_provider=self._descriptor.provider_id,
            origin_provider=self._descriptor.provider_id,
            source_family=self._descriptor.source_family,
            match_scope=MatchScope.EXACT_OBSERVABLE,
            attributes={"classification": "benign", "fields_withheld": True},
            raw_reference_id=raw_reference.id if raw_reference else None,
        )
        return NormalizedPayload(
            evidence=(evidence,),
            warnings=("subscription returns a subset of fields",),
        )


class GreyNoiseLikeAdapter(PartialResultAdapter):
    """Alias kept for readability at call sites."""
