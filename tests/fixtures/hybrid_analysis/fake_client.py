"""A scriptable in-memory Hybrid Analysis client.

Adapter tests run against this rather than mocked HTTP internals, so they stay
about the adapter's decisions — which reports it chooses, what it keeps, what it
refuses to store — instead of about httpx. It records every call, which is what
makes the "at most three requests" and "never asked for a sample" assertions
possible.
"""

from __future__ import annotations

from typing import Any

from fixtures.hybrid_analysis import payloads
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.providers.errors import ProviderError
from ti_recon.providers.hybrid_analysis.client import (
    ContainerReport,
    HybridAnalysisResponse,
)
from ti_recon.providers.result import RateLimitSnapshot

__all__ = ["ClientFactory", "FakeHybridAnalysisClient"]


class FakeHybridAnalysisClient:
    """Scripted answers plus a call log."""

    SEARCH = "search_hash"
    SUMMARY = "report_summary"
    KEY = "key_current"

    def __init__(
        self,
        *,
        search_payload: Any | None = None,
        summaries: dict[str, Any] | None = None,
        default_summary: Any | None = None,
        key_payload: Any | None = None,
        rate_limit: RateLimitSnapshot | None = None,
    ) -> None:
        self.search_payload = (
            payloads.search_hash_malicious() if search_payload is None else search_payload
        )
        self.summaries = summaries or {}
        self.default_summary = (
            payloads.summary_malicious() if default_summary is None else default_summary
        )
        self.key_payload = payloads.key_current() if key_payload is None else key_payload
        self.rate_limit = rate_limit
        self.calls: list[tuple[str, str]] = []
        self.errors: dict[str, ProviderError] = {}
        self.containers: set[str] = set()
        self.missing: set[str] = set()
        self.closed = False

    # --- scripting ---------------------------------------------------- #

    def fail(self, operation: str, error: ProviderError) -> None:
        self.errors[operation] = error

    def mark_container(self, report_id: str, related: tuple[str, ...] = ()) -> None:
        self.containers.add(report_id)
        self._related = related

    def mark_missing(self, report_id: str) -> None:
        self.missing.add(report_id)

    # --- inspection --------------------------------------------------- #

    def called(self, operation: str) -> bool:
        return any(name == operation for name, _ in self.calls)

    def call_count(self, operation: str) -> int:
        return sum(1 for name, _ in self.calls if name == operation)

    def details(self, operation: str) -> list[str]:
        return [detail for name, detail in self.calls if name == operation]

    @property
    def request_count(self) -> int:
        return len(self.calls)

    # --- the read-only surface ---------------------------------------- #

    async def search_hash(
        self, *, file_hash: str, credential: CredentialMaterial
    ) -> HybridAnalysisResponse:
        self._record(self.SEARCH, file_hash)
        return HybridAnalysisResponse(self.search_payload, self.rate_limit)

    async def report_summary(
        self, *, report_id: str, credential: CredentialMaterial
    ) -> HybridAnalysisResponse:
        self._record(self.SUMMARY, report_id)
        if report_id in self.containers:
            raise ContainerReport(report_id, getattr(self, "_related", ()))
        if report_id in self.missing:
            from ti_recon.enums import ProviderErrorCategory
            from ti_recon.providers.errors import provider_error_for

            raise provider_error_for(
                ProviderErrorCategory.NOT_FOUND, "hybrid_analysis", operation="summary"
            )
        payload = self.summaries.get(report_id, self.default_summary)
        return HybridAnalysisResponse(payload, self.rate_limit)

    async def key_current(self, *, credential: CredentialMaterial) -> HybridAnalysisResponse:
        self._record(self.KEY, "current")
        return HybridAnalysisResponse(self.key_payload, self.rate_limit)

    async def aclose(self) -> None:
        self.closed = True

    def _record(self, operation: str, detail: str) -> None:
        error = self.errors.get(operation)
        self.calls.append((operation, detail))
        if error is not None:
            raise error


class ClientFactory:
    """Hands the same fake client to every lookup, so calls accumulate."""

    def __init__(self, client: FakeHybridAnalysisClient) -> None:
        self.client = client

    def __call__(self) -> Any:
        return self.client
