"""A scriptable in-memory :class:`UrlscanClient`.

Adapter tests run against this rather than against mocked HTTP internals, so
they stay about the adapter's decisions — what it fetches, what it refuses to
fetch — instead of about httpx. It records every call, which is what makes the
"no artifact was retrieved" assertions possible.
"""

from __future__ import annotations

from typing import Any

from fixtures.urlscan import payloads
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.providers.errors import ProviderError, ProviderNotFoundError
from ti_recon.providers.urlscan.client import UrlscanArtifact, UrlscanJsonResult

__all__ = ["FakeUrlscanClient", "FakeUrlscanClientFactory"]


class FakeUrlscanClient:
    """An in-memory urlscan client with scripted answers."""

    def __init__(
        self,
        *,
        search_payload: dict[str, Any] | None = None,
        result_payloads: dict[str, dict[str, Any]] | None = None,
        quotas_payload: dict[str, Any] | None = None,
        quotas_by_user: dict[str, dict[str, Any]] | None = None,
        screenshot: UrlscanArtifact | None = None,
        dom: UrlscanArtifact | None = None,
        response_bodies: dict[str, UrlscanArtifact] | None = None,
        rate_limit_headers: dict[str, str] | None = None,
    ) -> None:
        self.search_payload = (
            payloads.search_payload() if search_payload is None else search_payload
        )
        self.result_payloads = (
            {payloads.SCAN_ID: payloads.result_payload()}
            if result_payloads is None
            else result_payloads
        )
        self.quotas_payload = (
            payloads.quotas_payload() if quotas_payload is None else quotas_payload
        )
        # Per-analyst quota answers, because urlscan plans differ per account
        # and the historical range one analyst may search is not another's.
        self.quotas_by_user = quotas_by_user or {}
        self.screenshot = screenshot
        self.dom = dom
        self.response_bodies = response_bodies or {}
        self.rate_limit_headers = rate_limit_headers or {}

        self.calls: list[tuple[str, str]] = []
        self.errors: dict[str, ProviderError] = {}
        self.closed = False

    # -- scripting ------------------------------------------------------- #

    def fail(self, operation: str, error: ProviderError) -> None:
        """Make one operation raise."""
        self.errors[operation] = error

    def called(self, operation: str) -> bool:
        return any(name == operation for name, _ in self.calls)

    def call_count(self, operation: str) -> int:
        return sum(1 for name, _ in self.calls if name == operation)

    # -- the client protocol --------------------------------------------- #

    async def get_quotas(self, *, credential: CredentialMaterial) -> UrlscanJsonResult:
        self._record("quotas", credential.user_id)
        payload = self.quotas_by_user.get(credential.user_id, self.quotas_payload)
        return UrlscanJsonResult(payload=payload)

    async def search(
        self,
        *,
        query: str,
        size: int,
        search_after: str | None = None,
        credential: CredentialMaterial,
    ) -> UrlscanJsonResult:
        self._record("search", query)
        self.last_search_size = size
        return UrlscanJsonResult(
            payload=self.search_payload, rate_limit_headers=dict(self.rate_limit_headers)
        )

    async def get_result(
        self, *, scan_id: str, credential: CredentialMaterial
    ) -> UrlscanJsonResult:
        self._record("result", scan_id)
        payload = self.result_payloads.get(scan_id)
        if payload is None:
            raise ProviderNotFoundError("urlscan", operation="urlscan.result")
        return UrlscanJsonResult(payload=payload)

    async def get_screenshot(
        self, *, scan_id: str, credential: CredentialMaterial
    ) -> UrlscanArtifact:
        self._record("screenshot", scan_id)
        if self.screenshot is None:
            raise ProviderNotFoundError("urlscan", operation="urlscan.screenshot")
        return self.screenshot

    async def get_dom(self, *, scan_id: str, credential: CredentialMaterial) -> UrlscanArtifact:
        self._record("dom", scan_id)
        if self.dom is None:
            raise ProviderNotFoundError("urlscan", operation="urlscan.dom")
        return self.dom

    async def get_response_body(
        self, *, body_sha256: str, credential: CredentialMaterial
    ) -> UrlscanArtifact:
        self._record("response_body", body_sha256)
        artifact = self.response_bodies.get(body_sha256)
        if artifact is None:
            raise ProviderNotFoundError("urlscan", operation="urlscan.response_body")
        return artifact

    async def aclose(self) -> None:
        self.closed = True

    def _record(self, operation: str, detail: str) -> None:
        error = self.errors.get(operation)
        self.calls.append((operation, detail))
        if error is not None:
            raise error


class FakeUrlscanClientFactory:
    """Hands the same fake client to every lookup, so calls accumulate."""

    def __init__(self, client: FakeUrlscanClient) -> None:
        self.client = client

    def __call__(self) -> FakeUrlscanClient:
        return self.client
