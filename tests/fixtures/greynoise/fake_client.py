"""A scriptable in-memory :class:`GreyNoiseClient`.

Adapter tests run against this rather than against mocked HTTP internals, so
they stay about the adapter's decisions — which endpoint it reaches for, whether
it probes, what it remembers — instead of about httpx. It records every call,
which is what makes the "the paid endpoint was never touched again" assertions
possible.
"""

from __future__ import annotations

from typing import Any

from fixtures.greynoise import payloads
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.providers.errors import ProviderError
from ti_recon.providers.greynoise.client import GreyNoiseJsonResult

__all__ = ["FakeGreyNoiseClient", "FakeGreyNoiseClientFactory"]


class FakeGreyNoiseClient:
    """An in-memory GreyNoise client with scripted answers."""

    #: Operation labels the tests assert on.
    FULL = "ip_context"
    QUICK = "ip_context_quick"
    COMMUNITY = "community"

    def __init__(
        self,
        *,
        full_payload: dict[str, Any] | None = None,
        quick_payload: dict[str, Any] | None = None,
        community_payload: dict[str, Any] | None = None,
        full_status: int = 200,
        community_status: int = 200,
        metering_headers: dict[str, str] | None = None,
    ) -> None:
        self.full_payload = (
            payloads.full_context_payload() if full_payload is None else full_payload
        )
        self.quick_payload = (
            payloads.quick_context_payload() if quick_payload is None else quick_payload
        )
        self.community_payload = (
            payloads.community_payload() if community_payload is None else community_payload
        )
        self.full_status = full_status
        self.community_status = community_status
        self.metering_headers = metering_headers or {}

        self.calls: list[tuple[str, str]] = []
        self.errors: dict[str, ProviderError] = {}
        self.closed = False

    # -- scripting ------------------------------------------------------- #

    def fail(self, operation: str, error: ProviderError) -> None:
        """Make one operation raise."""
        self.errors[operation] = error

    def succeed(self, operation: str) -> None:
        self.errors.pop(operation, None)

    def called(self, operation: str) -> bool:
        return any(name == operation for name, _ in self.calls)

    def call_count(self, operation: str) -> int:
        return sum(1 for name, _ in self.calls if name == operation)

    def details(self, operation: str) -> list[str]:
        """Every address one operation was asked about, in order."""
        return [detail for name, detail in self.calls if name == operation]

    # -- the client protocol --------------------------------------------- #

    async def get_ip_context(
        self, *, ip: str, quick: bool = False, credential: CredentialMaterial
    ) -> GreyNoiseJsonResult:
        operation = self.QUICK if quick else self.FULL
        self._record(operation, ip)
        return GreyNoiseJsonResult(
            payload=self.quick_payload if quick else self.full_payload,
            status_code=self.full_status,
            metering_headers=dict(self.metering_headers),
        )

    async def get_community(
        self, *, ip: str, credential: CredentialMaterial
    ) -> GreyNoiseJsonResult:
        self._record(self.COMMUNITY, ip)
        return GreyNoiseJsonResult(
            payload=self.community_payload,
            status_code=self.community_status,
            metering_headers=dict(self.metering_headers),
        )

    async def aclose(self) -> None:
        self.closed = True

    def _record(self, operation: str, detail: str) -> None:
        error = self.errors.get(operation)
        self.calls.append((operation, detail))
        if error is not None:
            raise error


class FakeGreyNoiseClientFactory:
    """Hands the same fake client to every lookup, so calls accumulate."""

    def __init__(self, client: FakeGreyNoiseClient) -> None:
        self.client = client

    def __call__(self) -> FakeGreyNoiseClient:
        return self.client
