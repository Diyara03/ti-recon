"""A scriptable in-memory :class:`CensysClient`.

Adapter tests run against this rather than against mocked HTTP internals, so
they stay about the adapter's decisions — which asset it asks for, whether it
spent a credit to answer a credential question — instead of about httpx. It
records every call, which is what makes the "no search was performed" and "the
credit endpoint was read instead of an asset" assertions possible.
"""

from __future__ import annotations

from typing import Any

from fixtures.censys import payloads
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.providers.censys.client import CensysJsonResult
from ti_recon.providers.errors import ProviderError, ProviderNotFoundError

__all__ = ["FakeCensysClient", "FakeCensysClientFactory"]


class FakeCensysClient:
    """An in-memory Censys client with scripted answers."""

    #: Operation labels the tests assert on.
    HOST = "host"
    WEB_PROPERTY = "web_property"
    USER_CREDITS = "user_credits"
    ORGANIZATION_CREDITS = "organization_credits"

    def __init__(
        self,
        *,
        hosts: dict[str, dict[str, Any]] | None = None,
        web_properties: dict[str, dict[str, Any]] | None = None,
        user_credits: dict[str, Any] | None = None,
        organization_credits: dict[str, Any] | None = None,
        metering_headers: dict[str, str] | None = None,
    ) -> None:
        self.hosts = {payloads.HOST_IP: payloads.host_payload()} if hosts is None else hosts
        self.web_properties = (
            {f"{payloads.WEB_PROPERTY_HOST}:443": payloads.web_property_payload()}
            if web_properties is None
            else web_properties
        )
        self.user_credits = (
            payloads.user_credits_payload() if user_credits is None else user_credits
        )
        self.organization_credits = (
            payloads.organization_credits_payload()
            if organization_credits is None
            else organization_credits
        )
        self.metering_headers = metering_headers or {}

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

    def details(self, operation: str) -> list[str]:
        return [detail for name, detail in self.calls if name == operation]

    # -- the client protocol --------------------------------------------- #

    async def get_host(self, *, ip: str, credential: CredentialMaterial) -> CensysJsonResult:
        self._record(self.HOST, ip)
        payload = self.hosts.get(ip)
        if payload is None:
            raise ProviderNotFoundError("censys", operation="censys.host")
        return CensysJsonResult(payload=payload, metering_headers=dict(self.metering_headers))

    async def get_web_property(
        self, *, hostname: str, port: int, credential: CredentialMaterial
    ) -> CensysJsonResult:
        identifier = f"{hostname}:{port}"
        self._record(self.WEB_PROPERTY, identifier)
        payload = self.web_properties.get(identifier)
        if payload is None:
            raise ProviderNotFoundError("censys", operation="censys.web_property")
        return CensysJsonResult(payload=payload, metering_headers=dict(self.metering_headers))

    async def get_user_credits(self, *, credential: CredentialMaterial) -> CensysJsonResult:
        self._record(self.USER_CREDITS, credential.user_id)
        return CensysJsonResult(payload=self.user_credits)

    async def get_organization_credits(
        self, *, organization_id: str, credential: CredentialMaterial
    ) -> CensysJsonResult:
        self._record(self.ORGANIZATION_CREDITS, organization_id)
        return CensysJsonResult(payload=self.organization_credits)

    async def aclose(self) -> None:
        self.closed = True

    def _record(self, operation: str, detail: str) -> None:
        error = self.errors.get(operation)
        self.calls.append((operation, detail))
        if error is not None:
            raise error


class FakeCensysClientFactory:
    """Hands the same fake client to every lookup, so calls accumulate."""

    def __init__(self, client: FakeCensysClient) -> None:
        self.client = client

    def __call__(self) -> FakeCensysClient:
        return self.client
