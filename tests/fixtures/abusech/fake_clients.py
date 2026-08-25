"""Scriptable in-memory clients for the three abuse.ch providers.

Adapter tests run against these rather than against mocked HTTP internals, so
they stay about each adapter's decisions — which query it sends, which records it
keeps, what it refuses to store — instead of about httpx. Each records every
call, which is what makes the "exactly one request" and "never asked for a
sample" assertions possible.
"""

from __future__ import annotations

from typing import Any

from fixtures.abusech import payloads
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.providers.abusech.client import AbuseChJsonResult
from ti_recon.providers.abusech.errors import query_status_of
from ti_recon.providers.errors import ProviderError

__all__ = [
    "ClientFactory",
    "FakeMalwareBazaarClient",
    "FakeThreatFoxClient",
    "FakeUrlhausClient",
]


class _Recorder:
    """Shared call recording and failure scripting."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.errors: dict[str, ProviderError] = {}
        self.closed = False

    def fail(self, operation: str, error: ProviderError) -> None:
        """Make one operation raise."""
        self.errors[operation] = error

    def called(self, operation: str) -> bool:
        return any(name == operation for name, _ in self.calls)

    def call_count(self, operation: str) -> int:
        return sum(1 for name, _ in self.calls if name == operation)

    def details(self, operation: str) -> list[str]:
        return [detail for name, detail in self.calls if name == operation]

    async def aclose(self) -> None:
        self.closed = True

    def _record(self, operation: str, detail: str) -> None:
        error = self.errors.get(operation)
        self.calls.append((operation, detail))
        if error is not None:
            raise error

    @staticmethod
    def _result(payload: dict[str, Any]) -> AbuseChJsonResult:
        return AbuseChJsonResult(payload=payload, query_status=query_status_of(payload))


class FakeThreatFoxClient(_Recorder):
    """An in-memory ThreatFox client with scripted answers."""

    SEARCH_IOC = "search_ioc"
    SEARCH_HASH = "search_hash"

    def __init__(
        self,
        *,
        ioc_payload: dict[str, Any] | None = None,
        hash_payload: dict[str, Any] | None = None,
    ) -> None:
        super().__init__()
        self.ioc_payload = payloads.threatfox_ioc_result() if ioc_payload is None else ioc_payload
        self.hash_payload = (
            payloads.threatfox_hash_result() if hash_payload is None else hash_payload
        )
        self.exact_matches: list[bool] = []

    async def search_ioc(
        self, *, search_term: str, exact_match: bool, credential: CredentialMaterial
    ) -> AbuseChJsonResult:
        self.exact_matches.append(exact_match)
        self._record(self.SEARCH_IOC, search_term)
        return self._result(self.ioc_payload)

    async def search_hash(
        self, *, file_hash: str, credential: CredentialMaterial
    ) -> AbuseChJsonResult:
        self._record(self.SEARCH_HASH, file_hash)
        return self._result(self.hash_payload)


class FakeUrlhausClient(_Recorder):
    """An in-memory URLhaus client with scripted answers."""

    LOOKUP_URL = "url"
    LOOKUP_HOST = "host"
    LOOKUP_PAYLOAD = "payload"

    def __init__(
        self,
        *,
        url_payload: dict[str, Any] | None = None,
        host_payload: dict[str, Any] | None = None,
        payload_payload: dict[str, Any] | None = None,
    ) -> None:
        super().__init__()
        self.url_payload = payloads.urlhaus_url_result() if url_payload is None else url_payload
        self.host_payload = payloads.urlhaus_host_result() if host_payload is None else host_payload
        self.payload_payload = (
            payloads.urlhaus_payload_result() if payload_payload is None else payload_payload
        )

    async def lookup_url(self, *, url: str, credential: CredentialMaterial) -> AbuseChJsonResult:
        self._record(self.LOOKUP_URL, url)
        return self._result(self.url_payload)

    async def lookup_host(self, *, host: str, credential: CredentialMaterial) -> AbuseChJsonResult:
        self._record(self.LOOKUP_HOST, host)
        return self._result(self.host_payload)

    async def lookup_payload(
        self, *, file_hash: str, credential: CredentialMaterial
    ) -> AbuseChJsonResult:
        self._record(self.LOOKUP_PAYLOAD, file_hash)
        return self._result(self.payload_payload)


class FakeMalwareBazaarClient(_Recorder):
    """An in-memory MalwareBazaar client with scripted answers."""

    GET_INFO = "get_info"

    def __init__(self, *, info_payload: dict[str, Any] | None = None) -> None:
        super().__init__()
        self.info_payload = payloads.malwarebazaar_found() if info_payload is None else info_payload

    async def get_info(
        self, *, file_hash: str, credential: CredentialMaterial
    ) -> AbuseChJsonResult:
        self._record(self.GET_INFO, file_hash)
        return self._result(self.info_payload)


class ClientFactory:
    """Hands the same fake client to every lookup, so calls accumulate."""

    def __init__(self, client: _Recorder) -> None:
        self.client = client

    def __call__(self) -> Any:
        return self.client
