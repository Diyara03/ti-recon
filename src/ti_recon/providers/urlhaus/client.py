"""The URLhaus HTTP client (Task 10).

The only module in the URLhaus package that performs I/O.

What this client deliberately cannot do
---------------------------------------

Three reads: one URL, one host, one payload. All of them are lookups against
URLhaus's own database.

URLhaus also offers URL submission, rescanning, payload **downloads** and bulk
feed exports. Downloading a payload means fetching live malware onto the machine
running TI Recon; submitting a URL publishes what an analyst is investigating.
Neither is reachable from here: there is no download path, no submission path,
and :data:`ALLOWED_PATHS` is the complete set of endpoints this client may
address.

Never the URL itself
--------------------

The most important thing this module does not do is visit the URL it is asked
about. A URLhaus lookup sends the URL *to URLhaus* as a form value and reads
what URLhaus already knows; the shared transport is pinned to the URLhaus origin,
so an analyst-supplied URL is data on the way out and can never become a request
target. Following one would mean fetching attacker infrastructure from TI
Recon's own network, with TI Recon's own address, carrying an abuse.ch key.

Input safety
------------

A URL and a host reach the provider verbatim, so both are bounded and
control-character checked first. A payload hash is shape-checked against the two
digest lengths URLhaus indexes, so a value that is not a digest never becomes a
query — and a SHA-1 is refused rather than sent to an API that cannot use it.
"""

from __future__ import annotations

from types import TracebackType
from typing import TYPE_CHECKING, Final, Protocol, Self

import httpx

from ti_recon.credentials.models import CredentialMaterial
from ti_recon.providers.abusech.client import AbuseChHttpClient, AbuseChJsonResult
from ti_recon.providers.abusech.config import URLHAUS_HOST, AbuseChConfig
from ti_recon.providers.abusech.values import hex_digest
from ti_recon.providers.errors import ProviderInvalidRequestError
from ti_recon.providers.transport import ProviderHttpClient
from ti_recon.providers.urlhaus.descriptor import URLHAUS_PROVIDER_ID

__all__ = [
    "ALLOWED_PATHS",
    "URLHAUS_HASH_LENGTHS",
    "UrlhausClient",
    "UrlhausConfig",
    "UrlhausHttpClient",
    "UrlhausOperation",
]


class UrlhausOperation:
    """Operation names used for logging, metrics and error attribution."""

    URL: Final[str] = "urlhaus.url"
    HOST: Final[str] = "urlhaus.host"
    PAYLOAD: Final[str] = "urlhaus.payload"


#: The complete set of URLhaus endpoints this integration may address.
#:
#: Unlike ThreatFox and MalwareBazaar, URLhaus distinguishes operations by path
#: rather than by a ``query`` field — so the allow-list is a set of paths, and it
#: contains no submission, download or feed endpoint.
ALLOWED_PATHS: Final[frozenset[str]] = frozenset({"v1/url/", "v1/host/", "v1/payload/"})

#: Digest lengths URLhaus indexes payloads by: MD5 and SHA-256.
URLHAUS_HASH_LENGTHS: Final[frozenset[int]] = frozenset({32, 64})

#: Bounds on values sent to the provider.
_MAX_URL: Final[int] = 2048
_MAX_HOST: Final[int] = 253


class UrlhausConfig(AbuseChConfig):
    """How to talk to URLhaus, minus the credential."""

    host: str = URLHAUS_HOST


class UrlhausClient(Protocol):
    """The read-only surface the rest of the URLhaus package may use.

    Passive by construction: nothing here submits a URL, triggers a rescan or
    downloads a payload. Adding any of those would mean changing this protocol,
    which is the point of having one.
    """

    async def lookup_url(
        self, *, url: str, credential: CredentialMaterial
    ) -> AbuseChJsonResult: ...

    async def lookup_host(
        self, *, host: str, credential: CredentialMaterial
    ) -> AbuseChJsonResult: ...

    async def lookup_payload(
        self, *, file_hash: str, credential: CredentialMaterial
    ) -> AbuseChJsonResult: ...

    async def aclose(self) -> None: ...


class UrlhausHttpClient:
    """:class:`UrlhausClient` over the shared abuse.ch transport."""

    def __init__(
        self,
        config: UrlhausConfig | None = None,
        *,
        provider_id: str = URLHAUS_PROVIDER_ID,
        transport: httpx.AsyncBaseTransport | None = None,
        http_client: ProviderHttpClient | None = None,
    ) -> None:
        self._config = UrlhausConfig() if config is None else config
        self._provider_id = provider_id
        self._client = AbuseChHttpClient(
            self._config,
            provider_id=provider_id,
            # URLhaus routes by path, so no ``query`` field is ever sent; the
            # empty set is correct and means "a query field would be refused".
            allowed_queries=frozenset(),
            transport=transport,
            http_client=http_client,
        )

    @property
    def config(self) -> UrlhausConfig:
        return self._config

    @property
    def provider_id(self) -> str:
        return self._provider_id

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #

    async def lookup_url(self, *, url: str, credential: CredentialMaterial) -> AbuseChJsonResult:
        """Ask URLhaus about one exact URL.

        The URL is sent *to URLhaus*; it is never fetched. This is the whole
        reason TI Recon can investigate a malware-distribution URL safely.
        """
        value = self._validate_text(url, limit=_MAX_URL, operation=UrlhausOperation.URL)
        return await self._client.query(
            "v1/url/",
            form={"url": value},
            operation=UrlhausOperation.URL,
            credential=credential,
        )

    async def lookup_host(self, *, host: str, credential: CredentialMaterial) -> AbuseChJsonResult:
        """Ask URLhaus what malware URLs it has tracked on one host."""
        value = self._validate_text(host, limit=_MAX_HOST, operation=UrlhausOperation.HOST)
        return await self._client.query(
            "v1/host/",
            form={"host": value},
            operation=UrlhausOperation.HOST,
            credential=credential,
        )

    async def lookup_payload(
        self, *, file_hash: str, credential: CredentialMaterial
    ) -> AbuseChJsonResult:
        """Ask URLhaus about one file it collected from a tracked URL.

        The field name depends on the digest length, because URLhaus indexes
        payloads under two separate keys. Sending a SHA-1 under either would be
        a request the API cannot answer, so it is refused here instead.
        """
        digest = hex_digest(file_hash, lengths=URLHAUS_HASH_LENGTHS)
        if digest is None:
            raise ProviderInvalidRequestError(
                self._provider_id,
                message="value is not an MD5 or SHA-256 digest",
                operation=UrlhausOperation.PAYLOAD,
            )
        field = "sha256_hash" if len(digest) == 64 else "md5_hash"
        return await self._client.query(
            "v1/payload/",
            form={field: digest},
            operation=UrlhausOperation.PAYLOAD,
            credential=credential,
        )

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        return f"<UrlhausHttpClient provider={self._provider_id} host={self._config.host}>"

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _validate_text(self, value: str, *, limit: int, operation: str) -> str:
        candidate = value.strip() if isinstance(value, str) else ""
        if not candidate:
            raise ProviderInvalidRequestError(
                self._provider_id, message="lookup value is empty", operation=operation
            )
        if len(candidate) > limit:
            raise ProviderInvalidRequestError(
                self._provider_id, message="lookup value is too long", operation=operation
            )
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in candidate):
            raise ProviderInvalidRequestError(
                self._provider_id,
                message="lookup value contains control characters",
                operation=operation,
            )
        return candidate


if TYPE_CHECKING:  # pragma: no cover - a compile-time conformance assertion
    # Fails type checking if the concrete client ever stops satisfying the
    # read-only protocol, which is what keeps "no submission, no download"
    # structural rather than a comment.
    _protocol_conformance: type[UrlhausClient] = UrlhausHttpClient
