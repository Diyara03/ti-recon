"""The GreyNoise HTTP client (Task 9).

The only module in the GreyNoise package that performs I/O. Everything above it
— normalization, the access-level decision, the adapter — works on plain parsed
payloads, so none of it can reach the network by accident.

What this client deliberately cannot do
---------------------------------------

Reads of two v3 endpoints, and nothing else. There is no GNQL query method, no
timeline method, no bulk or multi-IP method, no feed download and no PCAP or
session retrieval. GreyNoise offers all of those; the :class:`GreyNoiseClient`
protocol exposes none of them, the concrete implementation never calls
:meth:`~ti_recon.providers.transport.ProviderHttpClient.post`, and there is no
code path — not even an unused one — that would submit anything.

The deprecated v2 endpoints are equally absent. Only ``/v3/ip/{ip}`` and
``/v3/community/{ip}`` exist here.

Path safety
-----------

The single path parameter is an IP address. It is parsed with
:mod:`ipaddress` and re-rendered from the parsed object before it is
interpolated, so what reaches the URL is a canonical dotted quad and never the
caller's string. A value that is not an IPv4 address cannot become part of a
path at all.

Partial responses
-----------------

GreyNoise answers ``206`` when it returns a document with fields the account is
not entitled to see removed. That is a successful read of a reduced document,
not a failure, so the status travels back with the payload and the adapter
records the run as ``PARTIAL`` rather than discarding real evidence.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from types import TracebackType
from typing import TYPE_CHECKING, Any, Final, Protocol, Self

import httpx

from ti_recon.credentials.models import CredentialMaterial
from ti_recon.providers.errors import (
    ProviderError,
    ProviderInvalidRequestError,
    ProviderSchemaError,
)
from ti_recon.providers.greynoise.config import GreyNoiseConfig, build_transport_config
from ti_recon.providers.greynoise.descriptor import GREYNOISE_PROVIDER_ID
from ti_recon.providers.greynoise.errors import translate_status_error
from ti_recon.providers.transport import ProviderHttpClient

__all__ = [
    "GreyNoiseClient",
    "GreyNoiseHttpClient",
    "GreyNoiseJsonResult",
    "GreyNoiseOperation",
]


class GreyNoiseOperation:
    """Operation names used for logging, metrics and error attribution."""

    IP_CONTEXT: Final[str] = "greynoise.ip_context"
    IP_CONTEXT_QUICK: Final[str] = "greynoise.ip_context_quick"
    COMMUNITY: Final[str] = "greynoise.community"


#: Statuses that carry a usable document. ``206`` means "usable but reduced".
_SUCCESS_STATUSES: Final[frozenset[int]] = frozenset({200, 206})

#: The status GreyNoise uses for a document it trimmed for entitlement reasons.
PARTIAL_STATUS: Final[int] = 206

#: Metering headers worth carrying upwards. An allow-list, so no ``Set-Cookie``
#: or vendor header ever ends up in a result, a cache entry or a snapshot.
_METERING_HEADER_PREFIXES: Final[tuple[str, ...]] = ("x-ratelimit-", "x-rate-limit-")
_METERING_HEADERS: Final[frozenset[str]] = frozenset({"retry-after"})


@dataclass(frozen=True, slots=True)
class GreyNoiseJsonResult:
    """A decoded JSON response, its status, and the metering headers with it.

    ``status_code`` is kept because ``206`` is meaningful: it distinguishes a
    complete document from one GreyNoise reduced for this account.
    """

    payload: dict[str, Any]
    status_code: int = 200
    metering_headers: dict[str, str] = field(default_factory=dict)

    @property
    def is_partial(self) -> bool:
        return self.status_code == PARTIAL_STATUS


class GreyNoiseClient(Protocol):
    """The read-only surface the rest of the GreyNoise package may use.

    Passive by construction: nothing here causes GreyNoise to do anything except
    read out of its own database. Adding a hunting or submission method would
    mean changing this protocol, which is the point of having it.
    """

    async def get_ip_context(
        self, *, ip: str, quick: bool = False, credential: CredentialMaterial
    ) -> GreyNoiseJsonResult: ...

    async def get_community(
        self, *, ip: str, credential: CredentialMaterial
    ) -> GreyNoiseJsonResult: ...

    async def aclose(self) -> None: ...


class GreyNoiseHttpClient:
    """:class:`GreyNoiseClient` over the shared, host-pinned provider transport."""

    def __init__(
        self,
        config: GreyNoiseConfig | None = None,
        *,
        provider_id: str = GREYNOISE_PROVIDER_ID,
        transport: httpx.AsyncBaseTransport | None = None,
        http_client: ProviderHttpClient | None = None,
    ) -> None:
        self._config = GreyNoiseConfig() if config is None else config
        self._provider_id = provider_id
        self._http = (
            ProviderHttpClient(
                build_transport_config(self._config, provider_id=provider_id),
                transport=transport,
            )
            if http_client is None
            else http_client
        )

    @property
    def config(self) -> GreyNoiseConfig:
        return self._config

    @property
    def provider_id(self) -> str:
        return self._provider_id

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #

    async def get_ip_context(
        self, *, ip: str, quick: bool = False, credential: CredentialMaterial
    ) -> GreyNoiseJsonResult:
        """The full v3 IP context for one address.

        ``quick=True`` asks GreyNoise for the reduced form of the same document
        — the same endpoint, a cheaper answer. It is a *depth* choice, not an
        entitlement one: a full-access key at QUICK depth uses it deliberately.
        """
        address = self._validate_ip(ip, operation=GreyNoiseOperation.IP_CONTEXT)
        operation = GreyNoiseOperation.IP_CONTEXT_QUICK if quick else GreyNoiseOperation.IP_CONTEXT
        return await self._get_json(
            f"v3/ip/{address}",
            operation=operation,
            credential=credential,
            params={"quick": "true"} if quick else None,
        )

    async def get_community(
        self, *, ip: str, credential: CredentialMaterial
    ) -> GreyNoiseJsonResult:
        """The Community view of one address.

        A much smaller document, available to accounts that cannot read the full
        context. A 404 here is a legitimate answer — GreyNoise has no record of
        the address — and is translated into ``NOT_FOUND`` upstream.
        """
        address = self._validate_ip(ip, operation=GreyNoiseOperation.COMMUNITY)
        return await self._get_json(
            f"v3/community/{address}",
            operation=GreyNoiseOperation.COMMUNITY,
            credential=credential,
        )

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def aclose(self) -> None:
        await self._http.aclose()

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
        return f"<GreyNoiseHttpClient provider={self._provider_id} host={self._config.host}>"

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    async def _get_json(
        self,
        path: str,
        *,
        operation: str,
        credential: CredentialMaterial,
        params: dict[str, str | int] | None = None,
    ) -> GreyNoiseJsonResult:
        response = await self._http.get(
            path, params=params, credential=credential, operation=operation
        )
        if response.status_code in _SUCCESS_STATUSES:
            return GreyNoiseJsonResult(
                payload=self._decode_json(response, operation=operation),
                status_code=response.status_code,
                metering_headers=self._metering_headers(response.headers),
            )
        if 300 <= response.status_code < 400:
            # The transport never follows redirects, and GreyNoise's API has no
            # documented reason to send one. Treated as a shape change rather
            # than chased, because chasing it would carry the key elsewhere.
            raise ProviderSchemaError(
                self._provider_id,
                message="unexpected redirect from the provider API",
                operation=operation,
                provider_error_code=str(response.status_code),
            )
        raise translate_status_error(response, provider_id=self._provider_id, operation=operation)

    def _decode_json(self, response: httpx.Response, *, operation: str) -> dict[str, Any]:
        try:
            payload: Any = response.json()
        except ValueError as exc:
            raise ProviderSchemaError(
                self._provider_id, message="response was not valid JSON", operation=operation
            ) from exc
        if not isinstance(payload, dict):
            raise ProviderSchemaError(
                self._provider_id, message="response was not a JSON object", operation=operation
            )
        return payload

    def _validate_ip(self, value: str, *, operation: str) -> str:
        """Parse an IPv4 address and re-render it from the parsed object.

        Returning ``str(parsed)`` rather than the input is the point: whatever
        reaches the URL came out of :mod:`ipaddress`, so no caller string is
        ever interpolated into a path.
        """
        try:
            address = ipaddress.IPv4Address(value.strip())
        except (ValueError, AttributeError) as exc:
            raise self._invalid("value is not an IPv4 address", operation=operation) from exc
        return str(address)

    def _invalid(self, message: str, *, operation: str) -> ProviderError:
        return ProviderInvalidRequestError(self._provider_id, message=message, operation=operation)

    @staticmethod
    def _metering_headers(headers: httpx.Headers) -> dict[str, str]:
        return {
            name.lower(): value
            for name, value in headers.items()
            if name.lower().startswith(_METERING_HEADER_PREFIXES)
            or name.lower() in _METERING_HEADERS
        }


if TYPE_CHECKING:  # pragma: no cover - a compile-time conformance assertion
    # Fails type checking if the concrete client ever stops satisfying the
    # read-only protocol, which is what keeps "no hunting, no submission"
    # structural rather than a comment.
    _protocol_conformance: type[GreyNoiseClient] = GreyNoiseHttpClient
