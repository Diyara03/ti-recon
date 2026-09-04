"""The Censys Platform HTTP client (Task 9).

The only module in the Censys package that performs I/O. Everything above it —
asset derivation, normalization, the adapter — works on plain parsed payloads, so
none of it can reach the network by accident.

What this client deliberately cannot do
---------------------------------------

Four reads, and nothing else. Two of them cost a credit (the asset lookups) and
two cost none (the credit balances).

There is **no search method**. Censys's ``POST /v3/global/search/query`` is a
CenQL query endpoint: it needs query construction and escaping, it needs a
pagination strategy, it costs credits per page rather than per asset, and
deciding *what* to search for is planner work that does not exist yet. Exposing
it here would mean one of those decisions getting made by accident. The
:class:`CensysClient` protocol has no query method, the implementation never
calls :meth:`~ti_recon.providers.transport.ProviderHttpClient.post`, and there
is no code path — not even an unused one — that would submit a query, request a
rescan, start a live scan or run a discovery job.

Path safety
-----------

Three path parameters exist, and each is validated before interpolation:

* an IP address is parsed with :mod:`ipaddress` and re-rendered from the parsed
  object, so what reaches the URL came out of the parser rather than the caller;
* a hostname is IDNA-validated by the same normalizer that validates analyst
  input, and a port must be an integer in range;
* an organization id must match a strict identifier pattern.

Schema negotiation
------------------

Each asset endpoint asks for the exact response schema this adapter was written
against, via ``Accept``. A future incompatible schema is then a visible failure
rather than quietly reshaped evidence.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from types import TracebackType
from typing import TYPE_CHECKING, Any, Final, Protocol, Self

import httpx

from ti_recon.credentials.models import CredentialMaterial
from ti_recon.normalization.errors import NormalizationError
from ti_recon.normalization.observables import normalize_domain
from ti_recon.providers.censys.config import (
    CENSYS_HOST_ACCEPT,
    CENSYS_JSON_ACCEPT,
    CENSYS_WEB_PROPERTY_ACCEPT,
    CensysConfig,
    build_transport_config,
)
from ti_recon.providers.censys.descriptor import CENSYS_PROVIDER_ID
from ti_recon.providers.censys.errors import translate_status_error
from ti_recon.providers.censys.organizations import normalize_organization_id
from ti_recon.providers.errors import (
    ProviderError,
    ProviderInvalidRequestError,
    ProviderSchemaError,
)
from ti_recon.providers.transport import ProviderHttpClient

__all__ = [
    "CensysClient",
    "CensysHttpClient",
    "CensysJsonResult",
    "CensysOperation",
]


class CensysOperation:
    """Operation names used for logging, metrics and error attribution."""

    HOST: Final[str] = "censys.host"
    WEB_PROPERTY: Final[str] = "censys.web_property"
    USER_CREDITS: Final[str] = "censys.user_credits"
    ORGANIZATION_CREDITS: Final[str] = "censys.organization_credits"


#: Metering headers worth carrying upwards. An allow-list, so no ``Set-Cookie``
#: or vendor header ever ends up in a result, a cache entry or a snapshot.
_METERING_HEADER_PREFIXES: Final[tuple[str, ...]] = ("x-ratelimit-", "x-rate-limit-")
_METERING_HEADERS: Final[frozenset[str]] = frozenset({"retry-after"})


@dataclass(frozen=True, slots=True)
class CensysJsonResult:
    """A decoded JSON response plus the metering headers that came with it."""

    payload: dict[str, Any]
    metering_headers: dict[str, str] = field(default_factory=dict)


class CensysClient(Protocol):
    """The read-only surface the rest of the Censys package may use.

    Passive by construction: every method reads something Censys already
    scanned. Adding a search or a rescan would mean changing this protocol,
    which is the point of having it.
    """

    async def get_host(self, *, ip: str, credential: CredentialMaterial) -> CensysJsonResult: ...

    async def get_web_property(
        self, *, hostname: str, port: int, credential: CredentialMaterial
    ) -> CensysJsonResult: ...

    async def get_user_credits(self, *, credential: CredentialMaterial) -> CensysJsonResult: ...

    async def get_organization_credits(
        self, *, organization_id: str, credential: CredentialMaterial
    ) -> CensysJsonResult: ...

    async def aclose(self) -> None: ...


class CensysHttpClient:
    """:class:`CensysClient` over the shared, host-pinned provider transport."""

    def __init__(
        self,
        config: CensysConfig | None = None,
        *,
        provider_id: str = CENSYS_PROVIDER_ID,
        transport: httpx.AsyncBaseTransport | None = None,
        http_client: ProviderHttpClient | None = None,
    ) -> None:
        self._config = CensysConfig() if config is None else config
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
    def config(self) -> CensysConfig:
        return self._config

    @property
    def provider_id(self) -> str:
        return self._provider_id

    # ------------------------------------------------------------------ #
    # Asset reads — these cost credits
    # ------------------------------------------------------------------ #

    async def get_host(self, *, ip: str, credential: CredentialMaterial) -> CensysJsonResult:
        """Everything Censys last observed on one address."""
        address = self._validate_address(ip, operation=CensysOperation.HOST)
        return await self._get_json(
            f"v3/global/asset/host/{address}",
            operation=CensysOperation.HOST,
            credential=credential,
            accept=CENSYS_HOST_ACCEPT,
        )

    async def get_web_property(
        self, *, hostname: str, port: int, credential: CredentialMaterial
    ) -> CensysJsonResult:
        """Everything Censys last observed on one ``hostname:port``."""
        name = self._validate_hostname(hostname, operation=CensysOperation.WEB_PROPERTY)
        number = self._validate_port(port, operation=CensysOperation.WEB_PROPERTY)
        return await self._get_json(
            f"v3/global/asset/webproperty/{name}:{number}",
            operation=CensysOperation.WEB_PROPERTY,
            credential=credential,
            accept=CENSYS_WEB_PROPERTY_ACCEPT,
        )

    # ------------------------------------------------------------------ #
    # Account reads — these cost nothing
    # ------------------------------------------------------------------ #

    async def get_user_credits(self, *, credential: CredentialMaterial) -> CensysJsonResult:
        """The credit balance of the account the token belongs to.

        Free. This is what makes it possible to validate a token and notice an
        empty wallet without spending a credit to find out.
        """
        return await self._get_json(
            "v3/accounts/users/credits",
            operation=CensysOperation.USER_CREDITS,
            credential=credential,
            accept=CENSYS_JSON_ACCEPT,
        )

    async def get_organization_credits(
        self, *, organization_id: str, credential: CredentialMaterial
    ) -> CensysJsonResult:
        """The credit balance of one organization. Also free."""
        identifier = normalize_organization_id(organization_id)
        if identifier is None:
            raise self._invalid(
                "organization id has an unusable shape",
                operation=CensysOperation.ORGANIZATION_CREDITS,
            )
        return await self._get_json(
            f"v3/accounts/organizations/{identifier}/credits",
            operation=CensysOperation.ORGANIZATION_CREDITS,
            credential=credential,
            accept=CENSYS_JSON_ACCEPT,
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
        return f"<CensysHttpClient provider={self._provider_id} host={self._config.host}>"

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    async def _get_json(
        self,
        path: str,
        *,
        operation: str,
        credential: CredentialMaterial,
        accept: str,
    ) -> CensysJsonResult:
        response = await self._http.get(
            path,
            headers={"Accept": accept},
            credential=credential,
            operation=operation,
        )
        if 200 <= response.status_code < 300:
            return CensysJsonResult(
                payload=self._decode_json(response, operation=operation),
                metering_headers=self._metering_headers(response.headers),
            )
        if 300 <= response.status_code < 400:
            # The transport never follows redirects, and a redirect on an
            # authenticated API read is a provider-controlled way to move the
            # request elsewhere. Reported as a shape change rather than chased.
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

    def _validate_address(self, value: str, *, operation: str) -> str:
        """Parse an address and re-render it from the parsed object.

        Returning ``str(parsed)`` rather than the input is the point: whatever
        reaches the URL came out of :mod:`ipaddress`. IPv6 is accepted here — a
        Censys host asset is addressed the same way in both families.
        """
        try:
            address = ipaddress.ip_address(value.strip())
        except (ValueError, AttributeError) as exc:
            raise self._invalid("value is not an IP address", operation=operation) from exc
        return str(address)

    def _validate_hostname(self, value: str, *, operation: str) -> str:
        """IDNA-validate a hostname with the same normalizer analyst input uses.

        A hostname reaching this client came from a URL somebody is
        investigating, so it is not more trustworthy than something a user
        typed. The normalized form is ASCII and contains no delimiter that could
        escape a path segment.
        """
        try:
            normalized = normalize_domain(value)
        except NormalizationError as exc:
            raise self._invalid("value is not a hostname", operation=operation) from exc
        return normalized.canonical_value

    def _validate_port(self, value: int, *, operation: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            raise self._invalid("port is out of range", operation=operation)
        return value

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
    # read-only protocol, which is what keeps "no search, no rescan" structural
    # rather than a comment.
    _protocol_conformance: type[CensysClient] = CensysHttpClient
