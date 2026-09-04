"""The ThreatFox HTTP client (Task 10).

The only module in the ThreatFox package that performs I/O. Everything above it
— matching, normalization, the adapter — works on plain parsed payloads, so none
of it can reach the network by accident.

What this client deliberately cannot do
---------------------------------------

Two queries, and nothing else: ``search_ioc`` and ``search_hash``. Both are
reads about one observable.

ThreatFox also offers ``submit_ioc``, ``get_iocs``, ``taginfo`` and
``malwareinfo``. The first submits an analyst's indicator to a public database —
an active operation and a disclosure of what is being investigated. The others
are bulk and hunting workflows that belong to a query planner, not to a
per-observable lookup.

None of them can be reached from here. :data:`ALLOWED_QUERIES` is the complete
set this client may send, the shared transport refuses a form naming anything
else *before* building a request, and a test asserts the set directly. Because
these APIs take their parameters in a form body, that allow-list — rather than
"never calls POST" — is what makes passivity structural.

Input safety
------------

A search term is an analyst's observable and reaches the provider verbatim, so
it is bounded and control-character checked first. A hash is shape-checked
against the two digest lengths ThreatFox accepts, so a value that is not a
digest never becomes a query.
"""

from __future__ import annotations

from types import TracebackType
from typing import TYPE_CHECKING, Final, Protocol, Self

import httpx

from ti_recon.credentials.models import CredentialMaterial
from ti_recon.providers.abusech.client import (
    AbuseChBodyEncoding,
    AbuseChHttpClient,
    AbuseChJsonResult,
)
from ti_recon.providers.abusech.config import THREATFOX_HOST, AbuseChConfig
from ti_recon.providers.abusech.values import hex_digest
from ti_recon.providers.errors import ProviderInvalidRequestError
from ti_recon.providers.threatfox.descriptor import THREATFOX_PROVIDER_ID
from ti_recon.providers.transport import ProviderHttpClient

__all__ = [
    "ALLOWED_QUERIES",
    "THREATFOX_BODY_ENCODING",
    "THREATFOX_HASH_LENGTHS",
    "ThreatFoxClient",
    "ThreatFoxConfig",
    "ThreatFoxHttpClient",
    "ThreatFoxOperation",
]


class ThreatFoxOperation:
    """Operation names used for logging, metrics and error attribution."""

    SEARCH_IOC: Final[str] = "threatfox.search_ioc"
    SEARCH_HASH: Final[str] = "threatfox.search_hash"


#: The complete set of ThreatFox operations this integration may perform.
#:
#: ``submit_ioc`` is absent because submitting an analyst's indicator to a public
#: database is an active operation. ``get_iocs``, ``taginfo`` and ``malwareinfo``
#: are absent because they are bulk and hunting queries.
ALLOWED_QUERIES: Final[frozenset[str]] = frozenset({"search_ioc", "search_hash"})

#: Digest lengths ThreatFox's hash search accepts: MD5 and SHA-256.
THREATFOX_HASH_LENGTHS: Final[frozenset[int]] = frozenset({32, 64})

#: ThreatFox takes its parameters as a **JSON object**, not as form data.
#:
#: The one place the three abuse.ch platforms disagree, and the failure mode is
#: nasty: a form-encoded body is not rejected, it is *ignored*, and ThreatFox
#: answers as though nothing had been asked. That reads as ``no_result``, which
#: normalizes to a perfectly ordinary "not currently listed" — so a wrong
#: encoding here looks exactly like a clean lookup rather than like a bug.
#:
#: URLhaus and MalwareBazaar keep form encoding; MalwareBazaar's documentation
#: states it explicitly.
THREATFOX_BODY_ENCODING: Final[AbuseChBodyEncoding] = AbuseChBodyEncoding.JSON

#: The single API path. ThreatFox routes everything through one endpoint and
#: distinguishes operations by the ``query`` body field.
_API_PATH: Final[str] = "api/v1/"

#: Bound on a search term before it is sent. A URL observable can be long; it is
#: never unbounded.
_MAX_SEARCH_TERM: Final[int] = 2048


class ThreatFoxConfig(AbuseChConfig):
    """How to talk to ThreatFox, minus the credential."""

    host: str = THREATFOX_HOST


class ThreatFoxClient(Protocol):
    """The read-only surface the rest of the ThreatFox package may use.

    Passive by construction: neither method causes ThreatFox to record anything.
    Adding a submission or hunting method would mean changing this protocol,
    which is the point of having one.
    """

    async def search_ioc(
        self, *, search_term: str, exact_match: bool, credential: CredentialMaterial
    ) -> AbuseChJsonResult: ...

    async def search_hash(
        self, *, file_hash: str, credential: CredentialMaterial
    ) -> AbuseChJsonResult: ...

    async def aclose(self) -> None: ...


class ThreatFoxHttpClient:
    """:class:`ThreatFoxClient` over the shared abuse.ch transport."""

    def __init__(
        self,
        config: ThreatFoxConfig | None = None,
        *,
        provider_id: str = THREATFOX_PROVIDER_ID,
        transport: httpx.AsyncBaseTransport | None = None,
        http_client: ProviderHttpClient | None = None,
    ) -> None:
        self._config = ThreatFoxConfig() if config is None else config
        self._provider_id = provider_id
        self._client = AbuseChHttpClient(
            self._config,
            provider_id=provider_id,
            allowed_queries=ALLOWED_QUERIES,
            # ThreatFox reads a JSON object, unlike its two siblings. See
            # THREATFOX_BODY_ENCODING.
            body_encoding=THREATFOX_BODY_ENCODING,
            transport=transport,
            http_client=http_client,
        )

    @property
    def config(self) -> ThreatFoxConfig:
        return self._config

    @property
    def provider_id(self) -> str:
        return self._provider_id

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #

    async def search_ioc(
        self, *, search_term: str, exact_match: bool, credential: CredentialMaterial
    ) -> AbuseChJsonResult:
        """Search current ThreatFox IOCs for one observable.

        ``exact_match`` is the caller's decision and it matters. A domain or a
        URL is stored as itself, so an exact search is both correct and cheap.
        An address is usually stored as ``ip:port``, which an exact search for a
        bare address would never match — so that lookup asks for a loose match
        and then validates every result locally. See
        :mod:`ti_recon.providers.threatfox.matching`; nothing the provider
        returns becomes evidence without passing that check.
        """
        term = self._validate_search_term(search_term)
        return await self._client.query(
            _API_PATH,
            form={
                "query": "search_ioc",
                "search_term": term,
                # A JSON boolean, which is what ThreatFox's API documents. The
                # string "true" is not the same value to a JSON parser.
                "exact_match": exact_match,
            },
            operation=ThreatFoxOperation.SEARCH_IOC,
            credential=credential,
        )

    async def search_hash(
        self, *, file_hash: str, credential: CredentialMaterial
    ) -> AbuseChJsonResult:
        """Find the IOCs ThreatFox associates with one malware sample."""
        digest = hex_digest(file_hash, lengths=THREATFOX_HASH_LENGTHS)
        if digest is None:
            raise ProviderInvalidRequestError(
                self._provider_id,
                message="value is not an MD5 or SHA-256 digest",
                operation=ThreatFoxOperation.SEARCH_HASH,
            )
        return await self._client.query(
            _API_PATH,
            form={"query": "search_hash", "hash": digest},
            operation=ThreatFoxOperation.SEARCH_HASH,
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
        return f"<ThreatFoxHttpClient provider={self._provider_id} host={self._config.host}>"

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _validate_search_term(self, value: str) -> str:
        candidate = value.strip() if isinstance(value, str) else ""
        if not candidate:
            raise ProviderInvalidRequestError(
                self._provider_id,
                message="search term is empty",
                operation=ThreatFoxOperation.SEARCH_IOC,
            )
        if len(candidate) > _MAX_SEARCH_TERM:
            raise ProviderInvalidRequestError(
                self._provider_id,
                message="search term is too long",
                operation=ThreatFoxOperation.SEARCH_IOC,
            )
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in candidate):
            raise ProviderInvalidRequestError(
                self._provider_id,
                message="search term contains control characters",
                operation=ThreatFoxOperation.SEARCH_IOC,
            )
        return candidate


if TYPE_CHECKING:  # pragma: no cover - a compile-time conformance assertion
    # Fails type checking if the concrete client ever stops satisfying the
    # read-only protocol, which is what keeps "no submission, no hunting"
    # structural rather than a comment.
    _protocol_conformance: type[ThreatFoxClient] = ThreatFoxHttpClient
