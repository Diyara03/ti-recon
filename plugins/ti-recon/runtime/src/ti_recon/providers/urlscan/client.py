"""The urlscan.io HTTP client (Task 8).

The only module in the urlscan package that performs I/O. Everything above it —
search building, normalization, forensics — works on plain parsed payloads and
bounded byte strings, so none of it can reach the network by accident.

What this client deliberately cannot do
---------------------------------------

There is **no submission method**. urlscan's ``POST /api/v1/scan`` makes
urlscan's crawler visit a URL: an active operation against the target and, for a
public scan, a disclosure of what is being investigated. The
:class:`UrlscanClient` protocol exposes reads only, the concrete implementation
never calls :meth:`~ti_recon.providers.transport.ProviderHttpClient.post`, and
there is no code path — not even an unused one — that would submit, rescan,
delete, change visibility or download a stored sample.

Every identifier that reaches a URL path is validated against a strict pattern
first. A scan id is a UUID and a response body is addressed by its SHA-256; both
are checked before they are interpolated, so a hostile value from a search
result cannot become part of a path.

Redirects
---------

The shared transport never follows redirects, because a redirect is a
provider-controlled way to move an authenticated request to another host. Some
urlscan artifact URLs do redirect legitimately, though, so this client follows a
bounded number of hops **within urlscan.io only**. A redirect pointing anywhere
else is refused rather than followed: following it would hand the analyst's
API key to a host that is not urlscan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from types import TracebackType
from typing import TYPE_CHECKING, Any, Final, Protocol, Self
from urllib.parse import parse_qsl, urlsplit

import httpx

from ti_recon.credentials.models import CredentialMaterial
from ti_recon.providers.errors import (
    ProviderError,
    ProviderInvalidRequestError,
    ProviderSchemaError,
)
from ti_recon.providers.transport import (
    BoundedResponse,
    ProviderHttpClient,
    ProviderTransportSecurityError,
)
from ti_recon.providers.urlscan.config import UrlscanConfig, build_transport_config
from ti_recon.providers.urlscan.descriptor import URLSCAN_PROVIDER_ID
from ti_recon.providers.urlscan.errors import translate_status_error

__all__ = [
    "MAX_SEARCH_SIZE",
    "UrlscanArtifact",
    "UrlscanClient",
    "UrlscanHttpClient",
    "UrlscanJsonResult",
    "UrlscanOperation",
]


class UrlscanOperation:
    """Operation names used for logging, metrics and error attribution."""

    QUOTAS: Final[str] = "urlscan.quotas"
    SEARCH: Final[str] = "urlscan.search"
    RESULT: Final[str] = "urlscan.result"
    SCREENSHOT: Final[str] = "urlscan.screenshot"
    DOM: Final[str] = "urlscan.dom"
    RESPONSE_BODY: Final[str] = "urlscan.response_body"


#: urlscan caps a search page at 10 000; TI Recon's own bounds are far smaller
#: and live in the search layer. This is only the hard ceiling the API accepts.
MAX_SEARCH_SIZE: Final[int] = 10_000

_QUOTAS_PATH: Final[str] = "user/quotas/"
_SEARCH_PATH: Final[str] = "api/v1/search/"

#: urlscan identifies a scan by UUID and a stored response body by its SHA-256.
#: Both are validated before they are interpolated into a path.
_SCAN_UUID_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{64}$")

#: urlscan's paging cursor is the previous hit's ``sort`` values joined by
#: commas: a timestamp and a scan id. Anything outside that shape is rejected
#: rather than passed through, since it becomes a query parameter.
_SEARCH_AFTER_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9A-Za-z_.:,+-]{1,200}$")

#: Bound on a query string. The search layer builds these from an allowlist;
#: this is a backstop against an unbounded value reaching the wire.
_MAX_QUERY_LENGTH: Final[int] = 1024

#: Rate-limit headers are the only response headers worth carrying upwards.
#: Keeping an allowlist means no ``Set-Cookie`` or vendor header ever ends up
#: in a result, a cache entry or a snapshot.
_RATE_LIMIT_HEADER_PREFIX: Final[str] = "x-rate-limit-"

_REDIRECT_STATUSES: Final[frozenset[int]] = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True, slots=True)
class UrlscanJsonResult:
    """A decoded JSON response plus the metering headers that came with it."""

    payload: dict[str, Any]
    rate_limit_headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class UrlscanArtifact:
    """A stored page artifact, read up to an agreed byte ceiling.

    ``truncated`` means urlscan had more to send than the configured cap
    allowed. A truncated screenshot is not a screenshot, so callers treat the
    flag as "unusable" for binary artifacts and as "partial" for text.
    """

    content: bytes
    content_type: str
    truncated: bool
    rate_limit_headers: dict[str, str] = field(default_factory=dict)

    @property
    def size_bytes(self) -> int:
        return len(self.content)


class UrlscanClient(Protocol):
    """The read-only surface the rest of the urlscan package may use.

    Passive by construction: there is no method here that causes urlscan to
    visit anything. Adding one would mean changing this protocol, which is the
    point of having it.
    """

    async def get_quotas(self, *, credential: CredentialMaterial) -> UrlscanJsonResult: ...

    async def search(
        self,
        *,
        query: str,
        size: int,
        search_after: str | None = None,
        credential: CredentialMaterial,
    ) -> UrlscanJsonResult: ...

    async def get_result(
        self, *, scan_id: str, credential: CredentialMaterial
    ) -> UrlscanJsonResult: ...

    async def get_screenshot(
        self, *, scan_id: str, credential: CredentialMaterial
    ) -> UrlscanArtifact: ...

    async def get_dom(self, *, scan_id: str, credential: CredentialMaterial) -> UrlscanArtifact: ...

    async def get_response_body(
        self, *, body_sha256: str, credential: CredentialMaterial
    ) -> UrlscanArtifact: ...

    async def aclose(self) -> None: ...


class UrlscanHttpClient:
    """:class:`UrlscanClient` over the shared, host-pinned provider transport."""

    def __init__(
        self,
        config: UrlscanConfig | None = None,
        *,
        provider_id: str = URLSCAN_PROVIDER_ID,
        transport: httpx.AsyncBaseTransport | None = None,
        http_client: ProviderHttpClient | None = None,
    ) -> None:
        self._config = UrlscanConfig() if config is None else config
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
    def config(self) -> UrlscanConfig:
        return self._config

    @property
    def provider_id(self) -> str:
        return self._provider_id

    # ------------------------------------------------------------------ #
    # JSON reads
    # ------------------------------------------------------------------ #

    async def get_quotas(self, *, credential: CredentialMaterial) -> UrlscanJsonResult:
        """The account's own quota state.

        Unlike GTI's, urlscan's quota endpoint takes the key as a header, so its
        path holds nothing sensitive and can be logged normally.
        """
        return await self._get_json(
            _QUOTAS_PATH, operation=UrlscanOperation.QUOTAS, credential=credential
        )

    async def search(
        self,
        *,
        query: str,
        size: int,
        search_after: str | None = None,
        credential: CredentialMaterial,
    ) -> UrlscanJsonResult:
        """Run a historical search.

        The query is *not* built here — the search layer composes it from an
        allowlist of fields and escaped values. What happens here is a shape
        check: a bounded, control-character-free string, sent as a query
        parameter rather than spliced into a path.
        """
        self._validate_query(query)
        params: dict[str, str | int] = {"q": query, "size": self._validate_size(size)}
        if search_after is not None:
            params["search_after"] = self._validate_search_after(search_after)
        return await self._get_json(
            _SEARCH_PATH,
            operation=UrlscanOperation.SEARCH,
            credential=credential,
            params=params,
        )

    async def get_result(
        self, *, scan_id: str, credential: CredentialMaterial
    ) -> UrlscanJsonResult:
        """One completed scan's stored result document."""
        validated = self._validate_scan_id(scan_id, operation=UrlscanOperation.RESULT)
        return await self._get_json(
            f"api/v1/result/{validated}/",
            operation=UrlscanOperation.RESULT,
            credential=credential,
        )

    # ------------------------------------------------------------------ #
    # Artifact reads (explicit forensics only)
    # ------------------------------------------------------------------ #

    async def get_screenshot(
        self, *, scan_id: str, credential: CredentialMaterial
    ) -> UrlscanArtifact:
        """The stored screenshot of a completed scan."""
        validated = self._validate_scan_id(scan_id, operation=UrlscanOperation.SCREENSHOT)
        return await self._get_artifact(
            f"screenshots/{validated}.png",
            operation=UrlscanOperation.SCREENSHOT,
            credential=credential,
            max_bytes=self._config.max_screenshot_bytes,
        )

    async def get_dom(self, *, scan_id: str, credential: CredentialMaterial) -> UrlscanArtifact:
        """The stored DOM snapshot of a completed scan.

        Returned as bytes and analysed statically. Nothing in TI Recon renders
        or executes it.
        """
        validated = self._validate_scan_id(scan_id, operation=UrlscanOperation.DOM)
        return await self._get_artifact(
            f"dom/{validated}/",
            operation=UrlscanOperation.DOM,
            credential=credential,
            max_bytes=self._config.max_dom_bytes,
        )

    async def get_response_body(
        self, *, body_sha256: str, credential: CredentialMaterial
    ) -> UrlscanArtifact:
        """One stored HTTP response body, addressed by its SHA-256.

        Only bodies urlscan already holds. This never fetches from the original
        site, and the digest is validated before it reaches the path.
        """
        validated = self._validate_sha256(body_sha256, operation=UrlscanOperation.RESPONSE_BODY)
        return await self._get_artifact(
            f"responses/{validated}/",
            operation=UrlscanOperation.RESPONSE_BODY,
            credential=credential,
            max_bytes=self._config.max_response_bytes,
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
        return f"<UrlscanHttpClient provider={self._provider_id} host={self._config.host}>"

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
    ) -> UrlscanJsonResult:
        current_path = path
        current_params = params
        for _ in range(self._config.max_redirect_hops + 1):
            response = await self._http.get(
                current_path,
                params=current_params,
                credential=credential,
                operation=operation,
            )
            redirect = self._same_origin_redirect(
                response.status_code, response.headers.get("location"), operation=operation
            )
            if redirect is None:
                if response.status_code >= 400:
                    raise translate_status_error(
                        response, provider_id=self._provider_id, operation=operation
                    )
                return UrlscanJsonResult(
                    payload=self._decode_json(response, operation=operation),
                    rate_limit_headers=self._rate_limit_headers(response.headers),
                )
            current_path, current_params = redirect
        raise self._error(ProviderInvalidRequestError, "too many redirects", operation=operation)

    async def _get_artifact(
        self,
        path: str,
        *,
        operation: str,
        credential: CredentialMaterial,
        max_bytes: int,
    ) -> UrlscanArtifact:
        current_path = path
        current_params: dict[str, str | int] | None = None
        for _ in range(self._config.max_redirect_hops + 1):
            response = await self._http.get_bounded(
                current_path,
                max_bytes=max_bytes,
                params=current_params,
                credential=credential,
                operation=operation,
            )
            redirect = self._same_origin_redirect(
                response.status_code, response.headers.get("location"), operation=operation
            )
            if redirect is None:
                if response.status_code >= 400:
                    raise self._artifact_status_error(response, operation=operation)
                return UrlscanArtifact(
                    content=response.content,
                    content_type=self._content_type(response.headers),
                    truncated=response.truncated,
                    rate_limit_headers=self._rate_limit_headers(response.headers),
                )
            current_path, current_params = redirect
        raise self._error(ProviderInvalidRequestError, "too many redirects", operation=operation)

    def _artifact_status_error(self, response: BoundedResponse, *, operation: str) -> ProviderError:
        """Normalize a failed artifact fetch.

        The body is not inspected for a message: an artifact endpoint returns
        page content, and page content is exactly what must never end up inside
        an error string.
        """
        return translate_status_error(
            httpx.Response(
                status_code=response.status_code,
                headers={
                    name: value
                    for name, value in response.headers.items()
                    if name.lower().startswith(_RATE_LIMIT_HEADER_PREFIX)
                    or name.lower() == "retry-after"
                },
            ),
            provider_id=self._provider_id,
            operation=operation,
            include_detail=False,
        )

    def _same_origin_redirect(
        self, status_code: int, location: str | None, *, operation: str
    ) -> tuple[str, dict[str, str | int] | None] | None:
        """Resolve a redirect, or refuse it.

        Returns the relative path and query to retry, or ``None`` when the
        response was not a redirect. A ``Location`` that leaves urlscan.io
        raises: the next request would carry the API key, and that key belongs
        to nobody but urlscan.
        """
        if status_code not in _REDIRECT_STATUSES:
            return None
        if not location:
            raise self._error(
                ProviderSchemaError, "redirect without a location", operation=operation
            )
        target = urlsplit(location.strip())
        if target.scheme or target.netloc:
            same_origin = target.scheme == "https" and target.hostname == self._config.hostname
            if not same_origin:
                raise ProviderTransportSecurityError(
                    self._provider_id,
                    message="refusing to follow a redirect off the provider host",
                    operation=operation,
                )
        if location.strip().startswith("//"):
            # Scheme-relative: already handled above when it carried a host, but
            # a bare "//" with no host is nonsense rather than a location.
            raise ProviderTransportSecurityError(
                self._provider_id,
                message="refusing to follow a scheme-relative redirect",
                operation=operation,
            )
        params: dict[str, str | int] | None = None
        if target.query:
            # Carried as parameters rather than inside the path, so the query
            # never reaches the transport's log line.
            params = dict(parse_qsl(target.query, keep_blank_values=True))
        return target.path or "/", params

    def _decode_json(self, response: httpx.Response, *, operation: str) -> dict[str, Any]:
        try:
            payload: Any = response.json()
        except ValueError as exc:
            raise self._error(
                ProviderSchemaError, "response was not valid JSON", operation=operation
            ) from exc
        if not isinstance(payload, dict):
            raise self._error(
                ProviderSchemaError, "response was not a JSON object", operation=operation
            )
        return payload

    @staticmethod
    def _rate_limit_headers(headers: httpx.Headers) -> dict[str, str]:
        return {
            name.lower(): value
            for name, value in headers.items()
            if name.lower().startswith(_RATE_LIMIT_HEADER_PREFIX)
        }

    @staticmethod
    def _content_type(headers: httpx.Headers) -> str:
        raw = headers.get("content-type", "application/octet-stream")
        # Parameters (charset, boundary) are dropped: the media type is all any
        # caller needs, and the rest is provider-controlled text.
        return raw.split(";", 1)[0].strip().lower() or "application/octet-stream"

    def _error(
        self, error_class: type[ProviderError], message: str, *, operation: str
    ) -> ProviderError:
        return error_class(self._provider_id, message=message, operation=operation)

    def _validate_scan_id(self, scan_id: str, *, operation: str) -> str:
        if not _SCAN_UUID_PATTERN.match(scan_id.strip()):
            raise self._error(
                ProviderInvalidRequestError, "scan id is not a UUID", operation=operation
            )
        return scan_id.strip().lower()

    def _validate_sha256(self, digest: str, *, operation: str) -> str:
        if not _SHA256_PATTERN.match(digest.strip()):
            raise self._error(
                ProviderInvalidRequestError,
                "response body id is not a SHA-256 digest",
                operation=operation,
            )
        return digest.strip().lower()

    def _validate_query(self, query: str) -> None:
        candidate = query.strip()
        if not candidate:
            raise self._error(
                ProviderInvalidRequestError,
                "search query is empty",
                operation=UrlscanOperation.SEARCH,
            )
        if len(candidate) > _MAX_QUERY_LENGTH:
            raise self._error(
                ProviderInvalidRequestError,
                "search query is too long",
                operation=UrlscanOperation.SEARCH,
            )
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in candidate):
            raise self._error(
                ProviderInvalidRequestError,
                "search query contains control characters",
                operation=UrlscanOperation.SEARCH,
            )

    def _validate_size(self, size: int) -> int:
        if size < 1 or size > MAX_SEARCH_SIZE:
            raise self._error(
                ProviderInvalidRequestError,
                "search size out of range",
                operation=UrlscanOperation.SEARCH,
            )
        return size

    def _validate_search_after(self, cursor: str) -> str:
        if not _SEARCH_AFTER_PATTERN.match(cursor.strip()):
            raise self._error(
                ProviderInvalidRequestError,
                "paging cursor has an unexpected shape",
                operation=UrlscanOperation.SEARCH,
            )
        return cursor.strip()


if TYPE_CHECKING:  # pragma: no cover - a compile-time conformance assertion
    # Fails type checking if the concrete client ever stops satisfying the
    # read-only protocol, which is what keeps "no submission method" structural
    # rather than a comment.
    _protocol_conformance: type[UrlscanClient] = UrlscanHttpClient
