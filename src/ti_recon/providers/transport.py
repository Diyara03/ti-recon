"""Shared async provider HTTP transport (Task 5).

One client per provider, pinned to that provider's API base URL. Adapters ask
for a **relative path**; there is deliberately no way to ask this client for an
arbitrary URL.

Why that matters
----------------

TI Recon investigates suspicious URLs. If any function here accepted a full URL,
then somewhere down the line an analyst-submitted URL would reach it — and TI
Recon would be fetching attacker-controlled infrastructure from its own network,
with its own IP, on behalf of whoever submitted the URL. A suspicious URL must
be handed to a provider API built to visit it (a URL scanner), never followed
directly.

So the boundary is structural rather than a rule to remember: the base URL is
fixed at construction, paths are resolved against it, and anything that would
leave the base URL raises :class:`ProviderTransportSecurityError`.

Not implemented here (Task 6)
-----------------------------

Response caching (Redis), a retry engine, exponential backoff with jitter,
coordinated 429 handling, quota counters, provider cooldown, and rate-limit
state shared across workers. This module performs exactly one HTTP attempt per
call.
"""

from __future__ import annotations

import logging
import time
from enum import StrEnum
from types import TracebackType
from typing import Any, Final, Self
from urllib.parse import urljoin, urlsplit

import httpx
from pydantic import Field, model_validator

from ti_recon import __version__
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import ProviderErrorCategory
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.errors import (
    ProviderError,
    ProviderTransientError,
    ProviderUnavailableError,
)
from ti_recon.security import SENSITIVE_KEY_PATTERN

__all__ = [
    "DEFAULT_USER_AGENT",
    "AuthConfig",
    "AuthPlacement",
    "ProviderHttpClient",
    "ProviderTimeoutError",
    "ProviderTransportClosed",
    "ProviderTransportError",
    "ProviderTransportSecurityError",
    "TransportConfig",
    "TransportTimeouts",
]

_logger = logging.getLogger(__name__)

#: Versioned User-Agent so providers can attribute and rate-limit our traffic.
DEFAULT_USER_AGENT: Final[str] = f"ti-recon/{__version__}"

_SAFE_METHODS: Final[frozenset[str]] = frozenset({"GET", "POST", "HEAD"})


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class ProviderTransportError(ProviderError):
    """Base class for transport-level failures."""


class ProviderTransportSecurityError(ProviderTransportError):
    """A request was refused because it would leave the provider's base URL.

    Not a transient condition and never retried: it means a caller tried to use
    a provider client as a general-purpose fetcher.
    """

    category = ProviderErrorCategory.INVALID_REQUEST


class ProviderTransportClosed(ProviderTransportError):
    """The client has been closed and can no longer be used."""

    category = ProviderErrorCategory.INVALID_REQUEST


class ProviderTimeoutError(ProviderTransientError):
    """The provider did not respond within the configured timeout."""


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


class TransportTimeouts(FrozenTiReconModel):
    """Explicit per-phase timeouts.

    All four are set explicitly and none may be disabled. A missing read timeout
    is how one slow provider stalls every worker in the pool.
    """

    connect: float = Field(default=5.0, gt=0.0, le=120.0)
    read: float = Field(default=20.0, gt=0.0, le=300.0)
    write: float = Field(default=10.0, gt=0.0, le=120.0)
    pool: float = Field(default=5.0, gt=0.0, le=120.0)

    def to_httpx(self) -> httpx.Timeout:
        return httpx.Timeout(connect=self.connect, read=self.read, write=self.write, pool=self.pool)


class AuthPlacement(StrEnum):
    """Where a provider expects its credential."""

    NONE = "none"
    HEADER = "header"
    QUERY = "query"


class AuthConfig(FrozenTiReconModel):
    """How to present a credential to one provider.

    Configuration, not a provider integration: it says *where* the credential
    goes, so adapters never touch the raw value and cannot accidentally put it
    somewhere loggable.
    """

    placement: AuthPlacement = AuthPlacement.NONE
    header_name: str | None = Field(default=None, max_length=64)
    query_param: str | None = Field(default=None, max_length=64)
    scheme: str | None = Field(default=None, max_length=32)

    @model_validator(mode="after")
    def _validate_auth(self) -> AuthConfig:
        if self.placement is AuthPlacement.HEADER and not self.header_name:
            msg = "header placement requires header_name"
            raise ValueError(msg)
        if self.placement is AuthPlacement.QUERY and not self.query_param:
            msg = "query placement requires query_param"
            raise ValueError(msg)
        return self

    @classmethod
    def for_auth_type(cls, auth_type: AuthType) -> AuthConfig:
        """A conventional placement for each auth type.

        Providers vary; an adapter overrides this when its provider differs.
        """
        match auth_type:
            case AuthType.BEARER_TOKEN | AuthType.OAUTH:
                return cls(
                    placement=AuthPlacement.HEADER,
                    header_name="Authorization",
                    scheme="Bearer",
                )
            case AuthType.AUTH_KEY:
                return cls(placement=AuthPlacement.HEADER, header_name="Auth-Key")
            case AuthType.API_KEY:
                return cls(placement=AuthPlacement.HEADER, header_name="X-Api-Key")


class TransportConfig(FrozenTiReconModel):
    """Everything a provider client needs, and nothing about a credential."""

    provider_id: str = Field(min_length=1, max_length=64)
    base_url: str = Field(min_length=8, max_length=500)
    timeouts: TransportTimeouts = TransportTimeouts()
    auth: AuthConfig = AuthConfig()
    user_agent: str = DEFAULT_USER_AGENT
    max_connections: int = Field(default=10, ge=1, le=200)
    max_keepalive_connections: int = Field(default=5, ge=0, le=200)
    default_headers: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_config(self) -> TransportConfig:
        parts = urlsplit(self.base_url)
        if parts.scheme != "https":
            msg = "provider base_url must use https"
            raise ValueError(msg)
        if not parts.hostname:
            msg = "provider base_url must include a host"
            raise ValueError(msg)
        if parts.query or parts.fragment:
            msg = "provider base_url must not carry a query or fragment"
            raise ValueError(msg)
        if not self.base_url.endswith("/"):
            # A base URL without a trailing slash silently drops its last path
            # segment when joined, which is a confusing way to leave the API.
            object.__setattr__(self, "base_url", self.base_url + "/")
        for name in self.default_headers:
            if SENSITIVE_KEY_PATTERN.search(name):
                msg = f"default_headers must not carry credential header {name!r}"
                raise ValueError(msg)
        return self

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #


class ProviderHttpClient:
    """An async HTTP client pinned to one provider's API.

    Connection pooling is persistent for the client's lifetime; TLS verification
    is always on and cannot be disabled through this class. Redirects are not
    followed, because a redirect is a provider-controlled way to move a request
    to another host.
    """

    def __init__(
        self,
        config: TransportConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._config = config
        self._closed = False
        headers = {"User-Agent": config.user_agent, **config.default_headers}
        self._client = httpx.AsyncClient(
            base_url=config.base_url,
            timeout=config.timeouts.to_httpx(),
            limits=httpx.Limits(
                max_connections=config.max_connections,
                max_keepalive_connections=config.max_keepalive_connections,
            ),
            headers=headers,
            # Never disabled: there is no configuration path that turns this off.
            verify=True,
            follow_redirects=False,
            transport=transport,
        )

    @property
    def config(self) -> TransportConfig:
        return self._config

    @property
    def provider_id(self) -> str:
        return self._config.provider_id

    @property
    def is_closed(self) -> bool:
        return self._closed

    # ------------------------------------------------------------------ #
    # Requests
    # ------------------------------------------------------------------ #

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str | int] | None = None,
        json: Any | None = None,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        credential: CredentialMaterial | None = None,
        operation: str | None = None,
    ) -> httpx.Response:
        """Perform one request against a path relative to the provider base URL.

        ``path`` is always relative. A leading ``/`` is accepted and treated as
        relative to the base URL, but anything that resolves outside the base URL
        — an absolute URL, a scheme-relative ``//host``, or ``..`` traversal —
        raises :class:`ProviderTransportSecurityError`.
        """
        if self._closed:
            raise ProviderTransportClosed(self.provider_id, operation=operation)
        upper = method.upper()
        if upper not in _SAFE_METHODS:
            raise ProviderTransportSecurityError(
                self.provider_id,
                message=f"method {upper!r} is not permitted",
                operation=operation,
            )
        url = self._resolve(path, operation=operation)
        request_headers = dict(headers or {})
        self._reject_credential_headers(request_headers, operation=operation)
        query = dict(params or {})
        self._apply_auth(request_headers, query, credential)

        started = time.perf_counter()
        try:
            response = await self._client.request(
                upper,
                url,
                params=query or None,
                json=json,
                data=data,
                headers=request_headers,
            )
        except httpx.TimeoutException as exc:
            self._log(upper, path, None, started, operation, outcome="timeout")
            raise ProviderTimeoutError(
                self.provider_id, message="request timed out", operation=operation
            ) from exc
        except httpx.TransportError as exc:
            self._log(upper, path, None, started, operation, outcome="transport_error")
            raise ProviderUnavailableError(
                self.provider_id, message="provider unreachable", operation=operation
            ) from exc

        self._verify_response_origin(response, operation=operation)
        self._log(upper, path, response.status_code, started, operation)
        return response

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        """Convenience wrapper for a GET against a relative provider path."""
        return await self.request("GET", path, **kwargs)

    async def post(self, path: str, **kwargs: Any) -> httpx.Response:
        """Convenience wrapper for a POST against a relative provider path."""
        return await self.request("POST", path, **kwargs)

    # ------------------------------------------------------------------ #
    # SSRF boundary
    # ------------------------------------------------------------------ #

    def _resolve(self, path: str, *, operation: str | None) -> str:
        candidate = path.strip()
        if not candidate:
            raise ProviderTransportSecurityError(
                self.provider_id, message="empty request path", operation=operation
            )
        if "://" in candidate or candidate.startswith("//"):
            raise ProviderTransportSecurityError(
                self.provider_id,
                message="absolute URLs are not permitted; use a relative provider path",
                operation=operation,
            )
        if (
            "\\" in candidate
            or any(ch.isspace() for ch in candidate)
            or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate)
        ):
            raise ProviderTransportSecurityError(
                self.provider_id,
                message="request path contains illegal characters",
                operation=operation,
            )
        relative = candidate.lstrip("/")
        if ".." in relative.split("/"):
            raise ProviderTransportSecurityError(
                self.provider_id,
                message="path traversal is not permitted",
                operation=operation,
            )
        resolved = urljoin(self._config.base_url, relative)
        if not resolved.startswith(self._config.base_url):
            raise ProviderTransportSecurityError(
                self.provider_id,
                message="request would leave the provider base URL",
                operation=operation,
            )
        return resolved

    def _verify_response_origin(self, response: httpx.Response, *, operation: str | None) -> None:
        """Refuse a response that came from anywhere but the configured host."""
        if response.url.host != self._config.host:
            raise ProviderTransportSecurityError(
                self.provider_id,
                message="response originated from an unexpected host",
                operation=operation,
            )

    # ------------------------------------------------------------------ #
    # Auth and logging
    # ------------------------------------------------------------------ #

    def _apply_auth(
        self,
        headers: dict[str, str],
        query: dict[str, str | int],
        credential: CredentialMaterial | None,
    ) -> None:
        """Attach the credential at the very last moment, in one place.

        Adapters never see the raw value; this is the only method that calls
        ``reveal()``.
        """
        auth = self._config.auth
        if credential is None or auth.placement is AuthPlacement.NONE:
            return
        secret = credential.reveal()
        if auth.placement is AuthPlacement.HEADER and auth.header_name:
            headers[auth.header_name] = f"{auth.scheme} {secret}" if auth.scheme else secret
        elif auth.placement is AuthPlacement.QUERY and auth.query_param:
            query[auth.query_param] = secret

    def _reject_credential_headers(self, headers: dict[str, str], *, operation: str | None) -> None:
        """Stop an adapter from passing a credential in as a plain header."""
        for name in headers:
            if SENSITIVE_KEY_PATTERN.search(name):
                raise ProviderTransportSecurityError(
                    self.provider_id,
                    message=(
                        f"header {name!r} must be supplied as a credential, not a plain header"
                    ),
                    operation=operation,
                )

    def _log(
        self,
        method: str,
        path: str,
        status: int | None,
        started: float,
        operation: str | None,
        *,
        outcome: str = "completed",
    ) -> None:
        """Log an allow-list of safe fields.

        Never headers, never cookies, never bodies, and never the query string —
        some providers accept credentials as query parameters, so logging query
        strings would leak keys for exactly those providers.
        """
        _logger.info(
            "provider request %s",
            outcome,
            extra={
                "provider": self.provider_id,
                "http_method": method,
                "provider_path": path.lstrip("/"),
                "operation": operation,
                "status_code": status,
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            },
        )

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def aclose(self) -> None:
        """Close the connection pool. Safe to call more than once."""
        if not self._closed:
            self._closed = True
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
        return (
            f"<ProviderHttpClient provider={self.provider_id} "
            f"base_url={self._config.base_url} closed={self._closed}>"
        )
