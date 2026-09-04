"""urlscan.io client configuration (Task 8).

Everything needed to reach urlscan except the credential. The API key is
resolved per user by the Task 4 layer and applied by the shared transport at
request time; it has no field here, so a configuration object is safe to log,
serialize or compare.
"""

from __future__ import annotations

from typing import Final
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from ti_recon import __version__
from ti_recon.credentials.enums import AuthType
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.transport import (
    AuthConfig,
    AuthPlacement,
    TransportConfig,
    TransportTimeouts,
)
from ti_recon.security import SENSITIVE_KEY_PATTERN

__all__ = [
    "URLSCAN_API_KEY_HEADER",
    "URLSCAN_AUTH_TYPE",
    "URLSCAN_HOST",
    "UrlscanConfig",
    "build_transport_config",
]

#: The only host this provider talks to. Not configurable from a request: the
#: API and the stored artifacts both live here, and nothing a caller supplies
#: may change where an authenticated request goes.
URLSCAN_HOST: Final[str] = "https://urlscan.io"

#: urlscan authenticates with its own header name rather than Authorization.
URLSCAN_API_KEY_HEADER: Final[str] = "API-Key"


class UrlscanConfig(FrozenTiReconModel):
    """How to talk to urlscan, minus the credential."""

    host: str = Field(default=URLSCAN_HOST, min_length=8, max_length=200)
    user_agent: str = Field(default=f"ti-recon/{__version__}", min_length=1, max_length=120)
    timeout_seconds: int = Field(default=30, ge=1, le=300)

    #: Artifact bodies can be large. Each cap is a byte ceiling enforced before
    #: a response is read into memory where the server declares a length, and
    #: again afterwards where it does not.
    max_screenshot_bytes: int = Field(default=5 * 1024 * 1024, ge=1, le=64 * 1024 * 1024)
    max_dom_bytes: int = Field(default=2 * 1024 * 1024, ge=1, le=64 * 1024 * 1024)
    max_response_bytes: int = Field(default=1024 * 1024, ge=1, le=16 * 1024 * 1024)

    #: Total bytes of stored response bodies one forensic run may retrieve.
    max_total_response_bytes: int = Field(default=5 * 1024 * 1024, ge=1, le=64 * 1024 * 1024)

    #: urlscan occasionally serves an artifact through a redirect. Following a
    #: bounded number of *same-origin* hops keeps that working; a cross-origin
    #: hop is refused rather than followed, because following it would send the
    #: analyst's API key to a host that is not urlscan.
    max_redirect_hops: int = Field(default=3, ge=0, le=10)

    @field_validator("host")
    @classmethod
    def _validate_host(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme != "https":
            msg = "urlscan host must use https"
            raise ValueError(msg)
        if not parts.hostname:
            msg = "urlscan host must include a hostname"
            raise ValueError(msg)
        if parts.path.strip("/") or parts.query or parts.fragment:
            msg = "urlscan host must be an origin with no path, query or fragment"
            raise ValueError(msg)
        return value.rstrip("/")

    @field_validator("user_agent")
    @classmethod
    def _validate_user_agent(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            msg = "user_agent must not be blank"
            raise ValueError(msg)
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            msg = "user_agent must not contain control characters"
            raise ValueError(msg)
        if SENSITIVE_KEY_PATTERN.search(stripped):
            msg = "user_agent must not contain credential-like text"
            raise ValueError(msg)
        return stripped

    @property
    def hostname(self) -> str:
        return urlsplit(self.host).hostname or ""

    @property
    def is_production_host(self) -> bool:
        return self.host == URLSCAN_HOST


def build_transport_config(config: UrlscanConfig, *, provider_id: str) -> TransportConfig:
    """The Task 5 transport configuration for urlscan.

    The API key travels as the ``API-Key`` header — never in a path, a query
    string or a body. ``AuthType.API_KEY``'s conventional placement is
    ``X-Api-Key``, so the header name is stated explicitly here rather than
    inherited.
    """
    return TransportConfig(
        provider_id=provider_id,
        base_url=config.host,
        timeouts=TransportTimeouts(
            connect=5.0,
            read=float(config.timeout_seconds),
            write=10.0,
            pool=5.0,
        ),
        auth=AuthConfig(
            placement=AuthPlacement.HEADER,
            header_name=URLSCAN_API_KEY_HEADER,
        ),
        user_agent=config.user_agent,
    )


#: Recorded so a reader can see the auth type this provider maps onto without
#: chasing the credential layer.
URLSCAN_AUTH_TYPE: Final[AuthType] = AuthType.API_KEY
