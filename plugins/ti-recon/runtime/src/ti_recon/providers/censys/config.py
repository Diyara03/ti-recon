"""Censys client configuration (Task 9).

Everything needed to reach the Censys Platform API except the credential. The
personal access token is resolved per user by the Task 4 layer and applied by the
shared transport at request time; it has no field here, so a configuration
object is safe to log, serialize or compare.

The organization id is *not* here either, for a different reason. It is not a
secret — it appears in a URL path — but it is per-connection: one analyst's token
belongs to one organization, and reading another connection's id would send a
request against somebody else's account. So it travels with the connection
metadata, resolved per lookup, and is never global configuration. See
:mod:`ti_recon.providers.censys.organizations`.

Schema-versioned Accept headers
-------------------------------

The Platform API negotiates a response schema through ``Accept``. Sending
``application/json`` would get whatever shape the API considers current, which
means a schema change could silently reshape normalized evidence. Each endpoint
therefore asks for the exact schema this adapter was written against, so a
future incompatible version is a visible failure rather than quietly different
data.
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
    "CENSYS_AUTH_TYPE",
    "CENSYS_HOST",
    "CENSYS_HOST_ACCEPT",
    "CENSYS_JSON_ACCEPT",
    "CENSYS_WEB_PROPERTY_ACCEPT",
    "CensysConfig",
    "build_transport_config",
]

#: The only host this provider talks to. Not configurable from a request:
#: nothing a caller supplies may change where an authenticated request goes.
CENSYS_HOST: Final[str] = "https://api.platform.censys.io"

#: The exact response schema each asset endpoint is asked for.
CENSYS_HOST_ACCEPT: Final[str] = "application/vnd.censys.api.v3.host.v1+json"
CENSYS_WEB_PROPERTY_ACCEPT: Final[str] = "application/vnd.censys.api.v3.webproperty.v1+json"

#: Used for the account endpoints, which are not schema-versioned.
CENSYS_JSON_ACCEPT: Final[str] = "application/json"


class CensysConfig(FrozenTiReconModel):
    """How to talk to Censys, minus the credential and the organization."""

    host: str = Field(default=CENSYS_HOST, min_length=8, max_length=200)
    user_agent: str = Field(default=f"ti-recon/{__version__}", min_length=1, max_length=120)
    timeout_seconds: int = Field(default=30, ge=1, le=300)

    @field_validator("host")
    @classmethod
    def _validate_host(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme != "https":
            msg = "censys host must use https"
            raise ValueError(msg)
        if not parts.hostname:
            msg = "censys host must include a hostname"
            raise ValueError(msg)
        if parts.path.strip("/") or parts.query or parts.fragment:
            msg = "censys host must be an origin with no path, query or fragment"
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
        return self.host == CENSYS_HOST


def build_transport_config(config: CensysConfig, *, provider_id: str) -> TransportConfig:
    """The Task 5 transport configuration for Censys.

    The token travels as ``Authorization: Bearer`` — never in a path, a query
    string or a body. The per-endpoint ``Accept`` header is supplied per request
    rather than here, because it differs between the two asset endpoints.
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
            header_name="Authorization",
            scheme="Bearer",
        ),
        user_agent=config.user_agent,
    )


#: Recorded so a reader can see the auth type this provider maps onto without
#: chasing the credential layer.
CENSYS_AUTH_TYPE: Final[AuthType] = AuthType.BEARER_TOKEN
