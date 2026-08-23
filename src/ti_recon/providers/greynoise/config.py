"""GreyNoise client configuration (Task 9).

Everything needed to reach GreyNoise except the credential. The API key is
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
    "GREYNOISE_API_KEY_HEADER",
    "GREYNOISE_AUTH_TYPE",
    "GREYNOISE_HOST",
    "GreyNoiseConfig",
    "build_transport_config",
]

#: The only host this provider talks to. Not configurable from a request:
#: nothing a caller supplies may change where an authenticated request goes.
GREYNOISE_HOST: Final[str] = "https://api.greynoise.io"

#: GreyNoise authenticates with a bare ``key`` header rather than
#: ``Authorization`` or ``X-Api-Key``.
GREYNOISE_API_KEY_HEADER: Final[str] = "key"


class GreyNoiseConfig(FrozenTiReconModel):
    """How to talk to GreyNoise, minus the credential."""

    host: str = Field(default=GREYNOISE_HOST, min_length=8, max_length=200)
    user_agent: str = Field(default=f"ti-recon/{__version__}", min_length=1, max_length=120)
    timeout_seconds: int = Field(default=20, ge=1, le=300)

    @field_validator("host")
    @classmethod
    def _validate_host(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme != "https":
            msg = "greynoise host must use https"
            raise ValueError(msg)
        if not parts.hostname:
            msg = "greynoise host must include a hostname"
            raise ValueError(msg)
        if parts.path.strip("/") or parts.query or parts.fragment:
            msg = "greynoise host must be an origin with no path, query or fragment"
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
        return self.host == GREYNOISE_HOST


def build_transport_config(config: GreyNoiseConfig, *, provider_id: str) -> TransportConfig:
    """The Task 5 transport configuration for GreyNoise.

    The API key travels as the ``key`` header — never in a path, a query string
    or a body. ``AuthType.API_KEY``'s conventional placement is ``X-Api-Key``,
    so the header name is stated explicitly here rather than inherited.
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
            header_name=GREYNOISE_API_KEY_HEADER,
        ),
        user_agent=config.user_agent,
        default_headers={"Accept": "application/json"},
    )


#: Recorded so a reader can see the auth type this provider maps onto without
#: chasing the credential layer.
GREYNOISE_AUTH_TYPE: Final[AuthType] = AuthType.API_KEY
