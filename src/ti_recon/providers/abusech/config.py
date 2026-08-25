"""abuse.ch client configuration (Task 10).

Everything the three clients need to reach their APIs, except the credential.
The Auth-Key is resolved per user by the Task 4 layer and applied by the shared
transport at request time; it has no field here, so a configuration object is
safe to log, serialize or compare.

One class serves all three platforms because they differ only in host: the
header, the request shape and the fair-use posture are identical. Each provider
package supplies its own host and the pinning works the same way — fixed at
construction, never influenced by a request.
"""

from __future__ import annotations

from typing import Final
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from ti_recon import __version__
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.abusech.family import ABUSE_CH_AUTH_HEADER
from ti_recon.providers.transport import (
    AuthConfig,
    AuthPlacement,
    TransportConfig,
    TransportTimeouts,
)
from ti_recon.security import SENSITIVE_KEY_PATTERN

__all__ = [
    "MALWAREBAZAAR_HOST",
    "THREATFOX_HOST",
    "URLHAUS_HOST",
    "AbuseChConfig",
    "build_transport_config",
]

#: The only hosts these providers talk to. Not configurable from a request.
THREATFOX_HOST: Final[str] = "https://threatfox-api.abuse.ch"
URLHAUS_HOST: Final[str] = "https://urlhaus-api.abuse.ch"
MALWAREBAZAAR_HOST: Final[str] = "https://mb-api.abuse.ch"


class AbuseChConfig(FrozenTiReconModel):
    """How to talk to one abuse.ch API, minus the credential."""

    host: str = Field(min_length=8, max_length=200)
    user_agent: str = Field(default=f"ti-recon/{__version__}", min_length=1, max_length=120)
    timeout_seconds: int = Field(default=30, ge=1, le=300)

    @field_validator("host")
    @classmethod
    def _validate_host(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme != "https":
            msg = "abuse.ch host must use https"
            raise ValueError(msg)
        if not parts.hostname:
            msg = "abuse.ch host must include a hostname"
            raise ValueError(msg)
        if parts.path.strip("/") or parts.query or parts.fragment:
            msg = "abuse.ch host must be an origin with no path, query or fragment"
            raise ValueError(msg)
        if parts.username is not None or parts.password is not None:
            # Userinfo in a base URL is either a credential in the wrong place or
            # a value written to look like a different host in a log line.
            msg = "abuse.ch host must not carry userinfo"
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


def build_transport_config(config: AbuseChConfig, *, provider_id: str) -> TransportConfig:
    """The Task 5 transport configuration for one abuse.ch API.

    The Auth-Key travels as the ``Auth-Key`` header — never in a path, a query
    string or a form field. That matters more than usual here: these APIs take
    their *parameters* in a form body, so a careless implementation could put the
    key alongside them. It cannot happen through this configuration, because the
    transport is the only thing that ever reads the secret and it only ever
    writes it to a header.
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
            header_name=ABUSE_CH_AUTH_HEADER,
        ),
        user_agent=config.user_agent,
        default_headers={"Accept": "application/json"},
    )
