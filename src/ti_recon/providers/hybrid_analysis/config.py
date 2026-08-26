"""How to talk to Hybrid Analysis, minus the credential (Task 12).

One host, one header, no secret field. A configuration object for this provider
is safe to log and serialize because there is nowhere in it to put a key.

User-Agent
----------

The API filters some endpoints on User-Agent, so a deterministic identifying
value is sent. It names the application and version and nothing else — no
analyst identity, no investigation id, no observable, no secret. A User-Agent is
one of the most widely logged strings in existence and is exactly the wrong place
to leak anything.
"""

from __future__ import annotations

from typing import Final
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from ti_recon import __version__
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.transport import (
    AuthConfig,
    AuthPlacement,
    TransportConfig,
    TransportTimeouts,
)
from ti_recon.security import SENSITIVE_KEY_PATTERN

__all__ = [
    "HYBRID_ANALYSIS_AUTH_HEADER",
    "HYBRID_ANALYSIS_HOST",
    "HYBRID_ANALYSIS_USER_AGENT",
    "HybridAnalysisConfig",
    "build_transport_config",
]

#: The only origin this provider talks to. Not configurable from a request.
HYBRID_ANALYSIS_HOST: Final[str] = "https://hybrid-analysis.com"

#: API v2 authenticates with a single header. There is deliberately no
#: api-secret: older knowledge-base and VxAPI material still describes a
#: key+secret pair, but the current v2 specification authenticates on this header
#: alone, and requiring a secret would make the provider unusable with a normal
#: self-signed key.
HYBRID_ANALYSIS_AUTH_HEADER: Final[str] = "api-key"

#: Application-identifying and nothing more.
HYBRID_ANALYSIS_USER_AGENT: Final[str] = f"ti-recon/{__version__}"


class HybridAnalysisConfig(FrozenTiReconModel):
    """Host, timeouts and User-Agent. No credential."""

    host: str = HYBRID_ANALYSIS_HOST
    user_agent: str = Field(default=HYBRID_ANALYSIS_USER_AGENT, min_length=1, max_length=120)
    timeout_seconds: int = Field(default=30, ge=1, le=300)

    @field_validator("host")
    @classmethod
    def _validate_host(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme != "https":
            msg = "hybrid analysis host must use https"
            raise ValueError(msg)
        if not parts.hostname:
            msg = "hybrid analysis host must include a hostname"
            raise ValueError(msg)
        if parts.path.strip("/") or parts.query or parts.fragment:
            msg = "hybrid analysis host must be an origin with no path, query or fragment"
            raise ValueError(msg)
        if parts.username is not None or parts.password is not None:
            # Userinfo in a base URL is either a credential in the wrong place or
            # a value written to read as a different host in a log line.
            msg = "hybrid analysis host must not carry userinfo"
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


def build_transport_config(config: HybridAnalysisConfig, *, provider_id: str) -> TransportConfig:
    """The Task 5 transport configuration for Hybrid Analysis.

    The key travels as the ``api-key`` header and nowhere else — never a path,
    never a query string. That matters specifically here because the hash being
    looked up *is* a query parameter, so a request URL is exactly the kind of
    string that ends up in a log or an error, and the credential must not be in
    it.
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
            header_name=HYBRID_ANALYSIS_AUTH_HEADER,
        ),
        user_agent=config.user_agent,
        default_headers={"Accept": "application/json"},
    )
