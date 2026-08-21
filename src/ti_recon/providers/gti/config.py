"""Google Threat Intelligence client configuration (Task 7).

Everything needed to build a GTI client *except* the credential. The API key is
resolved per user by the Task 4 credential layer and handed to the client at
construction; it deliberately has no field here, so a configuration object can
be logged, serialized or compared without any risk.
"""

from __future__ import annotations

import os
import re
from typing import Final
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from ti_recon import __version__
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.security import SENSITIVE_KEY_PATTERN

__all__ = [
    "DEFAULT_GTI_HOST",
    "DEFAULT_X_TOOL",
    "GTI_X_TOOL_ENV_VAR",
    "GTIConfig",
    "gti_config_from_env",
]

#: The only production GTI/VirusTotal API host.
DEFAULT_GTI_HOST: Final[str] = "https://www.virustotal.com"

GTI_X_TOOL_ENV_VAR: Final[str] = "GTI_X_TOOL"

_MAJOR_MINOR: Final[str] = ".".join(__version__.split(".")[:2])

#: Google asks integrations to identify themselves per request. The recommended
#: shape is ``organization.product.major.minor``; ours is derived from the
#: package version so it cannot drift out of sync with a release.
DEFAULT_X_TOOL: Final[str] = f"diyara03.ti-recon.{_MAJOR_MINOR}"

#: Control characters, including the CR/LF that would allow header injection.
_CONTROL_CHARACTERS: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")


class GTIConfig(FrozenTiReconModel):
    """How to talk to GTI, minus the credential.

    ``x_tool`` is **not** a secret: it identifies TI Recon to Google on every
    request, the same way a User-Agent identifies a browser. It is kept
    conceptually separate from ``agent`` (which becomes the HTTP User-Agent)
    because they answer different questions — *which integration is this* versus
    *which client library and version*.
    """

    #: Sent as the ``x-tool`` header on every GTI request.
    x_tool: str = Field(default=DEFAULT_X_TOOL, min_length=1, max_length=120)

    #: Passed to vt-py as its agent string; vt-py folds it into the User-Agent
    #: alongside its own version.
    agent: str = Field(default=f"ti-recon/{__version__}", min_length=1, max_length=120)

    #: Overridable only so a test double or an isolated environment can point
    #: elsewhere. Must still be an https origin — see the validator.
    host: str = Field(default=DEFAULT_GTI_HOST, min_length=8, max_length=200)

    timeout_seconds: int = Field(default=60, ge=1, le=600)

    @field_validator("x_tool", "agent")
    @classmethod
    def _validate_header_value(cls, value: str) -> str:
        """Reject blank and control-character values.

        Deliberately permissive otherwise: Google's formatting guidance for
        ``x-tool`` may change, and over-validating a free-form identifier would
        turn their documentation update into our outage. Control characters are
        the exception because a newline in a header value is header injection,
        not a formatting preference.
        """
        stripped = value.strip()
        if not stripped:
            msg = "value must not be blank"
            raise ValueError(msg)
        if _CONTROL_CHARACTERS.search(value):
            msg = "value must not contain control characters"
            raise ValueError(msg)
        return stripped

    @field_validator("host")
    @classmethod
    def _validate_host(cls, value: str) -> str:
        """Require an https origin with no path, query or fragment.

        The GTI API host is configuration, never user input: nothing in the
        request path may influence which host is contacted.
        """
        parts = urlsplit(value)
        if parts.scheme != "https":
            msg = "GTI host must use https"
            raise ValueError(msg)
        if not parts.hostname:
            msg = "GTI host must include a hostname"
            raise ValueError(msg)
        if parts.path.strip("/") or parts.query or parts.fragment:
            msg = "GTI host must be an origin with no path, query or fragment"
            raise ValueError(msg)
        return value.rstrip("/")

    @property
    def headers(self) -> dict[str, str]:
        """Extra headers for every GTI request.

        Only ``x-tool``. Authentication is vt-py's job — it sets ``X-Apikey``
        from the key it was constructed with, and vt-py applies user headers
        *after* its own, so a credential smuggled in here would silently
        override the real one.
        """
        return {"x-tool": self.x_tool}

    @property
    def is_production_host(self) -> bool:
        return self.host == DEFAULT_GTI_HOST


def gti_config_from_env(environ: dict[str, str] | None = None) -> GTIConfig:
    """Build a config from the environment, falling back to safe defaults.

    Only ``GTI_X_TOOL`` is read. The host is not environment-configurable: a
    misplaced variable must not be able to redirect provider traffic.
    """
    source = os.environ if environ is None else environ
    x_tool = source.get(GTI_X_TOOL_ENV_VAR, "").strip() or DEFAULT_X_TOOL
    if SENSITIVE_KEY_PATTERN.search(x_tool):
        # x-tool is not a secret, and something that looks like one landing here
        # is a misconfiguration worth refusing rather than transmitting.
        msg = f"{GTI_X_TOOL_ENV_VAR} must not contain credential-like text"
        raise ValueError(msg)
    return GTIConfig(x_tool=x_tool)
