"""GreyNoise client configuration (Task 9).

The configuration object exists partly to be *safe*: it holds no credential, so
it can be logged and serialized, and it pins the host so nothing a caller
supplies can move an authenticated request.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from ti_recon.credentials.enums import AuthType
from ti_recon.providers.greynoise import (
    GREYNOISE_API_KEY_HEADER,
    GREYNOISE_AUTH_TYPE,
    GREYNOISE_HOST,
    GreyNoiseConfig,
    build_transport_config,
)
from ti_recon.providers.transport import AuthPlacement
from ti_recon.security import SENSITIVE_KEY_PATTERN


def test_the_default_host_is_the_production_api() -> None:
    config = GreyNoiseConfig()
    assert config.host == GREYNOISE_HOST
    assert config.hostname == "api.greynoise.io"
    assert config.is_production_host is True


def test_the_key_travels_in_greynoises_own_header() -> None:
    """Not ``Authorization`` and not ``X-Api-Key``: GreyNoise uses ``key``."""
    transport = build_transport_config(GreyNoiseConfig(), provider_id="greynoise")
    assert transport.auth.placement is AuthPlacement.HEADER
    assert transport.auth.header_name == GREYNOISE_API_KEY_HEADER
    assert transport.auth.scheme is None
    assert GREYNOISE_AUTH_TYPE is AuthType.API_KEY


def test_the_transport_is_pinned_to_the_configured_host() -> None:
    transport = build_transport_config(GreyNoiseConfig(), provider_id="greynoise")
    assert transport.base_url.startswith(GREYNOISE_HOST)
    assert transport.host == "api.greynoise.io"


def test_the_transport_declares_explicit_timeouts() -> None:
    transport = build_transport_config(GreyNoiseConfig(timeout_seconds=45), provider_id="greynoise")
    assert transport.timeouts.read == 45.0
    assert transport.timeouts.connect > 0


def test_no_credential_header_is_ever_a_default_header() -> None:
    transport = build_transport_config(GreyNoiseConfig(), provider_id="greynoise")
    for name in transport.default_headers:
        assert SENSITIVE_KEY_PATTERN.search(name) is None


@pytest.mark.parametrize(
    "host",
    [
        "http://api.greynoise.io",
        "api.greynoise.io",
        "https://api.greynoise.io/v3",
        "https://api.greynoise.io?x=1",
        "https://",
    ],
)
def test_an_unusable_host_is_refused(host: str) -> None:
    with pytest.raises(ValidationError):
        GreyNoiseConfig(host=host)


def test_a_trailing_slash_is_normalized_away() -> None:
    assert GreyNoiseConfig(host="https://api.greynoise.io/").host == "https://api.greynoise.io"


@pytest.mark.parametrize("user_agent", ["", "   ", "ti-recon\nInjected: yes", "api_key=abc"])
def test_an_unusable_user_agent_is_refused(user_agent: str) -> None:
    with pytest.raises(ValidationError):
        GreyNoiseConfig(user_agent=user_agent)


def test_the_configuration_serializes_with_nothing_secret_in_it() -> None:
    serialized = json.dumps(GreyNoiseConfig().model_dump(mode="json"))
    assert SENSITIVE_KEY_PATTERN.search(serialized) is None
