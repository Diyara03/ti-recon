"""Censys client configuration (Task 9).

The configuration holds no credential and no organization id, so it can be
logged and serialized freely — and it pins the host, so nothing a caller
supplies can move an authenticated request.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from ti_recon.credentials.enums import AuthType
from ti_recon.providers.censys import (
    CENSYS_AUTH_TYPE,
    CENSYS_HOST,
    CENSYS_HOST_ACCEPT,
    CENSYS_WEB_PROPERTY_ACCEPT,
    CensysConfig,
    build_transport_config,
)
from ti_recon.providers.transport import AuthPlacement
from ti_recon.security import SENSITIVE_KEY_PATTERN


def test_the_default_host_is_the_platform_api() -> None:
    config = CensysConfig()
    assert config.host == CENSYS_HOST
    assert config.hostname == "api.platform.censys.io"
    assert config.is_production_host is True


def test_the_token_travels_as_a_bearer_header() -> None:
    transport = build_transport_config(CensysConfig(), provider_id="censys")
    assert transport.auth.placement is AuthPlacement.HEADER
    assert transport.auth.header_name == "Authorization"
    assert transport.auth.scheme == "Bearer"
    assert CENSYS_AUTH_TYPE is AuthType.BEARER_TOKEN


def test_the_transport_is_pinned_to_the_configured_host() -> None:
    transport = build_transport_config(CensysConfig(), provider_id="censys")
    assert transport.base_url.startswith(CENSYS_HOST)
    assert transport.host == "api.platform.censys.io"


def test_each_asset_endpoint_asks_for_its_own_schema() -> None:
    """Asking for plain JSON would let a schema change reshape evidence quietly."""
    assert CENSYS_HOST_ACCEPT != CENSYS_WEB_PROPERTY_ACCEPT
    assert "host.v1+json" in CENSYS_HOST_ACCEPT
    assert "webproperty.v1+json" in CENSYS_WEB_PROPERTY_ACCEPT


def test_no_credential_header_is_ever_a_default_header() -> None:
    """The token is applied by the transport, not carried in configuration."""
    transport = build_transport_config(CensysConfig(), provider_id="censys")
    assert transport.default_headers == {}


def test_the_transport_declares_explicit_timeouts() -> None:
    transport = build_transport_config(CensysConfig(timeout_seconds=45), provider_id="censys")
    assert transport.timeouts.read == 45.0
    assert transport.timeouts.connect > 0


@pytest.mark.parametrize(
    "host",
    [
        "http://api.platform.censys.io",
        "api.platform.censys.io",
        "https://api.platform.censys.io/v3",
        "https://api.platform.censys.io#x",
        "https://",
    ],
)
def test_an_unusable_host_is_refused(host: str) -> None:
    with pytest.raises(ValidationError):
        CensysConfig(host=host)


def test_a_trailing_slash_is_normalized_away() -> None:
    assert CensysConfig(host="https://api.platform.censys.io/").host == CENSYS_HOST


@pytest.mark.parametrize("user_agent", ["", "   ", "ti-recon\r\nX: y", "bearer abc"])
def test_an_unusable_user_agent_is_refused(user_agent: str) -> None:
    with pytest.raises(ValidationError):
        CensysConfig(user_agent=user_agent)


def test_the_configuration_carries_no_organization_id() -> None:
    """It is per-connection, not deployment-wide: one token, one organization."""
    assert "organization_id" not in CensysConfig().model_dump()


def test_the_configuration_serializes_with_nothing_secret_in_it() -> None:
    serialized = json.dumps(CensysConfig().model_dump(mode="json"))
    assert SENSITIVE_KEY_PATTERN.search(serialized) is None
