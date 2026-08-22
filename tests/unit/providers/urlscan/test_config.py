"""urlscan client configuration (Task 8).

The configuration decides where authenticated requests go, so what it refuses
matters as much as what it accepts.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ti_recon.credentials.enums import AuthType
from ti_recon.providers.transport import AuthPlacement
from ti_recon.providers.urlscan import (
    URLSCAN_API_KEY_HEADER,
    URLSCAN_AUTH_TYPE,
    URLSCAN_HOST,
    UrlscanConfig,
    build_transport_config,
)
from ti_recon.providers.urlscan.descriptor import URLSCAN_PROVIDER_ID


def test_defaults_point_at_urlscan() -> None:
    config = UrlscanConfig()
    assert config.host == URLSCAN_HOST == "https://urlscan.io"
    assert config.hostname == "urlscan.io"
    assert config.is_production_host is True


def test_the_configuration_holds_no_secret() -> None:
    """The API key is resolved per user and applied by the transport."""
    fields = set(UrlscanConfig.model_fields)
    assert not {"api_key", "key", "secret", "token"} & fields


@pytest.mark.parametrize(
    "host",
    [
        "http://urlscan.io",
        "https://urlscan.io/api/v1",
        "https://urlscan.io?q=1",
        "https://urlscan.io#frag",
        "https:///nohost",
    ],
)
def test_unsafe_hosts_are_rejected(host: str) -> None:
    with pytest.raises(ValidationError):
        UrlscanConfig(host=host)


def test_trailing_slash_is_normalized() -> None:
    assert UrlscanConfig(host="https://urlscan.io/").host == "https://urlscan.io"


def test_a_non_production_host_is_flagged() -> None:
    """Useful for tests, and visible rather than silent."""
    config = UrlscanConfig(host="https://urlscan.test")
    assert config.is_production_host is False


@pytest.mark.parametrize(
    "user_agent",
    ["   ", "ti-recon\nX-Api-Key: leaked", "api_key=abcdef1234567890"],
)
def test_bad_user_agents_are_rejected(user_agent: str) -> None:
    with pytest.raises(ValidationError):
        UrlscanConfig(user_agent=user_agent)


def test_every_artifact_cap_is_bounded_and_positive() -> None:
    config = UrlscanConfig()
    for cap in (
        config.max_screenshot_bytes,
        config.max_dom_bytes,
        config.max_response_bytes,
        config.max_total_response_bytes,
    ):
        assert 0 < cap <= 64 * 1024 * 1024
    with pytest.raises(ValidationError):
        UrlscanConfig(max_dom_bytes=0)
    with pytest.raises(ValidationError):
        UrlscanConfig(max_response_bytes=1024 * 1024 * 1024)


def test_redirect_hops_are_bounded() -> None:
    assert UrlscanConfig().max_redirect_hops <= 10
    with pytest.raises(ValidationError):
        UrlscanConfig(max_redirect_hops=50)


def test_transport_config_sends_the_key_as_a_header() -> None:
    """Never a query parameter: query strings reach logs, caches and referrers."""
    transport = build_transport_config(UrlscanConfig(), provider_id=URLSCAN_PROVIDER_ID)
    assert transport.auth.placement is AuthPlacement.HEADER
    assert transport.auth.header_name == URLSCAN_API_KEY_HEADER == "API-Key"
    assert transport.auth.query_param is None
    assert transport.auth.scheme is None


def test_transport_config_is_pinned_to_the_configured_host() -> None:
    transport = build_transport_config(UrlscanConfig(), provider_id=URLSCAN_PROVIDER_ID)
    assert transport.base_url == "https://urlscan.io/"
    assert transport.host == "urlscan.io"
    assert transport.provider_id == URLSCAN_PROVIDER_ID


def test_transport_timeouts_follow_the_configured_read_timeout() -> None:
    transport = build_transport_config(
        UrlscanConfig(timeout_seconds=12), provider_id=URLSCAN_PROVIDER_ID
    )
    assert transport.timeouts.read == 12.0
    assert transport.timeouts.connect > 0


def test_declared_auth_type() -> None:
    assert URLSCAN_AUTH_TYPE is AuthType.API_KEY


def test_a_valid_custom_user_agent_is_kept_and_trimmed() -> None:
    assert UrlscanConfig(user_agent="  ti-recon/edge  ").user_agent == "ti-recon/edge"
