"""The shared abuse.ch configuration and transport wiring (Task 10).

One config class serves three platforms because they differ only in host. What
matters here is what the class *cannot* express: a credential field, a
non-https origin, a path, or a header the transport did not put there.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ti_recon.providers.abusech import ABUSE_CH_AUTH_HEADER
from ti_recon.providers.abusech.config import (
    MALWAREBAZAAR_HOST,
    THREATFOX_HOST,
    URLHAUS_HOST,
    AbuseChConfig,
    build_transport_config,
)
from ti_recon.providers.transport import AuthPlacement

HOSTS = (THREATFOX_HOST, URLHAUS_HOST, MALWAREBAZAAR_HOST)


def test_the_three_origins_are_distinct_https_abusech_hosts() -> None:
    assert len(set(HOSTS)) == 3
    for host in HOSTS:
        assert host.startswith("https://")
        assert host.endswith("abuse.ch")


def test_a_trailing_slash_is_normalized_away() -> None:
    assert AbuseChConfig(host=f"{THREATFOX_HOST}/").host == THREATFOX_HOST


def test_the_hostname_is_derived_rather_than_configured() -> None:
    assert AbuseChConfig(host=THREATFOX_HOST).hostname == "threatfox-api.abuse.ch"


@pytest.mark.parametrize(
    "host",
    [
        "http://threatfox-api.abuse.ch",
        "ftp://threatfox-api.abuse.ch",
        "https://threatfox-api.abuse.ch/api/v1/",
        "https://threatfox-api.abuse.ch?x=1",
        "https://threatfox-api.abuse.ch#f",
        "https://evil.example@threatfox-api.abuse.ch",
        "https://",
        "not-a-url",
    ],
)
def test_a_host_that_is_not_a_plain_https_origin_is_refused(host: str) -> None:
    with pytest.raises(ValidationError):
        AbuseChConfig(host=host)


def test_the_config_has_no_field_for_a_credential() -> None:
    """So a configuration object is always safe to log and serialize."""
    fields = set(AbuseChConfig.model_fields)
    assert fields == {"host", "user_agent", "timeout_seconds"}


@pytest.mark.parametrize(
    "user_agent", ["", "   ", "ti-recon\r\nX: y", "ti-recon api_key=abc", "x" * 500]
)
def test_a_hostile_user_agent_is_refused(user_agent: str) -> None:
    with pytest.raises(ValidationError):
        AbuseChConfig(host=THREATFOX_HOST, user_agent=user_agent)


@pytest.mark.parametrize("seconds", [0, -1, 301])
def test_an_unreasonable_timeout_is_refused(seconds: int) -> None:
    with pytest.raises(ValidationError):
        AbuseChConfig(host=THREATFOX_HOST, timeout_seconds=seconds)


def test_the_transport_places_the_key_in_a_header_and_nowhere_else() -> None:
    """These APIs take parameters in a body; the credential must not join them."""
    transport = build_transport_config(AbuseChConfig(host=URLHAUS_HOST), provider_id="urlhaus")
    assert transport.provider_id == "urlhaus"
    assert transport.base_url.rstrip("/") == URLHAUS_HOST
    assert transport.auth is not None
    assert transport.auth.placement is AuthPlacement.HEADER
    assert transport.auth.header_name == ABUSE_CH_AUTH_HEADER
    assert transport.auth.query_param is None


def test_the_transport_asks_for_json_and_nothing_credential_shaped() -> None:
    transport = build_transport_config(
        AbuseChConfig(host=MALWAREBAZAAR_HOST), provider_id="malwarebazaar"
    )
    assert transport.default_headers == {"Accept": "application/json"}
    for name in transport.default_headers:
        assert ABUSE_CH_AUTH_HEADER.lower() != name.lower()


def test_the_configured_timeout_reaches_the_read_deadline() -> None:
    transport = build_transport_config(
        AbuseChConfig(host=THREATFOX_HOST, timeout_seconds=7), provider_id="threatfox"
    )
    assert transport.timeouts.read == 7.0
