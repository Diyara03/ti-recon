"""Shared provider HTTP transport (Task 5).

Covers the SSRF boundary, timeout configuration, TLS, safe logging and clean
shutdown. All network traffic is intercepted; nothing here reaches a real host.
"""

from __future__ import annotations

import inspect
import logging
from typing import Any

import httpx
import pytest
import respx
from pydantic import SecretStr, ValidationError

from ti_recon import __version__
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.providers import (
    DEFAULT_USER_AGENT,
    AuthConfig,
    AuthPlacement,
    ProviderHttpClient,
    ProviderTimeoutError,
    ProviderTransportClosed,
    ProviderTransportSecurityError,
    ProviderUnavailableError,
    TransportConfig,
    TransportTimeouts,
)
from ti_recon.providers.transport import (
    QueryStringRedactingFilter,
    install_transport_log_redaction,
)

BASE_URL = "https://api.fake-provider.test/v1/"
OTHER_HOST = "https://evil.example/"
SECRET = "fake-key-AAAA1111"


def make_config(**overrides: Any) -> TransportConfig:
    kwargs: dict[str, Any] = {"provider_id": "fake_provider", "base_url": BASE_URL}
    kwargs.update(overrides)
    return TransportConfig(**kwargs)


def make_credential(auth_type: AuthType = AuthType.API_KEY) -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id="user-a",
        provider_id="fake_provider",
        credential_group="fake_provider",
        auth_type=auth_type,
        secret=SecretStr(SECRET),
    )


@pytest.fixture
async def client() -> Any:
    transport_client = ProviderHttpClient(
        make_config(auth=AuthConfig(placement=AuthPlacement.HEADER, header_name="X-Api-Key"))
    )
    yield transport_client
    await transport_client.aclose()


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def test_base_url_gains_a_trailing_slash() -> None:
    config = make_config(base_url="https://api.fake-provider.test/v1")
    assert config.base_url == "https://api.fake-provider.test/v1/"


def test_plain_http_base_url_is_rejected() -> None:
    with pytest.raises(ValidationError, match="must use https"):
        make_config(base_url="http://api.fake-provider.test/v1/")


def test_base_url_without_a_host_is_rejected() -> None:
    with pytest.raises(ValidationError, match="must include a host"):
        make_config(base_url="https:///v1/")


def test_base_url_with_a_query_is_rejected() -> None:
    with pytest.raises(ValidationError, match="query or fragment"):
        make_config(base_url="https://api.fake-provider.test/v1/?k=1")


def test_credential_default_headers_are_rejected() -> None:
    with pytest.raises(ValidationError, match="credential header"):
        make_config(default_headers={"X-Apikey": SECRET})


def test_all_four_timeouts_are_configured_explicitly() -> None:
    timeouts = TransportTimeouts()
    assert timeouts.connect > 0
    assert timeouts.read > 0
    assert timeouts.write > 0
    assert timeouts.pool > 0


@pytest.mark.parametrize("field", ["connect", "read", "write", "pool"])
def test_timeouts_cannot_be_disabled(field: str) -> None:
    for value in (0, -1):
        with pytest.raises(ValidationError):
            TransportTimeouts(**{field: value})


def test_timeouts_reach_the_underlying_client() -> None:
    timeouts = TransportTimeouts(connect=1.5, read=2.5, write=3.5, pool=4.5)
    client = ProviderHttpClient(make_config(timeouts=timeouts))
    configured = client._client.timeout
    assert configured.connect == 1.5
    assert configured.read == 2.5
    assert configured.write == 3.5
    assert configured.pool == 4.5


def test_tls_verification_is_not_configurable() -> None:
    """There must be no way to switch TLS verification off."""
    assert "verify" not in TransportConfig.model_fields
    signature = inspect.signature(ProviderHttpClient.__init__)
    assert "verify" not in signature.parameters


def test_default_user_agent_is_versioned() -> None:
    assert DEFAULT_USER_AGENT == f"ti-recon/{__version__}"
    assert make_config().user_agent == DEFAULT_USER_AGENT


def test_redirects_are_not_followed() -> None:
    """A redirect is a provider-controlled way to move a request to another host."""
    client = ProviderHttpClient(make_config())
    assert client._client.follow_redirects is False


def test_auth_config_requires_a_header_name_for_header_placement() -> None:
    with pytest.raises(ValidationError, match="requires header_name"):
        AuthConfig(placement=AuthPlacement.HEADER)


def test_auth_config_requires_a_param_for_query_placement() -> None:
    with pytest.raises(ValidationError, match="requires query_param"):
        AuthConfig(placement=AuthPlacement.QUERY)


@pytest.mark.parametrize("auth_type", list(AuthType))
def test_conventional_placement_exists_for_every_auth_type(auth_type: AuthType) -> None:
    auth = AuthConfig.for_auth_type(auth_type)
    assert auth.placement is AuthPlacement.HEADER
    assert auth.header_name


# --------------------------------------------------------------------------- #
# Relative paths and base URL enforcement
# --------------------------------------------------------------------------- #


@respx.mock
async def test_relative_path_is_resolved_against_the_base_url(
    client: ProviderHttpClient,
) -> None:
    route = respx.get(f"{BASE_URL}ip/198.51.100.7").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    response = await client.get("ip/198.51.100.7")
    assert response.status_code == 200
    assert route.called
    assert str(route.calls[0].request.url) == f"{BASE_URL}ip/198.51.100.7"


@respx.mock
async def test_leading_slash_is_treated_as_relative(client: ProviderHttpClient) -> None:
    route = respx.get(f"{BASE_URL}ip/1.2.3.4").mock(return_value=httpx.Response(200))
    await client.get("/ip/1.2.3.4")
    assert route.called


@respx.mock
async def test_query_parameters_are_passed_through(client: ProviderHttpClient) -> None:
    route = respx.get(f"{BASE_URL}search").mock(return_value=httpx.Response(200))
    await client.get("search", params={"q": "evil.example", "limit": 10})
    assert route.called
    assert route.calls[0].request.url.params["q"] == "evil.example"


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.example/steal",
        "http://evil.example/steal",
        "//evil.example/steal",
        "https://api.fake-provider.test/v1/ok",
    ],
)
async def test_absolute_urls_are_refused(client: ProviderHttpClient, path: str) -> None:
    with pytest.raises(ProviderTransportSecurityError, match="absolute URLs"):
        await client.get(path)


async def test_path_traversal_is_refused(client: ProviderHttpClient) -> None:
    with pytest.raises(ProviderTransportSecurityError, match="traversal"):
        await client.get("../../admin")


async def test_traversal_that_would_leave_the_base_path_is_refused(
    client: ProviderHttpClient,
) -> None:
    with pytest.raises(ProviderTransportSecurityError):
        await client.get("a/../../other")


async def test_empty_path_is_refused(client: ProviderHttpClient) -> None:
    with pytest.raises(ProviderTransportSecurityError, match="empty request path"):
        await client.get("   ")


@pytest.mark.parametrize(
    "path", ["ip/ 1.2.3.4", "ip\\1.2.3.4", "ip/\n1.2.3.4", "ip/\r\nHost: evil"]
)
async def test_illegal_path_characters_are_refused(client: ProviderHttpClient, path: str) -> None:
    with pytest.raises(ProviderTransportSecurityError):
        await client.get(path)


async def test_no_arbitrary_fetch_api_exists() -> None:
    """A submitted IOC URL must have nowhere to go."""
    names = {name for name, _ in inspect.getmembers(ProviderHttpClient)}
    for forbidden in ("fetch", "fetch_url", "fetch_arbitrary_url", "open_url", "browse"):
        assert forbidden not in names
    for name in ("request", "get", "post"):
        parameters = inspect.signature(getattr(ProviderHttpClient, name)).parameters
        assert "url" not in parameters


async def test_a_submitted_ioc_url_cannot_be_used_as_a_path(
    client: ProviderHttpClient,
) -> None:
    """The concrete attack: hand the client the URL under investigation."""
    suspicious = "https://evil.example/malware.exe?id=1"
    with pytest.raises(ProviderTransportSecurityError):
        await client.get(suspicious)


@respx.mock
async def test_non_idempotent_methods_are_refused(client: ProviderHttpClient) -> None:
    for method in ("DELETE", "PUT", "PATCH", "OPTIONS", "TRACE"):
        with pytest.raises(ProviderTransportSecurityError, match="not permitted"):
            await client.request(method, "ip/1.2.3.4")


async def test_response_from_an_unexpected_host_is_refused() -> None:
    """Defence in depth if a proxy or misconfiguration answers from elsewhere."""
    async with ProviderHttpClient(make_config()) as client:
        foreign = httpx.Response(200, request=httpx.Request("GET", f"{OTHER_HOST}ip/1.2.3.4"))
        with pytest.raises(ProviderTransportSecurityError, match="unexpected host"):
            client._verify_response_origin(foreign, operation="lookup")


async def test_response_from_the_configured_host_is_accepted() -> None:
    async with ProviderHttpClient(make_config()) as client:
        expected = httpx.Response(200, request=httpx.Request("GET", f"{BASE_URL}ip/1.2.3.4"))
        client._verify_response_origin(expected, operation="lookup")


# --------------------------------------------------------------------------- #
# Credential handling
# --------------------------------------------------------------------------- #


@respx.mock
async def test_credential_is_applied_as_a_header(client: ProviderHttpClient) -> None:
    route = respx.get(f"{BASE_URL}ip/1.2.3.4").mock(return_value=httpx.Response(200))
    await client.get("ip/1.2.3.4", credential=make_credential())
    assert route.calls[0].request.headers["X-Api-Key"] == SECRET


@respx.mock
async def test_bearer_scheme_is_prefixed() -> None:
    config = make_config(auth=AuthConfig.for_auth_type(AuthType.BEARER_TOKEN))
    async with ProviderHttpClient(config) as client:
        route = respx.get(f"{BASE_URL}x").mock(return_value=httpx.Response(200))
        await client.get("x", credential=make_credential(AuthType.BEARER_TOKEN))
        assert route.calls[0].request.headers["Authorization"] == f"Bearer {SECRET}"


@respx.mock
async def test_credential_can_be_applied_as_a_query_parameter() -> None:
    config = make_config(auth=AuthConfig(placement=AuthPlacement.QUERY, query_param="apikey"))
    async with ProviderHttpClient(config) as client:
        route = respx.get(f"{BASE_URL}x").mock(return_value=httpx.Response(200))
        await client.get("x")
        assert "apikey" not in route.calls[0].request.url.params
        await client.get("x", credential=make_credential())
        assert route.calls[1].request.url.params["apikey"] == SECRET


@respx.mock
async def test_no_credential_means_no_auth_header(client: ProviderHttpClient) -> None:
    route = respx.get(f"{BASE_URL}x").mock(return_value=httpx.Response(200))
    await client.get("x")
    assert "X-Api-Key" not in route.calls[0].request.headers


async def test_adapter_supplied_credential_headers_are_refused(
    client: ProviderHttpClient,
) -> None:
    """A credential must arrive as a CredentialMaterial, not a plain header."""
    for name in ("X-Apikey", "Authorization", "Auth-Key", "Cookie"):
        with pytest.raises(ProviderTransportSecurityError, match="must be supplied"):
            await client.get("x", headers={name: SECRET})


async def test_only_the_transport_reveals_the_secret() -> None:
    """`reveal()` is called in exactly one place in the package."""
    import ti_recon.providers.transport as transport_module

    source = inspect.getsource(transport_module)
    assert source.count(".reveal()") == 1


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


@respx.mock
async def test_timeout_becomes_a_typed_transport_error(
    client: ProviderHttpClient,
) -> None:
    respx.get(f"{BASE_URL}x").mock(side_effect=httpx.ReadTimeout("too slow"))
    with pytest.raises(ProviderTimeoutError) as excinfo:
        await client.get("x", operation="lookup")
    assert excinfo.value.is_retryable is True


@respx.mock
async def test_connection_failure_becomes_provider_unavailable(
    client: ProviderHttpClient,
) -> None:
    respx.get(f"{BASE_URL}x").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(ProviderUnavailableError) as excinfo:
        await client.get("x")
    assert excinfo.value.is_retryable is True


@respx.mock
async def test_error_text_contains_no_secret(client: ProviderHttpClient) -> None:
    respx.get(f"{BASE_URL}x").mock(side_effect=httpx.ReadTimeout("too slow"))
    with pytest.raises(ProviderTimeoutError) as excinfo:
        await client.get("x", credential=make_credential())
    assert SECRET not in str(excinfo.value)


async def test_security_error_text_contains_no_secret(
    client: ProviderHttpClient,
) -> None:
    with pytest.raises(ProviderTransportSecurityError) as excinfo:
        await client.get("https://evil.example/x", credential=make_credential())
    assert SECRET not in str(excinfo.value)


@respx.mock
async def test_provider_error_status_codes_are_left_to_the_adapter(
    client: ProviderHttpClient,
) -> None:
    """The transport does not interpret HTTP status; each adapter maps its own."""
    respx.get(f"{BASE_URL}x").mock(return_value=httpx.Response(429, json={}))
    response = await client.get("x")
    assert response.status_code == 429


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #


@respx.mock
async def test_logging_records_safe_fields_only(
    client: ProviderHttpClient, caplog: pytest.LogCaptureFixture
) -> None:
    respx.get(f"{BASE_URL}ip/1.2.3.4").mock(return_value=httpx.Response(200))
    with caplog.at_level(logging.INFO, logger="ti_recon.providers.transport"):
        await client.get(
            "ip/1.2.3.4", params={"apikey": "should-not-be-logged"}, operation="lookup"
        )

    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.provider == "fake_provider"  # type: ignore[attr-defined]
    assert record.http_method == "GET"  # type: ignore[attr-defined]
    assert record.provider_path == "ip/1.2.3.4"  # type: ignore[attr-defined]
    assert record.status_code == 200  # type: ignore[attr-defined]
    assert record.latency_ms >= 0  # type: ignore[attr-defined]
    assert "should-not-be-logged" not in caplog.text


@respx.mock
async def test_logging_never_includes_credentials_or_headers(
    client: ProviderHttpClient, caplog: pytest.LogCaptureFixture
) -> None:
    respx.get(f"{BASE_URL}x").mock(return_value=httpx.Response(200))
    with caplog.at_level(logging.DEBUG):
        await client.get("x", credential=make_credential())
    text = caplog.text.lower()
    assert SECRET.lower() not in text
    for token in ("x-api-key", "authorization", "auth-key", "cookie", "bearer"):
        assert token not in text


@respx.mock
async def test_failures_are_logged_without_a_status(
    client: ProviderHttpClient, caplog: pytest.LogCaptureFixture
) -> None:
    respx.get(f"{BASE_URL}x").mock(side_effect=httpx.ReadTimeout("slow"))
    with (
        caplog.at_level(logging.INFO, logger="ti_recon.providers.transport"),
        pytest.raises(ProviderTimeoutError),
    ):
        await client.get("x")
    assert caplog.records[0].status_code is None  # type: ignore[attr-defined]


def test_logging_helper_does_not_accept_headers() -> None:
    parameters = inspect.signature(ProviderHttpClient._log).parameters
    assert "headers" not in parameters
    assert "query" not in parameters
    assert "body" not in parameters


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #


@respx.mock
async def test_context_manager_closes_the_client() -> None:
    respx.get(f"{BASE_URL}x").mock(return_value=httpx.Response(200))
    async with ProviderHttpClient(make_config()) as client:
        await client.get("x")
        assert client.is_closed is False
    assert client.is_closed is True


async def test_close_is_idempotent() -> None:
    client = ProviderHttpClient(make_config())
    await client.aclose()
    await client.aclose()
    assert client.is_closed is True


async def test_use_after_close_is_refused() -> None:
    client = ProviderHttpClient(make_config())
    await client.aclose()
    with pytest.raises(ProviderTransportClosed):
        await client.get("x")


@respx.mock
async def test_connection_pool_is_reused_across_requests(
    client: ProviderHttpClient,
) -> None:
    route = respx.get(f"{BASE_URL}x").mock(return_value=httpx.Response(200))
    underlying = client._client
    for _ in range(3):
        await client.get("x")
    assert route.call_count == 3
    assert client._client is underlying


def test_repr_exposes_no_credential(client: ProviderHttpClient) -> None:
    text = repr(client)
    assert "fake_provider" in text
    assert SECRET not in text


# --------------------------------------------------------------------------- #
# Scheme-shaped paths
#
# `urljoin` treats `mailto:x` or `javascript:x` as an absolute URL even though
# the string contains no "://", so the base-URL containment check — not the
# "://" check — is what stops these.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "path",
    [
        "javascript:alert(1)",
        "mailto:someone@evil.example",
        "data:text/html,<script>",
        "file:/etc/passwd",
    ],
)
async def test_scheme_shaped_paths_are_refused(client: ProviderHttpClient, path: str) -> None:
    with pytest.raises(ProviderTransportSecurityError, match="would leave the provider base URL"):
        await client.get(path)


@respx.mock
async def test_post_uses_the_same_boundary(client: ProviderHttpClient) -> None:
    route = respx.post(f"{BASE_URL}submit").mock(return_value=httpx.Response(200))
    await client.post("submit", json={"value": "evil.example"})
    assert route.called
    with pytest.raises(ProviderTransportSecurityError):
        await client.post("https://evil.example/submit")


def test_config_is_exposed_for_inspection(client: ProviderHttpClient) -> None:
    assert client.config.provider_id == "fake_provider"
    assert client.config.base_url == BASE_URL
    assert client.config.host == "api.fake-provider.test"


# --------------------------------------------------------------------------- #
# Bounded artifact reads
#
# Artifact bodies are sized by whoever is being investigated, so the transport
# must be able to stop reading rather than pull whatever the far end sends.
# --------------------------------------------------------------------------- #


@respx.mock
async def test_bounded_get_returns_a_complete_small_body(client: ProviderHttpClient) -> None:
    respx.get(f"{BASE_URL}artifact").mock(
        return_value=httpx.Response(200, content=b"small", headers={"Content-Type": "image/png"})
    )
    result = await client.get_bounded("artifact", max_bytes=1024)
    assert result.content == b"small"
    assert result.truncated is False
    assert result.is_success is True
    assert result.headers["content-type"] == "image/png"


@respx.mock
async def test_bounded_get_stops_at_the_cap(client: ProviderHttpClient) -> None:
    respx.get(f"{BASE_URL}artifact").mock(return_value=httpx.Response(200, content=b"x" * 5000))
    result = await client.get_bounded("artifact", max_bytes=100)
    assert len(result.content) == 100
    assert result.truncated is True


@respx.mock
async def test_bounded_get_marks_an_exact_fit_as_complete(client: ProviderHttpClient) -> None:
    respx.get(f"{BASE_URL}artifact").mock(return_value=httpx.Response(200, content=b"y" * 64))
    result = await client.get_bounded("artifact", max_bytes=64)
    assert result.content == b"y" * 64
    assert result.truncated is False


@respx.mock
async def test_bounded_get_applies_the_credential(client: ProviderHttpClient) -> None:
    route = respx.get(f"{BASE_URL}artifact").mock(return_value=httpx.Response(200, content=b"ok"))
    await client.get_bounded("artifact", max_bytes=16, credential=make_credential())
    assert route.calls.last.request.headers["X-Api-Key"] == SECRET


@respx.mock
async def test_bounded_get_returns_error_statuses_without_raising(
    client: ProviderHttpClient,
) -> None:
    """Status handling is the adapter's job; the transport only refuses to be unsafe."""
    respx.get(f"{BASE_URL}artifact").mock(return_value=httpx.Response(404, content=b"nope"))
    result = await client.get_bounded("artifact", max_bytes=16)
    assert result.status_code == 404
    assert result.is_success is False


async def test_bounded_get_keeps_the_ssrf_boundary(client: ProviderHttpClient) -> None:
    with pytest.raises(ProviderTransportSecurityError):
        await client.get_bounded(f"{OTHER_HOST}artifact", max_bytes=16)


async def test_bounded_get_rejects_a_non_positive_cap(client: ProviderHttpClient) -> None:
    with pytest.raises(ProviderTransportSecurityError, match="max_bytes"):
        await client.get_bounded("artifact", max_bytes=0)


async def test_bounded_get_refuses_a_closed_client() -> None:
    transport_client = ProviderHttpClient(make_config())
    await transport_client.aclose()
    with pytest.raises(ProviderTransportClosed):
        await transport_client.get_bounded("artifact", max_bytes=16)


@respx.mock
async def test_bounded_get_normalizes_a_timeout(client: ProviderHttpClient) -> None:
    respx.get(f"{BASE_URL}artifact").mock(side_effect=httpx.ReadTimeout("too slow"))
    with pytest.raises(ProviderTimeoutError):
        await client.get_bounded("artifact", max_bytes=16)


@respx.mock
async def test_bounded_get_normalizes_an_unreachable_provider(client: ProviderHttpClient) -> None:
    respx.get(f"{BASE_URL}artifact").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(ProviderUnavailableError):
        await client.get_bounded("artifact", max_bytes=16)


# --------------------------------------------------------------------------- #
# Third-party logging
#
# httpx logs every request at INFO with the full URL. `AuthPlacement.QUERY`
# exists, so for a provider that takes its key as a query parameter that line
# would print the credential on every request, at default level.
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_query_parameter_credential_never_reaches_an_httpx_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = ProviderHttpClient(
        make_config(auth=AuthConfig(placement=AuthPlacement.QUERY, query_param="apikey"))
    )
    respx.get(f"{BASE_URL}ip/1.2.3.4").mock(return_value=httpx.Response(200))
    try:
        with caplog.at_level(logging.DEBUG):
            await client.get("ip/1.2.3.4", credential=make_credential())
    finally:
        await client.aclose()

    rendered = "\n".join(record.getMessage() for record in caplog.records)
    assert SECRET not in rendered
    assert "[REDACTED]" in rendered


def test_the_redaction_filter_is_installed_once() -> None:
    install_transport_log_redaction()
    install_transport_log_redaction()
    installed = [
        existing
        for existing in logging.getLogger("httpx").filters
        if isinstance(existing, QueryStringRedactingFilter)
    ]
    assert len(installed) == 1


def test_the_filter_leaves_a_record_without_a_url_alone() -> None:
    record = logging.LogRecord("httpx", logging.INFO, __file__, 1, "plain %s", ("message",), None)
    assert QueryStringRedactingFilter().filter(record) is True
    assert record.args == ("message",)


@respx.mock
async def test_an_investigated_value_in_a_query_is_redacted_from_httpx_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The same filter that hides a key also stops a lookup value leaking.

    This module's own log line already omits the query string; httpx's did not.
    """
    client = ProviderHttpClient(make_config())
    respx.get(f"{BASE_URL}search").mock(return_value=httpx.Response(200))
    try:
        with caplog.at_level(logging.DEBUG):
            await client.get("search", params={"q": "victim-domain.example"})
    finally:
        await client.aclose()

    rendered = "\n".join(record.getMessage() for record in caplog.records)
    assert "victim-domain.example" not in rendered
    assert "[REDACTED]" in rendered


@respx.mock
async def test_a_url_without_a_query_is_logged_unchanged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    client = ProviderHttpClient(make_config())
    respx.get(f"{BASE_URL}ip/1.2.3.4").mock(return_value=httpx.Response(200))
    try:
        with caplog.at_level(logging.DEBUG):
            await client.get("ip/1.2.3.4")
    finally:
        await client.aclose()

    rendered = "\n".join(record.getMessage() for record in caplog.records)
    assert f"{BASE_URL}ip/1.2.3.4" in rendered
    assert "[REDACTED]" not in rendered


def test_the_filter_keeps_everything_that_is_not_the_query() -> None:
    """A redacted line must still be a usable line."""
    record = logging.LogRecord(
        "httpx",
        logging.INFO,
        __file__,
        1,
        'HTTP Request: %s %s "%s %d %s"',
        ("GET", "https://api.example/v1/search?q=secret-value", "HTTP/1.1", 200, "OK"),
        None,
    )
    assert QueryStringRedactingFilter().filter(record) is True
    message = record.getMessage()
    assert "secret-value" not in message
    assert "GET" in message
    assert "https://api.example/v1/search?[REDACTED]" in message
    assert "200" in message
    assert "OK" in message


def test_the_filter_leaves_a_record_with_no_arguments_alone() -> None:
    record = logging.LogRecord("httpx", logging.INFO, __file__, 1, "connected", None, None)
    assert QueryStringRedactingFilter().filter(record) is True
    assert record.getMessage() == "connected"


@respx.mock
async def test_a_query_parameter_credential_never_reaches_an_exception(
    client: ProviderHttpClient,
) -> None:
    """A failure carrying the URL would carry the key with it."""
    query_client = ProviderHttpClient(
        make_config(auth=AuthConfig(placement=AuthPlacement.QUERY, query_param="apikey"))
    )
    respx.get(f"{BASE_URL}x").mock(side_effect=httpx.ConnectError("refused"))
    try:
        with pytest.raises(ProviderUnavailableError) as caught:
            await query_client.get("x", credential=make_credential())
    finally:
        await query_client.aclose()

    text = f"{caught.value}\n{caught.value!r}\n{caught.value.args}"
    assert SECRET not in text
