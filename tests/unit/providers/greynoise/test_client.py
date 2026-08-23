"""The GreyNoise HTTP client (Task 9).

Everything here is intercepted; nothing reaches GreyNoise. The tests are mostly
about what the client refuses to do: leave the host, hunt, submit, or let a
caller's string reach a URL path.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from pydantic import SecretStr

from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.providers.errors import (
    ProviderAuthenticationError,
    ProviderInvalidRequestError,
    ProviderNotFoundError,
    ProviderPermissionError,
    ProviderRateLimitedError,
    ProviderSchemaError,
)
from ti_recon.providers.greynoise import (
    GreyNoiseClient,
    GreyNoiseConfig,
    GreyNoiseHttpClient,
)
from ti_recon.providers.greynoise import client as client_module

BASE = "https://api.greynoise.io"
FAKE_KEY = "greynoise-key-SHOULD-NOT-LEAK-1234567890"
ADDRESS = "198.51.100.7"


def make_credential() -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id="analyst-a",
        provider_id="greynoise",
        credential_group="greynoise",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(FAKE_KEY),
    )


@pytest.fixture
async def client() -> Any:
    greynoise_client = GreyNoiseHttpClient()
    yield greynoise_client
    await greynoise_client.aclose()


# --------------------------------------------------------------------------- #
# The client is read-only, and only reads two endpoints
# --------------------------------------------------------------------------- #


def test_the_protocol_exposes_exactly_two_reads() -> None:
    """Passivity is structural: there is no hunting or submission method."""
    methods = {name for name in dir(GreyNoiseClient) if not name.startswith("_")}
    assert methods == {"get_ip_context", "get_community", "aclose"}
    for forbidden in ("gnql", "query", "hunt", "timeline", "feed", "pcap", "bulk", "submit"):
        assert not any(forbidden in name for name in methods)


def test_the_concrete_client_never_posts_and_never_hunts() -> None:
    """No write verb and no hunting endpoint exists in the module's code.

    Docstrings are excluded deliberately — they *describe* the endpoints this
    integration refuses to call, and that prose is the point.
    """
    source = Path(inspect.getfile(client_module)).read_text(encoding="utf-8")
    tree = ast.parse(source)
    docstrings = {
        ast.get_docstring(node, clean=False)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    }

    called_attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "post" not in called_attributes
    assert "stream" not in called_attributes

    literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value not in docstrings
    ]
    for literal in literals:
        assert "POST" not in literal
        assert "gnql" not in literal.lower()
        assert "/v2/" not in literal


@respx.mock
async def test_no_read_ever_reaches_a_hunting_or_v2_endpoint(
    client: GreyNoiseHttpClient,
) -> None:
    gnql = respx.get(url__regex=rf"{BASE}/v3/gnql.*").mock(return_value=httpx.Response(200))
    v2 = respx.get(url__regex=rf"{BASE}/v2/.*").mock(return_value=httpx.Response(200))
    respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(return_value=httpx.Response(200, json={}))
    respx.get(f"{BASE}/v3/community/{ADDRESS}").mock(return_value=httpx.Response(200, json={}))

    credential = make_credential()
    await client.get_ip_context(ip=ADDRESS, credential=credential)
    await client.get_ip_context(ip=ADDRESS, quick=True, credential=credential)
    await client.get_community(ip=ADDRESS, credential=credential)

    assert not gnql.called
    assert not v2.called


# --------------------------------------------------------------------------- #
# The credential
# --------------------------------------------------------------------------- #


@respx.mock
async def test_the_key_travels_as_a_header_and_never_in_the_url(
    client: GreyNoiseHttpClient,
) -> None:
    route = respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(return_value=httpx.Response(200, json={}))
    await client.get_ip_context(ip=ADDRESS, credential=make_credential())
    request = route.calls.last.request
    assert request.headers["key"] == FAKE_KEY
    assert FAKE_KEY not in str(request.url)
    assert "authorization" not in {name.lower() for name in request.headers}


# --------------------------------------------------------------------------- #
# Paths are built from parsed addresses, never from caller strings
# --------------------------------------------------------------------------- #


@respx.mock
async def test_the_full_context_path_is_the_v3_ip_endpoint(
    client: GreyNoiseHttpClient,
) -> None:
    route = respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(
        return_value=httpx.Response(200, json={"ip": ADDRESS})
    )
    result = await client.get_ip_context(ip=ADDRESS, credential=make_credential())
    assert route.called
    assert result.payload == {"ip": ADDRESS}
    assert route.calls.last.request.url.params.get("quick") is None


@respx.mock
async def test_quick_asks_the_same_endpoint_for_less(client: GreyNoiseHttpClient) -> None:
    route = respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(return_value=httpx.Response(200, json={}))
    await client.get_ip_context(ip=ADDRESS, quick=True, credential=make_credential())
    assert route.calls.last.request.url.params["quick"] == "true"


@respx.mock
async def test_the_community_path_is_the_v3_community_endpoint(
    client: GreyNoiseHttpClient,
) -> None:
    route = respx.get(f"{BASE}/v3/community/{ADDRESS}").mock(
        return_value=httpx.Response(200, json={"ip": ADDRESS, "noise": True})
    )
    await client.get_community(ip=ADDRESS, credential=make_credential())
    assert route.called


@respx.mock
async def test_an_address_is_re_rendered_from_the_parser(
    client: GreyNoiseHttpClient,
) -> None:
    """What reaches the URL came out of ``ipaddress``, not from the caller."""
    route = respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(return_value=httpx.Response(200, json={}))
    await client.get_ip_context(ip=f"  {ADDRESS}  ", credential=make_credential())
    assert route.called


@respx.mock
@pytest.mark.parametrize(
    "value",
    [
        "not-an-ip",
        "",
        "   ",
        "198.51.100.7/24",
        "../../v2/noise/context",
        "198.51.100.7?x=1",
        "2001:db8::1",
        "198.51.100.007",
        "198.51.100.7 8.8.8.8",
    ],
)
async def test_a_value_that_is_not_an_ipv4_address_never_reaches_a_path(
    client: GreyNoiseHttpClient, value: str
) -> None:
    """Nothing is mocked, so a request that escaped validation would fail loudly."""
    with pytest.raises(ProviderInvalidRequestError):
        await client.get_ip_context(ip=value, credential=make_credential())
    with pytest.raises(ProviderInvalidRequestError):
        await client.get_community(ip=value, credential=make_credential())


@respx.mock
async def test_surrounding_whitespace_is_stripped_rather_than_refused() -> None:
    """A padded value is still one address; refusing it would be pedantry."""
    route = respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(return_value=httpx.Response(200, json={}))
    async with GreyNoiseHttpClient() as padded_client:
        await padded_client.get_ip_context(ip=f"\n {ADDRESS}\t", credential=make_credential())
    assert route.called


# --------------------------------------------------------------------------- #
# Statuses
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_partial_document_is_a_success_that_says_it_is_partial(
    client: GreyNoiseHttpClient,
) -> None:
    respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(
        return_value=httpx.Response(206, json={"ip": ADDRESS})
    )
    result = await client.get_ip_context(ip=ADDRESS, credential=make_credential())
    assert result.status_code == 206
    assert result.is_partial is True
    assert result.payload == {"ip": ADDRESS}


@respx.mock
async def test_a_complete_document_is_not_partial(client: GreyNoiseHttpClient) -> None:
    respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(return_value=httpx.Response(200, json={}))
    result = await client.get_ip_context(ip=ADDRESS, credential=make_credential())
    assert result.is_partial is False


@respx.mock
@pytest.mark.parametrize(
    ("status", "error"),
    [
        (401, ProviderAuthenticationError),
        (403, ProviderPermissionError),
        (404, ProviderNotFoundError),
        (429, ProviderRateLimitedError),
    ],
)
async def test_a_failure_becomes_a_typed_normalized_error(
    client: GreyNoiseHttpClient, status: int, error: type[Exception]
) -> None:
    respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(return_value=httpx.Response(status))
    with pytest.raises(error):
        await client.get_ip_context(ip=ADDRESS, credential=make_credential())


@respx.mock
async def test_a_redirect_is_refused_rather_than_followed(
    client: GreyNoiseHttpClient,
) -> None:
    """Following it would carry the analyst's key to wherever it points."""
    respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(
        return_value=httpx.Response(302, headers={"location": "https://elsewhere.example/x"})
    )
    with pytest.raises(ProviderSchemaError):
        await client.get_ip_context(ip=ADDRESS, credential=make_credential())


@respx.mock
async def test_a_non_json_body_is_a_schema_error(client: GreyNoiseHttpClient) -> None:
    respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(return_value=httpx.Response(200, text="<html>"))
    with pytest.raises(ProviderSchemaError):
        await client.get_ip_context(ip=ADDRESS, credential=make_credential())


@respx.mock
async def test_a_json_array_is_a_schema_error(client: GreyNoiseHttpClient) -> None:
    respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(return_value=httpx.Response(200, json=[1, 2]))
    with pytest.raises(ProviderSchemaError):
        await client.get_ip_context(ip=ADDRESS, credential=make_credential())


# --------------------------------------------------------------------------- #
# Headers carried upwards
# --------------------------------------------------------------------------- #


@respx.mock
async def test_only_metering_headers_are_carried_upwards(
    client: GreyNoiseHttpClient,
) -> None:
    """No ``Set-Cookie`` or vendor header ever reaches a result or a cache."""
    respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(
        return_value=httpx.Response(
            200,
            json={},
            headers={
                "X-RateLimit-Remaining": "42",
                "Retry-After": "5",
                "Set-Cookie": "session=secret-value",
                "X-Internal-Thing": "keep-out",
            },
        )
    )
    result = await client.get_ip_context(ip=ADDRESS, credential=make_credential())
    assert result.metering_headers == {"x-ratelimit-remaining": "42", "retry-after": "5"}
    assert "set-cookie" not in result.metering_headers
    assert "x-internal-thing" not in result.metering_headers


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #


async def test_the_client_can_be_used_as_a_context_manager() -> None:
    async with GreyNoiseHttpClient(GreyNoiseConfig()) as greynoise_client:
        assert greynoise_client.provider_id == "greynoise"


def test_the_repr_reveals_no_credential_surface() -> None:
    assert FAKE_KEY not in repr(GreyNoiseHttpClient())
    assert "api.greynoise.io" in repr(GreyNoiseHttpClient())
