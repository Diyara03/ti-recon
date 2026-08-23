"""The Censys Platform HTTP client (Task 9).

Everything here is intercepted; nothing reaches Censys. The tests are mostly
about what the client refuses to do: search, rescan, leave the host, or let a
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

from fixtures.censys import payloads
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.providers.censys import (
    CENSYS_HOST_ACCEPT,
    CENSYS_WEB_PROPERTY_ACCEPT,
    CensysClient,
    CensysConfig,
    CensysHttpClient,
)
from ti_recon.providers.censys import client as client_module
from ti_recon.providers.errors import (
    ProviderAuthenticationError,
    ProviderInvalidRequestError,
    ProviderNotFoundError,
    ProviderQuotaExceededError,
    ProviderRateLimitedError,
    ProviderSchemaError,
)

BASE = "https://api.platform.censys.io"
FAKE_TOKEN = "censys-pat-SHOULD-NOT-LEAK-1234567890"
ADDRESS = payloads.HOST_IP
HOSTNAME = payloads.WEB_PROPERTY_HOST


def make_credential() -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id="analyst-a",
        provider_id="censys",
        credential_group="censys",
        auth_type=AuthType.BEARER_TOKEN,
        secret=SecretStr(FAKE_TOKEN),
    )


@pytest.fixture
async def client() -> Any:
    censys_client = CensysHttpClient()
    yield censys_client
    await censys_client.aclose()


# --------------------------------------------------------------------------- #
# The client is read-only, and cannot search
# --------------------------------------------------------------------------- #


def test_the_protocol_exposes_four_reads_and_nothing_else() -> None:
    """Passivity is structural: there is no search, rescan or discovery method."""
    methods = {name for name in dir(CensysClient) if not name.startswith("_")}
    assert methods == {
        "get_host",
        "get_web_property",
        "get_user_credits",
        "get_organization_credits",
        "aclose",
    }
    for forbidden in ("search", "query", "cenql", "rescan", "discover", "collection", "submit"):
        assert not any(forbidden in name for name in methods)


def test_the_concrete_client_never_posts_and_never_queries() -> None:
    """No write verb and no search endpoint exists in the module's code.

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
        assert "search" not in literal.lower()
        assert "rescan" not in literal.lower()


@respx.mock
async def test_no_read_ever_reaches_the_search_endpoint(client: CensysHttpClient) -> None:
    search = respx.route(url__regex=rf"{BASE}/v3/global/search.*").mock(
        return_value=httpx.Response(200, json={})
    )
    respx.get(f"{BASE}/v3/global/asset/host/{ADDRESS}").mock(
        return_value=httpx.Response(200, json={})
    )
    respx.get(f"{BASE}/v3/global/asset/webproperty/{HOSTNAME}:443").mock(
        return_value=httpx.Response(200, json={})
    )
    respx.get(f"{BASE}/v3/accounts/users/credits").mock(return_value=httpx.Response(200, json={}))
    respx.get(f"{BASE}/v3/accounts/organizations/org-1/credits").mock(
        return_value=httpx.Response(200, json={})
    )

    credential = make_credential()
    await client.get_host(ip=ADDRESS, credential=credential)
    await client.get_web_property(hostname=HOSTNAME, port=443, credential=credential)
    await client.get_user_credits(credential=credential)
    await client.get_organization_credits(organization_id="org-1", credential=credential)

    assert not search.called


# --------------------------------------------------------------------------- #
# The credential
# --------------------------------------------------------------------------- #


@respx.mock
async def test_the_token_travels_as_a_bearer_header_and_never_in_the_url(
    client: CensysHttpClient,
) -> None:
    route = respx.get(f"{BASE}/v3/global/asset/host/{ADDRESS}").mock(
        return_value=httpx.Response(200, json={})
    )
    await client.get_host(ip=ADDRESS, credential=make_credential())
    request = route.calls.last.request
    assert request.headers["Authorization"] == f"Bearer {FAKE_TOKEN}"
    assert FAKE_TOKEN not in str(request.url)


# --------------------------------------------------------------------------- #
# Schema negotiation
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_host_read_asks_for_the_host_schema(client: CensysHttpClient) -> None:
    route = respx.get(f"{BASE}/v3/global/asset/host/{ADDRESS}").mock(
        return_value=httpx.Response(200, json={})
    )
    await client.get_host(ip=ADDRESS, credential=make_credential())
    assert route.calls.last.request.headers["Accept"] == CENSYS_HOST_ACCEPT


@respx.mock
async def test_a_web_property_read_asks_for_the_web_property_schema(
    client: CensysHttpClient,
) -> None:
    route = respx.get(f"{BASE}/v3/global/asset/webproperty/{HOSTNAME}:443").mock(
        return_value=httpx.Response(200, json={})
    )
    await client.get_web_property(hostname=HOSTNAME, port=443, credential=make_credential())
    assert route.calls.last.request.headers["Accept"] == CENSYS_WEB_PROPERTY_ACCEPT


# --------------------------------------------------------------------------- #
# Paths are built from validated parts
# --------------------------------------------------------------------------- #


@respx.mock
async def test_an_address_is_re_rendered_from_the_parser(client: CensysHttpClient) -> None:
    route = respx.get(f"{BASE}/v3/global/asset/host/{ADDRESS}").mock(
        return_value=httpx.Response(200, json={})
    )
    await client.get_host(ip=f"  {ADDRESS} ", credential=make_credential())
    assert route.called


@respx.mock
async def test_an_ipv6_address_reaches_the_host_endpoint(client: CensysHttpClient) -> None:
    route = respx.get(f"{BASE}/v3/global/asset/host/2001:db8::1").mock(
        return_value=httpx.Response(200, json={})
    )
    await client.get_host(ip="2001:db8::1", credential=make_credential())
    assert route.called


@respx.mock
@pytest.mark.parametrize(
    "value",
    ["not-an-ip", "", "   ", "../../accounts/users/credits", "198.51.100.7/24", "example.com"],
)
async def test_a_value_that_is_not_an_address_never_reaches_a_path(
    client: CensysHttpClient, value: str
) -> None:
    """Nothing is mocked, so a request that escaped validation would fail loudly."""
    with pytest.raises(ProviderInvalidRequestError):
        await client.get_host(ip=value, credential=make_credential())


@respx.mock
@pytest.mark.parametrize(
    "hostname",
    ["not a hostname", "", "../../v3/accounts", "example.com/x", "example.com:443"],
)
async def test_a_value_that_is_not_a_hostname_never_reaches_a_path(
    client: CensysHttpClient, hostname: str
) -> None:
    with pytest.raises(ProviderInvalidRequestError):
        await client.get_web_property(hostname=hostname, port=443, credential=make_credential())


@respx.mock
@pytest.mark.parametrize("port", [0, -1, 65_536, 999_999])
async def test_a_port_out_of_range_never_reaches_a_path(
    client: CensysHttpClient, port: int
) -> None:
    with pytest.raises(ProviderInvalidRequestError):
        await client.get_web_property(hostname=HOSTNAME, port=port, credential=make_credential())


@respx.mock
@pytest.mark.parametrize("organization_id", ["../users", "org/1", "", "   ", "org 1", "A" * 65])
async def test_an_unusable_organization_id_never_reaches_a_path(
    client: CensysHttpClient, organization_id: str
) -> None:
    with pytest.raises(ProviderInvalidRequestError):
        await client.get_organization_credits(
            organization_id=organization_id, credential=make_credential()
        )


@respx.mock
async def test_an_internationalized_hostname_is_sent_in_ascii(
    client: CensysHttpClient,
) -> None:
    route = respx.get(url__regex=rf"{BASE}/v3/global/asset/webproperty/xn--.*").mock(
        return_value=httpx.Response(200, json={})
    )
    await client.get_web_property(
        hostname="münchen.example", port=443, credential=make_credential()
    )
    assert route.called


# --------------------------------------------------------------------------- #
# Statuses
# --------------------------------------------------------------------------- #


@respx.mock
@pytest.mark.parametrize(
    ("status", "error"),
    [
        (401, ProviderAuthenticationError),
        (402, ProviderQuotaExceededError),
        (404, ProviderNotFoundError),
        (429, ProviderRateLimitedError),
    ],
)
async def test_a_failure_becomes_a_typed_normalized_error(
    client: CensysHttpClient, status: int, error: type[Exception]
) -> None:
    respx.get(f"{BASE}/v3/global/asset/host/{ADDRESS}").mock(return_value=httpx.Response(status))
    with pytest.raises(error):
        await client.get_host(ip=ADDRESS, credential=make_credential())


@respx.mock
async def test_a_redirect_is_refused_rather_than_followed(client: CensysHttpClient) -> None:
    """Following it would carry the analyst's token to wherever it points."""
    respx.get(f"{BASE}/v3/global/asset/host/{ADDRESS}").mock(
        return_value=httpx.Response(302, headers={"location": "https://elsewhere.example/x"})
    )
    with pytest.raises(ProviderSchemaError):
        await client.get_host(ip=ADDRESS, credential=make_credential())


@respx.mock
async def test_a_non_json_body_is_a_schema_error(client: CensysHttpClient) -> None:
    respx.get(f"{BASE}/v3/global/asset/host/{ADDRESS}").mock(
        return_value=httpx.Response(200, text="<html>")
    )
    with pytest.raises(ProviderSchemaError):
        await client.get_host(ip=ADDRESS, credential=make_credential())


@respx.mock
async def test_a_json_array_is_a_schema_error(client: CensysHttpClient) -> None:
    respx.get(f"{BASE}/v3/global/asset/host/{ADDRESS}").mock(
        return_value=httpx.Response(200, json=[1, 2])
    )
    with pytest.raises(ProviderSchemaError):
        await client.get_host(ip=ADDRESS, credential=make_credential())


# --------------------------------------------------------------------------- #
# Headers carried upwards
# --------------------------------------------------------------------------- #


@respx.mock
async def test_only_metering_headers_are_carried_upwards(client: CensysHttpClient) -> None:
    respx.get(f"{BASE}/v3/global/asset/host/{ADDRESS}").mock(
        return_value=httpx.Response(
            200,
            json={},
            headers={
                "X-RateLimit-Remaining": "9",
                "Set-Cookie": "session=secret-value",
                "X-Internal-Thing": "keep-out",
            },
        )
    )
    result = await client.get_host(ip=ADDRESS, credential=make_credential())
    assert result.metering_headers == {"x-ratelimit-remaining": "9"}
    assert "set-cookie" not in result.metering_headers


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #


async def test_the_client_can_be_used_as_a_context_manager() -> None:
    async with CensysHttpClient(CensysConfig()) as censys_client:
        assert censys_client.provider_id == "censys"


def test_the_repr_reveals_no_credential_surface() -> None:
    assert FAKE_TOKEN not in repr(CensysHttpClient())
    assert "api.platform.censys.io" in repr(CensysHttpClient())
