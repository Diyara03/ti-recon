"""The urlscan HTTP client (Task 8).

Everything here is intercepted; nothing reaches urlscan. The tests are mostly
about what the client refuses to do: leave the host, submit anything, or read an
unbounded artifact.
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
    ProviderInvalidRequestError,
    ProviderNotFoundError,
    ProviderRateLimitedError,
    ProviderSchemaError,
)
from ti_recon.providers.transport import ProviderTransportSecurityError
from ti_recon.providers.urlscan import (
    UrlscanClient,
    UrlscanConfig,
    UrlscanHttpClient,
)
from ti_recon.providers.urlscan import client as client_module

BASE = "https://urlscan.io"
FAKE_KEY = "urlscan-key-SHOULD-NOT-LEAK-12345"
SCAN_ID = "0195f3c2-4d6e-7a8b-9c0d-1e2f3a4b5c6d"
BODY_SHA256 = "a" * 64


def make_credential() -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id="user-a",
        provider_id="urlscan",
        credential_group="urlscan",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(FAKE_KEY),
    )


@pytest.fixture
async def client() -> Any:
    urlscan_client = UrlscanHttpClient()
    yield urlscan_client
    await urlscan_client.aclose()


# --------------------------------------------------------------------------- #
# The client is read-only by construction
# --------------------------------------------------------------------------- #


def test_the_protocol_exposes_no_write_operation() -> None:
    """Passivity is structural: there is no method that could submit a scan."""
    methods = {name for name in dir(UrlscanClient) if not name.startswith("_")}
    assert methods == {
        "get_quotas",
        "search",
        "get_result",
        "get_screenshot",
        "get_dom",
        "get_response_body",
        "aclose",
    }
    for forbidden in ("scan", "submit", "rescan", "delete", "post", "download"):
        assert not any(forbidden in name for name in methods)


def test_the_concrete_client_never_posts() -> None:
    """No write verb and no write endpoint exist in the module's code.

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
        assert "api/v1/scan" not in literal
        assert "downloads/" not in literal


@respx.mock
async def test_no_operation_ever_reaches_the_submission_endpoint(
    client: UrlscanHttpClient,
) -> None:
    submit = respx.post(f"{BASE}/api/v1/scan/").mock(return_value=httpx.Response(200))
    download = respx.get(url__regex=rf"{BASE}/downloads/.*").mock(return_value=httpx.Response(200))
    respx.get(f"{BASE}/user/quotas/").mock(return_value=httpx.Response(200, json={}))
    respx.get(f"{BASE}/api/v1/search/").mock(return_value=httpx.Response(200, json={}))
    respx.get(f"{BASE}/api/v1/result/{SCAN_ID}/").mock(return_value=httpx.Response(200, json={}))
    respx.get(f"{BASE}/screenshots/{SCAN_ID}.png").mock(return_value=httpx.Response(200))
    respx.get(f"{BASE}/dom/{SCAN_ID}/").mock(return_value=httpx.Response(200))
    respx.get(f"{BASE}/responses/{BODY_SHA256}/").mock(return_value=httpx.Response(200))

    credential = make_credential()
    await client.get_quotas(credential=credential)
    await client.search(query="page.domain:example.com", size=10, credential=credential)
    await client.get_result(scan_id=SCAN_ID, credential=credential)
    await client.get_screenshot(scan_id=SCAN_ID, credential=credential)
    await client.get_dom(scan_id=SCAN_ID, credential=credential)
    await client.get_response_body(body_sha256=BODY_SHA256, credential=credential)

    assert not submit.called
    assert not download.called


# --------------------------------------------------------------------------- #
# The credential
# --------------------------------------------------------------------------- #


@respx.mock
async def test_the_key_travels_as_a_header_and_never_in_the_url(
    client: UrlscanHttpClient,
) -> None:
    route = respx.get(f"{BASE}/api/v1/search/").mock(
        return_value=httpx.Response(200, json={"results": []})
    )
    await client.search(query="domain:example.com", size=5, credential=make_credential())
    request = route.calls.last.request
    assert request.headers["API-Key"] == FAKE_KEY
    assert FAKE_KEY not in str(request.url)
    assert FAKE_KEY not in request.url.query.decode()


@respx.mock
async def test_an_unauthenticated_call_carries_no_key_header(
    client: UrlscanHttpClient,
) -> None:
    """A missing credential is a missing header, never a partially-formed one."""
    route = respx.get(f"{BASE}/user/quotas/").mock(return_value=httpx.Response(200, json={}))
    await client._get_json("user/quotas/", operation="urlscan.quotas", credential=None)  # type: ignore[arg-type]
    assert "API-Key" not in route.calls.last.request.headers


# --------------------------------------------------------------------------- #
# JSON reads
# --------------------------------------------------------------------------- #


@respx.mock
async def test_search_sends_the_expected_parameters(client: UrlscanHttpClient) -> None:
    route = respx.get(f"{BASE}/api/v1/search/").mock(
        return_value=httpx.Response(200, json={"results": [], "total": 0})
    )
    result = await client.search(
        query="page.domain:example.com",
        size=25,
        search_after="1690000000000,scan-1",
        credential=make_credential(),
    )
    params = dict(route.calls.last.request.url.params)
    assert params == {
        "q": "page.domain:example.com",
        "size": "25",
        "search_after": "1690000000000,scan-1",
    }
    assert result.payload == {"results": [], "total": 0}


@respx.mock
async def test_result_reads_one_stored_scan(client: UrlscanHttpClient) -> None:
    respx.get(f"{BASE}/api/v1/result/{SCAN_ID}/").mock(
        return_value=httpx.Response(200, json={"task": {"uuid": SCAN_ID}})
    )
    result = await client.get_result(scan_id=SCAN_ID, credential=make_credential())
    assert result.payload["task"]["uuid"] == SCAN_ID


@respx.mock
async def test_quotas_is_read_over_a_header_authenticated_path(
    client: UrlscanHttpClient,
) -> None:
    """Unlike GTI's, urlscan's quota path holds nothing sensitive."""
    route = respx.get(f"{BASE}/user/quotas/").mock(
        return_value=httpx.Response(200, json={"limits": {}})
    )
    await client.get_quotas(credential=make_credential())
    assert FAKE_KEY not in str(route.calls.last.request.url)


@respx.mock
async def test_only_rate_limit_headers_are_carried_upwards(client: UrlscanHttpClient) -> None:
    respx.get(f"{BASE}/api/v1/search/").mock(
        return_value=httpx.Response(
            200,
            json={"results": []},
            headers={
                "X-Rate-Limit-Limit": "100",
                "X-Rate-Limit-Remaining": "97",
                "X-Rate-Limit-Scope": "minute",
                "Set-Cookie": "session=abc123",
                "Server": "nginx",
            },
        )
    )
    result = await client.search(query="domain:example.com", size=5, credential=make_credential())
    assert result.rate_limit_headers == {
        "x-rate-limit-limit": "100",
        "x-rate-limit-remaining": "97",
        "x-rate-limit-scope": "minute",
    }
    assert "set-cookie" not in result.rate_limit_headers
    assert "server" not in result.rate_limit_headers


@respx.mock
async def test_an_error_status_becomes_a_normalized_error(client: UrlscanHttpClient) -> None:
    respx.get(f"{BASE}/api/v1/result/{SCAN_ID}/").mock(return_value=httpx.Response(404))
    with pytest.raises(ProviderNotFoundError):
        await client.get_result(scan_id=SCAN_ID, credential=make_credential())


@respx.mock
async def test_a_rate_limited_search_reports_its_window(client: UrlscanHttpClient) -> None:
    respx.get(f"{BASE}/api/v1/search/").mock(
        return_value=httpx.Response(429, headers={"X-Rate-Limit-Scope": "minute"})
    )
    with pytest.raises(ProviderRateLimitedError):
        await client.search(query="domain:example.com", size=5, credential=make_credential())


@respx.mock
async def test_a_non_json_body_is_a_schema_error(client: UrlscanHttpClient) -> None:
    respx.get(f"{BASE}/api/v1/search/").mock(return_value=httpx.Response(200, text="<html>"))
    with pytest.raises(ProviderSchemaError):
        await client.search(query="domain:example.com", size=5, credential=make_credential())


@respx.mock
async def test_a_json_array_is_a_schema_error(client: UrlscanHttpClient) -> None:
    respx.get(f"{BASE}/api/v1/search/").mock(return_value=httpx.Response(200, json=[1, 2]))
    with pytest.raises(ProviderSchemaError):
        await client.search(query="domain:example.com", size=5, credential=make_credential())


# --------------------------------------------------------------------------- #
# Identifiers never become paths unchecked
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "scan_id",
    [
        "../../etc/passwd",
        "0195f3c2-4d6e-7a8b-9c0d-1e2f3a4b5c6d/../../user/quotas",
        "not-a-uuid",
        "",
        "0195f3c2-4d6e-7a8b-9c0d-1e2f3a4b5c6d?x=1",
        "https://evil.example/0195f3c2-4d6e-7a8b-9c0d-1e2f3a4b5c6d",
    ],
)
async def test_a_scan_id_that_is_not_a_uuid_never_reaches_a_path(
    client: UrlscanHttpClient, scan_id: str
) -> None:
    with pytest.raises(ProviderInvalidRequestError, match="UUID"):
        await client.get_result(scan_id=scan_id, credential=make_credential())


@pytest.mark.parametrize(
    "digest",
    ["../secret", "a" * 63, "a" * 65, "zz" * 32, "", "a" * 64 + "/.."],
)
async def test_a_body_id_that_is_not_a_digest_never_reaches_a_path(
    client: UrlscanHttpClient, digest: str
) -> None:
    with pytest.raises(ProviderInvalidRequestError, match="SHA-256"):
        await client.get_response_body(body_sha256=digest, credential=make_credential())


@respx.mock
async def test_identifiers_are_lowercased_before_use(client: UrlscanHttpClient) -> None:
    route = respx.get(f"{BASE}/api/v1/result/{SCAN_ID}/").mock(
        return_value=httpx.Response(200, json={})
    )
    await client.get_result(scan_id=SCAN_ID.upper(), credential=make_credential())
    assert route.called


@pytest.mark.parametrize(
    "query",
    ["", "   ", "page.domain:ex\nample.com", "x" * 2000],
)
async def test_unusable_queries_are_refused_before_the_wire(
    client: UrlscanHttpClient, query: str
) -> None:
    with pytest.raises(ProviderInvalidRequestError):
        await client.search(query=query, size=10, credential=make_credential())


@pytest.mark.parametrize("size", [0, -1, 10_001])
async def test_out_of_range_sizes_are_refused(client: UrlscanHttpClient, size: int) -> None:
    with pytest.raises(ProviderInvalidRequestError, match="size"):
        await client.search(query="domain:example.com", size=size, credential=make_credential())


@pytest.mark.parametrize(
    "cursor",
    ["1690000000000 ,x", "cursor&q=other", "'; DROP", "x" * 300, ""],
)
async def test_a_malformed_paging_cursor_is_refused(client: UrlscanHttpClient, cursor: str) -> None:
    with pytest.raises(ProviderInvalidRequestError, match="cursor"):
        await client.search(
            query="domain:example.com",
            size=10,
            search_after=cursor,
            credential=make_credential(),
        )


# --------------------------------------------------------------------------- #
# Artifacts
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_screenshot_is_returned_whole_when_it_fits(client: UrlscanHttpClient) -> None:
    respx.get(f"{BASE}/screenshots/{SCAN_ID}.png").mock(
        return_value=httpx.Response(
            200, content=b"\x89PNG-bytes", headers={"Content-Type": "image/png"}
        )
    )
    artifact = await client.get_screenshot(scan_id=SCAN_ID, credential=make_credential())
    assert artifact.content == b"\x89PNG-bytes"
    assert artifact.content_type == "image/png"
    assert artifact.truncated is False
    assert artifact.size_bytes == 10


@respx.mock
async def test_an_oversized_dom_is_capped_and_flagged() -> None:
    urlscan_client = UrlscanHttpClient(UrlscanConfig(max_dom_bytes=64))
    respx.get(f"{BASE}/dom/{SCAN_ID}/").mock(return_value=httpx.Response(200, content=b"z" * 4096))
    artifact = await urlscan_client.get_dom(scan_id=SCAN_ID, credential=make_credential())
    assert artifact.size_bytes == 64
    assert artifact.truncated is True
    await urlscan_client.aclose()


@respx.mock
async def test_each_artifact_kind_has_its_own_cap() -> None:
    config = UrlscanConfig(max_screenshot_bytes=10, max_dom_bytes=20, max_response_bytes=30)
    urlscan_client = UrlscanHttpClient(config)
    respx.get(f"{BASE}/screenshots/{SCAN_ID}.png").mock(
        return_value=httpx.Response(200, content=b"s" * 1000)
    )
    respx.get(f"{BASE}/dom/{SCAN_ID}/").mock(return_value=httpx.Response(200, content=b"d" * 1000))
    respx.get(f"{BASE}/responses/{BODY_SHA256}/").mock(
        return_value=httpx.Response(200, content=b"r" * 1000)
    )
    credential = make_credential()
    assert (
        await urlscan_client.get_screenshot(scan_id=SCAN_ID, credential=credential)
    ).size_bytes == 10
    assert (await urlscan_client.get_dom(scan_id=SCAN_ID, credential=credential)).size_bytes == 20
    body = await urlscan_client.get_response_body(body_sha256=BODY_SHA256, credential=credential)
    assert body.size_bytes == 30
    await urlscan_client.aclose()


@respx.mock
async def test_a_content_type_is_reduced_to_its_media_type(client: UrlscanHttpClient) -> None:
    respx.get(f"{BASE}/dom/{SCAN_ID}/").mock(
        return_value=httpx.Response(
            200, content=b"<html>", headers={"Content-Type": "text/html; charset=UTF-8"}
        )
    )
    artifact = await client.get_dom(scan_id=SCAN_ID, credential=make_credential())
    assert artifact.content_type == "text/html"


@respx.mock
async def test_an_artifact_without_a_content_type_gets_a_neutral_one(
    client: UrlscanHttpClient,
) -> None:
    respx.get(f"{BASE}/responses/{BODY_SHA256}/").mock(
        return_value=httpx.Response(200, content=b"body", headers={"Content-Type": ""})
    )
    artifact = await client.get_response_body(body_sha256=BODY_SHA256, credential=make_credential())
    assert artifact.content_type == "application/octet-stream"


@respx.mock
async def test_a_failed_artifact_fetch_never_echoes_page_content(
    client: UrlscanHttpClient,
) -> None:
    respx.get(f"{BASE}/dom/{SCAN_ID}/").mock(
        return_value=httpx.Response(
            403,
            json={"message": "<html>private page body with a session cookie</html>"},
        )
    )
    with pytest.raises(Exception) as caught:
        await client.get_dom(scan_id=SCAN_ID, credential=make_credential())
    text = str(caught.value)
    assert "private page body" not in text
    assert "cookie" not in text
    assert "permission" in text


# --------------------------------------------------------------------------- #
# Redirects: bounded, and never off the host
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_same_origin_redirect_is_followed(client: UrlscanHttpClient) -> None:
    respx.get(f"{BASE}/screenshots/{SCAN_ID}.png").mock(
        return_value=httpx.Response(302, headers={"Location": f"{BASE}/screenshots/moved.png"})
    )
    final = respx.get(f"{BASE}/screenshots/moved.png").mock(
        return_value=httpx.Response(200, content=b"png", headers={"Content-Type": "image/png"})
    )
    artifact = await client.get_screenshot(scan_id=SCAN_ID, credential=make_credential())
    assert artifact.content == b"png"
    assert final.calls.last.request.headers["API-Key"] == FAKE_KEY


@respx.mock
async def test_a_relative_redirect_keeps_its_query_out_of_the_path(
    client: UrlscanHttpClient,
) -> None:
    respx.get(f"{BASE}/api/v1/result/{SCAN_ID}/").mock(
        return_value=httpx.Response(301, headers={"Location": "/api/v1/result/moved/?v=2"})
    )
    final = respx.get(f"{BASE}/api/v1/result/moved/").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    result = await client.get_result(scan_id=SCAN_ID, credential=make_credential())
    assert result.payload == {"ok": True}
    assert dict(final.calls.last.request.url.params) == {"v": "2"}


@respx.mock
@pytest.mark.parametrize(
    "location",
    [
        "https://evil.example/steal",
        "http://urlscan.io/downgrade",
        "https://urlscan.io.evil.example/lookalike",
        "//evil.example/scheme-relative",
        "//",
    ],
)
async def test_a_redirect_off_the_host_is_refused(client: UrlscanHttpClient, location: str) -> None:
    """Following it would hand the analyst's key to somebody else."""
    respx.get(f"{BASE}/api/v1/result/{SCAN_ID}/").mock(
        return_value=httpx.Response(302, headers={"Location": location})
    )
    stolen = respx.get(url__regex=r"https?://(evil\.example|urlscan\.io\.evil\.example)/.*").mock(
        return_value=httpx.Response(200, json={})
    )
    with pytest.raises(ProviderTransportSecurityError, match="redirect"):
        await client.get_result(scan_id=SCAN_ID, credential=make_credential())
    assert not stolen.called


@respx.mock
async def test_a_redirect_without_a_location_is_a_schema_error(
    client: UrlscanHttpClient,
) -> None:
    respx.get(f"{BASE}/api/v1/result/{SCAN_ID}/").mock(return_value=httpx.Response(302))
    with pytest.raises(ProviderSchemaError, match="redirect"):
        await client.get_result(scan_id=SCAN_ID, credential=make_credential())


@respx.mock
async def test_a_redirect_loop_terminates() -> None:
    urlscan_client = UrlscanHttpClient(UrlscanConfig(max_redirect_hops=2))
    route = respx.get(f"{BASE}/api/v1/result/{SCAN_ID}/").mock(
        return_value=httpx.Response(302, headers={"Location": f"/api/v1/result/{SCAN_ID}/"})
    )
    with pytest.raises(ProviderInvalidRequestError, match="redirects"):
        await urlscan_client.get_result(scan_id=SCAN_ID, credential=make_credential())
    assert route.call_count == 3
    await urlscan_client.aclose()


@respx.mock
async def test_an_artifact_redirect_loop_terminates() -> None:
    urlscan_client = UrlscanHttpClient(UrlscanConfig(max_redirect_hops=1))
    route = respx.get(f"{BASE}/dom/{SCAN_ID}/").mock(
        return_value=httpx.Response(307, headers={"Location": f"/dom/{SCAN_ID}/"})
    )
    with pytest.raises(ProviderInvalidRequestError, match="redirects"):
        await urlscan_client.get_dom(scan_id=SCAN_ID, credential=make_credential())
    assert route.call_count == 2
    await urlscan_client.aclose()


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #


def test_repr_carries_no_credential() -> None:
    text = repr(UrlscanHttpClient())
    assert FAKE_KEY not in text
    assert "urlscan.io" in text


@respx.mock
async def test_the_client_works_as_an_async_context_manager() -> None:
    respx.get(f"{BASE}/user/quotas/").mock(return_value=httpx.Response(200, json={}))
    async with UrlscanHttpClient() as urlscan_client:
        result = await urlscan_client.get_quotas(credential=make_credential())
    assert result.payload == {}


def test_a_custom_host_is_honoured_for_tests() -> None:
    urlscan_client = UrlscanHttpClient(UrlscanConfig(host="https://urlscan.test"))
    assert urlscan_client.config.hostname == "urlscan.test"
    assert urlscan_client.provider_id == "urlscan"
