"""urlscan security properties (Task 8).

Two things this integration must never do: leak the analyst's API key, and reach
an endpoint that would make urlscan act on the internet. Both are proved here at
the HTTP level, through the real client with the network intercepted, so the
guarantees hold for the code that actually runs rather than for a fake.

The fake key below is deliberately shaped to be obviously synthetic, so a hit
anywhere in this repository is unambiguous.
"""

from __future__ import annotations

import ast
import inspect
import json
import logging
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from pydantic import SecretStr

from fixtures.urlscan import payloads
from ti_recon.artifacts import ArtifactScope, InMemoryArtifactStore
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    InvestigationDepth,
    ProviderCapability,
    ProviderOperation,
)
from ti_recon.execution import ExecutionScope, ManualClock
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.transport import ProviderTransportSecurityError
from ti_recon.providers.urlscan import UrlscanAdapter, UrlscanConfig, UrlscanHttpClient
from ti_recon.providers.urlscan import client as client_module
from ti_recon.providers.urlscan import forensics as forensics_module

LEAKY_KEY = "urlscan-key-SHOULD-NOT-LEAK-12345"
OTHER_KEY = "urlscan-key-BELONGS-TO-ANALYST-B-67890"
BASE = "https://urlscan.io"
SCAN_ID = payloads.SCAN_ID
DOM_BYTES = b'<html><form action="https://collector.evil.example/x"></form></html>'

FORENSIC_CAPABILITIES = frozenset({ProviderCapability.REPUTATION, ProviderCapability.WEB_FORENSICS})


def credential(secret: str = LEAKY_KEY, user_id: str = "analyst-a") -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id=user_id,
        provider_id="urlscan",
        credential_group="urlscan",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(secret),
    )


def request_for(**overrides: Any) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": normalize_observable("login.evil.example").intel_object,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.REPUTATION}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


def route_the_whole_stack() -> dict[str, respx.Route]:
    """Intercept every endpoint the integration could plausibly touch."""
    return {
        "search": respx.get(f"{BASE}/api/v1/search/").mock(
            return_value=httpx.Response(200, json=payloads.search_payload())
        ),
        "result": respx.get(f"{BASE}/api/v1/result/{SCAN_ID}/").mock(
            return_value=httpx.Response(200, json=payloads.result_payload())
        ),
        "quotas": respx.get(f"{BASE}/user/quotas/").mock(
            return_value=httpx.Response(200, json=payloads.quotas_payload())
        ),
        "screenshot": respx.get(f"{BASE}/screenshots/{SCAN_ID}.png").mock(
            return_value=httpx.Response(200, content=b"\x89PNG-bytes")
        ),
        "dom": respx.get(f"{BASE}/dom/{SCAN_ID}/").mock(
            return_value=httpx.Response(200, content=DOM_BYTES)
        ),
        "responses": respx.get(url__regex=rf"{BASE}/responses/.*").mock(
            return_value=httpx.Response(200, content=b"console.log(1)")
        ),
        # The endpoints this integration must never reach.
        "scan": respx.post(url__regex=rf"{BASE}/api/v1/scan.*").mock(
            return_value=httpx.Response(200, json={})
        ),
        "downloads": respx.get(url__regex=rf"{BASE}/downloads/.*").mock(
            return_value=httpx.Response(200, content=b"MZ")
        ),
    }


def adapter_with_store() -> tuple[UrlscanAdapter, InMemoryArtifactStore]:
    store = InMemoryArtifactStore()
    return (
        UrlscanAdapter(config=UrlscanConfig(), artifact_store=store, clock=ManualClock()),
        store,
    )


# --------------------------------------------------------------------------- #
# Active endpoints are unreachable
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_full_forensic_lookup_never_submits_or_downloads() -> None:
    """The heaviest thing this integration does, and it still touches neither."""
    routes = route_the_whole_stack()
    adapter, _ = adapter_with_store()
    await adapter.lookup(
        request_for(depth=InvestigationDepth.DEEP, requested_capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    assert routes["search"].called
    assert routes["dom"].called
    assert not routes["scan"].called
    assert not routes["downloads"].called


@respx.mock
async def test_only_get_requests_are_ever_made() -> None:
    route_the_whole_stack()
    adapter, _ = adapter_with_store()
    await adapter.lookup(
        request_for(depth=InvestigationDepth.DEEP, requested_capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    methods = {call.request.method for call in respx.calls}
    assert methods == {"GET"}


def test_no_write_endpoint_appears_in_the_clients_code() -> None:
    """Structural, not aspirational: the URL simply is not in the module."""
    tree = ast.parse(Path(inspect.getfile(client_module)).read_text(encoding="utf-8"))
    docstrings = {
        ast.get_docstring(node, clean=False)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    }
    literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value not in docstrings
    ]
    for literal in literals:
        for forbidden in ("api/v1/scan", "downloads/", "liveshot", "/delete"):
            assert forbidden not in literal


def test_nothing_in_the_package_executes_retrieved_content() -> None:
    tree = ast.parse(Path(inspect.getfile(forensics_module)).read_text(encoding="utf-8"))
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called & {"eval", "exec", "compile", "__import__"}


# --------------------------------------------------------------------------- #
# The key goes in exactly one place
# --------------------------------------------------------------------------- #


@respx.mock
async def test_the_key_is_a_header_and_never_appears_in_a_url() -> None:
    route_the_whole_stack()
    adapter, _ = adapter_with_store()
    await adapter.lookup(
        request_for(depth=InvestigationDepth.DEEP, requested_capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    assert respx.calls
    for call in respx.calls:
        assert LEAKY_KEY not in str(call.request.url)
        assert LEAKY_KEY not in call.request.url.query.decode()
        assert call.request.headers.get("API-Key") == LEAKY_KEY


@respx.mock
async def test_the_key_never_reaches_a_log_line(caplog: pytest.LogCaptureFixture) -> None:
    route_the_whole_stack()
    adapter, _ = adapter_with_store()
    with caplog.at_level(logging.DEBUG):
        await adapter.lookup(
            request_for(
                depth=InvestigationDepth.DEEP, requested_capabilities=FORENSIC_CAPABILITIES
            ),
            credential(),
        )
    text = "\n".join(
        [record.getMessage() for record in caplog.records]
        + [json.dumps(record.__dict__, default=str) for record in caplog.records]
    )
    assert LEAKY_KEY not in text
    assert "SHOULD-NOT-LEAK" not in text


@respx.mock
async def test_no_page_content_reaches_a_log_line(caplog: pytest.LogCaptureFixture) -> None:
    """A logged DOM is a logged session cookie, sooner or later."""
    route_the_whole_stack()
    adapter, _ = adapter_with_store()
    with caplog.at_level(logging.DEBUG):
        await adapter.lookup(
            request_for(
                depth=InvestigationDepth.DEEP, requested_capabilities=FORENSIC_CAPABILITIES
            ),
            credential(),
        )
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert "<html>" not in text
    assert "collector.evil.example" not in text
    assert "console.log" not in text


@respx.mock
async def test_no_query_string_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    """Some providers take keys as query parameters; none of them get logged."""
    route_the_whole_stack()
    adapter, _ = adapter_with_store()
    with caplog.at_level(logging.INFO):
        await adapter.lookup(request_for(), credential())
    for record in caplog.records:
        assert "?" not in str(getattr(record, "provider_path", ""))
        assert "page.domain" not in json.dumps(record.__dict__, default=str)


def test_a_cache_key_is_built_from_ids_and_never_from_a_secret() -> None:
    scope = ExecutionScope.for_user(
        provider_id="urlscan", user_id="analyst-a", provider_connection_id="conn-1"
    )
    assert LEAKY_KEY not in scope.identity
    assert "analyst-a" in scope.identity


def test_a_credential_never_appears_in_a_request_object() -> None:
    serialized = json.dumps(request_for().model_dump(mode="json"))
    assert LEAKY_KEY not in serialized
    assert "secret" not in serialized


def test_a_credential_does_not_survive_being_printed() -> None:
    material = credential()
    for rendering in (repr(material), str(material), json.dumps(material.model_dump(mode="json"))):
        assert LEAKY_KEY not in rendering


# --------------------------------------------------------------------------- #
# The host boundary
# --------------------------------------------------------------------------- #


@respx.mock
async def test_an_off_host_redirect_never_receives_the_key() -> None:
    """Following it would hand the analyst's key to somebody who is not urlscan."""
    respx.get(f"{BASE}/api/v1/search/").mock(
        return_value=httpx.Response(302, headers={"Location": "https://evil.example/steal"})
    )
    stolen = respx.get(url__regex=r"https://evil\.example/.*").mock(
        return_value=httpx.Response(200, json={})
    )
    client = UrlscanHttpClient()
    try:
        with pytest.raises(ProviderTransportSecurityError):
            await client.search(query='domain:"x.example"', size=5, credential=credential())
    finally:
        await client.aclose()
    assert not stolen.called


async def test_no_analyst_supplied_url_can_become_a_request_target() -> None:
    """A suspicious URL is investigated through urlscan, never fetched directly."""
    client = UrlscanHttpClient()
    try:
        for hostile in (
            "https://evil.example/",
            "//evil.example/",
            "../../../etc/passwd",
            "0195f3c2-4d6e-7a8b-9c0d-1e2f3a4b5c6d/../../user/quotas",
        ):
            with pytest.raises(Exception) as caught:
                await client.get_result(scan_id=hostile, credential=credential())
            assert "UUID" in str(caught.value)
    finally:
        await client.aclose()


# --------------------------------------------------------------------------- #
# One analyst's page content stays theirs
# --------------------------------------------------------------------------- #


@respx.mock
async def test_captured_artifacts_are_not_reachable_by_another_analyst() -> None:
    route_the_whole_stack()
    adapter, store = adapter_with_store()
    await adapter.lookup(
        request_for(depth=InvestigationDepth.DEEP, requested_capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    mine = ArtifactScope(user_id="analyst-a", investigation_id="inv-1")
    theirs = ArtifactScope(user_id="analyst-b", investigation_id="inv-1")
    stored = store.list(mine)
    assert stored
    assert store.list(theirs) == ()
    assert store.content(theirs, stored[0].id) is None


@respx.mock
async def test_stored_page_content_is_not_in_the_result_that_gets_cached() -> None:
    route_the_whole_stack()
    adapter, _ = adapter_with_store()
    envelope = await adapter.lookup(
        request_for(depth=InvestigationDepth.DEEP, requested_capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    serialized = json.dumps(envelope.model_dump(mode="json"))
    assert "<html>" not in serialized
    assert "console.log" not in serialized
    assert OTHER_KEY not in serialized
