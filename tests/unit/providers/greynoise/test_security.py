"""GreyNoise security boundaries (Task 9).

Everything here is about what must never happen: the key reaching a URL, a log
line or a cache key; a lookup leaving the pinned host; an analyst-supplied value
becoming a request target.
"""

from __future__ import annotations

import ast
import inspect
import logging
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from pydantic import SecretStr

from fixtures.greynoise import payloads
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import ProviderCapability, ProviderOperation
from ti_recon.execution.cache import build_cache_key
from ti_recon.execution.models import ExecutionScope
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.errors import ProviderSchemaError
from ti_recon.providers.greynoise import GreyNoiseAdapter, build_greynoise_descriptor
from ti_recon.providers.greynoise import adapter as adapter_module
from ti_recon.providers.greynoise import client as client_module
from ti_recon.providers.greynoise import normalizer as normalizer_module
from ti_recon.providers.transport import ProviderTransportSecurityError
from ti_recon.security import SENSITIVE_KEY_PATTERN

BASE = "https://api.greynoise.io"
LEAKY_KEY = "greynoise-key-SHOULD-NOT-LEAK-1234567890"
ADDRESS = payloads.SCANNER_IP


def credential(secret: str = LEAKY_KEY, user_id: str = "analyst-a") -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id=user_id,
        provider_id="greynoise",
        credential_group="greynoise",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(secret),
    )


def request_for(**overrides: Any) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": normalize_observable(ADDRESS).intel_object,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.SCANNER_CONTEXT}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


def route_the_endpoints() -> dict[str, respx.Route]:
    return {
        "full": respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(
            return_value=httpx.Response(200, json=payloads.full_context_payload())
        ),
        "community": respx.get(f"{BASE}/v3/community/{ADDRESS}").mock(
            return_value=httpx.Response(200, json=payloads.community_payload())
        ),
    }


# --------------------------------------------------------------------------- #
# Nothing active, nothing hunting
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_lookup_only_ever_issues_get_requests() -> None:
    route_the_endpoints()
    adapter = GreyNoiseAdapter()
    await adapter.lookup(request_for(), credential())
    assert respx.calls
    for call in respx.calls:
        assert call.request.method == "GET"


@respx.mock
async def test_a_lookup_never_reaches_a_hunting_or_feed_endpoint() -> None:
    route_the_endpoints()
    forbidden = respx.route(url__regex=rf"{BASE}/(?!v3/(ip|community)/).*").mock(
        return_value=httpx.Response(200, json={})
    )
    adapter = GreyNoiseAdapter()
    await adapter.lookup(request_for(), credential())
    assert not forbidden.called


def test_no_module_in_the_package_executes_anything() -> None:
    """Static analysis only: no eval, no exec, no subprocess anywhere."""
    for module in (client_module, adapter_module, normalizer_module):
        source = Path(inspect.getfile(module)).read_text(encoding="utf-8")
        tree = ast.parse(source)
        called = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert "eval" not in called
        assert "exec" not in called
        assert "compile" not in called
        assert "subprocess" not in source


def test_the_descriptor_declares_nothing_active() -> None:
    descriptor = build_greynoise_descriptor()
    assert descriptor.supports_active is False
    assert ProviderCapability.ACTIVE_SCAN not in descriptor.capabilities


# --------------------------------------------------------------------------- #
# The credential
# --------------------------------------------------------------------------- #


@respx.mock
async def test_the_key_is_a_header_and_never_appears_in_a_url() -> None:
    route_the_endpoints()
    adapter = GreyNoiseAdapter()
    await adapter.lookup(request_for(), credential())
    for call in respx.calls:
        assert LEAKY_KEY not in str(call.request.url)
        assert call.request.headers["key"] == LEAKY_KEY


@respx.mock
async def test_the_key_never_reaches_a_log_line(caplog: pytest.LogCaptureFixture) -> None:
    route_the_endpoints()
    adapter = GreyNoiseAdapter()
    with caplog.at_level(logging.DEBUG):
        await adapter.lookup(request_for(), credential())
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert LEAKY_KEY not in text
    assert "SHOULD-NOT-LEAK" not in text
    for record in caplog.records:
        assert LEAKY_KEY not in str(record.__dict__)


@respx.mock
async def test_a_failed_probe_logs_only_a_normalized_category(
    caplog: pytest.LogCaptureFixture,
) -> None:
    respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(
        return_value=httpx.Response(403, json={"message": f"key {LEAKY_KEY} lacks access"})
    )
    respx.get(f"{BASE}/v3/community/{ADDRESS}").mock(
        return_value=httpx.Response(200, json=payloads.community_payload())
    )
    adapter = GreyNoiseAdapter()
    with caplog.at_level(logging.INFO):
        await adapter.lookup(request_for(), credential())
    for record in caplog.records:
        assert LEAKY_KEY not in str(record.__dict__)


def test_a_cache_key_is_built_from_ids_and_never_from_a_secret() -> None:
    scope = ExecutionScope.for_user(
        provider_id="greynoise", user_id="analyst-a", provider_connection_id="conn-1"
    )
    key = build_cache_key(
        scope=scope, descriptor=build_greynoise_descriptor(), request=request_for()
    )
    assert LEAKY_KEY not in key.storage_key
    assert SENSITIVE_KEY_PATTERN.search(key.storage_key) is None


def test_a_credential_never_appears_in_a_request_object() -> None:
    dumped = request_for().model_dump_json()
    assert LEAKY_KEY not in dumped
    assert SENSITIVE_KEY_PATTERN.search(dumped) is None


def test_a_credential_does_not_survive_being_printed() -> None:
    material = credential()
    assert LEAKY_KEY not in repr(material)
    assert LEAKY_KEY not in str(material)
    assert LEAKY_KEY not in material.model_dump_json()


# --------------------------------------------------------------------------- #
# The host boundary
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_redirect_off_the_host_never_receives_the_key() -> None:
    """The transport does not follow redirects; the client refuses to chase one."""
    respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(
        return_value=httpx.Response(302, headers={"location": "https://evil.example/collect"})
    )
    elsewhere = respx.get("https://evil.example/collect").mock(
        return_value=httpx.Response(200, json={})
    )
    adapter = GreyNoiseAdapter()
    with pytest.raises(ProviderSchemaError):
        await adapter.lookup(request_for(), credential())
    assert not elsewhere.called


@respx.mock
async def test_no_analyst_supplied_value_can_become_a_request_target() -> None:
    """There is no ``fetch_arbitrary_url``; a path leaving the base URL raises.

    Nothing is mocked, so a path that escaped the guard would fail loudly rather
    than reach the network.
    """
    client = client_module.GreyNoiseHttpClient()
    try:
        for path in (
            "https://evil.example/x",
            "//evil.example/x",
            "../../../etc/passwd",
        ):
            with pytest.raises(ProviderTransportSecurityError):
                await client._http.get(path, credential=credential())
    finally:
        await client.aclose()


# --------------------------------------------------------------------------- #
# Nothing provider-controlled becomes unbounded
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_hostile_document_cannot_grow_the_evidence_without_bound() -> None:
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["tags"] = [{"name": "x" * 5_000} for _ in range(5_000)]
    payload["internet_scanner_intelligence"]["cves"] = [
        f"CVE-2026-{index:05d}" for index in range(5_000)
    ]
    respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(return_value=httpx.Response(200, json=payload))

    adapter = GreyNoiseAdapter()
    envelope = await adapter.lookup(request_for(), credential())
    serialized = envelope.model_dump_json()
    assert len(serialized) < 200_000
    tags = next(
        item.attributes["tags"] for item in envelope.evidence if item.claim_type == "greynoise_tags"
    )
    assert len(tags) <= 25
    assert all(len(tag) <= 200 for tag in tags)


@respx.mock
async def test_control_characters_from_a_document_are_stripped() -> None:
    payload = payloads.full_context_payload()
    payload["internet_scanner_intelligence"]["metadata"]["organization"] = "Evil\x00Corp\r\nX: y"
    respx.get(f"{BASE}/v3/ip/{ADDRESS}").mock(return_value=httpx.Response(200, json=payload))

    adapter = GreyNoiseAdapter()
    envelope = await adapter.lookup(request_for(), credential())
    organization = next(
        item.attributes["organization"]
        for item in envelope.evidence
        if item.claim_type == "greynoise_network_context"
    )
    assert "\x00" not in organization
    assert "\n" not in organization
