"""Censys security boundaries (Task 9).

Everything here is about what must never happen: the token reaching a URL, a log
line or a cache key; a lookup leaving the pinned host; a search being issued;
attacker-authored banner or body text being stored in an evidence record.
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

from fixtures.censys import payloads
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import ProviderCapability, ProviderOperation
from ti_recon.execution.cache import build_cache_key
from ti_recon.execution.models import ExecutionScope
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.censys import CensysAdapter, build_censys_descriptor
from ti_recon.providers.censys import adapter as adapter_module
from ti_recon.providers.censys import assets as assets_module
from ti_recon.providers.censys import client as client_module
from ti_recon.providers.censys import normalizer as normalizer_module
from ti_recon.providers.errors import ProviderSchemaError
from ti_recon.providers.transport import ProviderTransportSecurityError
from ti_recon.security import SENSITIVE_KEY_PATTERN

BASE = "https://api.platform.censys.io"
LEAKY_TOKEN = "censys-pat-SHOULD-NOT-LEAK-1234567890"
ADDRESS = payloads.HOST_IP


def credential(secret: str = LEAKY_TOKEN, user_id: str = "analyst-a") -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id=user_id,
        provider_id="censys",
        credential_group="censys",
        auth_type=AuthType.BEARER_TOKEN,
        secret=SecretStr(secret),
    )


def request_for(**overrides: Any) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": normalize_observable(ADDRESS).intel_object,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.CURRENT_INFRASTRUCTURE}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


def route_the_whole_stack() -> dict[str, respx.Route]:
    return {
        "host": respx.get(f"{BASE}/v3/global/asset/host/{ADDRESS}").mock(
            return_value=httpx.Response(200, json=payloads.host_payload())
        ),
        "web_property": respx.get(
            f"{BASE}/v3/global/asset/webproperty/{payloads.WEB_PROPERTY_HOST}:443"
        ).mock(return_value=httpx.Response(200, json=payloads.web_property_payload())),
        "credits": respx.get(f"{BASE}/v3/accounts/users/credits").mock(
            return_value=httpx.Response(200, json=payloads.user_credits_payload())
        ),
    }


# --------------------------------------------------------------------------- #
# Nothing active, nothing searched
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_lookup_only_ever_issues_get_requests() -> None:
    route_the_whole_stack()
    adapter = CensysAdapter()
    await adapter.lookup(request_for(), credential())
    assert respx.calls
    for call in respx.calls:
        assert call.request.method == "GET"


@respx.mock
async def test_a_lookup_never_reaches_the_search_or_rescan_endpoints() -> None:
    route_the_whole_stack()
    search = respx.route(url__regex=rf"{BASE}/v3/global/search.*").mock(
        return_value=httpx.Response(200, json={})
    )
    other = respx.route(url__regex=rf"{BASE}/(?!v3/(global/asset|accounts)/).*").mock(
        return_value=httpx.Response(200, json={})
    )

    adapter = CensysAdapter()
    await adapter.lookup(request_for(), credential())
    await adapter.lookup(
        request_for(
            intel_object=normalize_observable(
                f"https://{payloads.WEB_PROPERTY_HOST}/login"
            ).intel_object
        ),
        credential(),
    )
    assert not search.called
    assert not other.called


def test_no_module_in_the_package_executes_anything() -> None:
    """Static analysis only: no eval, no exec, no subprocess anywhere."""
    for module in (client_module, adapter_module, normalizer_module, assets_module):
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
    descriptor = build_censys_descriptor()
    assert descriptor.supports_active is False
    assert ProviderCapability.ACTIVE_SCAN not in descriptor.capabilities


def test_censys_is_not_declared_as_a_web_forensics_provider() -> None:
    """urlscan owns that; nothing here retrieves a response body."""
    assert ProviderCapability.WEB_FORENSICS not in build_censys_descriptor().capabilities


# --------------------------------------------------------------------------- #
# The credential
# --------------------------------------------------------------------------- #


@respx.mock
async def test_the_token_is_a_header_and_never_appears_in_a_url() -> None:
    route_the_whole_stack()
    adapter = CensysAdapter()
    await adapter.lookup(request_for(), credential())
    for call in respx.calls:
        assert LEAKY_TOKEN not in str(call.request.url)
        assert call.request.headers["Authorization"] == f"Bearer {LEAKY_TOKEN}"


@respx.mock
async def test_the_token_never_reaches_a_log_line(caplog: pytest.LogCaptureFixture) -> None:
    route_the_whole_stack()
    adapter = CensysAdapter()
    with caplog.at_level(logging.DEBUG):
        await adapter.lookup(request_for(), credential())
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert LEAKY_TOKEN not in text
    assert "SHOULD-NOT-LEAK" not in text
    for record in caplog.records:
        assert LEAKY_TOKEN not in str(record.__dict__)


@respx.mock
async def test_a_failed_balance_read_logs_only_a_normalized_category(
    caplog: pytest.LogCaptureFixture,
) -> None:
    respx.get(f"{BASE}/v3/global/asset/host/{ADDRESS}").mock(
        return_value=httpx.Response(200, json=payloads.host_payload())
    )
    respx.get(f"{BASE}/v3/accounts/users/credits").mock(
        return_value=httpx.Response(500, json={"message": f"token {LEAKY_TOKEN} broke us"})
    )
    adapter = CensysAdapter()
    with caplog.at_level(logging.INFO):
        await adapter.lookup(request_for(), credential())
    for record in caplog.records:
        assert LEAKY_TOKEN not in str(record.__dict__)


def test_a_cache_key_is_built_from_ids_and_never_from_a_secret() -> None:
    scope = ExecutionScope.for_user(
        provider_id="censys", user_id="analyst-a", provider_connection_id="conn-1"
    )
    key = build_cache_key(scope=scope, descriptor=build_censys_descriptor(), request=request_for())
    assert LEAKY_TOKEN not in key.storage_key
    assert SENSITIVE_KEY_PATTERN.search(key.storage_key) is None


def test_a_credential_never_appears_in_a_request_object() -> None:
    dumped = request_for().model_dump_json()
    assert LEAKY_TOKEN not in dumped
    assert SENSITIVE_KEY_PATTERN.search(dumped) is None


def test_a_credential_does_not_survive_being_printed() -> None:
    material = credential()
    assert LEAKY_TOKEN not in repr(material)
    assert LEAKY_TOKEN not in str(material)
    assert LEAKY_TOKEN not in material.model_dump_json()


# --------------------------------------------------------------------------- #
# The host boundary
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_redirect_off_the_host_never_receives_the_token() -> None:
    respx.get(f"{BASE}/v3/accounts/users/credits").mock(
        return_value=httpx.Response(200, json=payloads.user_credits_payload())
    )
    respx.get(f"{BASE}/v3/global/asset/host/{ADDRESS}").mock(
        return_value=httpx.Response(302, headers={"location": "https://evil.example/collect"})
    )
    elsewhere = respx.get("https://evil.example/collect").mock(
        return_value=httpx.Response(200, json={})
    )
    adapter = CensysAdapter()
    with pytest.raises(ProviderSchemaError):
        await adapter.lookup(request_for(), credential())
    assert not elsewhere.called


@respx.mock
async def test_no_analyst_supplied_value_can_become_a_request_target() -> None:
    """There is no ``fetch_arbitrary_url``; a path leaving the base URL raises.

    Nothing is mocked, so a path that escaped the guard would fail loudly rather
    than reach the network.
    """
    client = client_module.CensysHttpClient()
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


@respx.mock
async def test_an_investigated_url_is_never_fetched_directly() -> None:
    """A suspicious URL is asked *about*, never visited."""
    route_the_whole_stack()
    target = respx.route(host="login.example.com").mock(return_value=httpx.Response(200))
    adapter = CensysAdapter()
    await adapter.lookup(
        request_for(
            intel_object=normalize_observable(
                f"https://{payloads.WEB_PROPERTY_HOST}/login"
            ).intel_object
        ),
        credential(),
    )
    assert not target.called


# --------------------------------------------------------------------------- #
# Nothing provider-controlled becomes unbounded or attacker-authored
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_hostile_asset_cannot_grow_the_evidence_without_bound() -> None:
    payload = payloads.host_payload(
        services=[
            {
                "port": 1000 + index,
                "protocol": "HTTP",
                "banner": "x" * 10_000,
                "labels": ["y" * 5_000] * 100,
            }
            for index in range(1_000)
        ],
        dns={"names": [f"h{index}.example.com" for index in range(2_000)]},
        labels=[f"label-{index}" for index in range(2_000)],
    )
    respx.get(f"{BASE}/v3/global/asset/host/{ADDRESS}").mock(
        return_value=httpx.Response(200, json=payload)
    )
    respx.get(f"{BASE}/v3/accounts/users/credits").mock(
        return_value=httpx.Response(200, json=payloads.user_credits_payload())
    )

    adapter = CensysAdapter()
    envelope = await adapter.lookup(request_for(), credential())
    serialized = envelope.model_dump_json()
    assert len(serialized) < 400_000
    assert "x" * 10_000 not in serialized


@respx.mock
async def test_no_banner_survives_into_an_evidence_record() -> None:
    """A banner is whatever the scanned host chose to send."""
    route_the_whole_stack()
    adapter = CensysAdapter()
    envelope = await adapter.lookup(request_for(), credential())
    serialized = envelope.model_dump_json()
    assert "ATTACKER-CONTROLLED-TEXT" not in serialized
    assert "banner" not in serialized


@respx.mock
async def test_no_page_body_survives_into_an_evidence_record() -> None:
    route_the_whole_stack()
    adapter = CensysAdapter()
    envelope = await adapter.lookup(
        request_for(
            intel_object=normalize_observable(
                f"https://{payloads.WEB_PROPERTY_HOST}/login"
            ).intel_object
        ),
        credential(),
    )
    serialized = envelope.model_dump_json()
    assert "ATTACKER CONTROLLED PAGE" not in serialized
    assert "<html>" not in serialized
    assert "html_title" not in serialized


@respx.mock
async def test_control_characters_from_a_document_are_stripped() -> None:
    payload = payloads.host_payload(
        autonomous_system={"asn": 64500, "name": "Evil\x00Corp\r\nX: y"}
    )
    respx.get(f"{BASE}/v3/global/asset/host/{ADDRESS}").mock(
        return_value=httpx.Response(200, json=payload)
    )
    respx.get(f"{BASE}/v3/accounts/users/credits").mock(
        return_value=httpx.Response(200, json=payloads.user_credits_payload())
    )
    adapter = CensysAdapter()
    envelope = await adapter.lookup(request_for(), credential())
    name = next(
        item.attributes["as_name"]
        for item in envelope.evidence
        if item.claim_type == "censys_network_ownership"
    )
    assert "\x00" not in name
    assert "\n" not in name
