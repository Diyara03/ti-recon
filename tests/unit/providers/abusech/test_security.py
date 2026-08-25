"""abuse.ch security boundaries (Task 10).

Everything here is about what must never happen: the Auth-Key beside the form
fields it authenticates, a lookup leaving its pinned origin, a URL from a
provider response becoming a request, a write query reaching an API that offers
several, or provider-authored text arriving unbounded.

These three providers need the boundary stated more carefully than their
siblings, for one structural reason: their APIs take parameters in a **form
body**, so every lookup is an HTTP POST. The proof used elsewhere in this
repository — "this integration never calls ``post``" — is unavailable, and would
be misleading if it were used. Passivity here is a property of the query
allow-lists, and that is what these tests assert.
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
from pydantic import SecretStr, ValidationError

from fixtures.abusech import payloads
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
    ProviderCapability,
    ProviderOperation,
)
from ti_recon.execution.cache import build_cache_key
from ti_recon.execution.models import ExecutionScope
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.abusech import ABUSE_CH_AUTH_HEADER, ABUSE_CH_PROVIDER_IDS
from ti_recon.providers.abusech import client as shared_client_module
from ti_recon.providers.abusech.client import AbuseChHttpClient
from ti_recon.providers.abusech.config import (
    MALWAREBAZAAR_HOST,
    THREATFOX_HOST,
    URLHAUS_HOST,
    AbuseChConfig,
)
from ti_recon.providers.errors import (
    ProviderAuthenticationError,
    ProviderInvalidRequestError,
    ProviderSchemaError,
)
from ti_recon.providers.malwarebazaar import MalwareBazaarAdapter, build_malwarebazaar_descriptor
from ti_recon.providers.malwarebazaar import adapter as malwarebazaar_adapter_module
from ti_recon.providers.malwarebazaar import client as malwarebazaar_client_module
from ti_recon.providers.malwarebazaar import normalizer as malwarebazaar_normalizer_module
from ti_recon.providers.threatfox import ThreatFoxAdapter, build_threatfox_descriptor
from ti_recon.providers.threatfox import adapter as threatfox_adapter_module
from ti_recon.providers.threatfox import client as threatfox_client_module
from ti_recon.providers.threatfox import normalizer as threatfox_normalizer_module
from ti_recon.providers.transport import ProviderTransportSecurityError
from ti_recon.providers.urlhaus import UrlhausAdapter, build_urlhaus_descriptor
from ti_recon.providers.urlhaus import adapter as urlhaus_adapter_module
from ti_recon.providers.urlhaus import client as urlhaus_client_module
from ti_recon.providers.urlhaus import normalizer as urlhaus_normalizer_module

LEAKY_KEY = "abusech-key-SHOULD-NOT-LEAK-1234567890"

THREATFOX_ENDPOINT = f"{THREATFOX_HOST}/api/v1/"
URLHAUS_URL_ENDPOINT = f"{URLHAUS_HOST}/v1/url/"
MALWAREBAZAAR_ENDPOINT = f"{MALWAREBAZAAR_HOST}/api/v1/"

PROVIDER_MODULES = {
    "threatfox": (
        threatfox_client_module,
        threatfox_adapter_module,
        threatfox_normalizer_module,
    ),
    "urlhaus": (urlhaus_client_module, urlhaus_adapter_module, urlhaus_normalizer_module),
    "malwarebazaar": (
        malwarebazaar_client_module,
        malwarebazaar_adapter_module,
        malwarebazaar_normalizer_module,
    ),
}

DESCRIPTORS = (
    build_threatfox_descriptor(),
    build_urlhaus_descriptor(),
    build_malwarebazaar_descriptor(),
)


def credential(provider_id: str = "threatfox", user_id: str = "analyst-a") -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id=user_id,
        provider_id=provider_id,
        credential_group="abuse_ch",
        auth_type=AuthType.AUTH_KEY,
        secret=SecretStr(LEAKY_KEY),
    )


def file_object() -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=payloads.SAMPLE_SHA256,
        display_value=payloads.SAMPLE_SHA256,
        properties={"hashes": {"SHA-256": payloads.SAMPLE_SHA256}},
    )


def request_for(
    subject: str | IntelObject = payloads.SCANNER_IP, **overrides: Any
) -> ProviderRequest:
    target = (
        subject if isinstance(subject, IntelObject) else normalize_observable(subject).intel_object
    )
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": target,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.REPUTATION}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


def route_threatfox() -> respx.Route:
    return respx.post(THREATFOX_ENDPOINT).mock(
        return_value=httpx.Response(200, json=payloads.threatfox_ioc_result())
    )


def route_urlhaus() -> respx.Route:
    return respx.post(URLHAUS_URL_ENDPOINT).mock(
        return_value=httpx.Response(200, json=payloads.urlhaus_url_result())
    )


def route_malwarebazaar() -> respx.Route:
    return respx.post(MALWAREBAZAAR_ENDPOINT).mock(
        return_value=httpx.Response(200, json=payloads.malwarebazaar_found())
    )


async def run_all_three() -> None:
    """One real lookup per provider, through the real HTTP transport."""
    route_threatfox()
    route_urlhaus()
    route_malwarebazaar()
    await ThreatFoxAdapter().lookup(request_for(), credential("threatfox"))
    await UrlhausAdapter().lookup(request_for(payloads.MALICIOUS_URL), credential("urlhaus"))
    await MalwareBazaarAdapter().lookup(request_for(file_object()), credential("malwarebazaar"))


# --------------------------------------------------------------------------- #
# The credential
# --------------------------------------------------------------------------- #


@respx.mock
async def test_the_key_is_a_header_and_never_a_form_field() -> None:
    """The risk these providers add: a key sitting beside the form parameters."""
    await run_all_three()
    assert len(respx.calls) == 3
    for call in respx.calls:
        body = call.request.content.decode()
        assert call.request.headers[ABUSE_CH_AUTH_HEADER] == LEAKY_KEY
        assert LEAKY_KEY not in body
        assert "auth" not in body.lower()
        assert "api_key" not in body.lower()


@respx.mock
async def test_the_key_never_appears_in_a_url() -> None:
    await run_all_three()
    for call in respx.calls:
        assert LEAKY_KEY not in str(call.request.url)
        assert str(call.request.url.query, "utf-8") == ""


@respx.mock
async def test_the_key_never_reaches_a_log_line(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        await run_all_three()
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert LEAKY_KEY not in text
    assert "SHOULD-NOT-LEAK" not in text
    for record in caplog.records:
        assert LEAKY_KEY not in str(record.__dict__)


@respx.mock
async def test_a_rejected_key_is_never_echoed_back_into_an_error() -> None:
    """Provider text is scrubbed: an API that echoes a key must not be relayed."""
    respx.post(THREATFOX_ENDPOINT).mock(
        return_value=httpx.Response(
            401, json={"query_status": "no_api_key", "detail": f"key {LEAKY_KEY} rejected"}
        )
    )
    with pytest.raises(ProviderAuthenticationError) as raised:
        await ThreatFoxAdapter().lookup(request_for(), credential("threatfox"))
    assert LEAKY_KEY not in str(raised.value)
    assert "SHOULD-NOT-LEAK" not in str(raised.value)


@pytest.mark.parametrize("provider_id", sorted(ABUSE_CH_PROVIDER_IDS))
def test_a_cache_key_is_built_from_ids_and_never_from_the_shared_secret(provider_id: str) -> None:
    descriptor = next(item for item in DESCRIPTORS if item.provider_id == provider_id)
    key = build_cache_key(
        scope=ExecutionScope.for_user(
            provider_id=provider_id, user_id="analyst-a", provider_connection_id="conn-1"
        ),
        descriptor=descriptor,
        request=request_for(file_object()),
    )
    assert LEAKY_KEY not in key.storage_key
    assert "abusech-key" not in key.storage_key


def test_the_credential_does_not_survive_being_printed() -> None:
    material = credential()
    assert LEAKY_KEY not in repr(material)
    assert LEAKY_KEY not in str(material)
    assert LEAKY_KEY not in material.model_dump_json()


def test_a_credential_never_appears_in_a_request_object() -> None:
    assert LEAKY_KEY not in request_for().model_dump_json()


# --------------------------------------------------------------------------- #
# Passivity, proved where it actually lives
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("allowed", "refused"),
    [
        (frozenset({"search_ioc"}), "submit_ioc"),
        (frozenset({"search_hash"}), "get_file"),
        (frozenset({"get_info"}), "upload"),
        (frozenset({"get_info"}), "add_comment"),
        (frozenset({"get_info"}), "get_recent"),
    ],
)
async def test_a_query_outside_the_allow_list_never_becomes_a_request(
    allowed: frozenset[str], refused: str
) -> None:
    """The passivity gate. Checked before a request is built, not after.

    Nothing is mocked here on purpose: a form that escaped the allow-list would
    reach the network and fail loudly rather than pass silently.
    """
    client = AbuseChHttpClient(
        AbuseChConfig(host=THREATFOX_HOST), provider_id="threatfox", allowed_queries=allowed
    )
    try:
        with pytest.raises(ProviderInvalidRequestError, match="not permitted"):
            await client.query(
                "api/v1/",
                form={"query": refused, "hash": payloads.SAMPLE_SHA256},
                operation="test",
                credential=credential(),
            )
    finally:
        await client.aclose()


@respx.mock
async def test_no_write_endpoint_is_ever_reached() -> None:
    forbidden = respx.route(
        url__regex=r"https://.*abuse\.ch/(?!(api/v1/|v1/(url|host|payload)/)$).*"
    ).mock(return_value=httpx.Response(200, json={}))
    await run_all_three()
    assert not forbidden.called


@respx.mock
async def test_a_lookup_never_asks_for_a_sample_or_a_feed() -> None:
    await run_all_three()
    for call in respx.calls:
        path = call.request.url.path
        body = call.request.content.decode()
        for forbidden in ("download", "feed", "rescan", "submit", "upload"):
            assert forbidden not in path
            assert forbidden not in body


@pytest.mark.parametrize("provider_id", sorted(PROVIDER_MODULES))
def test_no_module_in_any_package_executes_anything(provider_id: str) -> None:
    """Static analysis only: no eval, no exec, no subprocess, no renderer."""
    for module in PROVIDER_MODULES[provider_id]:
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


def test_only_safe_methods_exist_on_the_shared_transport() -> None:
    """POST is how these APIs are read; it is not a door to anything else."""
    source = Path(inspect.getfile(shared_client_module)).read_text(encoding="utf-8")
    for forbidden in (".put(", ".patch(", ".delete("):
        assert forbidden not in source


# --------------------------------------------------------------------------- #
# The host boundary
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_redirect_off_the_host_never_receives_the_key() -> None:
    respx.post(URLHAUS_URL_ENDPOINT).mock(
        return_value=httpx.Response(302, headers={"location": "https://evil.example/collect"})
    )
    elsewhere = respx.post("https://evil.example/collect").mock(
        return_value=httpx.Response(200, json={})
    )
    with pytest.raises(ProviderSchemaError):
        await UrlhausAdapter().lookup(request_for(payloads.MALICIOUS_URL), credential("urlhaus"))
    assert not elsewhere.called


@respx.mock
@pytest.mark.parametrize("host", [THREATFOX_HOST, URLHAUS_HOST, MALWAREBAZAAR_HOST])
async def test_no_analyst_supplied_value_can_become_a_request_target(host: str) -> None:
    """There is no ``fetch_arbitrary_url``; a path leaving the origin raises.

    Nothing is mocked, so a path that escaped the guard would fail loudly rather
    than reach the network.
    """
    client = AbuseChHttpClient(
        AbuseChConfig(host=host), provider_id="threatfox", allowed_queries=frozenset({"search_ioc"})
    )
    try:
        for path in (
            "https://evil.example/x",
            "//evil.example/x",
            "../../../etc/passwd",
            "http://169.254.169.254/latest/meta-data/",
        ):
            with pytest.raises(ProviderTransportSecurityError):
                await client.query(
                    path,
                    form={"query": "search_ioc", "search_term": payloads.SCANNER_IP},
                    operation="test",
                    credential=credential(),
                )
    finally:
        await client.aclose()


@respx.mock
async def test_a_malicious_url_from_a_response_is_never_contacted() -> None:
    """Provider content is data. A URLhaus result is not a browsing instruction."""
    route_urlhaus()
    victim = respx.route(host="malware.example").mock(return_value=httpx.Response(200))
    envelope = await UrlhausAdapter().lookup(
        request_for(payloads.MALICIOUS_URL, depth=InvestigationDepth.DEEP),
        credential("urlhaus"),
    )
    assert envelope.evidence
    assert not victim.called
    for call in respx.calls:
        assert call.request.url.host.endswith("abuse.ch")


def test_every_provider_is_pinned_to_its_own_origin() -> None:
    hosts = {THREATFOX_HOST, URLHAUS_HOST, MALWAREBAZAAR_HOST}
    assert len(hosts) == 3
    for host in hosts:
        assert host.startswith("https://")
        assert host.endswith("abuse.ch")
        assert AbuseChConfig(host=host).host == host


@pytest.mark.parametrize(
    "host",
    [
        "http://threatfox-api.abuse.ch",
        "https://threatfox-api.abuse.ch/api/v1/",
        "https://evil.example@threatfox-api.abuse.ch",
        "not-a-url",
    ],
)
def test_a_host_that_is_not_a_plain_https_origin_is_refused(host: str) -> None:
    with pytest.raises(ValidationError):
        AbuseChConfig(host=host)


# --------------------------------------------------------------------------- #
# Form values are untrusted on the way out too
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "form",
    [
        {},
        {"query": "search_ioc", "search_term": ""},
        {"query": "search_ioc", "search_term": "a\r\nX-Injected: y"},
        {"query": "search_ioc", "search_term": "a\x00b"},
        {"query": "search_ioc", "search_term": "x" * 5_000},
        {"query": "search_ioc", "auth_key": LEAKY_KEY},
        {"query": "search_ioc", "api-key": LEAKY_KEY},
    ],
)
async def test_a_malformed_or_credential_bearing_form_is_refused(form: dict[str, str]) -> None:
    """Nothing is mocked: an escaped form would hit the network and fail loudly."""
    client = AbuseChHttpClient(
        AbuseChConfig(host=THREATFOX_HOST),
        provider_id="threatfox",
        allowed_queries=frozenset({"search_ioc"}),
    )
    try:
        with pytest.raises(ProviderInvalidRequestError):
            await client.query("api/v1/", form=form, operation="test", credential=credential())
    finally:
        await client.aclose()


# --------------------------------------------------------------------------- #
# Nothing provider-controlled becomes unbounded
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_hostile_threatfox_document_cannot_grow_the_evidence() -> None:
    hostile = payloads.threatfox_ioc_result()
    hostile["data"] = [
        {
            "ioc": f"{payloads.SCANNER_IP}:{port}",
            "ioc_type": "ip:port",
            "threat_type": "botnet_cc",
            "malware_printable": "X" * 5_000,
            "confidence_level": 100,
            "tags": [f"tag-{index}" for index in range(2_000)],
        }
        for port in range(1, 500)
    ]
    respx.post(THREATFOX_ENDPOINT).mock(return_value=httpx.Response(200, json=hostile))
    envelope = await ThreatFoxAdapter().lookup(
        request_for(depth=InvestigationDepth.DEEP), credential("threatfox")
    )
    assert len(envelope.model_dump_json()) < 200_000


@respx.mock
async def test_a_hostile_malwarebazaar_document_cannot_grow_the_evidence() -> None:
    hostile = payloads.malwarebazaar_found(
        tags=[f"tag-{index}" for index in range(3_000)],
        yara_rules=[
            {"rule_name": f"rule_{index}", "description": "d" * 3_000} for index in range(500)
        ],
        file_information=[{"context": "url", "value": "u" * 3_000} for _ in range(500)],
        vendor_intel={f"vendor-{index}": {"verdict": "malicious"} for index in range(200)},
    )
    respx.post(MALWAREBAZAAR_ENDPOINT).mock(return_value=httpx.Response(200, json=hostile))
    envelope = await MalwareBazaarAdapter().lookup(
        request_for(file_object(), depth=InvestigationDepth.DEEP), credential("malwarebazaar")
    )
    assert len(envelope.model_dump_json()) < 200_000


@respx.mock
async def test_a_response_that_is_not_json_is_a_schema_error() -> None:
    respx.post(MALWAREBAZAAR_ENDPOINT).mock(
        return_value=httpx.Response(200, text="<html>not json</html>")
    )
    with pytest.raises(ProviderSchemaError):
        await MalwareBazaarAdapter().lookup(request_for(file_object()), credential("malwarebazaar"))


@respx.mock
async def test_a_json_array_where_an_object_belongs_is_a_schema_error() -> None:
    respx.post(MALWAREBAZAAR_ENDPOINT).mock(return_value=httpx.Response(200, json=[1, 2, 3]))
    with pytest.raises(ProviderSchemaError):
        await MalwareBazaarAdapter().lookup(request_for(file_object()), credential("malwarebazaar"))
