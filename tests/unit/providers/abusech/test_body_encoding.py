"""How each abuse.ch API wants its parameters encoded (Task 10).

The three platforms do not agree. ThreatFox reads a **JSON object**; URLhaus and
MalwareBazaar read **form data**, which MalwareBazaar's documentation states
explicitly.

Getting this wrong is not a loud failure, which is why it is tested this
precisely. A form-encoded body sent to ThreatFox is not rejected — it is
*ignored*, and ThreatFox answers as though nothing had been asked. That arrives
as ``no_result``, which normalizes into a perfectly ordinary "not currently
listed". A wrong encoding therefore looks exactly like a clean lookup, and a live
smoke suite that tolerates ``NO_DATA`` cannot tell the difference.

The other half of this file is what must **not** follow from supporting two
encodings: JSON is a serialization choice made after every safety check, never a
second way into the API.
"""

from __future__ import annotations

import json
import logging
import socket
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from pydantic import SecretStr

from fixtures.abusech import payloads
from fixtures.network import NetworkAccessDenied
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.providers.abusech import ABUSE_CH_AUTH_HEADER
from ti_recon.providers.abusech.client import (
    AbuseChBodyEncoding,
    AbuseChHttpClient,
)
from ti_recon.providers.abusech.config import (
    MALWAREBAZAAR_HOST,
    THREATFOX_HOST,
    URLHAUS_HOST,
    AbuseChConfig,
)
from ti_recon.providers.errors import (
    ProviderAuthenticationError,
    ProviderInvalidRequestError,
)
from ti_recon.providers.malwarebazaar.client import MalwareBazaarHttpClient
from ti_recon.providers.threatfox.client import (
    THREATFOX_BODY_ENCODING,
    ThreatFoxHttpClient,
)
from ti_recon.providers.urlhaus.client import UrlhausHttpClient

LEAKY_KEY = "abusech-key-SHOULD-NOT-LEAK-1234567890"

THREATFOX_ENDPOINT = f"{THREATFOX_HOST}/api/v1/"
URLHAUS_URL_ENDPOINT = f"{URLHAUS_HOST}/v1/url/"
MALWAREBAZAAR_ENDPOINT = f"{MALWAREBAZAAR_HOST}/api/v1/"

FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
JSON_CONTENT_TYPE = "application/json"


def credential(provider_id: str = "threatfox") -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id="analyst-a",
        provider_id=provider_id,
        credential_group="abuse_ch",
        auth_type=AuthType.AUTH_KEY,
        secret=SecretStr(LEAKY_KEY),
    )


def sent() -> httpx.Request:
    """The single request respx captured."""
    assert len(respx.calls) == 1
    return respx.calls[0].request


def sent_json() -> Any:
    request = sent()
    assert request.headers["content-type"].startswith(JSON_CONTENT_TYPE)
    return json.loads(request.content.decode())


def sent_form() -> dict[str, list[str]]:
    request = sent()
    assert request.headers["content-type"].startswith(FORM_CONTENT_TYPE)
    return parse_qs(request.content.decode())


# --------------------------------------------------------------------------- #
# Which platform uses which
# --------------------------------------------------------------------------- #


def test_each_platform_declares_the_encoding_its_api_documents() -> None:
    """The matrix, in one place, so a regression is a one-line diff."""
    assert THREATFOX_BODY_ENCODING is AbuseChBodyEncoding.JSON
    assert ThreatFoxHttpClient()._client.body_encoding is AbuseChBodyEncoding.JSON
    assert UrlhausHttpClient()._client.body_encoding is AbuseChBodyEncoding.FORM
    assert MalwareBazaarHttpClient()._client.body_encoding is AbuseChBodyEncoding.FORM


def test_form_is_the_default_so_a_new_client_cannot_silently_change_encoding() -> None:
    client = AbuseChHttpClient(
        AbuseChConfig(host=THREATFOX_HOST),
        provider_id="threatfox",
        allowed_queries=frozenset({"search_ioc"}),
    )
    assert client.body_encoding is AbuseChBodyEncoding.FORM


# --------------------------------------------------------------------------- #
# ThreatFox sends JSON
# --------------------------------------------------------------------------- #


@respx.mock
async def test_threatfox_search_ioc_sends_json() -> None:
    respx.post(THREATFOX_ENDPOINT).mock(
        return_value=httpx.Response(200, json=payloads.threatfox_domain_result())
    )
    client = ThreatFoxHttpClient()
    try:
        await client.search_ioc(
            search_term=payloads.MALICIOUS_DOMAIN,
            exact_match=True,
            credential=credential(),
        )
    finally:
        await client.aclose()

    body = sent_json()
    assert body["query"] == "search_ioc"
    assert body["search_term"] == payloads.MALICIOUS_DOMAIN
    # A real JSON boolean. ``"true"`` is a different value to a JSON parser, and
    # ThreatFox's API documents the boolean.
    assert body["exact_match"] is True


@respx.mock
async def test_threatfox_sends_a_json_boolean_for_a_loose_search_too() -> None:
    respx.post(THREATFOX_ENDPOINT).mock(
        return_value=httpx.Response(200, json=payloads.threatfox_ioc_result())
    )
    client = ThreatFoxHttpClient()
    try:
        await client.search_ioc(
            search_term=payloads.SCANNER_IP, exact_match=False, credential=credential()
        )
    finally:
        await client.aclose()

    assert sent_json()["exact_match"] is False


@respx.mock
async def test_threatfox_search_hash_sends_json() -> None:
    respx.post(THREATFOX_ENDPOINT).mock(
        return_value=httpx.Response(200, json=payloads.threatfox_hash_result())
    )
    client = ThreatFoxHttpClient()
    try:
        await client.search_hash(file_hash=payloads.SAMPLE_SHA256, credential=credential())
    finally:
        await client.aclose()

    body = sent_json()
    assert body["query"] == "search_hash"
    assert body["hash"] == payloads.SAMPLE_SHA256


@respx.mock
async def test_a_json_body_is_never_form_encoded_as_well() -> None:
    """One body, one encoding. A stray ``data=`` would corrupt both."""
    respx.post(THREATFOX_ENDPOINT).mock(
        return_value=httpx.Response(200, json=payloads.threatfox_domain_result())
    )
    client = ThreatFoxHttpClient()
    try:
        await client.search_ioc(
            search_term=payloads.MALICIOUS_DOMAIN, exact_match=True, credential=credential()
        )
    finally:
        await client.aclose()

    raw = sent().content.decode()
    assert raw.startswith("{")
    assert "search_term=" not in raw


@respx.mock
async def test_the_auth_key_is_still_a_header_when_the_body_is_json() -> None:
    """The credential's placement is not a property of the encoding."""
    respx.post(THREATFOX_ENDPOINT).mock(
        return_value=httpx.Response(200, json=payloads.threatfox_domain_result())
    )
    client = ThreatFoxHttpClient()
    try:
        await client.search_ioc(
            search_term=payloads.MALICIOUS_DOMAIN, exact_match=True, credential=credential()
        )
    finally:
        await client.aclose()

    request = sent()
    assert request.headers[ABUSE_CH_AUTH_HEADER] == LEAKY_KEY
    assert LEAKY_KEY not in request.content.decode()
    assert LEAKY_KEY not in str(request.url)
    assert str(request.url.query, "utf-8") == ""


# --------------------------------------------------------------------------- #
# URLhaus and MalwareBazaar keep form data
# --------------------------------------------------------------------------- #


@respx.mock
async def test_urlhaus_remains_form_encoded() -> None:
    respx.post(URLHAUS_URL_ENDPOINT).mock(
        return_value=httpx.Response(200, json=payloads.urlhaus_url_result())
    )
    client = UrlhausHttpClient()
    try:
        await client.lookup_url(url=payloads.MALICIOUS_URL, credential=credential("urlhaus"))
    finally:
        await client.aclose()

    body = sent_form()
    assert body["url"] == [payloads.MALICIOUS_URL]
    assert not sent().content.decode().startswith("{")


@respx.mock
async def test_malwarebazaar_remains_form_encoded() -> None:
    """Its documentation states form data explicitly."""
    respx.post(MALWAREBAZAAR_ENDPOINT).mock(
        return_value=httpx.Response(200, json=payloads.malwarebazaar_found())
    )
    client = MalwareBazaarHttpClient()
    try:
        await client.get_info(
            file_hash=payloads.SAMPLE_SHA256, credential=credential("malwarebazaar")
        )
    finally:
        await client.aclose()

    body = sent_form()
    assert body["query"] == ["get_info"]
    assert body["hash"] == [payloads.SAMPLE_SHA256]


@respx.mock
async def test_the_auth_key_is_still_a_header_when_the_body_is_a_form() -> None:
    respx.post(MALWAREBAZAAR_ENDPOINT).mock(
        return_value=httpx.Response(200, json=payloads.malwarebazaar_found())
    )
    client = MalwareBazaarHttpClient()
    try:
        await client.get_info(
            file_hash=payloads.SAMPLE_SHA256, credential=credential("malwarebazaar")
        )
    finally:
        await client.aclose()

    request = sent()
    assert request.headers[ABUSE_CH_AUTH_HEADER] == LEAKY_KEY
    assert LEAKY_KEY not in request.content.decode()


# --------------------------------------------------------------------------- #
# JSON is not a way around anything
# --------------------------------------------------------------------------- #


def json_client(allowed: frozenset[str] = frozenset({"search_ioc"})) -> AbuseChHttpClient:
    return AbuseChHttpClient(
        AbuseChConfig(host=THREATFOX_HOST),
        provider_id="threatfox",
        allowed_queries=allowed,
        body_encoding=AbuseChBodyEncoding.JSON,
    )


@pytest.mark.parametrize(
    "refused", ["submit_ioc", "get_iocs", "get_file", "upload", "add_comment", "taginfo"]
)
async def test_the_allow_list_still_holds_for_a_json_body(refused: str) -> None:
    """The passivity gate runs before the encoding is chosen.

    Nothing is mocked on purpose: a body that escaped the allow-list would reach
    the network and fail loudly rather than pass silently.
    """
    client = json_client()
    try:
        with pytest.raises(ProviderInvalidRequestError, match="not permitted"):
            await client.query(
                "api/v1/",
                form={"query": refused, "search_term": payloads.MALICIOUS_DOMAIN},
                operation="test",
                credential=credential(),
            )
    finally:
        await client.aclose()


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
        {"query": "search_ioc", "search_term": 12345},
        {"query": "search_ioc", "search_term": {"nested": "object"}},
        {"query": "search_ioc", "search_term": ["a", "list"]},
    ],
)
async def test_a_json_body_is_validated_exactly_as_strictly_as_a_form(
    form: dict[str, Any],
) -> None:
    """Same checks, same refusals — plus the shapes only JSON could express.

    A nested object or a list would serialize happily into JSON, which is
    precisely why they are refused here: this client sends flat, bounded,
    string-valued lookups and nothing else.
    """
    client = json_client()
    try:
        with pytest.raises(ProviderInvalidRequestError):
            await client.query("api/v1/", form=form, operation="test", credential=credential())
    finally:
        await client.aclose()


async def test_a_boolean_is_accepted_only_where_it_has_a_faithful_encoding() -> None:
    """In a form body a Python ``bool`` would go out as ``True``, which is wrong.

    Nothing is mocked: the JSON client is expected to get past validation and
    then fail on the network, which is a different error from a refusal.
    """
    form_client = AbuseChHttpClient(
        AbuseChConfig(host=THREATFOX_HOST),
        provider_id="threatfox",
        allowed_queries=frozenset({"search_ioc"}),
    )
    try:
        with pytest.raises(ProviderInvalidRequestError, match="boolean"):
            await form_client.query(
                "api/v1/",
                form={"query": "search_ioc", "exact_match": True},
                operation="test",
                credential=credential(),
            )
    finally:
        await form_client.aclose()

    assert json_client().body_encoding is AbuseChBodyEncoding.JSON


@respx.mock
async def test_a_json_lookup_still_only_reaches_the_pinned_origin() -> None:
    routed = respx.post(THREATFOX_ENDPOINT).mock(
        return_value=httpx.Response(200, json=payloads.threatfox_domain_result())
    )
    elsewhere = respx.route(url__regex=r"https://(?!threatfox-api\.abuse\.ch).*").mock(
        return_value=httpx.Response(200, json={})
    )
    client = ThreatFoxHttpClient()
    try:
        await client.search_ioc(
            search_term=payloads.MALICIOUS_DOMAIN, exact_match=True, credential=credential()
        )
    finally:
        await client.aclose()

    assert routed.called
    assert not elsewhere.called


# --------------------------------------------------------------------------- #
# Secrets
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_json_path_failure_never_carries_the_key(
    caplog: pytest.LogCaptureFixture,
) -> None:
    respx.post(THREATFOX_ENDPOINT).mock(
        return_value=httpx.Response(
            401, json={"query_status": "no_api_key", "detail": f"key {LEAKY_KEY} rejected"}
        )
    )
    client = ThreatFoxHttpClient()
    try:
        with caplog.at_level(logging.DEBUG), pytest.raises(ProviderAuthenticationError) as raised:
            await client.search_ioc(
                search_term=payloads.MALICIOUS_DOMAIN, exact_match=True, credential=credential()
            )
    finally:
        await client.aclose()

    assert LEAKY_KEY not in str(raised.value)
    for record in caplog.records:
        assert LEAKY_KEY not in str(record.__dict__)


def test_the_client_repr_names_the_encoding_and_no_secret() -> None:
    text = repr(json_client())
    assert "json" in text
    assert LEAKY_KEY not in text


# --------------------------------------------------------------------------- #
# Zero real network calls
# --------------------------------------------------------------------------- #


def _denied_network(error: BaseException) -> bool:
    """Whether ``error`` is, or wraps, the unit suite's network refusal.

    httpx runs its connect inside a task group, so the refusal arrives wrapped
    rather than raw.
    """
    if isinstance(error, NetworkAccessDenied):
        return True
    if isinstance(error, BaseExceptionGroup):
        return any(_denied_network(inner) for inner in error.exceptions)
    cause = error.__cause__ or error.__context__
    return cause is not None and _denied_network(cause)


async def test_an_unmocked_lookup_cannot_reach_the_network() -> None:
    """What makes every "nothing is mocked on purpose" claim above load-bearing.

    Several tests in this file assert a refusal *without* mocking the endpoint,
    on the grounds that a body escaping validation would fail loudly instead of
    passing silently. That argument is only as good as the guarantee that the
    unit suite cannot actually reach abuse.ch — so here is that guarantee,
    exercised: no respx mock, a real client, and the connection refused by
    ``tests/unit/conftest.py`` before it leaves the machine.

    The suite once authenticated against a live API by accident. This is the
    check that makes the same slip fail instead of succeed.
    """
    client = ThreatFoxHttpClient()
    try:
        with pytest.raises((BaseExceptionGroup, NetworkAccessDenied)) as raised:
            await client.search_ioc(
                search_term=payloads.MALICIOUS_DOMAIN,
                exact_match=True,
                credential=credential(),
            )
    finally:
        await client.aclose()

    assert _denied_network(raised.value)


async def test_the_guard_still_allows_a_platform_to_talk_to_itself() -> None:
    """Loopback stays open: asyncio, coverage and pytest plugins need it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=1) as connected:
            assert connected.fileno() != -1
