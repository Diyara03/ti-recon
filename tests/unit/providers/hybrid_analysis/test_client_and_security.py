"""The Hybrid Analysis client's surface and boundaries (Task 12).

Everything here is about what must never happen: the key reaching a URL, a log or
a cache key; a submission or a download becoming reachable; a provider string
choosing a destination; a malformed hash spending an allowance.
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
from pydantic import SecretStr, ValidationError

from fixtures.hybrid_analysis import payloads
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
)
from ti_recon.execution.cache import build_cache_key
from ti_recon.execution.models import ExecutionScope
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers import ProviderRequest
from ti_recon.providers.errors import (
    ProviderAuthenticationError,
    ProviderInvalidRequestError,
    ProviderPermissionError,
    ProviderRateLimitedError,
    ProviderSchemaError,
    ProviderUnavailableError,
)
from ti_recon.providers.hybrid_analysis import (
    ALLOWED_PATHS,
    HYBRID_ANALYSIS_AUTH_HEADER,
    HYBRID_ANALYSIS_HOST,
    HYBRID_ANALYSIS_USER_AGENT,
    ContainerReport,
    HybridAnalysisAdapter,
    HybridAnalysisConfig,
    HybridAnalysisHttpClient,
    build_hybrid_analysis_descriptor,
    category_for_status,
    read_key_info,
)
from ti_recon.providers.hybrid_analysis import adapter as adapter_module
from ti_recon.providers.hybrid_analysis import client as client_module
from ti_recon.providers.hybrid_analysis import errors as errors_module
from ti_recon.providers.hybrid_analysis import models as models_module
from ti_recon.providers.hybrid_analysis import normalizer as normalizer_module
from ti_recon.providers.transport import ProviderTransportSecurityError
from ti_recon.security import SENSITIVE_KEY_PATTERN

LEAKY_KEY = "ha-key-SHOULD-NOT-LEAK-1234567890"
SEARCH_URL = f"{HYBRID_ANALYSIS_HOST}/api/v2/search/hash"
KEY_URL = f"{HYBRID_ANALYSIS_HOST}/api/v2/key/current"

PACKAGE_MODULES = (
    client_module,
    adapter_module,
    errors_module,
    models_module,
    normalizer_module,
)


def credential(secret: str = LEAKY_KEY) -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id="analyst-a",
        provider_id="hybrid_analysis",
        credential_group="hybrid_analysis",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(secret),
    )


def summary_url(report_id: str) -> str:
    return f"{HYBRID_ANALYSIS_HOST}/api/v2/report/{report_id}/summary"


def file_object() -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=payloads.SAMPLE_SHA256,
        display_value=payloads.SAMPLE_SHA256,
        properties={"hashes": {"SHA-256": payloads.SAMPLE_SHA256}},
    )


def request_for(**overrides: Any) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": file_object(),
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.FILE_BEHAVIOR}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


async def run_lookup(depth: InvestigationDepth = InvestigationDepth.STANDARD) -> Any:
    """One real lookup through the real transport, with routes mocked."""
    respx.get(SEARCH_URL).mock(
        return_value=httpx.Response(200, json=payloads.search_hash_malicious())
    )
    respx.route(url__startswith=f"{HYBRID_ANALYSIS_HOST}/api/v2/report/").mock(
        return_value=httpx.Response(200, json=payloads.summary_malicious())
    )
    return await HybridAnalysisAdapter().lookup(request_for(depth=depth), credential())


# --------------------------------------------------------------------------- #
# The permitted surface
# --------------------------------------------------------------------------- #


def test_only_three_reads_are_permitted() -> None:
    assert ALLOWED_PATHS == {
        "api/v2/search/hash",
        "api/v2/report/{id}/summary",
        "api/v2/key/current",
    }


@pytest.mark.parametrize(
    "forbidden",
    [
        "submit",
        "quick-scan",
        "sample",
        "pcap",
        "memory",
        "screenshot",
        "dropped-file",
        "refresh",
        "overview",
        "feed",
        "yara",
        "collection",
    ],
)
def test_no_dangerous_route_is_reachable(forbidden: str) -> None:
    assert not any(forbidden in path for path in ALLOWED_PATHS)


def test_the_client_protocol_exposes_no_transfer_method() -> None:
    """Passivity is structural: there is nothing else to call."""
    surface = {name for name in dir(HybridAnalysisHttpClient) if not name.startswith("_")}
    assert {"search_hash", "report_summary", "key_current"} <= surface
    for forbidden in ("submit", "download", "upload", "detonate", "rescan", "refresh", "sample"):
        assert not any(forbidden in name for name in surface)


@pytest.mark.parametrize("module", PACKAGE_MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_no_module_issues_a_write_or_reaches_a_forbidden_route(module: Any) -> None:
    """Read on the AST, not the prose: the docstrings name the absent routes."""
    tree = ast.parse(Path(inspect.getfile(module)).read_text(encoding="utf-8"))
    attribute_calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    for forbidden in ("post", "put", "patch", "delete", "stream"):
        assert forbidden not in attribute_calls, f"{module.__name__} calls {forbidden}"
    # No literal in the package may name a route outside the allow-list. The
    # report path is assembled from a shape plus a validated id, so the two
    # normalization literals are expected and are checked as prefixes of a
    # permitted shape rather than as whole paths.
    literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    for literal in literals:
        if not literal.startswith("api/v2"):
            continue
        assert literal in ALLOWED_PATHS or any(
            path.startswith(literal.replace("[^/]+", "{id}")) for path in ALLOWED_PATHS
        ), literal


async def test_a_path_outside_the_allow_list_is_refused_before_a_request() -> None:
    """Nothing is mocked: an escape would hit the network and fail loudly."""
    client = HybridAnalysisHttpClient()
    try:
        for path in (
            "api/v2/submit/file",
            "api/v2/report/job-1/pcap",
            "api/v2/overview/abc/refresh",
            "api/v2/quick-scan/url",
        ):
            with pytest.raises(ProviderInvalidRequestError, match="not permitted"):
                await client._get(path, params=None, operation="test", credential=credential())
    finally:
        await client.aclose()


def test_the_descriptor_declares_nothing_active() -> None:
    descriptor = build_hybrid_analysis_descriptor()
    assert descriptor.supports_active is False
    assert ProviderCapability.ACTIVE_SCAN not in descriptor.capabilities


@respx.mock
async def test_a_lookup_only_issues_get_requests() -> None:
    await run_lookup()
    assert respx.calls
    for call in respx.calls:
        assert call.request.method == "GET"


@respx.mock
async def test_a_lookup_never_reaches_a_submission_or_download_route() -> None:
    forbidden = respx.route(
        url__regex=rf"{HYBRID_ANALYSIS_HOST}/api/v2/(?!search/hash|report/[^/]+/summary|key/current).*"
    ).mock(return_value=httpx.Response(200, json={}))
    await run_lookup(InvestigationDepth.DEEP)
    assert not forbidden.called


# --------------------------------------------------------------------------- #
# The credential
# --------------------------------------------------------------------------- #


@respx.mock
async def test_the_key_is_a_header_and_never_in_the_url() -> None:
    """Load-bearing here: the hash under investigation *is* a query parameter."""
    await run_lookup()
    assert respx.calls
    for call in respx.calls:
        assert call.request.headers[HYBRID_ANALYSIS_AUTH_HEADER] == LEAKY_KEY
        assert LEAKY_KEY not in str(call.request.url)
        assert not call.request.content


@respx.mock
async def test_the_key_never_reaches_a_log_line(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        await run_lookup()
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert LEAKY_KEY not in text
    assert "SHOULD-NOT-LEAK" not in text
    for record in caplog.records:
        assert LEAKY_KEY not in str(record.__dict__)


@respx.mock
async def test_an_error_body_echoing_the_key_is_dropped() -> None:
    respx.get(SEARCH_URL).mock(
        return_value=httpx.Response(401, json={"message": f"api-key {LEAKY_KEY} rejected"})
    )
    with pytest.raises(ProviderAuthenticationError) as raised:
        await HybridAnalysisAdapter().lookup(request_for(), credential())
    assert LEAKY_KEY not in str(raised.value)
    assert "SHOULD-NOT-LEAK" not in str(raised.value)


def test_the_key_endpoint_response_cannot_leak_the_key() -> None:
    """`/key/current` returns the API key itself, in a field called `api_key`.

    The reader builds an allow-listed dictionary rather than filtering a copy, so
    the key is never picked up — and `user` is ignored too, because nothing here
    needs to know who owns the key.
    """
    info = read_key_info(payloads.key_current())
    assert info == {"auth_level": 100, "auth_level_name": "restricted"}
    serialized = json.dumps(info)
    assert "SECRET-KEY-VALUE-MUST-NOT-LEAK" not in serialized
    assert "api_key" not in serialized
    assert "analyst@example.test" not in serialized


@respx.mock
async def test_validation_does_not_retain_the_key_from_its_own_response() -> None:
    respx.get(KEY_URL).mock(return_value=httpx.Response(200, json=payloads.key_current()))
    validation = await HybridAnalysisAdapter().validate_credentials(credential())
    serialized = validation.model_dump_json()
    assert "SECRET-KEY-VALUE-MUST-NOT-LEAK" not in serialized
    assert LEAKY_KEY not in serialized


def test_a_cache_key_is_built_from_ids_and_never_from_a_secret() -> None:
    key = build_cache_key(
        scope=ExecutionScope.for_user(
            provider_id="hybrid_analysis", user_id="analyst-a", provider_connection_id="conn-1"
        ),
        descriptor=build_hybrid_analysis_descriptor(),
        request=request_for(),
    )
    assert LEAKY_KEY not in key.storage_key
    assert SENSITIVE_KEY_PATTERN.search(key.storage_key) is None


def test_the_credential_does_not_survive_being_printed() -> None:
    material = credential()
    assert LEAKY_KEY not in repr(material)
    assert LEAKY_KEY not in str(material)
    assert LEAKY_KEY not in material.model_dump_json()


def test_the_user_agent_identifies_the_application_and_nothing_else() -> None:
    """One of the most widely logged strings in existence."""
    assert HYBRID_ANALYSIS_USER_AGENT.startswith("ti-recon/")
    assert SENSITIVE_KEY_PATTERN.search(HYBRID_ANALYSIS_USER_AGENT) is None


@pytest.mark.parametrize(
    "user_agent", ["", "   ", "ti-recon\r\nX: y", "ti-recon api_key=abc", "x" * 500]
)
def test_a_hostile_user_agent_is_refused(user_agent: str) -> None:
    with pytest.raises(ValidationError):
        HybridAnalysisConfig(user_agent=user_agent)


@respx.mock
async def test_the_user_agent_is_actually_sent() -> None:
    await run_lookup()
    for call in respx.calls:
        assert call.request.headers["user-agent"] == HYBRID_ANALYSIS_USER_AGENT


# --------------------------------------------------------------------------- #
# Requests
# --------------------------------------------------------------------------- #


@respx.mock
@pytest.mark.parametrize(
    "digest", [payloads.SAMPLE_SHA256, payloads.SAMPLE_SHA1, payloads.SAMPLE_MD5]
)
async def test_a_hash_search_is_a_get_with_the_digest_as_a_query_value(digest: str) -> None:
    route = respx.get(SEARCH_URL).mock(
        return_value=httpx.Response(200, json=payloads.search_hash_no_reports())
    )
    client = HybridAnalysisHttpClient()
    try:
        await client.search_hash(file_hash=digest, credential=credential())
    finally:
        await client.aclose()
    assert route.called
    request = respx.calls[0].request
    assert request.method == "GET"
    assert request.url.params["hash"] == digest


@pytest.mark.parametrize("digest", ["", "   ", "zz" + "a" * 62, "a" * 63, "a" * 128, "not-a-hash"])
async def test_a_malformed_digest_never_becomes_a_request(digest: str) -> None:
    """Nothing mocked: a request that could only be rejected wastes an allowance."""
    client = HybridAnalysisHttpClient()
    try:
        with pytest.raises(ProviderInvalidRequestError):
            await client.search_hash(file_hash=digest, credential=credential())
    finally:
        await client.aclose()


@pytest.mark.parametrize(
    "report_id", ["../../key/current", "job/1", "job 1", "", "a" * 200, "job;rm -rf /"]
)
async def test_a_hostile_report_id_never_becomes_a_path(report_id: str) -> None:
    """Report ids arrive from a provider response: untrusted on the way back out."""
    client = HybridAnalysisHttpClient()
    try:
        with pytest.raises(ProviderInvalidRequestError, match="unexpected shape"):
            await client.report_summary(report_id=report_id, credential=credential())
    finally:
        await client.aclose()


@respx.mock
async def test_a_report_id_with_an_environment_suffix_is_accepted() -> None:
    route = respx.get(summary_url("job-100:110")).mock(
        return_value=httpx.Response(200, json=payloads.summary_malicious())
    )
    client = HybridAnalysisHttpClient()
    try:
        await client.report_summary(report_id="job-100:110", credential=credential())
    finally:
        await client.aclose()
    assert route.called


@respx.mock
async def test_no_analyst_value_can_become_a_request_target() -> None:
    """There is no `fetch_arbitrary_url`; a path leaving the origin raises."""
    client = HybridAnalysisHttpClient()
    try:
        for path in ("https://evil.example/x", "//evil.example/x", "../../../etc/passwd"):
            with pytest.raises(ProviderTransportSecurityError):
                await client._http.get(path, credential=credential())
    finally:
        await client.aclose()


@respx.mock
async def test_a_redirect_off_the_host_never_receives_the_key() -> None:
    respx.get(SEARCH_URL).mock(
        return_value=httpx.Response(302, headers={"location": "https://evil.example/collect"})
    )
    elsewhere = respx.get("https://evil.example/collect").mock(
        return_value=httpx.Response(200, json={})
    )
    with pytest.raises(ProviderSchemaError):
        await HybridAnalysisAdapter().lookup(request_for(), credential())
    assert not elsewhere.called


@respx.mock
async def test_a_provider_returned_domain_is_never_contacted() -> None:
    """Provider content is data. A contacted C2 is not a destination."""
    victim = respx.route(host="c2.malware.example").mock(return_value=httpx.Response(200))
    envelope = await run_lookup(InvestigationDepth.DEEP)
    assert envelope.objects
    assert not victim.called
    for call in respx.calls:
        assert call.request.url.host == "hybrid-analysis.com"


@pytest.mark.parametrize(
    "host",
    [
        "http://hybrid-analysis.com",
        "https://hybrid-analysis.com/api/v2",
        "https://evil.example@hybrid-analysis.com",
        "not-a-url",
    ],
)
def test_a_host_that_is_not_a_plain_https_origin_is_refused(host: str) -> None:
    with pytest.raises(ValidationError):
        HybridAnalysisConfig(host=host)


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (400, ProviderErrorCategory.INVALID_REQUEST),
        (401, ProviderErrorCategory.AUTHENTICATION_ERROR),
        (403, ProviderErrorCategory.PERMISSION_ERROR),
        (404, ProviderErrorCategory.NOT_FOUND),
        (429, ProviderErrorCategory.RATE_LIMITED),
        (500, ProviderErrorCategory.TRANSIENT_ERROR),
        (502, ProviderErrorCategory.PROVIDER_UNAVAILABLE),
        (503, ProviderErrorCategory.PROVIDER_UNAVAILABLE),
        (418, ProviderErrorCategory.INVALID_REQUEST),
        (599, ProviderErrorCategory.TRANSIENT_ERROR),
    ],
)
def test_status_codes_map_to_categories(status: int, expected: ProviderErrorCategory) -> None:
    assert category_for_status(status) is expected


@respx.mock
@pytest.mark.parametrize(
    ("status", "error_type"),
    [
        (401, ProviderAuthenticationError),
        (403, ProviderPermissionError),
        (429, ProviderRateLimitedError),
        (503, ProviderUnavailableError),
    ],
)
async def test_a_failing_search_raises_the_typed_error(
    status: int, error_type: type[Exception]
) -> None:
    respx.get(SEARCH_URL).mock(return_value=httpx.Response(status, json={"message": "no"}))
    with pytest.raises(error_type):
        await HybridAnalysisAdapter().lookup(request_for(), credential())


@respx.mock
@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Exceeded maximum API requests", ProviderErrorCategory.RATE_LIMITED),
        ("Quota limit has been exceeded", ProviderErrorCategory.QUOTA_EXCEEDED),
    ],
)
async def test_quota_prose_upgrades_the_category(
    message: str, expected: ProviderErrorCategory
) -> None:
    """The API reports exhaustion in prose, not with its own status.

    Reading it as a bad request would make the executor retry a refusal that no
    retry can satisfy.
    """
    respx.get(SEARCH_URL).mock(return_value=httpx.Response(400, json={"message": message}))
    adapter = HybridAnalysisAdapter()
    with pytest.raises(Exception) as raised:
        await adapter.lookup(request_for(), credential())
    assert adapter.classify_error(raised.value) is expected  # type: ignore[arg-type]


@respx.mock
async def test_a_container_status_is_not_a_provider_failure() -> None:
    """410 means the identifier names an archive. A real answer, not an outage."""
    respx.get(SEARCH_URL).mock(
        return_value=httpx.Response(200, json=payloads.search_hash_malicious())
    )
    respx.route(url__startswith=f"{HYBRID_ANALYSIS_HOST}/api/v2/report/").mock(
        return_value=httpx.Response(410, json={"related_reports": [{"report_id": "job-900:110"}]})
    )
    adapter = HybridAnalysisAdapter()
    envelope = await adapter.lookup(request_for(), credential())
    # Reported as partial coverage, and the sample-level assessment survives.
    assert envelope.status.value == "partial"
    assert adapter.classify_error(ContainerReport("x")) is ProviderErrorCategory.PARTIAL_RESULT


@respx.mock
async def test_a_non_json_body_is_a_schema_error() -> None:
    respx.get(SEARCH_URL).mock(return_value=httpx.Response(200, text="<html>nope</html>"))
    with pytest.raises(ProviderSchemaError):
        await HybridAnalysisAdapter().lookup(request_for(), credential())


# --------------------------------------------------------------------------- #
# Rate limits
# --------------------------------------------------------------------------- #


@respx.mock
async def test_api_limits_become_a_rate_limit_snapshot() -> None:
    respx.get(SEARCH_URL).mock(
        return_value=httpx.Response(
            200,
            json=payloads.search_hash_no_reports(),
            headers={
                "Api-Limits": json.dumps(
                    {"limits": {"minute": 5, "hour": 200}, "used": {"minute": 1, "hour": 12}}
                )
            },
        )
    )
    envelope = await HybridAnalysisAdapter().lookup(request_for(), credential())
    assert envelope.rate_limit is not None
    windows = {item.window_name: item for item in envelope.rate_limit.windows}
    assert windows["minute"].limit == 5
    assert windows["minute"].remaining == 4
    assert windows["hour"].remaining == 188


@respx.mock
@pytest.mark.parametrize(
    "header",
    ["not json", "[]", '{"limits": "nope"}', "", '{"limits": {"minute": "abc"}}', "x" * 5000],
)
async def test_a_malformed_api_limits_header_is_ignored_safely(header: str) -> None:
    """No snapshot rather than a fabricated one.

    A zeroed snapshot would tell the quota pre-check the provider is exhausted
    and stop it being called at all; not knowing lets the executor try.
    """
    respx.get(SEARCH_URL).mock(
        return_value=httpx.Response(
            200, json=payloads.search_hash_no_reports(), headers={"Api-Limits": header}
        )
    )
    envelope = await HybridAnalysisAdapter().lookup(request_for(), credential())
    assert envelope.rate_limit is None


@respx.mock
async def test_an_absent_api_limits_header_invents_nothing() -> None:
    respx.get(SEARCH_URL).mock(
        return_value=httpx.Response(200, json=payloads.search_hash_no_reports())
    )
    envelope = await HybridAnalysisAdapter().lookup(request_for(), credential())
    assert envelope.rate_limit is None


# --------------------------------------------------------------------------- #
# Static safety
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("module", PACKAGE_MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_no_module_executes_anything(module: Any) -> None:
    """Provider text is data: no eval, no subprocess, no shell."""
    tree = ast.parse(Path(inspect.getfile(module)).read_text(encoding="utf-8"))
    bare = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    for forbidden in ("eval", "exec", "__import__"):
        assert forbidden not in bare
    for forbidden in ("subprocess", "os.system", "pty", "shlex"):
        assert forbidden not in imported


def test_no_vxapi_dependency_is_taken() -> None:
    """The shared transport already provides the controls a wrapper would bypass."""
    for module in PACKAGE_MODULES:
        source = Path(inspect.getfile(module)).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert not any(name.startswith("vxapi") for name in imported)
        assert not any("falcon" in name for name in imported)
