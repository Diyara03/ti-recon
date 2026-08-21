"""GTI configuration, client boundary and lifecycle (Task 7).

The vt-py-backed client is exercised with a stubbed ``vt.Client`` rather than a
mocked ``aiohttp`` stack: what matters is which paths and headers this wrapper
produces, not how vt-py serializes them.
"""

from __future__ import annotations

import inspect
from collections.abc import Mapping
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError
from vt.error import APIError

from fixtures.gti import payloads
from ti_recon import __version__
from ti_recon.enums import ProviderErrorCategory
from ti_recon.providers.errors import ProviderError
from ti_recon.providers.gti import (
    DEFAULT_GTI_HOST,
    DEFAULT_X_TOOL,
    FORBIDDEN_VT_METHODS,
    GTI_COLLECTIONS,
    GTI_X_TOOL_ENV_VAR,
    GTIClient,
    GTIConfig,
    GTIObject,
    GTIPathError,
    GTIRelationshipDescriptor,
    VtPyGTIClient,
    VtPyGTIClientFactory,
    gti_config_from_env,
    url_identifier,
)

SECRET = "vt-key-SHOULD-NOT-LEAK-12345"


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def test_defaults_are_production_safe() -> None:
    config = GTIConfig()
    assert config.host == DEFAULT_GTI_HOST
    assert config.host.startswith("https://")
    assert config.is_production_host is True
    assert config.x_tool == DEFAULT_X_TOOL
    assert config.agent == f"ti-recon/{__version__}"


def test_the_default_x_tool_follows_the_recommended_shape() -> None:
    """organization.product.major.minor, derived from the package version."""
    organization, product, major, minor = DEFAULT_X_TOOL.split(".")
    assert organization == "diyara03"
    assert product == "ti-recon"
    assert f"{major}.{minor}" == ".".join(__version__.split(".")[:2])


def test_x_tool_is_the_only_extra_header() -> None:
    assert GTIConfig(x_tool="org.tool.1.0").headers == {"x-tool": "org.tool.1.0"}


def test_no_credential_header_is_ever_added_by_config() -> None:
    """vt-py applies user headers after its own, so one here would win."""
    from ti_recon.security import SENSITIVE_KEY_PATTERN

    for name in GTIConfig().headers:
        assert SENSITIVE_KEY_PATTERN.search(name) is None


def test_config_has_no_credential_field() -> None:
    """A config object must be safe to log or serialize."""
    from ti_recon.security import SENSITIVE_KEY_PATTERN

    for name in GTIConfig.model_fields:
        assert SENSITIVE_KEY_PATTERN.search(name) is None
    assert SECRET not in GTIConfig().model_dump_json()


@pytest.mark.parametrize("value", ["", "   ", "\t"])
def test_a_blank_x_tool_is_rejected(value: str) -> None:
    with pytest.raises(ValidationError):
        GTIConfig(x_tool=value)


@pytest.mark.parametrize("value", ["org.tool\n1.0", "org\rtool", "org\x00tool"])
def test_control_characters_are_rejected(value: str) -> None:
    """A newline in a header value is header injection, not formatting."""
    with pytest.raises(ValidationError, match="control characters"):
        GTIConfig(x_tool=value)


def test_an_unusual_but_printable_x_tool_is_accepted() -> None:
    """Google may change its guidance; we do not want to be the outage."""
    assert GTIConfig(x_tool="MyOrg TI-Recon (v0.1)").x_tool == "MyOrg TI-Recon (v0.1)"


def test_surrounding_whitespace_is_trimmed() -> None:
    assert GTIConfig(x_tool="  org.tool.1.0  ").x_tool == "org.tool.1.0"


@pytest.mark.parametrize(
    "host",
    [
        "http://www.virustotal.com",
        "https://www.virustotal.com/api/v3",
        "https://www.virustotal.com?x=1",
        "https:///nohost",
    ],
)
def test_an_unsafe_host_is_rejected(host: str) -> None:
    with pytest.raises(ValidationError):
        GTIConfig(host=host)


def test_a_trailing_slash_is_normalized_away() -> None:
    assert GTIConfig(host="https://gti.test/").host == "https://gti.test"


def test_tls_verification_is_not_configurable() -> None:
    """There must be no path to switch certificate checking off."""
    assert "verify_ssl" not in GTIConfig.model_fields
    assert "verify" not in GTIConfig.model_fields
    assert "verify_ssl" not in inspect.signature(VtPyGTIClient.__init__).parameters
    source = inspect.getsource(__import__("ti_recon.providers.gti.client", fromlist=["x"]))
    assert "verify_ssl=False" not in source


def test_the_host_is_not_environment_configurable() -> None:
    """A stray variable must not be able to redirect provider traffic."""
    config = gti_config_from_env({"GTI_HOST": "https://evil.example", "VT_HOST": "x"})
    assert config.host == DEFAULT_GTI_HOST


def test_the_environment_can_set_x_tool() -> None:
    config = gti_config_from_env({GTI_X_TOOL_ENV_VAR: "acme.tirecon.1.4"})
    assert config.x_tool == "acme.tirecon.1.4"


def test_a_blank_environment_x_tool_falls_back_to_the_default() -> None:
    assert gti_config_from_env({GTI_X_TOOL_ENV_VAR: "   "}).x_tool == DEFAULT_X_TOOL
    assert gti_config_from_env({}).x_tool == DEFAULT_X_TOOL


def test_a_credential_shaped_x_tool_is_refused() -> None:
    with pytest.raises(ValueError, match="credential-like"):
        gti_config_from_env({GTI_X_TOOL_ENV_VAR: "apikey=abc123"})


# --------------------------------------------------------------------------- #
# GTIObject accessors
# --------------------------------------------------------------------------- #


def test_object_accessors_tolerate_absent_fields() -> None:
    """GTI's schema evolves; a missing field must read as absent, not raise."""
    obj = GTIObject(object_type="file", object_id="abc", attributes={"reputation": -5})
    assert obj.attribute("reputation") == -5
    assert obj.attribute("not_sent") is None
    assert obj.attribute("not_sent", "fallback") == "fallback"


def test_nested_traversal_stops_safely_at_a_non_mapping() -> None:
    obj = GTIObject(
        object_type="file",
        object_id="abc",
        attributes={"gti_assessment": {"verdict": {"value": "VERDICT_MALICIOUS"}}},
    )
    assert obj.nested("gti_assessment", "verdict", "value") == "VERDICT_MALICIOUS"
    assert obj.nested("gti_assessment", "verdict", "value", "deeper") is None
    assert obj.nested("gti_assessment", "absent", "value") is None
    assert obj.nested("reputation", "value", default="none") == "none"


def test_mapping_accessor_ignores_a_scalar_where_a_mapping_was_expected() -> None:
    """A provider turning an object into a scalar degrades, it does not crash."""
    obj = GTIObject(object_type="file", object_id="abc", attributes={"last_analysis_stats": 7})
    assert obj.mapping("last_analysis_stats") == {}
    assert obj.mapping("absent") == {}


# --------------------------------------------------------------------------- #
# Path safety
# --------------------------------------------------------------------------- #


class StubVtClient:
    """Records the paths and params vt-py would have been asked for."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.init_args = args
        self.init_kwargs = kwargs
        self.paths: list[tuple[str, Any]] = []
        self.closed = False
        self.object_result: Any = None
        self.json_result: Any = {}
        self.raise_error: BaseException | None = None

    async def get_object_async(self, path: str, params: Any = None) -> Any:
        self.paths.append((path, params))
        if self.raise_error is not None:
            raise self.raise_error
        return self.object_result

    async def get_json_async(self, path: str, params: Any = None) -> Any:
        self.paths.append((path, params))
        if self.raise_error is not None:
            raise self.raise_error
        return self.json_result

    async def close_async(self) -> None:
        self.closed = True


def make_client(stub: StubVtClient, **config_kwargs: Any) -> VtPyGTIClient:
    """A real wrapper with its vt.Client replaced by the stub."""
    client = VtPyGTIClient(SecretStr(SECRET), GTIConfig(**config_kwargs))
    client._client = stub  # type: ignore[assignment]
    return client


async def test_a_primary_lookup_builds_a_collection_path() -> None:
    stub = StubVtClient()
    stub.object_result = _VtObjectStub(payloads.file_object())
    client = make_client(stub)

    result = await client.get_primary_object(
        collection="files",
        object_id=payloads.EMPTY_FILE_SHA256,
        exclude_attributes=("last_analysis_results",),
    )

    path, params = stub.paths[0]
    assert path == f"/files/{payloads.EMPTY_FILE_SHA256}"
    assert params == {"exclude_attributes": "last_analysis_results"}
    assert isinstance(result, GTIObject)
    assert result.object_type == "file"


async def test_descriptors_use_the_relationships_path() -> None:
    stub = StubVtClient()
    stub.json_result = payloads.descriptor_page(("domain", "evil.example"))
    client = make_client(stub)

    descriptors = await client.get_relationship_descriptors(
        collection="files",
        object_id=payloads.EMPTY_FILE_SHA256,
        relationship="contacted_domains",
        limit=5,
    )

    path, params = stub.paths[0]
    assert path == f"/files/{payloads.EMPTY_FILE_SHA256}/relationships/contacted_domains"
    assert params == {"limit": 5}
    assert descriptors == (
        GTIRelationshipDescriptor(object_type="domain", object_id="evil.example"),
    )


async def test_full_objects_use_the_relationship_path_without_relationships() -> None:
    """Descriptors and full objects are genuinely different endpoints."""
    stub = StubVtClient()
    stub.json_result = payloads.object_page(payloads.domain_object())
    client = make_client(stub)

    objects = await client.get_relationship_objects(
        collection="files",
        object_id=payloads.EMPTY_FILE_SHA256,
        relationship="contacted_domains",
        limit=3,
    )

    path, _ = stub.paths[0]
    assert path == f"/files/{payloads.EMPTY_FILE_SHA256}/contacted_domains"
    assert "/relationships/" not in path
    assert len(objects) == 1
    assert objects[0].object_type == "domain"


@pytest.mark.parametrize(
    "object_id",
    [
        "../../users/abc",
        "abc/def",
        "abc?x=1",
        "https://evil.example",
        "abc#frag",
        "with space",
        "abc\ndef",
        "",
    ],
)
async def test_an_unsafe_object_id_never_reaches_a_path(object_id: str) -> None:
    stub = StubVtClient()
    client = make_client(stub)
    with pytest.raises(GTIPathError):
        await client.get_primary_object(collection="files", object_id=object_id)
    assert stub.paths == []


async def test_an_unsafe_object_id_is_not_echoed_back() -> None:
    """An id derived from analyst input does not belong in an exception."""
    client = make_client(StubVtClient())
    with pytest.raises(GTIPathError) as excinfo:
        await client.get_primary_object(collection="files", object_id="secret/../thing")
    assert "secret" not in str(excinfo.value)


@pytest.mark.parametrize("collection", ["users", "intelligence", "..", "FILES", ""])
async def test_only_known_collections_are_reachable(collection: str) -> None:
    stub = StubVtClient()
    client = make_client(stub)
    with pytest.raises(GTIPathError, match="collection"):
        await client.get_primary_object(collection=collection, object_id="abc")
    assert stub.paths == []


def test_the_known_collections_are_the_four_ioc_collections() -> None:
    assert GTI_COLLECTIONS == {"files", "domains", "ip_addresses", "urls"}


@pytest.mark.parametrize("relationship", ["../users", "Contacted_Domains", "a b", "", "x" * 80])
async def test_an_unsafe_relationship_name_is_refused(relationship: str) -> None:
    stub = StubVtClient()
    client = make_client(stub)
    with pytest.raises(GTIPathError, match="relationship"):
        await client.get_relationship_descriptors(
            collection="files", object_id="abc", relationship=relationship, limit=5
        )
    assert stub.paths == []


async def test_a_requested_limit_is_clamped_rather_than_refused() -> None:
    """A policy mistake should cost a smaller page, not an outage."""
    stub = StubVtClient()
    stub.json_result = payloads.descriptor_page()
    client = make_client(stub)

    await client.get_relationship_descriptors(
        collection="files", object_id="abc", relationship="contacted_domains", limit=10_000
    )
    _, params = stub.paths[0]
    assert params is not None
    assert params["limit"] == 40

    await client.get_relationship_descriptors(
        collection="files", object_id="abc", relationship="contacted_domains", limit=0
    )
    _, params = stub.paths[1]
    assert params is not None
    assert params["limit"] == 1


# --------------------------------------------------------------------------- #
# URL identifiers
# --------------------------------------------------------------------------- #


def test_a_url_becomes_an_opaque_identifier() -> None:
    """The suspicious URL is the object asked about, never a path we fetch."""
    identifier = url_identifier("https://evil.example/payload?a=1")
    assert identifier
    assert "://" not in identifier
    assert "evil.example" not in identifier
    assert "/" not in identifier


def test_url_identifiers_are_stable() -> None:
    assert url_identifier("https://evil.example/a") == url_identifier("https://evil.example/a")
    assert url_identifier("https://evil.example/a") != url_identifier("https://evil.example/b")


async def test_a_url_lookup_sends_only_the_identifier() -> None:
    stub = StubVtClient()
    stub.object_result = _VtObjectStub(payloads.url_object())
    client = make_client(stub)
    identifier = url_identifier("https://evil.example/payload")

    await client.get_primary_object(collection="urls", object_id=identifier)

    path, _ = stub.paths[0]
    assert path == f"/urls/{identifier}"
    assert "evil.example" not in path


# --------------------------------------------------------------------------- #
# Quota path secrecy
# --------------------------------------------------------------------------- #


async def test_the_quota_path_carries_the_key_but_never_escapes() -> None:
    stub = StubVtClient()
    stub.json_result = payloads.overall_quotas_payload()
    client = make_client(stub)

    data = await client.get_quota()

    path, _ = stub.paths[0]
    # The key is in the request, as GTI's API requires...
    assert path == f"/users/{SECRET}/overall_quotas"
    # ...but nothing about it comes back out.
    assert SECRET not in str(data)
    assert "api_requests_hourly" in data


async def test_a_quota_failure_reveals_neither_the_path_nor_the_key() -> None:
    stub = StubVtClient()
    stub.raise_error = APIError("ForbiddenError", f"GET /users/{SECRET}/overall_quotas refused")
    client = make_client(stub)

    with pytest.raises(ProviderError) as excinfo:
        await client.get_quota()

    rendered = str(excinfo.value)
    assert SECRET not in rendered
    assert "overall_quotas" not in rendered
    assert excinfo.value.category is ProviderErrorCategory.PERMISSION_ERROR


async def test_the_client_repr_reveals_no_credential() -> None:
    client = make_client(StubVtClient())
    text = repr(client)
    assert SECRET not in text
    assert DEFAULT_GTI_HOST in text
    assert DEFAULT_X_TOOL in text


# --------------------------------------------------------------------------- #
# Errors and lifecycle
# --------------------------------------------------------------------------- #


async def test_api_errors_become_normalized_provider_errors() -> None:
    stub = StubVtClient()
    stub.raise_error = APIError("NotFoundError", "not found")
    client = make_client(stub)

    with pytest.raises(ProviderError) as excinfo:
        await client.get_primary_object(collection="files", object_id="abc")
    assert excinfo.value.category is ProviderErrorCategory.NOT_FOUND


async def test_relationship_failures_are_entitlement_sensitive() -> None:
    """Enterprise-gated relationships map Forbidden to a plan limitation."""
    stub = StubVtClient()
    stub.raise_error = APIError("ForbiddenError", "not included in your plan")
    client = make_client(stub)

    with pytest.raises(ProviderError) as excinfo:
        await client.get_relationship_descriptors(
            collection="files", object_id="abc", relationship="associations", limit=5
        )
    assert excinfo.value.category is ProviderErrorCategory.PLAN_LIMITED


async def test_a_primary_lookup_forbidden_is_a_permission_problem() -> None:
    """The primary lookup is not entitlement-gated, so Forbidden means access."""
    stub = StubVtClient()
    stub.raise_error = APIError("ForbiddenError", "refused")
    client = make_client(stub)

    with pytest.raises(ProviderError) as excinfo:
        await client.get_primary_object(collection="files", object_id="abc")
    assert excinfo.value.category is ProviderErrorCategory.PERMISSION_ERROR


async def test_close_is_idempotent_and_closes_the_session() -> None:
    stub = StubVtClient()
    client = make_client(stub)
    await client.close()
    await client.close()
    assert stub.closed is True
    assert client.is_closed is True


async def test_use_after_close_is_refused() -> None:
    client = VtPyGTIClient(SecretStr(SECRET))
    await client.close()
    with pytest.raises(RuntimeError, match="closed"):
        await client.get_primary_object(collection="files", object_id="abc")


async def test_closing_an_unused_client_opens_nothing() -> None:
    """Lazy construction means an unused client never created a session."""
    client = VtPyGTIClient(SecretStr(SECRET))
    await client.close()
    assert client.is_closed is True


async def test_the_context_manager_closes_the_session() -> None:
    stub = StubVtClient()
    async with make_client(stub) as client:
        assert client.is_closed is False
    assert stub.closed is True


def test_an_empty_api_key_is_refused() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        VtPyGTIClient(SecretStr(""))


# --------------------------------------------------------------------------- #
# vt.Client construction
# --------------------------------------------------------------------------- #


async def test_the_vt_client_is_built_with_x_tool_and_no_credential_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_vt_client(apikey: str, **kwargs: Any) -> StubVtClient:
        captured["apikey"] = apikey
        captured.update(kwargs)
        stub = StubVtClient()
        stub.json_result = {}
        return stub

    import ti_recon.providers.gti.client as client_module

    monkeypatch.setattr(client_module.vt, "Client", fake_vt_client)
    client = VtPyGTIClient(SecretStr(SECRET), GTIConfig(x_tool="acme.tool.9.9"))
    await client.get_file_behavior_summary(file_id=payloads.EMPTY_FILE_SHA256)

    assert captured["apikey"] == SECRET
    assert captured["headers"] == {"x-tool": "acme.tool.9.9"}
    assert captured["agent"] == f"ti-recon/{__version__}"
    assert captured["host"] == DEFAULT_GTI_HOST
    assert captured["trust_env"] is False
    # Never set by us: vt-py owns authentication, and a user header applied
    # after its own would override the real credential.
    assert "verify_ssl" not in captured
    for key in captured:
        assert key.lower() not in {"x-apikey", "authorization"}


def test_the_factory_creates_one_client_per_credential() -> None:
    factory = VtPyGTIClientFactory(GTIConfig(x_tool="acme.tool.1.0"))
    first = factory.create(SecretStr("key-a"))
    second = factory.create(SecretStr("key-b"))
    assert first is not second
    assert isinstance(first, GTIClient)
    assert factory.config.x_tool == "acme.tool.1.0"
    assert repr(factory) == f"<VtPyGTIClientFactory host={DEFAULT_GTI_HOST}>"
    assert "key-a" not in repr(first)


# --------------------------------------------------------------------------- #
# Passive-only boundary
# --------------------------------------------------------------------------- #


def test_no_active_vt_method_is_referenced_in_the_gti_package() -> None:
    """Task 7 is passive enrichment; an active call here is a scope violation."""
    import ti_recon.providers.gti.client as client_module
    import ti_recon.providers.gti.config as config_module
    import ti_recon.providers.gti.errors as errors_module

    for module in (client_module, config_module, errors_module):
        source = inspect.getsource(module)
        for method in FORBIDDEN_VT_METHODS:
            # The wrapper's own allow-list constant names them; nothing calls them.
            assert f".{method}(" not in source, f"{module.__name__} calls {method}"


def test_the_client_protocol_offers_only_reads() -> None:
    operations = {name for name in dir(GTIClient) if not name.startswith("_")}
    assert operations == {
        "get_primary_object",
        "get_relationship_descriptors",
        "get_relationship_objects",
        "get_quota",
        "get_file_behavior_summary",
        "close",
    }


def test_a_malformed_object_without_identity_is_rejected() -> None:
    import ti_recon.providers.gti.client as client_module

    with pytest.raises(ValueError, match="type or id"):
        client_module._object_from_payload({"attributes": {}})
    with pytest.raises(ValueError, match="not a mapping"):
        client_module._object_from_payload(["not", "a", "mapping"])


def test_descriptor_entries_without_identity_are_skipped_not_fatal() -> None:
    """One malformed entry must not discard a whole useful relationship."""
    import ti_recon.providers.gti.client as client_module

    page = {
        "data": [
            {"type": "domain", "id": "good.example"},
            {"type": "domain"},
            {"id": "no-type.example"},
            "not-a-mapping",
        ]
    }
    descriptors = client_module._to_descriptors(page, limit=10)
    assert [d.object_id for d in descriptors] == ["good.example"]


def test_object_pages_skip_unusable_entries() -> None:
    import ti_recon.providers.gti.client as client_module

    page = {"data": [payloads.domain_object(), {"attributes": {}}]}
    objects = client_module._to_objects(page, limit=10)
    assert len(objects) == 1


def test_a_page_without_data_is_empty_not_an_error() -> None:
    import ti_recon.providers.gti.client as client_module

    assert client_module._to_descriptors({}, limit=5) == ()
    assert client_module._to_objects("nonsense", limit=5) == ()
    assert client_module._data_items({"data": {"type": "x", "id": "y"}}) == [
        {"type": "x", "id": "y"}
    ]


class _VtObjectStub:
    """Stands in for ``vt.Object``: only ``to_dict`` is used at the boundary."""

    def __init__(self, payload: Mapping[str, Any]) -> None:
        self._payload = dict(payload)

    def to_dict(self) -> dict[str, Any]:
        return self._payload
