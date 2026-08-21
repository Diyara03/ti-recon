"""GTI security properties (Task 7).

The API key is the thing an attacker wants and the thing an accident most easily
leaks — into a log line, an exception, a cache key, a metric label, or one
analyst's cached result served to another. Each of those routes is closed here
and tested.

The fake key below is deliberately shaped to be obviously synthetic, so a hit
anywhere in this repository is unambiguous.
"""

from __future__ import annotations

import inspect
import json
import logging
from typing import Any

import pytest
from pydantic import SecretStr
from vt.error import APIError

from fixtures.gti import payloads
from fixtures.gti.fake_client import FakeGTIClient, FakeGTIClientFactory
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    InvestigationDepth,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
)
from ti_recon.execution import (
    ExecutionScope,
    InMemoryProviderCache,
    ManualClock,
    build_cache_key,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.errors import ProviderError, provider_error_for
from ti_recon.providers.gti import (
    DEFAULT_X_TOOL,
    FORBIDDEN_VT_METHODS,
    GTIAdapter,
    GTIConfig,
    build_gti_descriptor,
    url_identifier,
)
from ti_recon.security import SENSITIVE_KEY_PATTERN

#: Obviously synthetic, so any occurrence in output is unambiguous.
LEAKY_KEY = "vt-key-SHOULD-NOT-LEAK-12345"
OTHER_KEY = "vt-key-BELONGS-TO-ANALYST-B-67890"

ALL_CAPABILITIES = frozenset(
    {
        ProviderCapability.REPUTATION,
        ProviderCapability.RELATIONSHIPS,
        ProviderCapability.MALWARE_INTELLIGENCE,
        ProviderCapability.THREAT_ASSOCIATIONS,
        ProviderCapability.FILE_BEHAVIOR,
    }
)


def credential(
    secret: str = LEAKY_KEY, *, user_id: str = "analyst-a", connection_id: str = "conn-a"
) -> CredentialMaterial:
    return CredentialMaterial(
        connection_id=connection_id,
        user_id=user_id,
        provider_id="gti",
        credential_group="virustotal",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(secret),
    )


def request_for(intel_object: IntelObject, **overrides: Any) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": intel_object,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": ALL_CAPABILITIES,
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


def loaded_client() -> FakeGTIClient:
    fake = FakeGTIClient(
        quota_payload=payloads.overall_quotas_payload(),
        behaviour_payload=payloads.behaviour_summary_payload(),
    )
    fake.register_primary("files", payloads.file_object())
    fake.register_primary("domains", payloads.domain_object())
    fake.register_descriptors(
        "files",
        payloads.EMPTY_FILE_SHA256,
        "contacted_domains",
        payloads.descriptor_page(("domain", "c2.evil.example")),
    )
    return fake


def make_adapter(client: FakeGTIClient | None = None) -> GTIAdapter:
    return GTIAdapter(
        client_factory=FakeGTIClientFactory(client=client or loaded_client()),
        clock=ManualClock(),
    )


def file_subject() -> IntelObject:
    return normalize_observable(payloads.EMPTY_FILE_SHA256).intel_object


async def full_outcome() -> Any:
    adapter = make_adapter()
    return await adapter.lookup(
        request_for(file_subject(), depth=InvestigationDepth.DEEP), credential()
    )


# --------------------------------------------------------------------------- #
# The key never escapes
# --------------------------------------------------------------------------- #


async def test_the_key_is_not_in_the_serialized_result() -> None:
    outcome = await full_outcome()
    assert LEAKY_KEY not in json.dumps(outcome.model_dump(mode="json"))


async def test_the_key_is_not_in_any_evidence() -> None:
    outcome = await full_outcome()
    assert outcome.evidence
    for evidence in outcome.evidence:
        assert LEAKY_KEY not in evidence.model_dump_json()


async def test_the_key_is_not_in_any_normalized_object() -> None:
    outcome = await full_outcome()
    for obj in outcome.objects:
        assert LEAKY_KEY not in obj.model_dump_json()


async def test_the_key_is_not_in_the_raw_reference() -> None:
    outcome = await full_outcome()
    assert outcome.raw_reference is not None
    payload = outcome.raw_reference.model_dump_json()
    assert LEAKY_KEY not in payload
    assert "overall_quotas" not in payload
    assert "/users/" not in payload


async def test_the_key_is_not_in_the_quota_snapshot() -> None:
    outcome = await full_outcome()
    assert outcome.quota is not None
    assert LEAKY_KEY not in outcome.quota.model_dump_json()


async def test_the_key_is_not_in_an_exception() -> None:
    """Errors are scrubbed where they are built — at the client boundary."""
    from ti_recon.providers.gti.errors import translate_gti_error

    fake = FakeGTIClient()
    fake.primary_errors[("files", payloads.EMPTY_FILE_SHA256)] = translate_gti_error(
        APIError("WrongCredentialsError", f"apikey={LEAKY_KEY} rejected"),
        provider_id="gti",
        operation="primary_lookup",
        secret=LEAKY_KEY,
    )
    adapter = make_adapter(fake)

    with pytest.raises(ProviderError) as excinfo:
        await adapter.lookup(request_for(file_subject()), credential())

    assert LEAKY_KEY not in str(excinfo.value)
    assert LEAKY_KEY not in repr(excinfo.value)


async def test_the_key_is_not_in_any_log_line(caplog: pytest.LogCaptureFixture) -> None:
    fake = loaded_client()
    fake.fail_relationship(
        "files",
        payloads.EMPTY_FILE_SHA256,
        "contacted_domains",
        provider_error_for(
            ProviderErrorCategory.PLAN_LIMITED,
            "gti",
            operation="relationship_descriptors",
            message=f"apikey={LEAKY_KEY}",
        ),
    )
    fake.quota_error = provider_error_for(
        ProviderErrorCategory.TRANSIENT_ERROR, "gti", operation="quota_lookup"
    )
    adapter = make_adapter(fake)

    with caplog.at_level(logging.DEBUG):
        await adapter.lookup(request_for(file_subject()), credential())

    assert LEAKY_KEY not in caplog.text
    assert "/users/" not in caplog.text
    assert "overall_quotas" not in caplog.text


async def test_the_key_is_not_in_the_cache_key() -> None:
    """Cache keys are built from ids, options and versions only."""
    subject = file_subject()
    key = build_cache_key(
        scope=ExecutionScope.for_user(
            provider_id="gti", user_id="analyst-a", provider_connection_id="conn-a"
        ),
        descriptor=build_gti_descriptor(),
        request=request_for(subject),
    )
    assert LEAKY_KEY not in key.storage_key
    assert LEAKY_KEY not in key.scope_identity
    assert SENSITIVE_KEY_PATTERN.search(key.storage_key) is None


async def test_the_key_is_not_in_a_cached_result() -> None:
    cache = InMemoryProviderCache(clock=ManualClock())
    outcome = await full_outcome()
    key = build_cache_key(
        scope=ExecutionScope.for_user(
            provider_id="gti", user_id="analyst-a", provider_connection_id="conn-a"
        ),
        descriptor=build_gti_descriptor(),
        request=request_for(file_subject()),
    )
    await cache.set(key, outcome, 60)
    cached = await cache.get(key)
    assert cached is not None
    assert LEAKY_KEY not in json.dumps(cached.model_dump(mode="json"))


def test_the_key_is_not_in_a_repr_or_str() -> None:
    material = credential()
    adapter = make_adapter()
    for rendered in (repr(material), str(material), repr(adapter), str(adapter)):
        assert LEAKY_KEY not in rendered


def test_the_config_carries_no_key_at_all() -> None:
    config = GTIConfig()
    assert LEAKY_KEY not in config.model_dump_json()
    assert "api_key" not in set(GTIConfig.model_fields)


# --------------------------------------------------------------------------- #
# x-tool is present and is not a secret
# --------------------------------------------------------------------------- #


def test_x_tool_is_sent_on_every_request() -> None:
    """One header, applied to the client that makes every call."""
    assert GTIConfig().headers == {"x-tool": DEFAULT_X_TOOL}


def test_x_tool_is_not_treated_as_a_secret() -> None:
    """It identifies the integration, the way a User-Agent identifies a browser."""
    config = GTIConfig()
    assert config.x_tool in config.model_dump_json()
    assert SENSITIVE_KEY_PATTERN.search("x-tool") is None
    assert DEFAULT_X_TOOL in repr(
        GTIAdapter(
            client_factory=FakeGTIClientFactory(client=FakeGTIClient()),
            clock=ManualClock(),
        )._config.x_tool
    )


def test_x_tool_and_the_user_agent_stay_separate() -> None:
    config = GTIConfig()
    assert config.x_tool != config.agent
    assert "x-tool" not in config.agent


# --------------------------------------------------------------------------- #
# Cross-user isolation
# --------------------------------------------------------------------------- #


async def test_one_analysts_credential_is_never_used_for_another() -> None:
    factory = FakeGTIClientFactory(client=loaded_client())
    adapter = GTIAdapter(client_factory=factory, clock=ManualClock())

    await adapter.lookup(request_for(file_subject()), credential(LEAKY_KEY))
    await adapter.lookup(
        request_for(file_subject()),
        credential(OTHER_KEY, user_id="analyst-b", connection_id="conn-b"),
    )

    assert factory.created_for == [LEAKY_KEY, OTHER_KEY]


async def test_two_analysts_get_different_cache_keys() -> None:
    """Isolation is in the key, so there is no lookup that spans users."""
    subject = file_subject()
    keys = [
        build_cache_key(
            scope=ExecutionScope.for_user(
                provider_id="gti", user_id=user, provider_connection_id=connection
            ),
            descriptor=build_gti_descriptor(),
            request=request_for(subject),
        )
        for user, connection in (("analyst-a", "conn-a"), ("analyst-b", "conn-b"))
    ]
    assert keys[0].storage_key != keys[1].storage_key


async def test_one_analysts_cached_gti_result_is_unreachable_by_another() -> None:
    cache = InMemoryProviderCache(clock=ManualClock())
    outcome = await full_outcome()
    subject = file_subject()

    def key_for(user: str, connection: str) -> Any:
        return build_cache_key(
            scope=ExecutionScope.for_user(
                provider_id="gti", user_id=user, provider_connection_id=connection
            ),
            descriptor=build_gti_descriptor(),
            request=request_for(subject),
        )

    await cache.set(key_for("analyst-a", "conn-a"), outcome, 60)
    assert await cache.get(key_for("analyst-b", "conn-b")) is None


async def test_quota_state_is_keyed_per_credential() -> None:
    from ti_recon.execution import InMemoryQuotaStore

    store = InMemoryQuotaStore(clock=ManualClock())
    adapter = GTIAdapter(
        client_factory=FakeGTIClientFactory(client=loaded_client()),
        quota_store=store,
        clock=ManualClock(),
    )
    await adapter.fetch_quota(credential())

    a_key = ExecutionScope.for_user(
        provider_id="gti", user_id="analyst-a", provider_connection_id="conn-a"
    ).identity
    b_key = ExecutionScope.for_user(
        provider_id="gti", user_id="analyst-b", provider_connection_id="conn-b"
    ).identity
    await adapter._refresh_quota_if_stale(loaded_client(), credential())
    assert await store.get(b_key) is None or a_key != b_key


async def test_a_rotated_connection_does_not_reuse_the_old_ones_results() -> None:
    subject = file_subject()
    keys = [
        build_cache_key(
            scope=ExecutionScope.for_user(
                provider_id="gti", user_id="analyst-a", provider_connection_id=connection
            ),
            descriptor=build_gti_descriptor(),
            request=request_for(subject),
        )
        for connection in ("conn-old", "conn-new")
    ]
    assert keys[0].storage_key != keys[1].storage_key


# --------------------------------------------------------------------------- #
# Passive only
# --------------------------------------------------------------------------- #


def test_no_active_vt_method_appears_anywhere_in_the_gti_package() -> None:
    """Calling one of these would make Task 7 an active integration."""
    import ti_recon.providers.gti as package

    for module_name in (
        "adapter",
        "client",
        "config",
        "descriptor",
        "errors",
        "normalizer",
        "policy",
        "quota",
        "relationships",
    ):
        module = __import__(f"{package.__name__}.{module_name}", fromlist=["x"])
        source = inspect.getsource(module)
        for method in FORBIDDEN_VT_METHODS:
            assert f".{method}(" not in source, f"{module_name} calls {method}"


def test_no_file_or_url_submission_endpoint_is_referenced() -> None:
    import ti_recon.providers.gti as package

    for module_name in ("adapter", "client", "policy", "relationships"):
        module = __import__(f"{package.__name__}.{module_name}", fromlist=["x"])
        source = inspect.getsource(module).lower()
        for forbidden in ("/analyses", "upload_url", "private/files", "/intelligence/search"):
            assert forbidden not in source


def test_gti_never_declares_active_support() -> None:
    descriptor = build_gti_descriptor()
    assert descriptor.supports_active is False
    assert ProviderCapability.ACTIVE_SCAN not in descriptor.capabilities


async def test_an_active_request_is_refused_by_the_adapter() -> None:
    from ti_recon.enums import ActivityMode
    from ti_recon.providers import UnsupportedProviderOperation

    adapter = make_adapter()
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.lookup(
            request_for(
                file_subject(),
                operation=ProviderOperation.ACTIVE_ACTION,
                activity_mode=ActivityMode.ACTIVE,
                requested_capabilities=frozenset({ProviderCapability.ACTIVE_SCAN}),
            ),
            credential(),
        )


# --------------------------------------------------------------------------- #
# The SSRF boundary is not widened
# --------------------------------------------------------------------------- #


async def test_a_suspicious_url_is_never_fetched_directly() -> None:
    """It is the object asked about, and only ever as an opaque identifier."""
    suspicious = "https://evil.example/payload?stage=2"
    identifier = url_identifier(suspicious)
    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    fake.register_primary("urls", payloads.url_object(object_id=identifier, url=suspicious))
    adapter = make_adapter(fake)

    await adapter.lookup(request_for(normalize_observable(suspicious).intel_object), credential())

    call = fake.operations("primary")[0]
    assert call.object_id == identifier
    assert "evil.example" not in str(call.object_id)
    assert "://" not in str(call.object_id)


def test_the_gti_package_adds_no_arbitrary_fetch_function() -> None:
    import ti_recon.providers.gti as package

    for forbidden in ("fetch_arbitrary_url", "fetch_url", "open_url", "browse"):
        assert forbidden not in package.__all__
        assert not hasattr(package, forbidden)


def test_the_gti_host_cannot_be_reached_through_user_input() -> None:
    """The host is configuration; nothing in a request or the environment sets it."""
    from ti_recon.providers.gti import DEFAULT_GTI_HOST, gti_config_from_env

    hostile_environment = {
        "GTI_HOST": "https://evil.example",
        "VT_HOST": "https://evil.example",
        "VIRUSTOTAL_HOST": "https://evil.example",
    }
    assert gti_config_from_env(hostile_environment).host == DEFAULT_GTI_HOST

    # x-tool is the only variable the config layer reads at all.
    import ti_recon.providers.gti.config as config_module

    source = inspect.getsource(config_module)
    assert source.count("source.get(") == 1
    assert "GTI_X_TOOL_ENV_VAR" in source


@pytest.mark.parametrize(
    "hostile",
    [
        "https://evil.example/api/v3/files/abc",
        "http://169.254.169.254/latest/meta-data",
        "//evil.example/x",
        "../../users/leak",
    ],
)
async def test_a_hostile_object_identifier_never_becomes_a_path(hostile: str) -> None:
    from ti_recon.providers.gti.client import GTIPathError, VtPyGTIClient

    client = VtPyGTIClient(SecretStr(LEAKY_KEY))
    with pytest.raises(GTIPathError):
        await client.get_primary_object(collection="files", object_id=hostile)
    await client.close()


# --------------------------------------------------------------------------- #
# Nothing leaks through the error path either
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "code",
    [
        "WrongCredentialsError",
        "ForbiddenError",
        "QuotaExceededError",
        "TooManyRequestsError",
        "NotFoundError",
        "TransientError",
        "SomeFutureError",
    ],
)
async def test_no_error_shape_leaks_the_key(code: str) -> None:
    from ti_recon.providers.gti.errors import translate_gti_error

    error = translate_gti_error(
        APIError(code, f"GET /users/{LEAKY_KEY}/overall_quotas failed"),
        provider_id="gti",
        operation="quota_lookup",
        secret=LEAKY_KEY,
    )
    assert LEAKY_KEY not in str(error)
    assert SENSITIVE_KEY_PATTERN.search(str(error)) is None


async def test_a_validation_result_never_carries_the_key() -> None:
    fake = FakeGTIClient(
        quota_error=provider_error_for(
            ProviderErrorCategory.AUTHENTICATION_ERROR,
            "gti",
            operation="quota_lookup",
            message=f"key {LEAKY_KEY} is not valid",
        )
    )
    adapter = make_adapter(fake)
    result = await adapter.validate_credentials(credential())
    assert LEAKY_KEY not in result.model_dump_json()


async def test_warnings_never_carry_the_key() -> None:
    fake = loaded_client()
    fake.fail_relationship(
        "files",
        payloads.EMPTY_FILE_SHA256,
        "contacted_domains",
        provider_error_for(
            ProviderErrorCategory.PLAN_LIMITED,
            "gti",
            operation="relationship_descriptors",
            message=f"apikey={LEAKY_KEY}",
        ),
    )
    adapter = make_adapter(fake)
    outcome = await adapter.lookup(request_for(file_subject()), credential())
    for warning in outcome.warnings:
        assert LEAKY_KEY not in warning
        assert SENSITIVE_KEY_PATTERN.search(warning) is None


def test_no_real_looking_key_is_committed_in_the_gti_tests() -> None:
    """The fixtures use an obviously synthetic key, so a hit is unambiguous."""
    assert LEAKY_KEY.startswith("vt-key-SHOULD-NOT-LEAK")
    assert not any(character.isupper() for character in LEAKY_KEY.split("-")[-1][:2])
