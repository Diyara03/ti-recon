"""GTI primary IOC lookups (Task 7).

Every observable type reaches the right collection with the right identifier,
and nothing active happens on any path.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import SecretStr

from fixtures.gti import payloads
from fixtures.gti.fake_client import FakeGTIClient, FakeGTIClientFactory
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    ActivityMode,
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution import ManualClock
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest, UnsupportedProviderOperation
from ti_recon.providers.errors import ProviderError, provider_error_for
from ti_recon.providers.gti import (
    DEFAULT_EXCLUDED_ATTRIBUTES,
    GTIAdapter,
    collection_for_object_type,
    url_identifier,
)

SECRET = "vt-key-SHOULD-NOT-LEAK-12345"


def credential(secret: str = SECRET, *, user_id: str = "analyst-a") -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-a",
        user_id=user_id,
        provider_id="gti",
        credential_group="virustotal",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(secret),
    )


def observable(raw: str) -> IntelObject:
    return normalize_observable(raw).intel_object


def file_object(digest: str = payloads.EMPTY_FILE_SHA256) -> IntelObject:
    return observable(digest)


def request_for(
    intel_object: IntelObject,
    *,
    capability: ProviderCapability = ProviderCapability.REPUTATION,
    **overrides: Any,
) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": intel_object,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({capability}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


def make_adapter(
    client: FakeGTIClient | None = None, **kwargs: Any
) -> tuple[GTIAdapter, FakeGTIClient]:
    fake = client if client is not None else FakeGTIClient()
    adapter = GTIAdapter(
        client_factory=FakeGTIClientFactory(client=fake), clock=ManualClock(), **kwargs
    )
    return adapter, fake


# --------------------------------------------------------------------------- #
# Collection routing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("object_type", "expected"),
    [
        (IntelObjectType.IPV4_ADDR, "ip_addresses"),
        (IntelObjectType.IPV6_ADDR, "ip_addresses"),
        (IntelObjectType.DOMAIN_NAME, "domains"),
        (IntelObjectType.URL, "urls"),
        (IntelObjectType.FILE, "files"),
    ],
)
def test_each_observable_type_maps_to_a_collection(
    object_type: IntelObjectType, expected: str
) -> None:
    assert collection_for_object_type(object_type) == expected


def test_types_gti_does_not_serve_have_no_collection() -> None:
    assert collection_for_object_type(IntelObjectType.MALWARE) is None
    assert collection_for_object_type(IntelObjectType.AUTONOMOUS_SYSTEM) is None


async def test_an_unsupported_object_type_fails_cleanly() -> None:
    adapter, client = make_adapter()
    malware = IntelObject(
        object_class=ObjectClass.THREAT,
        object_type=IntelObjectType.MALWARE,
        canonical_value="ExampleRAT",
        display_value="ExampleRAT",
    )
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.lookup(request_for(malware), credential())
    assert client.calls == []


# --------------------------------------------------------------------------- #
# IPv4 / IPv6
# --------------------------------------------------------------------------- #


async def test_an_ipv4_lookup_uses_the_ip_collection() -> None:
    fake = FakeGTIClient()
    fake.register_primary("ip_addresses", payloads.ip_object(object_id="198.51.100.7"))
    adapter, client = make_adapter(fake)

    outcome = await adapter.lookup(request_for(observable("198.51.100.7")), credential())

    call = client.operations("primary")[0]
    assert call.collection == "ip_addresses"
    assert call.object_id == "198.51.100.7"
    assert outcome.status is ProviderRunStatus.SUCCESS


async def test_an_ipv6_lookup_uses_the_same_collection() -> None:
    fake = FakeGTIClient()
    fake.register_primary("ip_addresses", payloads.ip_object(object_id="2001:db8::1"))
    adapter, client = make_adapter(fake)

    await adapter.lookup(request_for(observable("2001:0db8::1")), credential())

    call = client.operations("primary")[0]
    assert call.collection == "ip_addresses"
    assert call.object_id == "2001:db8::1"


async def test_ip_metadata_is_preserved_as_context() -> None:
    """An AS owner is infrastructure context, never malicious evidence."""
    fake = FakeGTIClient()
    fake.register_primary("ip_addresses", payloads.ip_object())
    adapter, _ = make_adapter(fake)

    outcome = await adapter.lookup(request_for(observable("198.51.100.7")), credential())

    enriched = outcome.objects[0]
    gti = enriched.properties["gti"]
    assert gti["asn"] == 64500
    assert gti["as_owner"] == "Synthetic Hosting BV"
    assert gti["network"] == "198.51.100.0/24"
    assert gti["country"] == "NL"
    assert gti["regional_internet_registry"] == "RIPE NCC"
    # Infrastructure ownership is context: a hosting company's name is not a
    # claim about the IP, and nothing here points toward malicious.
    assert "as_owner" not in {e.claim_type for e in outcome.evidence}
    assert not [e for e in outcome.evidence if e.effect is EvidenceEffect.SUPPORTS_MALICIOUS]


# --------------------------------------------------------------------------- #
# Domain
# --------------------------------------------------------------------------- #


async def test_a_domain_lookup_uses_the_domain_collection() -> None:
    fake = FakeGTIClient()
    fake.register_primary("domains", payloads.domain_object())
    adapter, client = make_adapter(fake)

    await adapter.lookup(request_for(observable("evil.example")), credential())

    call = client.operations("primary")[0]
    assert call.collection == "domains"
    assert call.object_id == "evil.example"


async def test_a_defanged_domain_is_normalized_before_the_lookup() -> None:
    fake = FakeGTIClient()
    fake.register_primary("domains", payloads.domain_object())
    adapter, client = make_adapter(fake)

    await adapter.lookup(request_for(observable("evil[.]example")), credential())

    assert client.operations("primary")[0].object_id == "evil.example"


async def test_domain_metadata_is_preserved() -> None:
    fake = FakeGTIClient()
    fake.register_primary("domains", payloads.domain_object())
    adapter, _ = make_adapter(fake)

    outcome = await adapter.lookup(request_for(observable("evil.example")), credential())

    gti = outcome.objects[0].properties["gti"]
    assert gti["registrar"] == "Synthetic Registrar Ltd"
    assert gti["categories"] == {"synthetic-feed": "malware"}
    assert gti["tags"] == ["dga"]
    assert gti["creation_date"].startswith("20")


# --------------------------------------------------------------------------- #
# URL
# --------------------------------------------------------------------------- #


async def test_a_url_lookup_sends_an_identifier_not_the_url() -> None:
    """The suspicious URL is the object asked about, never a path we fetch."""
    url = "https://evil.example/payload"
    identifier = url_identifier(url)
    fake = FakeGTIClient()
    fake.register_primary("urls", payloads.url_object(object_id=identifier, url=url))
    adapter, client = make_adapter(fake)

    await adapter.lookup(request_for(observable(url)), credential())

    call = client.operations("primary")[0]
    assert call.collection == "urls"
    assert call.object_id == identifier
    assert "evil.example" not in str(call.object_id)
    assert "://" not in str(call.object_id)


async def test_a_defanged_url_is_normalized_then_identified() -> None:
    fake = FakeGTIClient()
    identifier = url_identifier("http://evil.example/a")
    fake.register_primary(
        "urls", payloads.url_object(object_id=identifier, url="http://evil.example/a")
    )
    adapter, client = make_adapter(fake)

    await adapter.lookup(request_for(observable("hxxp://evil[.]example/a")), credential())

    assert client.operations("primary")[0].object_id == identifier


async def test_url_metadata_is_preserved() -> None:
    url = "https://evil.example/payload"
    identifier = url_identifier(url)
    fake = FakeGTIClient()
    fake.register_primary("urls", payloads.url_object(object_id=identifier, url=url))
    adapter, _ = make_adapter(fake)

    outcome = await adapter.lookup(request_for(observable(url)), credential())

    gti = outcome.objects[0].properties["gti"]
    assert gti["url"] == url
    assert gti["last_final_url"] == f"{url}?stage=2"
    assert gti["title"] == "Synthetic landing page"
    assert gti["times_submitted"] == 3


# --------------------------------------------------------------------------- #
# Hashes
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "digest",
    [payloads.EMPTY_FILE_MD5, payloads.EMPTY_FILE_SHA1, payloads.EMPTY_FILE_SHA256],
)
async def test_every_hash_length_reaches_the_file_collection(digest: str) -> None:
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object(object_id=digest))
    adapter, client = make_adapter(fake)

    outcome = await adapter.lookup(request_for(file_object(digest)), credential())

    call = client.operations("primary")[0]
    assert call.collection == "files"
    assert call.object_id == digest
    assert outcome.status is ProviderRunStatus.SUCCESS


async def test_the_strongest_known_hash_is_used_as_the_identifier() -> None:
    """A SHA-256 identifies a file unambiguously where an MD5 can collide."""
    both = IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=payloads.EMPTY_FILE_MD5,
        display_value=payloads.EMPTY_FILE_MD5,
        properties={
            "hashes": {
                "MD5": payloads.EMPTY_FILE_MD5,
                "SHA-256": payloads.EMPTY_FILE_SHA256,
            }
        },
    )
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    adapter, client = make_adapter(fake)

    await adapter.lookup(request_for(both), credential())

    assert client.operations("primary")[0].object_id == payloads.EMPTY_FILE_SHA256


async def test_a_file_submitted_by_md5_learns_its_other_hashes() -> None:
    """The identity GTI reveals is preserved without silently re-keying."""
    submitted = file_object(payloads.EMPTY_FILE_MD5)
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object(object_id=payloads.EMPTY_FILE_MD5))
    adapter, _ = make_adapter(fake)

    outcome = await adapter.lookup(request_for(submitted), credential())

    enriched = outcome.objects[0]
    assert enriched.hashes == {
        "MD5": payloads.EMPTY_FILE_MD5,
        "SHA-1": payloads.EMPTY_FILE_SHA1,
        "SHA-256": payloads.EMPTY_FILE_SHA256,
    }
    # Identity resolution is a later layer's decision, not the adapter's.
    assert enriched.id == submitted.id
    assert enriched.canonical_key == submitted.canonical_key


async def test_file_metadata_is_preserved() -> None:
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    adapter, _ = make_adapter(fake)

    outcome = await adapter.lookup(request_for(file_object()), credential())

    gti = outcome.objects[0].properties["gti"]
    assert gti["size"] == 4096
    assert gti["type_description"] == "Win32 EXE"
    assert gti["type_tag"] == "peexe"
    assert gti["meaningful_name"] == "synthetic-sample.exe"
    assert gti["tags"] == ["peexe", "persistence"]
    assert gti["times_submitted"] == 7
    assert gti["first_submission_date"].endswith("+00:00")


async def test_no_file_is_downloaded_or_submitted() -> None:
    """Task 7 is passive: the hash is the only thing that travels."""
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    adapter, client = make_adapter(fake)

    await adapter.lookup(request_for(file_object()), credential())

    assert {call.operation for call in client.calls} <= {"primary", "quota"}


# --------------------------------------------------------------------------- #
# Response efficiency
# --------------------------------------------------------------------------- #


async def test_per_engine_results_are_excluded_from_every_lookup() -> None:
    """The aggregate is normalized; the per-engine breakdown is never used."""
    fake = FakeGTIClient()
    fake.register_primary("domains", payloads.domain_object())
    adapter, client = make_adapter(fake)

    await adapter.lookup(request_for(observable("evil.example")), credential())

    assert client.operations("primary")[0].exclude_attributes == ("last_analysis_results",)
    assert DEFAULT_EXCLUDED_ATTRIBUTES == ("last_analysis_results",)


async def test_nothing_else_is_excluded_by_default() -> None:
    """Trimming further would be guessing which evidence we do not need."""
    for excluded in DEFAULT_EXCLUDED_ATTRIBUTES:
        assert excluded not in {
            "gti_assessment",
            "gti_confidence_score",
            "last_analysis_stats",
            "reputation",
        }


async def test_exclusions_are_configurable() -> None:
    from ti_recon.providers.gti import GTILookupPolicy

    fake = FakeGTIClient()
    fake.register_primary("domains", payloads.domain_object())
    adapter, client = make_adapter(fake, lookup_policy=GTILookupPolicy(excluded_attributes=()))

    await adapter.lookup(request_for(observable("evil.example")), credential())
    assert client.operations("primary")[0].exclude_attributes == ()


# --------------------------------------------------------------------------- #
# Not found
# --------------------------------------------------------------------------- #


async def test_a_not_found_object_becomes_no_data() -> None:
    fake = FakeGTIClient()
    fake.primary_errors[("files", payloads.EMPTY_FILE_SHA256)] = provider_error_for(
        ProviderErrorCategory.NOT_FOUND, "gti", operation="primary_lookup"
    )
    adapter, _ = make_adapter(fake)

    outcome = await adapter.lookup(request_for(file_object()), credential())

    assert outcome.status is ProviderRunStatus.NO_DATA
    assert outcome.evidence == ()
    assert outcome.objects == ()
    assert outcome.has_data is False


async def test_no_data_is_not_benign() -> None:
    """ "GTI has never seen this" says nothing about whether it is safe."""
    fake = FakeGTIClient()
    fake.primary_errors[("domains", "unknown.example")] = provider_error_for(
        ProviderErrorCategory.NOT_FOUND, "gti", operation="primary_lookup"
    )
    adapter, _ = make_adapter(fake)

    outcome = await adapter.lookup(request_for(observable("unknown.example")), credential())

    assert outcome.status is ProviderRunStatus.NO_DATA
    assert not [e for e in outcome.evidence if e.effect.value == "supports_benign"]


async def test_a_no_data_envelope_is_cacheable_so_repeats_cost_nothing() -> None:
    """Returning an envelope rather than raising is what enables negative caching."""
    from ti_recon.execution import CachePolicy

    fake = FakeGTIClient()
    fake.primary_errors[("files", payloads.EMPTY_FILE_SHA256)] = provider_error_for(
        ProviderErrorCategory.NOT_FOUND, "gti", operation="primary_lookup"
    )
    adapter, _ = make_adapter(fake)
    request = request_for(file_object())

    outcome = await adapter.lookup(request, credential())
    ttl = CachePolicy().ttl_for(outcome, request)

    assert ttl is not None
    assert ttl == CachePolicy().no_data_ttl_seconds


async def test_other_errors_still_propagate_for_task_6_to_judge() -> None:
    fake = FakeGTIClient()
    fake.primary_errors[("domains", "evil.example")] = provider_error_for(
        ProviderErrorCategory.RATE_LIMITED, "gti", operation="primary_lookup"
    )
    adapter, _ = make_adapter(fake)

    with pytest.raises(ProviderError) as excinfo:
        await adapter.lookup(request_for(observable("evil.example")), credential())
    assert excinfo.value.category is ProviderErrorCategory.RATE_LIMITED


# --------------------------------------------------------------------------- #
# Envelope shape
# --------------------------------------------------------------------------- #


async def test_the_envelope_records_provider_and_versions() -> None:
    fake = FakeGTIClient()
    fake.register_primary("domains", payloads.domain_object())
    adapter, _ = make_adapter(fake)

    outcome = await adapter.lookup(request_for(observable("evil.example")), credential())

    assert outcome.provider == "gti"
    assert outcome.api_version == "v3"
    assert outcome.adapter_version == adapter.descriptor.adapter_version
    assert outcome.operation is ProviderOperation.LOOKUP


async def test_the_raw_reference_points_at_the_object_not_a_payload() -> None:
    fake = FakeGTIClient()
    fake.register_primary("domains", payloads.domain_object())
    adapter, _ = make_adapter(fake)

    outcome = await adapter.lookup(request_for(observable("evil.example")), credential())

    reference = outcome.raw_reference
    assert reference is not None
    assert reference.provider == "gti"
    assert reference.storage_key == "gti/domain/evil.example/lookup"
    assert "overall_quotas" not in reference.storage_key
    assert SECRET not in reference.model_dump_json()


async def test_the_envelope_carries_no_verdict() -> None:
    fake = FakeGTIClient()
    fake.register_primary("domains", payloads.domain_object())
    adapter, _ = make_adapter(fake)

    outcome = await adapter.lookup(request_for(observable("evil.example")), credential())

    dumped = outcome.model_dump()
    assert {"verdict", "risk_score", "confidence"}.isdisjoint(dumped)


async def test_the_serialized_envelope_carries_no_credential() -> None:
    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    fake.register_primary("files", payloads.file_object())
    adapter, _ = make_adapter(fake)

    outcome = await adapter.lookup(request_for(file_object()), credential())

    payload = json.dumps(outcome.model_dump(mode="json"))
    assert SECRET not in payload
    lowered = payload.lower()
    for token in ("api_key", "apikey", "auth-key", "authorization", "bearer "):
        assert token not in lowered


async def test_quota_rides_along_when_it_was_refreshed() -> None:
    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    fake.register_primary("domains", payloads.domain_object())
    adapter, _ = make_adapter(fake)

    outcome = await adapter.lookup(request_for(observable("evil.example")), credential())

    assert outcome.quota is not None
    assert outcome.quota.bucket("api_requests_daily") is not None


async def test_a_missing_credential_is_refused_before_any_call() -> None:
    adapter, client = make_adapter()
    with pytest.raises(ProviderError) as excinfo:
        await adapter.lookup(request_for(observable("evil.example")), None)
    assert excinfo.value.category is ProviderErrorCategory.INVALID_REQUEST
    assert client.calls == []


async def test_the_client_is_closed_after_every_lookup() -> None:
    fake = FakeGTIClient()
    fake.register_primary("domains", payloads.domain_object())
    adapter, client = make_adapter(fake)
    await adapter.lookup(request_for(observable("evil.example")), credential())
    assert client.closed is True


async def test_the_client_is_closed_even_when_the_lookup_fails() -> None:
    fake = FakeGTIClient()
    fake.primary_errors[("domains", "evil.example")] = provider_error_for(
        ProviderErrorCategory.TRANSIENT_ERROR, "gti", operation="primary_lookup"
    )
    adapter, client = make_adapter(fake)
    with pytest.raises(ProviderError):
        await adapter.lookup(request_for(observable("evil.example")), credential())
    assert client.closed is True


async def test_one_users_credential_builds_only_their_client() -> None:
    fake = FakeGTIClient()
    fake.register_primary("domains", payloads.domain_object())
    factory = FakeGTIClientFactory(client=fake)
    adapter = GTIAdapter(client_factory=factory, clock=ManualClock())

    await adapter.lookup(request_for(observable("evil.example")), credential(SECRET))
    await adapter.lookup(
        request_for(observable("evil.example")),
        credential("vt-key-OTHER-ANALYST", user_id="analyst-b"),
    )

    assert factory.created_for == [SECRET, "vt-key-OTHER-ANALYST"]


# --------------------------------------------------------------------------- #
# The pure normalize() half
# --------------------------------------------------------------------------- #


def test_normalize_works_from_a_stored_payload_with_no_client() -> None:
    adapter, _ = make_adapter()
    payload = payloads.file_object()

    result = adapter.normalize(request_for(file_object()), payload)

    assert len(result.objects) == 1
    gti = result.objects[0].properties["gti"]
    assert gti["object_id"] == payloads.EMPTY_FILE_SHA256
    assert gti["object_type"] == "file"


def test_normalize_is_deterministic() -> None:
    adapter, _ = make_adapter()
    request = request_for(file_object())
    first = adapter.normalize(request, payloads.file_object())
    second = adapter.normalize(request, payloads.file_object())
    assert first.objects[0].properties == second.objects[0].properties


def test_normalize_tolerates_a_payload_with_no_attributes() -> None:
    adapter, _ = make_adapter()
    result = adapter.normalize(
        request_for(observable("evil.example")), {"type": "domain", "id": "evil.example"}
    )
    assert result.objects[0].properties["gti"]["object_id"] == "evil.example"


def test_normalize_ignores_attributes_it_does_not_model() -> None:
    """An added GTI field must not become a model field."""
    adapter, _ = make_adapter()
    payload = payloads.domain_object(
        extra_attributes={"some_future_field": {"deeply": ["nested", 1]}}
    )
    result = adapter.normalize(request_for(observable("evil.example")), payload)
    assert "some_future_field" not in result.objects[0].properties["gti"]


# --------------------------------------------------------------------------- #
# Depth and mode
# --------------------------------------------------------------------------- #


async def test_a_quick_lookup_fetches_only_the_primary_object() -> None:
    fake = FakeGTIClient(quota_payload=payloads.overall_quotas_payload())
    fake.register_primary("files", payloads.file_object())
    adapter, client = make_adapter(fake)

    await adapter.lookup(request_for(file_object(), depth=InvestigationDepth.QUICK), credential())

    assert client.operations("descriptors") == []
    assert client.operations("objects") == []
    assert client.operations("behaviour") == []


async def test_a_passive_request_stays_passive() -> None:
    fake = FakeGTIClient()
    fake.register_primary("files", payloads.file_object())
    adapter, client = make_adapter(fake)

    request = request_for(file_object())
    assert request.activity_mode is ActivityMode.PASSIVE
    await adapter.lookup(request, credential())

    assert client.operations("behaviour") == []
    assert adapter.descriptor.supports_active is False
