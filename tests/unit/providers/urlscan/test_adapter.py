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
    URLSCAN_NOT_SEARCHABLE,
    URLSCAN_SCAN_UNRETRIEVABLE,
    UrlscanAdapter,
)
from ti_recon.providers.urlscan.client import UrlscanArtifact, UrlscanHttpClient
from ti_recon.providers.urlscan.config import UrlscanConfig
from ti_recon.providers.urlscan.policy import UrlscanLookupPolicy

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


async def test_an_unsearchable_observable_reports_the_gap() -> None:
    md5 = "c" * 32
    adapter, fake = make_adapter()
    envelope = await adapter.lookup(
        make_request(intel_object=observable(IntelObjectType.FILE, md5, {"hashes": {"MD5": md5}})),
        credential(),
    )
    assert envelope.status is ProviderRunStatus.NO_DATA
    assert URLSCAN_NOT_SEARCHABLE in envelope.warnings
    assert not fake.called("search")


async def test_no_scans_at_all_is_no_data_not_a_failure() -> None:
    adapter, _ = make_adapter(FakeUrlscanClient(search_payload={"results": []}))
    envelope = await adapter.lookup(make_request(), credential())
    assert envelope.status is ProviderRunStatus.NO_DATA
    assert envelope.evidence == ()
    assert envelope.error_category is None


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
