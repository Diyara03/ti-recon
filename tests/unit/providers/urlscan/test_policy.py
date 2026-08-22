"""urlscan lookup and execution policy (Task 8).

Mostly one question: what has to be true before TI Recon will pull page content.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ti_recon.artifacts import ArtifactKind
from ti_recon.enums import (
    ActivityMode,
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
    ProviderCapability,
    ProviderOperation,
)
from ti_recon.execution.models import CacheScope
from ti_recon.execution.policy import CachePolicy
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.urlscan.policy import (
    FORENSICS_DEPTH,
    HistoricalRangeSource,
    UrlscanLookupPolicy,
    build_urlscan_execution_policy,
    forensics_requested,
    resolve_search_window,
)
from ti_recon.providers.urlscan.search import (
    DEEP_FALLBACK_LOOKBACK_DAYS,
    DEPTH_SEARCH_LIMITS,
    MAX_LOOKBACK_DAYS,
    MAX_LOOKBACK_MONTHS,
    SearchLimits,
    lookback_days_for_months,
)

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)

REPUTATION = frozenset({ProviderCapability.REPUTATION})
FORENSICS = frozenset({ProviderCapability.REPUTATION, ProviderCapability.WEB_FORENSICS})


def request_for(
    *,
    depth: InvestigationDepth,
    capabilities: frozenset[ProviderCapability],
    activity_mode: ActivityMode = ActivityMode.PASSIVE,
) -> ProviderRequest:
    intel_object = IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.DOMAIN_NAME,
        canonical_value="login.evil.example",
        display_value="login.evil.example",
    )
    return ProviderRequest(
        investigation_id="inv-1",
        intel_object=intel_object,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=capabilities,
        depth=depth,
        activity_mode=activity_mode,
    )


# --------------------------------------------------------------------------- #
# The forensics gate
# --------------------------------------------------------------------------- #


def test_both_halves_of_the_gate_are_required() -> None:
    assert forensics_requested(request_for(depth=FORENSICS_DEPTH, capabilities=FORENSICS)) is True


@pytest.mark.parametrize(
    ("depth", "capabilities"),
    [
        (InvestigationDepth.DEEP, REPUTATION),
        (InvestigationDepth.STANDARD, FORENSICS),
        (InvestigationDepth.QUICK, FORENSICS),
        (InvestigationDepth.STANDARD, REPUTATION),
    ],
)
def test_half_the_gate_is_never_enough(
    depth: InvestigationDepth, capabilities: frozenset[ProviderCapability]
) -> None:
    assert forensics_requested(request_for(depth=depth, capabilities=capabilities)) is False


def test_an_operator_can_refuse_forensics_regardless_of_the_request() -> None:
    request = request_for(depth=FORENSICS_DEPTH, capabilities=FORENSICS)
    policy = UrlscanLookupPolicy(allow_web_forensics=False)
    assert forensics_requested(request, policy) is False


def test_forensics_is_only_ever_a_deep_operation() -> None:
    assert FORENSICS_DEPTH is InvestigationDepth.DEEP


def test_an_active_request_would_not_be_permitted_either() -> None:
    """Forensics is passive; the check exists so that stays true by construction."""
    request = request_for(
        depth=FORENSICS_DEPTH,
        capabilities=frozenset({ProviderCapability.WEB_FORENSICS}),
        activity_mode=ActivityMode.ACTIVE,
    )
    assert forensics_requested(request) is False


# --------------------------------------------------------------------------- #
# What a forensic run may retrieve
# --------------------------------------------------------------------------- #


def test_the_default_policy_permits_the_three_artifact_kinds() -> None:
    policy = UrlscanLookupPolicy()
    for kind in (ArtifactKind.SCREENSHOT, ArtifactKind.DOM, ArtifactKind.RESPONSE_BODY):
        assert policy.allows(kind) is True


def test_switching_forensics_off_disallows_every_kind() -> None:
    policy = UrlscanLookupPolicy(allow_web_forensics=False)
    assert policy.allows(ArtifactKind.DOM) is False


def test_a_narrower_policy_permits_only_what_it_lists() -> None:
    policy = UrlscanLookupPolicy(forensic_artifacts=frozenset({ArtifactKind.DOM}))
    assert policy.allows(ArtifactKind.DOM) is True
    assert policy.allows(ArtifactKind.SCREENSHOT) is False


def test_response_body_retrieval_is_small_by_default() -> None:
    """The interesting bodies are the page's scripts, not its images."""
    assert UrlscanLookupPolicy().max_response_bodies <= 10


def test_quota_refresh_can_be_disabled_two_ways() -> None:
    assert UrlscanLookupPolicy().quota_refresh_enabled is True
    assert UrlscanLookupPolicy(refresh_quota_on_lookup=False).quota_refresh_enabled is False
    assert UrlscanLookupPolicy(quota_ttl_seconds=0).quota_refresh_enabled is False


# --------------------------------------------------------------------------- #
# Execution policy
# --------------------------------------------------------------------------- #


def test_results_are_never_cached_across_analysts() -> None:
    """An authenticated search can return scans only one analyst's key may see."""
    policy = build_urlscan_execution_policy()
    assert policy.cache.scope is CacheScope.USER
    assert policy.cache.scope is not CacheScope.GLOBAL


def test_a_negative_answer_expires_sooner_than_a_positive_one() -> None:
    cache = build_urlscan_execution_policy().cache
    assert cache.no_data_ttl_seconds < cache.success_ttl_seconds


def test_a_partial_answer_is_not_cached_at_all() -> None:
    assert build_urlscan_execution_policy().cache.partial_ttl_seconds is None


def test_the_policy_names_the_provider_it_configures() -> None:
    assert build_urlscan_execution_policy().provider_id == "urlscan"


def test_an_operator_can_override_the_cache_policy() -> None:
    cache = CachePolicy(success_ttl_seconds=60)
    assert build_urlscan_execution_policy(cache=cache).cache is cache


def test_concurrency_is_bounded() -> None:
    assert build_urlscan_execution_policy(max_concurrency=2).max_concurrency == 2


# --------------------------------------------------------------------------- #
# Search bounds
# --------------------------------------------------------------------------- #


def test_search_limits_come_from_depth_by_default() -> None:
    window = resolve_search_window(InvestigationDepth.QUICK, now=NOW)
    assert window.limits.page_size == DEPTH_SEARCH_LIMITS[InvestigationDepth.QUICK].page_size


def test_an_operator_can_retune_the_bounds_without_touching_code() -> None:
    tuned = SearchLimits(page_size=5, max_candidates=1, max_per_group=1, lookback_days=7)
    policy = UrlscanLookupPolicy(search_limits={InvestigationDepth.DEEP: tuned})
    assert resolve_search_window(InvestigationDepth.DEEP, policy, now=NOW).limits == tuned


def test_an_unlisted_depth_falls_back_to_the_standard_bounds() -> None:
    policy = UrlscanLookupPolicy(search_limits={})
    window = resolve_search_window(InvestigationDepth.DEEP, policy, now=NOW)
    assert window.limits == DEPTH_SEARCH_LIMITS[InvestigationDepth.STANDARD]


# --------------------------------------------------------------------------- #
# Depth semantics: recent, broader-recent, and as far back as permitted
# --------------------------------------------------------------------------- #


def test_a_quick_lookup_stays_recent_on_a_generous_account() -> None:
    """Nobody asked for more; a big entitlement does not widen a triage query."""
    window = resolve_search_window(InvestigationDepth.QUICK, max_search_range_months=120, now=NOW)
    assert window.lookback_days == 30
    assert window.source is HistoricalRangeSource.CONFIGURED


def test_a_standard_lookup_stays_broad_recent_on_a_generous_account() -> None:
    window = resolve_search_window(
        InvestigationDepth.STANDARD, max_search_range_months=120, now=NOW
    )
    assert window.lookback_days == 180
    assert window.source is HistoricalRangeSource.CONFIGURED


def test_a_deep_lookup_reaches_a_four_year_entitlement() -> None:
    """A kit first scanned in 2022 is what identifies its 2026 redeployment."""
    window = resolve_search_window(InvestigationDepth.DEEP, max_search_range_months=48, now=NOW)
    assert window.source is HistoricalRangeSource.PROVIDER_LIMIT
    assert window.account_months == 48
    assert NOW - timedelta(days=window.lookback_days) == datetime(2022, 8, 22, 12, tzinfo=UTC)


def test_a_deep_lookup_reaches_a_ten_year_entitlement() -> None:
    window = resolve_search_window(InvestigationDepth.DEEP, max_search_range_months=120, now=NOW)
    assert window.source is HistoricalRangeSource.PROVIDER_LIMIT
    assert NOW - timedelta(days=window.lookback_days) == datetime(2016, 8, 22, 12, tzinfo=UTC)


def test_a_deep_lookup_narrows_to_a_small_entitlement() -> None:
    """ "As far back as permitted" cuts both ways."""
    window = resolve_search_window(InvestigationDepth.DEEP, max_search_range_months=6, now=NOW)
    assert window.lookback_days == 181
    assert window.source is HistoricalRangeSource.PROVIDER_LIMIT


def test_a_standard_lookup_clamps_to_a_smaller_entitlement() -> None:
    window = resolve_search_window(InvestigationDepth.STANDARD, max_search_range_months=3, now=NOW)
    assert window.lookback_days == 92
    assert window.source is HistoricalRangeSource.PROVIDER_LIMIT
    assert window.account_months == 3


def test_a_quick_lookup_never_exceeds_the_smallest_entitlement_urlscan_can_report() -> None:
    """One month is the narrowest range the months field can express.

    In August that month is 31 days, so QUICK's own 30-day window is already
    inside it and stands unchanged.
    """
    window = resolve_search_window(InvestigationDepth.QUICK, max_search_range_months=1, now=NOW)
    assert window.lookback_days <= lookback_days_for_months(1, now=NOW)
    assert window.lookback_days == 30


def test_a_quick_lookup_clamps_when_the_entitlement_is_genuinely_narrower() -> None:
    """A month shorter than thirty days does narrow even a triage query."""
    march = datetime(2026, 3, 15, 12, 0, tzinfo=UTC)
    window = resolve_search_window(InvestigationDepth.QUICK, max_search_range_months=1, now=march)
    assert window.lookback_days == 28
    assert window.source is HistoricalRangeSource.PROVIDER_LIMIT
    assert march - timedelta(days=window.lookback_days) == datetime(2026, 2, 15, 12, tzinfo=UTC)


def test_the_result_budget_is_identical_at_thirty_days_and_at_ten_years() -> None:
    """Historical breadth and result volume are separate controls."""
    narrow = resolve_search_window(InvestigationDepth.DEEP, max_search_range_months=1, now=NOW)
    wide = resolve_search_window(InvestigationDepth.DEEP, max_search_range_months=120, now=NOW)
    assert wide.lookback_days > narrow.lookback_days
    for attribute in ("page_size", "max_candidates", "max_per_group"):
        assert getattr(wide.limits, attribute) == getattr(narrow.limits, attribute)
        assert getattr(wide.limits, attribute) == getattr(
            DEPTH_SEARCH_LIMITS[InvestigationDepth.DEEP], attribute
        )


# --------------------------------------------------------------------------- #
# When the account maximum is unusable
# --------------------------------------------------------------------------- #


def test_a_deep_lookup_without_account_metadata_uses_the_finite_fallback() -> None:
    window = resolve_search_window(InvestigationDepth.DEEP, max_search_range_months=None, now=NOW)
    assert window.lookback_days == DEEP_FALLBACK_LOOKBACK_DAYS == 365
    assert window.source is HistoricalRangeSource.FALLBACK
    assert window.is_fallback is True
    assert window.account_months is None


@pytest.mark.parametrize("months", [None, 0, -1, -48])
def test_an_unusable_account_maximum_never_produces_an_unbounded_window(
    months: int | None,
) -> None:
    """Zero has no defined meaning, so it is treated as "we do not know"."""
    for depth in InvestigationDepth:
        window = resolve_search_window(depth, max_search_range_months=months, now=NOW)
        assert 1 <= window.lookback_days <= MAX_LOOKBACK_DAYS
        assert window.limits.since.startswith("now-")


def test_only_deep_calls_a_missing_maximum_a_fallback() -> None:
    """QUICK and STANDARD never wanted the account maximum in the first place."""
    for depth in (InvestigationDepth.QUICK, InvestigationDepth.STANDARD):
        window = resolve_search_window(depth, max_search_range_months=None, now=NOW)
        assert window.source is HistoricalRangeSource.CONFIGURED
        assert window.is_fallback is False


def test_an_absurd_account_maximum_is_bounded_by_our_own_ceiling() -> None:
    window = resolve_search_window(InvestigationDepth.DEEP, max_search_range_months=6_000, now=NOW)
    assert window.lookback_days <= MAX_LOOKBACK_DAYS
    assert window.account_months == MAX_LOOKBACK_MONTHS


def test_clamping_applies_to_an_operator_tuned_policy_too() -> None:
    tuned = SearchLimits(page_size=5, max_candidates=1, max_per_group=1, lookback_days=300)
    policy = UrlscanLookupPolicy(search_limits={InvestigationDepth.DEEP: tuned})
    window = resolve_search_window(
        InvestigationDepth.DEEP, policy, max_search_range_months=1, now=NOW
    )
    assert window.lookback_days == 31


def test_every_depth_the_policy_can_return_is_bounded() -> None:
    policy = UrlscanLookupPolicy(search_limits={})
    for depth in InvestigationDepth:
        assert resolve_search_window(depth, policy, now=NOW).lookback_days >= 1
