"""urlscan lookup and execution policy (Task 8).

Mostly one question: what has to be true before TI Recon will pull page content.
"""

from __future__ import annotations

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
    UrlscanLookupPolicy,
    build_urlscan_execution_policy,
    forensics_requested,
    search_limits_for,
)
from ti_recon.providers.urlscan.search import DEPTH_SEARCH_LIMITS, SearchLimits

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
# Search bounds
# --------------------------------------------------------------------------- #


def test_search_limits_come_from_depth_by_default() -> None:
    assert (
        search_limits_for(InvestigationDepth.QUICK) == DEPTH_SEARCH_LIMITS[InvestigationDepth.QUICK]
    )


def test_an_operator_can_retune_the_bounds_without_touching_code() -> None:
    tuned = SearchLimits(page_size=5, max_candidates=1, max_per_group=1, since="now-7d")
    policy = UrlscanLookupPolicy(search_limits={InvestigationDepth.DEEP: tuned})
    assert search_limits_for(InvestigationDepth.DEEP, policy) == tuned


def test_an_unlisted_depth_falls_back_to_the_standard_bounds() -> None:
    policy = UrlscanLookupPolicy(search_limits={})
    assert (
        search_limits_for(InvestigationDepth.DEEP, policy)
        == DEPTH_SEARCH_LIMITS[InvestigationDepth.STANDARD]
    )


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
