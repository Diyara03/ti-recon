"""GreyNoise lookup and execution policy (Task 9).

Two things are being protected here. Depth must never buy extra requests, and a
GreyNoise result must never be served to an analyst whose subscription would
have produced a different document.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ti_recon.enums import InvestigationDepth
from ti_recon.execution.models import CacheScope
from ti_recon.providers.greynoise import (
    DEPTH_DETAIL,
    GreyNoiseAccessMode,
    GreyNoiseDetail,
    GreyNoiseLookupPolicy,
    build_greynoise_execution_policy,
    detail_for_depth,
)


def test_every_depth_has_a_configured_detail() -> None:
    assert set(DEPTH_DETAIL) == set(InvestigationDepth)


def test_quick_asks_greynoise_for_the_reduced_document() -> None:
    assert DEPTH_DETAIL[InvestigationDepth.QUICK].quick is True


def test_standard_and_deep_ask_for_the_full_document() -> None:
    assert DEPTH_DETAIL[InvestigationDepth.STANDARD].quick is False
    assert DEPTH_DETAIL[InvestigationDepth.DEEP].quick is False


def test_only_deep_records_the_sensor_detail() -> None:
    """It costs no extra request either way; depth decides whether to keep it."""
    assert DEPTH_DETAIL[InvestigationDepth.QUICK].include_sensor_detail is False
    assert DEPTH_DETAIL[InvestigationDepth.STANDARD].include_sensor_detail is False
    assert DEPTH_DETAIL[InvestigationDepth.DEEP].include_sensor_detail is True


def test_quick_keeps_only_the_cheapest_context() -> None:
    detail = DEPTH_DETAIL[InvestigationDepth.QUICK]
    assert detail.include_tags is False
    assert detail.include_cves is False
    assert detail.include_network_context is False


def test_deep_keeps_everything_standard_keeps() -> None:
    standard = DEPTH_DETAIL[InvestigationDepth.STANDARD]
    deep = DEPTH_DETAIL[InvestigationDepth.DEEP]
    assert deep.include_tags >= standard.include_tags
    assert deep.include_cves >= standard.include_cves
    assert deep.include_network_context >= standard.include_network_context


def test_an_unset_depth_falls_back_to_the_standard_shape() -> None:
    policy = GreyNoiseLookupPolicy(depth_detail={})
    assert policy.detail(InvestigationDepth.DEEP) == DEPTH_DETAIL[InvestigationDepth.STANDARD]


def test_the_detail_helper_works_with_and_without_a_policy() -> None:
    assert detail_for_depth(InvestigationDepth.QUICK).quick is True
    policy = GreyNoiseLookupPolicy(
        depth_detail={InvestigationDepth.QUICK: GreyNoiseDetail(quick=False)}
    )
    assert detail_for_depth(InvestigationDepth.QUICK, policy).quick is False


def test_auto_is_the_default_access_mode() -> None:
    assert GreyNoiseLookupPolicy().access_mode is GreyNoiseAccessMode.AUTO


def test_the_community_probe_is_enabled_by_default() -> None:
    """Without it a free-tier analyst would get nothing instead of something."""
    assert GreyNoiseLookupPolicy().allow_community_probe is True


def test_a_zero_ttl_switches_access_caching_off() -> None:
    assert GreyNoiseLookupPolicy(access_ttl_seconds=0).access_caching_enabled is False
    assert GreyNoiseLookupPolicy().access_caching_enabled is True


@pytest.mark.parametrize("ttl", [-1, 90_000])
def test_an_out_of_range_access_ttl_is_refused(ttl: int) -> None:
    with pytest.raises(ValidationError):
        GreyNoiseLookupPolicy(access_ttl_seconds=ttl)


# --------------------------------------------------------------------------- #
# Execution policy
# --------------------------------------------------------------------------- #


def test_results_are_never_shared_between_analysts() -> None:
    """Two GreyNoise plans do not see the same document for the same address."""
    policy = build_greynoise_execution_policy()
    assert policy.cache.scope is CacheScope.USER
    assert policy.cache.scope is not CacheScope.GLOBAL


def test_the_policy_names_the_provider_it_applies_to() -> None:
    assert build_greynoise_execution_policy().provider_id == "greynoise"


def test_a_negative_answer_expires_sooner_than_a_positive_one() -> None:
    """ "Never observed" is what changes the first time an address scans."""
    cache = build_greynoise_execution_policy().cache
    assert cache.no_data_ttl_seconds < cache.success_ttl_seconds


def test_a_trimmed_document_is_never_cached() -> None:
    """Otherwise it could later be mistaken for a complete one."""
    assert build_greynoise_execution_policy().cache.partial_ttl_seconds is None


def test_the_concurrency_default_is_bounded() -> None:
    assert 1 <= build_greynoise_execution_policy().max_concurrency <= 8


def test_an_operator_can_override_the_concurrency() -> None:
    assert build_greynoise_execution_policy(max_concurrency=1).max_concurrency == 1
