"""Censys lookup and execution policy (Task 9).

Two things are being protected here. Depth must never buy extra requests — one
asset read is one credit — and a Censys result must never be served to an
analyst whose account would have seen something different.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ti_recon.enums import InvestigationDepth
from ti_recon.execution.models import CacheScope
from ti_recon.providers.censys import (
    DEFAULT_MAX_CONCURRENCY,
    DEPTH_DETAIL,
    MAX_CERTIFICATES,
    MAX_DNS_NAMES,
    MAX_SERVICES,
    CensysDetail,
    CensysLookupPolicy,
    build_censys_execution_policy,
    detail_for_depth,
)


def test_every_depth_has_a_configured_detail() -> None:
    assert set(DEPTH_DETAIL) == set(InvestigationDepth)


def test_quick_keeps_only_a_summary() -> None:
    detail = DEPTH_DETAIL[InvestigationDepth.QUICK]
    assert detail.include_services is False
    assert detail.include_dns is False
    assert detail.include_tls is False
    assert detail.include_vulnerabilities is False
    assert detail.include_labels is True


def test_standard_keeps_the_bounded_middle_ground() -> None:
    detail = DEPTH_DETAIL[InvestigationDepth.STANDARD]
    assert detail.include_services is True
    assert detail.include_dns is True
    assert detail.include_tls is True
    assert detail.include_vulnerabilities is True
    assert detail.max_services < MAX_SERVICES


def test_deep_raises_the_bounds_to_the_ceilings() -> None:
    detail = DEPTH_DETAIL[InvestigationDepth.DEEP]
    assert detail.max_services == MAX_SERVICES
    assert detail.max_dns_names == MAX_DNS_NAMES
    assert detail.max_certificates == MAX_CERTIFICATES


def test_deep_never_keeps_less_than_standard() -> None:
    standard = DEPTH_DETAIL[InvestigationDepth.STANDARD]
    deep = DEPTH_DETAIL[InvestigationDepth.DEEP]
    assert deep.max_services >= standard.max_services
    assert deep.max_dns_names >= standard.max_dns_names
    assert deep.max_certificates >= standard.max_certificates
    assert deep.max_endpoints >= standard.max_endpoints
    assert deep.max_vulnerabilities >= standard.max_vulnerabilities


def test_no_depth_can_ask_for_an_unbounded_expansion() -> None:
    """The normalizer's ceiling is the hard limit; a policy chooses below it."""
    for detail in DEPTH_DETAIL.values():
        assert detail.max_services <= MAX_SERVICES
        assert detail.max_dns_names <= MAX_DNS_NAMES
        assert detail.max_certificates <= MAX_CERTIFICATES


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_services", MAX_SERVICES + 1),
        ("max_dns_names", MAX_DNS_NAMES + 1),
        ("max_certificates", MAX_CERTIFICATES + 1),
        ("max_services", -1),
    ],
)
def test_a_bound_beyond_the_ceiling_is_refused(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        CensysDetail(**{field: value})


def test_an_unset_depth_falls_back_to_the_standard_shape() -> None:
    policy = CensysLookupPolicy(depth_detail={})
    assert policy.detail(InvestigationDepth.DEEP) == DEPTH_DETAIL[InvestigationDepth.STANDARD]


def test_the_detail_helper_works_with_and_without_a_policy() -> None:
    assert detail_for_depth(InvestigationDepth.QUICK).include_services is False
    policy = CensysLookupPolicy(
        depth_detail={InvestigationDepth.QUICK: CensysDetail(include_services=True)}
    )
    assert detail_for_depth(InvestigationDepth.QUICK, policy).include_services is True


def test_a_zero_ttl_switches_the_credit_refresh_off() -> None:
    assert CensysLookupPolicy(credit_ttl_seconds=0).credit_refresh_enabled is False
    assert CensysLookupPolicy(refresh_credits_on_lookup=False).credit_refresh_enabled is False
    assert CensysLookupPolicy().credit_refresh_enabled is True


# --------------------------------------------------------------------------- #
# Execution policy
# --------------------------------------------------------------------------- #


def test_results_are_never_shared_between_analysts() -> None:
    """A lookup is charged to whichever account's token paid for it."""
    policy = build_censys_execution_policy()
    assert policy.cache.scope is CacheScope.USER
    assert policy.cache.scope is not CacheScope.GLOBAL


def test_the_policy_names_the_provider_it_applies_to() -> None:
    assert build_censys_execution_policy().provider_id == "censys"


def test_a_successful_asset_read_is_cached_generously() -> None:
    """A repeated lookup that hits the cache is one credit rather than two."""
    cache = build_censys_execution_policy().cache
    assert cache.success_ttl_seconds >= 3600


def test_a_negative_answer_expires_sooner_than_a_positive_one() -> None:
    cache = build_censys_execution_policy().cache
    assert cache.no_data_ttl_seconds < cache.success_ttl_seconds


def test_a_partial_document_is_never_cached() -> None:
    assert build_censys_execution_policy().cache.partial_ttl_seconds is None


def test_the_default_concurrency_is_one() -> None:
    """The plan's per-minute allowance cannot be discovered, so be conservative."""
    assert DEFAULT_MAX_CONCURRENCY == 1
    assert build_censys_execution_policy().max_concurrency == 1


def test_an_operator_who_knows_their_plan_can_raise_it() -> None:
    assert build_censys_execution_policy(max_concurrency=4).max_concurrency == 4
