"""Optional Hybrid Analysis live smoke tests (Task 12).

**Disabled by default.** Along with the GTI, urlscan, GreyNoise, Censys and
abuse.ch suites these are the only tests in the repository that touch a real API,
and they stay off unless explicitly enabled:

.. code-block:: bash

    RUN_HYBRID_ANALYSIS_LIVE_TESTS=1 HYBRID_ANALYSIS_API_KEY=<key> \\
        uv run pytest tests/live -q

Without both variables every test here skips, so a default ``pytest`` run, CI and
pre-commit never contact Hybrid Analysis.

What a full run costs
---------------------

A restricted, self-signed key is documented at roughly **5 requests per minute
and 200 per hour**, which is the smallest allowance of any provider in this
repository. So this suite is built around the smallest number of requests that
can exercise the report-summary normalization path at all:

===============================  =====================================
Check                            Cost
===============================  =====================================
capability discovery             no request at all
unsupported observable           no request at all
credential acceptance            proved by the search — 0 extra
every report-index assertion     **one** ``GET /search/hash``, shared
every behaviour assertion        **one** ``GET /report/{id}/summary``, shared
the repeat-lookup assertion      served from the Task 6 cache
===============================  =====================================

**A full run performs at most two physical requests.** STANDARD depth, so at most
one summary. That is enforced by the code rather than by a comment or by test
ordering: :func:`live_lookup` performs the pair once, caches both outcomes in a
module-level slot, and every assertion reads that same pair.
``/key/current`` is deliberately *not* called — a successful search already
proves the key is accepted, and spending a request to ask permission first would
be 20% of a minute's allowance.

Nothing is submitted and nothing is downloaded
----------------------------------------------

No sample, no PCAP, no memory dump, no screenshot, no dropped file, no report
archive, no quick scan, no overview refresh. The integration has no code path for
any of them and this suite does not add one.

What these check, and what they deliberately do not
---------------------------------------------------

They check that a search succeeds, that the report index normalizes with the
right provenance and lineage, that a selected summary normalizes into behaviour,
and that an identical request is served from cache.

They assert **no particular verdict**. The chosen target may be re-analysed,
re-verdicted or have reports expire, and a test that fails because a sandbox
re-scored a sample is a test that teaches you to ignore failures. So the answer
is accepted as ``SUCCESS``, ``PARTIAL`` or ``NO_DATA``, and the assertions that
need a *report* skip themselves when there is none.

About the target
----------------

:data:`SMOKE_SHA256` is the EICAR test file — unambiguously not customer data,
present in essentially every malware repository, and safe to name in a source
file. Its presence in Hybrid Analysis could not be confirmed before committing:
the public site requires completing their vetting process to view samples, so
there is no way to check from outside the API. If it turns out to have no
accessible report, the suite reports skips rather than failures and the constant
can be pointed at any hash the operator knows is present.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import pytest
from pydantic import SecretStr

from ti_recon.credentials import (
    AuthType,
    CredentialManager,
    CredentialResolver,
    CredentialStatus,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.enums import (
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
    ProviderCapability,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution import (
    ConcurrencyLimiter,
    ExecutionContext,
    InMemoryCooldownStore,
    InMemoryProviderCache,
    InMemoryQuotaStore,
    ProviderExecutionOutcome,
    ProviderExecutor,
    ProviderPolicyRegistry,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers import ProviderRequest
from ti_recon.providers.hybrid_analysis import (
    ASSESSMENT_CLAIM_TYPE,
    BEHAVIOUR_CLAIM_TYPE,
    COVERAGE_CLAIM_TYPE,
    HYBRID_ANALYSIS_PROVIDER_ID,
    HYBRID_ANALYSIS_SOURCE_FAMILY,
    MAX_REQUESTS_PER_LOOKUP,
    HybridAnalysisAdapter,
    build_hybrid_analysis_execution_policy,
    lineage_group_for_sample,
)

RUN_LIVE_ENV_VAR = "RUN_HYBRID_ANALYSIS_LIVE_TESTS"
API_KEY_ENV_VAR = "HYBRID_ANALYSIS_API_KEY"

#: The EICAR test file's SHA-256. See the module docstring for why this one, and
#: why its presence could not be verified before committing.
SMOKE_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

LIVE_USER = "live-analyst"

_enabled = os.environ.get(RUN_LIVE_ENV_VAR) == "1"
_api_key = os.environ.get(API_KEY_ENV_VAR, "")

pytestmark = pytest.mark.skipif(
    not (_enabled and _api_key),
    reason=(
        f"hybrid analysis live tests are off. "
        f"Enable with {RUN_LIVE_ENV_VAR}=1 and {API_KEY_ENV_VAR}=<key>."
    ),
)


def smoke_file() -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=SMOKE_SHA256,
        display_value=SMOKE_SHA256,
        properties={"hashes": {"SHA-256": SMOKE_SHA256}},
    )


def request_for(
    subject: IntelObject | str,
    *,
    depth: InvestigationDepth = InvestigationDepth.STANDARD,
) -> ProviderRequest:
    if isinstance(subject, str):
        from ti_recon.normalization import normalize_observable

        target = normalize_observable(subject).intel_object
    else:
        target = subject
    return ProviderRequest(
        investigation_id="live-smoke",
        intel_object=target,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
        depth=depth,
    )


def live_credential() -> Any:
    from ti_recon.credentials.models import CredentialMaterial

    return CredentialMaterial(
        connection_id="live-connection",
        user_id=LIVE_USER,
        provider_id=HYBRID_ANALYSIS_PROVIDER_ID,
        credential_group=HYBRID_ANALYSIS_PROVIDER_ID,
        auth_type=AuthType.API_KEY,
        secret=SecretStr(_api_key),
    )


# --------------------------------------------------------------------------- #
# Zero-request checks
# --------------------------------------------------------------------------- #


async def test_capability_discovery_makes_no_request() -> None:
    discovery = await HybridAnalysisAdapter().discover_capabilities(None)
    assert ProviderCapability.FILE_BEHAVIOR in discovery.capabilities
    assert ProviderCapability.REPUTATION not in discovery.capabilities


async def test_an_unsupported_observable_costs_no_request() -> None:
    """A domain has no sandbox-report lookup, so nothing is spent."""
    envelope = await HybridAnalysisAdapter().lookup(request_for("example.com"), live_credential())
    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert envelope.status is not ProviderRunStatus.NO_DATA


# --------------------------------------------------------------------------- #
# The shared lookup, performed once
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class LiveLookup:
    """The two outcomes of one identical request, issued back to back.

    ``first`` cost at most two provider requests. ``second`` cost nothing: it went
    through the same executor, cache and connection, so the Task 6 cache answered
    it.
    """

    first: ProviderExecutionOutcome
    second: ProviderExecutionOutcome


#: Computed at most once per session. A module-level slot rather than a fixture
#: because fixture scope and test ordering are exactly the things that must not
#: be able to turn two requests into twenty.
_LOOKUP: LiveLookup | None = None


async def live_lookup() -> LiveLookup:
    """Perform the run's single lookup pair, or return the cached result."""
    global _LOOKUP
    if _LOOKUP is None:
        _LOOKUP = await _perform_single_lookup()
    return _LOOKUP


async def _perform_single_lookup() -> LiveLookup:
    """Every request this file makes, in one place."""
    secrets = InMemorySecretStore()
    connections = InMemoryConnectionRepository()
    manager = CredentialManager(secrets, connections)
    resolver = CredentialResolver(secrets, connections)
    await manager.create_connection(
        user_id=LIVE_USER,
        provider_id=HYBRID_ANALYSIS_PROVIDER_ID,
        secret=SecretStr(_api_key),
        auth_type=AuthType.API_KEY,
        status=CredentialStatus.ACTIVE,
    )

    executor = ProviderExecutor(
        credential_resolver=resolver,
        cache=InMemoryProviderCache(),
        quota_store=InMemoryQuotaStore(),
        cooldown_store=InMemoryCooldownStore(),
        limiter=ConcurrencyLimiter(max_concurrency=1),
        policies=ProviderPolicyRegistry(policies=[build_hybrid_analysis_execution_policy()]),
    )
    context = ExecutionContext(authenticated_user_id=LIVE_USER, request_id="live-req")
    request = request_for(smoke_file())

    # The only provider-touching call in this file: one search plus, at STANDARD
    # depth, at most one report summary.
    first = await executor.execute(HybridAnalysisAdapter(), request, context)
    # Identical request, same executor and cache: this must not reach out.
    second = await executor.execute(HybridAnalysisAdapter(), request, context)
    return LiveLookup(first=first, second=second)


async def answered() -> ProviderExecutionOutcome:
    """The first outcome, or a skip if the provider refused it.

    Skipping rather than failing when a key is throttled or unentitled: that is
    an account fact, not a defect in the integration.
    """
    lookup = await live_lookup()
    if lookup.first.status not in {
        ProviderRunStatus.SUCCESS,
        ProviderRunStatus.PARTIAL,
        ProviderRunStatus.NO_DATA,
    }:
        pytest.skip(f"hybrid analysis returned {lookup.first.status.value}")
    assert lookup.first.result is not None
    return lookup.first


async def with_reports() -> Any:
    """The result, or a skip if the provider holds no report for the target."""
    outcome = await answered()
    assert outcome.result is not None
    if outcome.status is ProviderRunStatus.NO_DATA:
        pytest.skip("no accessible sandbox report for the smoke target")
    return outcome.result


def claim(result: Any, claim_type: str) -> Any:
    return next((item for item in result.evidence if item.claim_type == claim_type), None)


# --------------------------------------------------------------------------- #
# Everything below reads that one lookup
# --------------------------------------------------------------------------- #


async def test_the_lookup_flows_through_the_executor() -> None:
    lookup = await live_lookup()
    assert lookup.first.provider_id == HYBRID_ANALYSIS_PROVIDER_ID
    assert lookup.first.attempts >= 1
    assert lookup.first.cache_hit is False
    assert lookup.first.status in {
        ProviderRunStatus.SUCCESS,
        ProviderRunStatus.PARTIAL,
        ProviderRunStatus.NO_DATA,
    }


async def test_the_repeat_lookup_costs_no_second_request() -> None:
    """The Task 6 guarantee, against the real API."""
    lookup = await live_lookup()
    assert lookup.second.cache_hit is True
    assert lookup.second.attempts == 0
    assert lookup.second.called_provider is False


async def test_the_run_stayed_within_its_request_budget() -> None:
    """Reported by the provider's own coverage record."""
    result = await answered()
    assert result.result is not None
    coverage = claim(result.result, COVERAGE_CLAIM_TYPE)
    assert coverage is not None
    assert coverage.attributes["provider_requests"] <= MAX_REQUESTS_PER_LOOKUP
    assert coverage.attributes["summaries_requested"] <= 1
    assert coverage.attributes["depth"] == InvestigationDepth.STANDARD.value


async def test_the_result_is_a_structurally_valid_v2_answer() -> None:
    outcome = await answered()
    assert outcome.result is not None
    assert outcome.result.provider == HYBRID_ANALYSIS_PROVIDER_ID
    assert outcome.result.api_version == "v2"


async def test_every_record_carries_sample_level_provenance() -> None:
    result = await with_reports()
    coverage = claim(result, COVERAGE_CLAIM_TYPE)
    assert coverage is not None
    expected = lineage_group_for_sample(coverage.attributes.get("sample_sha256"))
    for evidence in result.evidence:
        assert evidence.transport_provider == HYBRID_ANALYSIS_PROVIDER_ID
        assert evidence.origin_provider == HYBRID_ANALYSIS_PROVIDER_ID
        assert evidence.source_family == HYBRID_ANALYSIS_SOURCE_FAMILY
        assert evidence.lineage_group_id == expected
        # Admiralty grading is TI Recon policy, never a provider's to claim.
        assert evidence.source_reliability is None
        assert evidence.information_credibility is None


async def test_no_live_result_is_ever_benign() -> None:
    """Whatever the real API returned, in whatever state."""
    outcome = await answered()
    assert outcome.result is not None
    for evidence in outcome.result.evidence:
        assert evidence.effect is not EvidenceEffect.SUPPORTS_BENIGN


async def test_one_directional_finding_at_most() -> None:
    """Many reports are still one provider observing one sample."""
    result = await with_reports()
    directional = [
        item for item in result.evidence if item.effect is not EvidenceEffect.CONTEXT_ONLY
    ]
    assert len(directional) <= 1
    if directional:
        assert directional[0].claim_type == ASSESSMENT_CLAIM_TYPE


async def test_the_report_index_normalizes() -> None:
    result = await with_reports()
    assessment = claim(result, ASSESSMENT_CLAIM_TYPE)
    assert assessment is not None
    assert assessment.attributes["report_count"] >= 1
    assert assessment.attributes["means_benign"] is False
    assert isinstance(assessment.attributes["verdicts_by_environment"], dict)


async def test_coverage_never_claims_it_read_every_report() -> None:
    result = await with_reports()
    coverage = claim(result, COVERAGE_CLAIM_TYPE)
    assert coverage is not None
    assert "selection_strategy" in coverage.attributes
    if coverage.attributes["report_count"] > 1:
        assert coverage.attributes["all_reports_summarized"] is False


async def test_a_retrieved_summary_normalizes_into_behaviour() -> None:
    """The path this suite exists to exercise."""
    result = await with_reports()
    behaviour = claim(result, BEHAVIOUR_CLAIM_TYPE)
    if behaviour is None:
        pytest.skip("no report summary was retrievable for the smoke target")
    assert behaviour.effect is EvidenceEffect.CONTEXT_ONLY
    assert "state" in behaviour.attributes
    assert "observed_execution" in behaviour.attributes
    assert behaviour.attributes["report_id"]


async def test_no_submitter_metadata_reaches_a_live_result() -> None:
    """Against whatever this real report happened to carry."""
    outcome = await answered()
    assert outcome.result is not None
    serialized = outcome.result.model_dump_json()
    for excluded in (
        "document_password",
        "custom_commandline",
        "environment_variable",
        "custom_system_date_time",
    ):
        assert excluded not in serialized


async def test_nothing_in_the_result_carries_the_key() -> None:
    outcome = await answered()
    assert outcome.result is not None
    assert _api_key not in outcome.result.model_dump_json()
