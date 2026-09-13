"""Which warninglist matched, and what entry, reaches the analyst (Task 24 Phase 3).

T24-FINDING-01. A warninglist match travelled as a Task 15 context signal
carrying only a slug and a matcher, and the report never read the signals, so
an analyst saw ``false_positive_context: satisfied`` and nothing about which
list matched. The compiled list now carries the upstream name, the match
record and the signal carry name and matched entry, and the report has a
bounded ``context`` section the text renderer prints as
"Matched misp list: <name> (<slug>) — <category>; matched <entry>".
Context only: never a verdict, never safety.
"""

from __future__ import annotations

import pytest

from fixtures.investigation.stack import _semantics_for
from ti_recon.correlation.orchestrator import CorrelatedInvestigationOrchestrator
from ti_recon.credentials import (
    CredentialResolver,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.execution import (
    ConcurrencyLimiter,
    ExecutionContext,
    FixedJitter,
    InMemoryCooldownStore,
    InMemoryProviderCache,
    InMemoryQuotaStore,
    ManualClock,
    ProviderExecutor,
    ProviderPolicyRegistry,
    RecordingSleeper,
)
from ti_recon.investigation import InvestigationRequest
from ti_recon.investigation.composition import build_default_reasoning_engines
from ti_recon.investigation.engine import InvestigationOrchestrator
from ti_recon.normalization import normalize_observable
from ti_recon.planning import AdaptiveEnrichmentOrchestrator, AdaptiveEnrichmentPlanner
from ti_recon.planning.catalog import build_default_planning_registry
from ti_recon.planning.policy import ProviderPlanningRegistry
from ti_recon.providers.misp_warninglists import MispWarningListsAdapter
from ti_recon.providers.registry import ProviderRegistry
from ti_recon.reasoning.fusion.engine import EvidenceFusionEngine
from ti_recon.reporting import build_analyst_report, render_text
from ti_recon.reporting.models import ANALYST_REPORT_SCHEMA_VERSION

USER = "analyst-context"


async def _investigate(value: str):
    """The local dataset alone, over the real snapshot, for one observable."""
    registry = ProviderRegistry([MispWarningListsAdapter()])
    profiles = ProviderPlanningRegistry(tuple(build_default_planning_registry().all()))
    clock = ManualClock()
    secrets, connections = InMemorySecretStore(), InMemoryConnectionRepository()
    executor = ProviderExecutor(
        credential_resolver=CredentialResolver(secrets, connections),
        cache=InMemoryProviderCache(clock=clock),
        quota_store=InMemoryQuotaStore(clock=clock),
        cooldown_store=InMemoryCooldownStore(clock=clock),
        limiter=ConcurrencyLimiter(max_concurrency=2),
        policies=ProviderPolicyRegistry(policies=[]),
        clock=clock,
        sleeper=RecordingSleeper(clock),
        jitter=FixedJitter(0.0),
    )
    base = build_default_reasoning_engines()
    engines = type(base)(
        temporal=base.temporal,
        false_positive=base.false_positive,
        fusion=EvidenceFusionEngine(translators=_semantics_for([])),
        readiness=base.readiness,
    )
    orchestrator = InvestigationOrchestrator(
        correlation=CorrelatedInvestigationOrchestrator(
            enrichment=AdaptiveEnrichmentOrchestrator(
                planner=AdaptiveEnrichmentPlanner(registry=registry, profiles=profiles),
                executor=executor,
                registry=registry,
            )
        ),
        engines=engines,
        clock=clock,
    )
    return await orchestrator.investigate(
        InvestigationRequest(root=normalize_observable(value).intel_object),
        ExecutionContext(authenticated_user_id=USER),
    )


@pytest.mark.asyncio
async def test_a_documentation_address_names_the_list_that_matched() -> None:
    """192.0.2.0/24 is reserved by RFC 5737; the shipped snapshot lists it."""
    result = await _investigate("192.0.2.1")
    report = build_analyst_report(result)

    items = [item for item in report.context.items if item.source_family == "misp"]
    assert items, "the local dataset should have matched the reserved range"
    item = next(entry for entry in items if entry.matched_entry.startswith("192.0.2."))
    assert item.dataset_key
    assert item.dataset_name
    assert item.signal_type == "private_or_special_use"
    assert item.scope == "exact_observable"
    assert item.host_component_only is False
    assert item.matcher == "cidr"

    rendered = render_text(report)
    assert "Context (what a source lists this object as; never a verdict)" in rendered
    assert f"Matched misp list: {item.dataset_name} ({item.dataset_key})" in rendered
    assert f"matched {item.matched_entry} via cidr" in rendered
    assert "context only, explains nothing by itself" in rendered
    # Context never becomes a verdict or a reason to call anything safe.
    assert report.assessment.verdict.value == "inconclusive"
    assert report.assessment_basis.items == ()


@pytest.mark.asyncio
async def test_a_url_host_match_says_it_is_about_the_host_only() -> None:
    """A public resolver's hostname is listed; the URL on it is not thereby anything."""
    result = await _investigate("http://dns.google/x")
    report = build_analyst_report(result)
    host_items = [item for item in report.context.items if item.host_component_only]
    assert host_items
    assert all(item.scope == "same_host" for item in host_items)
    # One line per dataset match: the specific category stands for the
    # generic warninglist_match and host-component marker emitted beside it.
    keys = [(item.dataset_key, item.subject_key) for item in report.context.items]
    assert len(keys) == len(set(keys))
    assert not any(
        item.signal_type in {"warninglist_match", "host_component_context"}
        for item in report.context.items
        if any(
            other.dataset_key == item.dataset_key and other is not item
            for other in report.context.items
        )
    )
    rendered = render_text(report)
    assert "host component only, does not describe the exact URL" in rendered


@pytest.mark.asyncio
async def test_no_match_renders_no_context_section() -> None:
    result = await _investigate("e" * 64)
    report = build_analyst_report(result)
    assert report.context.items == ()
    assert "Context (" not in render_text(report)


def test_the_schema_version_moved_with_the_added_section() -> None:
    # 1.1.0 added this section; 1.2.0 added ``source_checks[].capabilities``.
    assert ANALYST_REPORT_SCHEMA_VERSION == "1.2.0"
