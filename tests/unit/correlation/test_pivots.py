"""Budgets, privacy, cycles and the limits of automatic pivoting (Task 14).

Every test here runs the real Task 13 planner and Task 6 executor over fake
providers. Nothing reaches the network, and the repository's non-loopback guard is
active — a test that accidentally tried would fail rather than quietly succeed.
"""

from __future__ import annotations

import pytest

from fixtures.correlation import (
    DIGEST_A,
    BareObjectAdapter,
    ScriptedAdapter,
    Stack,
    file_object,
)
from fixtures.planning.fakes import FakeProviderSpec
from ti_recon.correlation import (
    CorrelatedEnrichmentResult,
    GraphLimits,
    PivotMode,
    PivotPolicy,
    PivotSelectionReason,
    PivotSkipReason,
)
from ti_recon.correlation.policy import DEFAULT_PIVOT_BUDGETS, MAX_AUTOMATIC_PIVOT_HOP
from ti_recon.enums import (
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    RelationshipType,
)
from ti_recon.planning import EnrichmentPlanningRequest, PlanningConstraints
from ti_recon.planning.models import CallCostClass, ProviderLocality

CONTACTS = RelationshipType.CONTACTS
RESOLVES = RelationshipType.RESOLVES_TO
DOWNLOADS = RelationshipType.DOWNLOADS


def spec(
    provider_id: str = "sandbox",
    *,
    family: str | None = None,
    locality: ProviderLocality = ProviderLocality.REMOTE,
) -> FakeProviderSpec:
    return FakeProviderSpec(
        provider_id=provider_id,
        source_family=family or f"{provider_id}_family",
        capabilities=frozenset({ProviderCapability.REPUTATION}),
        locality=locality,
        cost_class=(
            CallCostClass.ZERO if locality is ProviderLocality.LOCAL else CallCostClass.LOW
        ),
        capability_invariant_response=True,
    )


async def run(
    stack: Stack,
    *,
    depth: InvestigationDepth = InvestigationDepth.DEEP,
    policy: PivotPolicy | None = None,
    constraints: PlanningConstraints | None = None,
) -> CorrelatedEnrichmentResult:
    await stack.add_credentials()
    request = EnrichmentPlanningRequest(
        intel_object=file_object(sha256=DIGEST_A),
        depth=depth,
        constraints=constraints or PlanningConstraints(),
    )
    return await stack.orchestrator.run(
        request,
        stack.context(),
        investigation_id="inv-1",
        pivot_policy=policy or PivotPolicy(mode=PivotMode.ENRICH, allow_remote_pivot_lookup=True),
    )


def candidate(result: CorrelatedEnrichmentResult, key: str):  # type: ignore[no-untyped-def]
    return next(item for item in result.pivot_candidates if item.target_node_key == key)


# --------------------------------------------------------------------------- #
# Modes
# --------------------------------------------------------------------------- #


async def test_the_default_policy_makes_no_pivot_calls() -> None:
    """Building a graph must never quietly start querying third parties."""
    stack = Stack([ScriptedAdapter(spec(), {DIGEST_A: ((CONTACTS, "evil.example", "net"),)})])
    result = await run(stack, policy=PivotPolicy())
    assert result.pivot_mode is PivotMode.RECOMMEND
    assert result.pivot_runs == ()
    assert stack.all_subjects == [DIGEST_A]


async def test_none_mode_builds_the_graph_and_ranks_nothing() -> None:
    stack = Stack([ScriptedAdapter(spec(), {DIGEST_A: ((CONTACTS, "evil.example", "net"),)})])
    result = await run(stack, policy=PivotPolicy(mode=PivotMode.NONE))
    assert result.pivot_candidates == ()
    assert any(node.node_key == "domain-name:evil.example" for node in result.graph_nodes)


async def test_recommend_ranks_candidates_and_still_calls_nobody() -> None:
    stack = Stack([ScriptedAdapter(spec(), {DIGEST_A: ((CONTACTS, "evil.example", "net"),)})])
    result = await run(stack, policy=PivotPolicy(mode=PivotMode.RECOMMEND))
    entry = candidate(result, "domain-name:evil.example")
    assert entry.skip_reason is PivotSkipReason.RECOMMEND_ONLY
    assert result.pivot_runs == ()
    assert stack.all_subjects == [DIGEST_A]


async def test_remote_pivot_lookup_is_inert_without_enrich_mode() -> None:
    """Refused at construction rather than accepted and ignored, so nobody
    believes pivots are running when they are not."""
    with pytest.raises(ValueError, match="no meaning unless mode is ENRICH"):
        PivotPolicy(mode=PivotMode.RECOMMEND, allow_remote_pivot_lookup=True)


async def test_enrich_queries_the_pivot_through_task_13() -> None:
    stack = Stack([ScriptedAdapter(spec(), {DIGEST_A: ((CONTACTS, "evil.example", "net"),)})])
    result = await run(stack)
    assert [run_.target_node_key for run_ in result.pivot_runs] == ["domain-name:evil.example"]
    assert stack.all_subjects == [DIGEST_A, "evil.example"]
    assert result.pivot_runs[0].selection_reason is PivotSelectionReason.DIRECT_BEHAVIOR_RELATION


# --------------------------------------------------------------------------- #
# Budgets
# --------------------------------------------------------------------------- #


def test_the_documented_budgets_per_depth() -> None:
    assert DEFAULT_PIVOT_BUDGETS[InvestigationDepth.QUICK] == (0, 0)
    assert DEFAULT_PIVOT_BUDGETS[InvestigationDepth.STANDARD] == (2, 3)
    assert DEFAULT_PIVOT_BUDGETS[InvestigationDepth.DEEP] == (5, 8)


async def test_quick_makes_no_automatic_pivot_calls_at_all() -> None:
    """Triage that quietly fans out to third parties is not triage."""
    stack = Stack([ScriptedAdapter(spec(), {DIGEST_A: ((CONTACTS, "evil.example", "net"),)})])
    result = await run(stack, depth=InvestigationDepth.QUICK)
    assert result.pivot_runs == ()
    assert result.pivot_budget.max_targets == 0
    assert stack.all_subjects == [DIGEST_A]
    assert candidate(result, "domain-name:evil.example").skip_reason is (
        PivotSkipReason.TARGET_BUDGET
    )


async def test_standard_enriches_at_most_two_targets() -> None:
    script = {DIGEST_A: tuple((CONTACTS, f"evil{index}.example", "net") for index in range(6))}
    stack = Stack([ScriptedAdapter(spec(), script)])
    result = await run(stack, depth=InvestigationDepth.STANDARD)
    assert len(result.pivot_runs) <= 2
    assert result.pivot_budget.targets_used <= 2
    assert result.total_remote_pivot_runs <= 3


async def test_deep_enriches_at_most_five_targets_within_the_shared_budget() -> None:
    script = {DIGEST_A: tuple((CONTACTS, f"evil{index}.example", "net") for index in range(12))}
    stack = Stack([ScriptedAdapter(spec(), script)])
    result = await run(stack, depth=InvestigationDepth.DEEP)
    assert len(result.pivot_runs) <= 5
    assert result.total_remote_pivot_runs <= 8
    assert result.pivot_budget.remote_runs_used <= result.pivot_budget.max_remote_provider_runs


async def test_the_remote_budget_is_shared_and_handed_down_as_a_reduction() -> None:
    """The critical property: three providers per pivot times five pivots would be
    fifteen remote calls from one submitted hash if each got a fresh budget."""
    providers = [
        ScriptedAdapter(
            spec(f"p{index}", family=f"family{index}"),
            {DIGEST_A: ((CONTACTS, "evil.example", "net"),)},
        )
        for index in range(3)
    ]
    stack = Stack(providers)
    result = await run(
        stack,
        policy=PivotPolicy(
            mode=PivotMode.ENRICH,
            allow_remote_pivot_lookup=True,
            max_remote_provider_runs=2,
        ),
    )
    assert result.total_remote_pivot_runs <= 2
    # And Task 13 was told, rather than merely watched: its own budget for the
    # pivot never exceeded what was left.
    for pivot in result.pivot_runs:
        assert pivot.enrichment.budget.max_remote_provider_runs <= 2


async def test_a_later_pivot_receives_only_what_earlier_ones_left() -> None:
    providers = [
        ScriptedAdapter(
            spec(f"p{index}", family=f"family{index}"),
            {
                DIGEST_A: (
                    (CONTACTS, "one.example", "net"),
                    (CONTACTS, "two.example", "net"),
                    (CONTACTS, "three.example", "net"),
                )
            },
        )
        for index in range(3)
    ]
    stack = Stack(providers)
    result = await run(
        stack,
        policy=PivotPolicy(
            mode=PivotMode.ENRICH, allow_remote_pivot_lookup=True, max_remote_provider_runs=4
        ),
    )
    budgets = [pivot.enrichment.budget.max_remote_provider_runs for pivot in result.pivot_runs]
    assert budgets == sorted(budgets, reverse=True)
    assert result.total_remote_pivot_runs <= 4


async def test_a_cache_hit_costs_the_pivot_budget_nothing() -> None:
    """Task 13's accounting, unchanged: only a real call counts.

    The pivot target is also reachable from the root's own result, so the second
    lookup is served from cache — and a budget charged on decisions rather than
    calls would have counted it.
    """
    stack = Stack(
        [
            ScriptedAdapter(
                spec(),
                {
                    DIGEST_A: ((CONTACTS, "evil.example", "net"),),
                    "evil.example": ((RESOLVES, "8.8.4.4", "pdns"),),
                },
            )
        ]
    )
    result = await run(stack)
    first = await stack.orchestrator.run(
        EnrichmentPlanningRequest(
            intel_object=file_object(sha256=DIGEST_A), depth=InvestigationDepth.DEEP
        ),
        stack.context(),
        investigation_id="inv-1",
        pivot_policy=PivotPolicy(mode=PivotMode.ENRICH, allow_remote_pivot_lookup=True),
    )
    assert result.total_remote_pivot_runs >= 1
    # The whole second investigation is answered from cache and spends nothing.
    assert first.total_remote_pivot_runs == 0
    assert first.root_enrichment.budget.remote_runs_used == 0


# --------------------------------------------------------------------------- #
# Privacy
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "address",
    ["10.0.0.1", "127.0.0.1", "169.254.10.1", "192.168.1.5", "224.0.0.1", "::1"],
)
async def test_a_non_global_address_is_graphed_but_never_disclosed(address: str) -> None:
    """A sandbox reports its own analysis network, and a customer's internal range
    is often more sensitive than the malware that touched it."""
    stack = Stack([ScriptedAdapter(spec(), {DIGEST_A: ((CONTACTS, address, "net"),)})])
    result = await run(stack)
    key = next(
        node.node_key
        for node in result.graph_nodes
        if node.object_type in {IntelObjectType.IPV4_ADDR, IntelObjectType.IPV6_ADDR}
    )
    assert candidate(result, key).skip_reason is PivotSkipReason.NON_GLOBAL_IP
    assert address not in stack.all_subjects
    # The relationship survives: not disclosing it is not the same as deleting it.
    assert any(edge.target_key == key for edge in result.graph_edges)


async def test_a_url_with_userinfo_is_never_disclosed_automatically() -> None:
    stack = Stack(
        [
            ScriptedAdapter(
                spec(),
                {DIGEST_A: ((CONTACTS, "https://user:pass@evil.example/a", "net"),)},
            )
        ]
    )
    result = await run(stack)
    url_key = next(
        node.node_key for node in result.graph_nodes if node.object_type is IntelObjectType.URL
    )
    assert candidate(result, url_key).skip_reason is PivotSkipReason.SENSITIVE_URL
    assert not any("@" in subject for subject in stack.all_subjects)


async def test_a_url_with_a_credential_shaped_parameter_is_not_disclosed() -> None:
    """Only the parameter *name* is inspected; the value is never read.

    And the tempting fix is refused by construction: stripping the query would be
    asking about a different observable and reporting the answer as this one's.
    """
    stack = Stack(
        [
            ScriptedAdapter(
                spec(),
                {DIGEST_A: ((CONTACTS, "https://evil.example/a?api_key=zzz", "net"),)},
            )
        ]
    )
    result = await run(stack)
    url_key = next(
        node.node_key for node in result.graph_nodes if node.object_type is IntelObjectType.URL
    )
    assert candidate(result, url_key).skip_reason is PivotSkipReason.SENSITIVE_URL
    assert "https://evil.example/a" not in stack.all_subjects


async def test_task_14_cannot_switch_remote_lookups_back_on() -> None:
    """The root investigation said no third parties. That decision stands."""
    stack = Stack([ScriptedAdapter(spec(), {DIGEST_A: ((CONTACTS, "evil.example", "net"),)})])
    result = await run(
        stack,
        constraints=PlanningConstraints(allow_remote_lookup=False),
        policy=PivotPolicy(mode=PivotMode.ENRICH, allow_remote_pivot_lookup=True),
    )
    assert stack.all_subjects == []
    assert result.total_remote_pivot_runs == 0


async def test_remote_pivots_are_off_unless_asked_for_separately() -> None:
    """Following a lead the provider chose is a wider disclosure than looking up
    what the analyst typed, so one consent must not imply the other."""
    stack = Stack([ScriptedAdapter(spec(), {DIGEST_A: ((CONTACTS, "evil.example", "net"),)})])
    result = await run(stack, policy=PivotPolicy(mode=PivotMode.ENRICH))
    assert stack.all_subjects == [DIGEST_A]
    assert result.total_remote_pivot_runs == 0
    assert candidate(result, "domain-name:evil.example").skip_reason is (
        PivotSkipReason.REMOTE_PIVOTS_DISABLED
    )


async def test_a_local_provider_still_answers_when_remote_pivots_are_off() -> None:
    """Task 13's locality policy decides that — no provider is named here."""
    local = ScriptedAdapter(
        spec("local_context", locality=ProviderLocality.LOCAL),
        {DIGEST_A: ((CONTACTS, "evil.example", "net"),), "evil.example": ()},
    )
    stack = Stack([local])
    result = await run(
        stack,
        policy=PivotPolicy(
            mode=PivotMode.ENRICH, explicit_targets=frozenset({"domain-name:evil.example"})
        ),
    )
    assert "evil.example" in stack.all_subjects
    assert result.total_remote_pivot_runs == 0


# --------------------------------------------------------------------------- #
# Hops and cycles
# --------------------------------------------------------------------------- #


async def test_automatic_enrichment_stops_one_hop_from_the_root() -> None:
    """A pivot's discoveries are graphed and never queried about.

    Otherwise one file becomes forty domains, four hundred addresses and two
    thousand URLs, none of which anybody chose to investigate.
    """
    stack = Stack(
        [
            ScriptedAdapter(
                spec(),
                {
                    DIGEST_A: ((CONTACTS, "evil.example", "net"),),
                    "evil.example": ((RESOLVES, "8.8.4.4", "pdns"),),
                    "8.8.4.4": ((CONTACTS, "further.example", "net"),),
                },
            )
        ]
    )
    result = await run(stack)
    assert MAX_AUTOMATIC_PIVOT_HOP == 1
    assert stack.all_subjects == [DIGEST_A, "evil.example"]
    assert any(node.node_key == "ipv4-addr:8.8.4.4" for node in result.graph_nodes)
    assert candidate(result, "ipv4-addr:8.8.4.4").skip_reason is PivotSkipReason.HOP_LIMIT


async def test_a_cycle_back_to_the_root_does_not_enrich_it_twice() -> None:
    """A→B and B→A is a legitimate graph. Looping over it is not."""
    stack = Stack(
        [
            ScriptedAdapter(
                spec(),
                {
                    DIGEST_A: ((CONTACTS, "evil.example", "net"),),
                    "evil.example": (
                        (DOWNLOADS, DIGEST_A, "payloads"),
                        (CONTACTS, "third.example", "net"),
                    ),
                },
            )
        ]
    )
    result = await run(stack)
    assert stack.all_subjects.count(DIGEST_A) == 1
    assert len(result.pivot_runs) == 1
    root = next(node for node in result.graph_nodes if node.is_root)
    assert root.enriched


async def test_one_target_named_by_several_providers_is_enriched_once() -> None:
    providers = [
        ScriptedAdapter(
            spec(f"p{index}", family=f"family{index}"),
            {DIGEST_A: ((CONTACTS, "evil.example", "net"),)},
        )
        for index in range(3)
    ]
    stack = Stack(providers)
    result = await run(stack)
    assert [run_.target_node_key for run_ in result.pivot_runs] == ["domain-name:evil.example"]
    assert sum(1 for value in stack.all_subjects if value == "evil.example") <= len(providers)
    edge = next(
        edge for edge in result.graph_edges if edge.target_key == "domain-name:evil.example"
    )
    assert len(edge.asserting_source_families) >= 2


async def test_pivot_depth_is_one_step_below_the_root() -> None:
    stack = Stack([ScriptedAdapter(spec(), {DIGEST_A: ((CONTACTS, "evil.example", "net"),)})])
    deep = await run(stack, depth=InvestigationDepth.DEEP)
    assert deep.pivot_runs[0].depth is InvestigationDepth.STANDARD

    standard_stack = Stack(
        [ScriptedAdapter(spec(), {DIGEST_A: ((CONTACTS, "evil.example", "net"),)})]
    )
    standard = await run(standard_stack, depth=InvestigationDepth.STANDARD)
    assert standard.pivot_runs[0].depth is InvestigationDepth.QUICK


# --------------------------------------------------------------------------- #
# Ranking and eligibility
# --------------------------------------------------------------------------- #


async def test_a_direct_artifact_outranks_shared_infrastructure() -> None:
    """A file this sample dropped is squarely part of the investigation; an
    address a contacted domain once resolved to is somebody else's neighbour."""
    stack = Stack(
        [
            ScriptedAdapter(
                spec(),
                {
                    DIGEST_A: (
                        (CONTACTS, "shared.example", "net"),
                        (RelationshipType.DROPS, "b" * 64, "extracted_files"),
                    ),
                    "shared.example": ((RESOLVES, "8.8.4.4", "pdns"),),
                },
            )
        ]
    )
    result = await run(stack, policy=PivotPolicy(mode=PivotMode.RECOMMEND))
    keys = [item.target_node_key for item in result.pivot_candidates]
    assert keys.index(f"file:sha256:{'b' * 64}") < keys.index("domain-name:shared.example")


async def test_an_unlinked_object_is_never_automatically_pivoted() -> None:
    """Nobody said how it relates to anything, so nothing licenses asking about
    it — and inventing a `related-to` to justify one would be worse."""
    stack = Stack(
        [
            ScriptedAdapter(spec(), {DIGEST_A: ((CONTACTS, "evil.example", "net"),)}),
            BareObjectAdapter(spec("orphan", family="orphan_family")),
        ]
    )
    result = await run(stack)
    assert candidate(result, "domain-name:lonely.example").skip_reason is (
        PivotSkipReason.UNLINKED_OBJECT
    )
    assert "lonely.example" not in stack.all_subjects


async def test_an_unsupported_target_type_is_not_pivoted() -> None:
    """No provider takes an autonomous system as a lookup subject."""
    stack = Stack(
        [
            ScriptedAdapter(
                spec(),
                {DIGEST_A: ((CONTACTS, "203.0.113.5", "net"),)},
            )
        ]
    )
    result = await run(stack)
    assert all(
        item.target_type in {IntelObjectType.IPV4_ADDR, IntelObjectType.DOMAIN_NAME}
        or item.skip_reason is PivotSkipReason.UNSUPPORTED_TARGET
        for item in result.pivot_candidates
    )


async def test_ranking_does_not_depend_on_provider_order() -> None:
    def build(order: list[int]) -> Stack:
        adapters = [
            ScriptedAdapter(
                spec(f"p{index}", family=f"family{index}"),
                {
                    DIGEST_A: (
                        (CONTACTS, f"evil{index}.example", "net"),
                        (RESOLVES, f"203.0.113.{index + 1}", "pdns"),
                    )
                },
            )
            for index in order
        ]
        return Stack(adapters)

    forward = await run(build([0, 1, 2]), policy=PivotPolicy(mode=PivotMode.RECOMMEND))
    reverse = await run(build([2, 1, 0]), policy=PivotPolicy(mode=PivotMode.RECOMMEND))
    assert [item.target_node_key for item in forward.pivot_candidates] == [
        item.target_node_key for item in reverse.pivot_candidates
    ]


# --------------------------------------------------------------------------- #
# Limits and reporting
# --------------------------------------------------------------------------- #


async def test_graph_ceilings_are_enforced_and_reported() -> None:
    script = {DIGEST_A: tuple((CONTACTS, f"evil{index}.example", "net") for index in range(50))}
    stack = Stack(
        [ScriptedAdapter(spec(), script)],
        limits=GraphLimits(max_nodes=5, max_edges=3, max_pivot_candidates=2),
    )
    result = await run(stack, policy=PivotPolicy(mode=PivotMode.RECOMMEND))
    assert len(result.graph_nodes) <= 5
    assert len(result.graph_edges) <= 3
    assert len(result.pivot_candidates) <= 2
    assert result.truncation.any_truncation
    assert result.truncation.nodes_dropped > 0
    assert any(
        issue.issue_type.value == "graph_limit_reached" for issue in result.correlation_issues
    )


async def test_the_result_carries_no_verdict_of_any_kind() -> None:
    stack = Stack([ScriptedAdapter(spec(), {DIGEST_A: ((CONTACTS, "evil.example", "net"),)})])
    result = await run(stack)

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | {name for item in value.values() for name in keys(item)}
        if isinstance(value, (list, tuple)):
            return {name for item in value for name in keys(item)}
        return set()

    every = keys(result.model_dump())
    for forbidden in ("verdict", "risk", "score", "malicious", "benign", "severity"):
        assert not [name for name in every if forbidden in name], forbidden


async def test_metrics_count_without_naming_anything() -> None:
    stack = Stack([ScriptedAdapter(spec(), {DIGEST_A: ((CONTACTS, "evil.example", "net"),)})])
    await run(stack)
    metric = stack.metrics.records[0]
    assert metric.graph_nodes >= 2
    assert metric.pivots_enriched == 1
    dumped = metric.model_dump()
    assert DIGEST_A not in repr(dumped)
    assert "evil.example" not in repr(dumped)


async def test_two_analysts_investigating_one_observable_share_nothing() -> None:
    """The same canonical keys, two separate graphs. Correlation is investigation
    knowledge; sharing it would leak who is looking at what."""
    first = Stack([ScriptedAdapter(spec(), {DIGEST_A: ((CONTACTS, "evil.example", "net"),)})])
    second = Stack([ScriptedAdapter(spec(), {DIGEST_A: ((CONTACTS, "evil.example", "net"),)})])
    left = await run(first)
    await second.add_credentials("analyst-b")
    right = await second.orchestrator.run(
        EnrichmentPlanningRequest(
            intel_object=file_object(sha256=DIGEST_A), depth=InvestigationDepth.DEEP
        ),
        second.context("analyst-b"),
        investigation_id="inv-2",
        pivot_policy=PivotPolicy(mode=PivotMode.ENRICH, allow_remote_pivot_lookup=True),
    )
    assert left.root_node_key == right.root_node_key
    # Same identity, and analyst B paid for their own lookups rather than reading
    # analyst A's graph.
    assert right.total_remote_pivot_runs >= 1
    assert second.all_subjects == [DIGEST_A, "evil.example"]
