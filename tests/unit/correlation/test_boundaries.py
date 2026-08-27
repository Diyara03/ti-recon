"""What the correlation package may not do, and what it must serialize (Task 14).

Structural guards on the AST rather than on prose: a module may discuss the
network in a docstring while never importing a socket, and a check that read
comments would fire on its own explanation.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from fixtures.correlation import DIGEST_A, envelope, file_object, graph_for, observable
from ti_recon.correlation import (
    PIVOT_RANKING_FACTORS,
    CorrelationIssueType,
    GraphLimits,
    InMemoryCorrelationMetricsSink,
    PivotBudget,
    PivotMode,
    PivotPolicy,
    RelationBasis,
    RelationshipAssertion,
)
from ti_recon.correlation.policy import PIVOT_DEPTH_DOWNSHIFT
from ti_recon.enums import InvestigationDepth, RelationshipType

CORRELATION_PACKAGE = Path("src/ti_recon/correlation")

#: Modules that may not reach the network, hold a secret, or call a provider.
#: The orchestrator is excluded: it is the one module that drives Task 13, and it
#: still touches no adapter and no credential.
PURE_MODULES = tuple(
    path
    for path in sorted(CORRELATION_PACKAGE.glob("*.py"))
    if path.name not in {"orchestrator.py", "__init__.py"}
)


def imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            found.add(node.module or "")
        elif isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
    return found


# --------------------------------------------------------------------------- #
# Network
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("path", PURE_MODULES, ids=lambda item: item.name)
def test_no_correlation_module_can_reach_the_network(path: Path) -> None:
    """Correlation reads what providers already returned. A pivot is a canonical
    observable handed to Task 13, never a resolution, a fetch or a socket."""
    forbidden = {"socket", "httpx", "requests", "urllib.request", "dns", "asyncio"}
    assert not (imports(path) & forbidden), path.name


@pytest.mark.parametrize("path", PURE_MODULES, ids=lambda item: item.name)
def test_no_correlation_module_imports_a_provider_or_a_credential(path: Path) -> None:
    """Provider selection is Task 13's, credentials are Task 4's, and a graph that
    could reach either would eventually be asked to."""
    found = imports(path)
    # `providers.result` is the framework's own envelope type — the thing every
    # provider returns and the only input this package has. A concrete
    # integration is what must stay out.
    assert not [
        item
        for item in found
        if item.startswith("ti_recon.providers.") and item != "ti_recon.providers.result"
    ], path.name
    assert not [item for item in found if item.startswith("ti_recon.credentials")], path.name
    assert "SecretStr" not in path.read_text(encoding="utf-8")


def test_the_orchestrator_touches_no_adapter_and_no_credential() -> None:
    """It drives Task 13 and nothing below it."""
    path = CORRELATION_PACKAGE / "orchestrator.py"
    found = imports(path)
    assert not [
        item
        for item in found
        if item.startswith("ti_recon.providers.") and not item.endswith(".result")
    ]
    assert not [item for item in found if item.startswith("ti_recon.credentials")]


def test_no_correlation_module_resolves_or_fetches_anything() -> None:
    # `.get` and `.resolve` are deliberately absent: both are ordinary local calls
    # here — a mapping read and the file-identity resolver — and a *network* one
    # would need an import the guard above already forbids.
    forbidden_calls = {"getaddrinfo", "gethostbyname", "post", "fetch", "connect", "urlopen"}
    offenders = [
        f"{path.name}: {node.func.attr}"
        for path in (*PURE_MODULES, CORRELATION_PACKAGE / "orchestrator.py")
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in forbidden_calls
    ]
    assert offenders == []


# --------------------------------------------------------------------------- #
# Ranking and policy as data
# --------------------------------------------------------------------------- #


def test_the_ranking_factors_are_documented_as_data() -> None:
    assert PIVOT_RANKING_FACTORS == (
        "explicitly_selected",
        "relationship_directness",
        "automatically_eligible",
        "not_previously_enriched",
        "supported_target_type",
        "relationship_fan_out",
        "distance_from_root",
        "node_key",
    )
    # Deliberately absent: how many families asserted the relationship. Ranking on
    # it is the first step towards "two providers agreed, therefore malicious".
    assert not [item for item in PIVOT_RANKING_FACTORS if "famil" in item]
    assert not [item for item in PIVOT_RANKING_FACTORS if "score" in item]


def test_a_pivot_is_never_run_at_the_depth_that_found_it() -> None:
    assert PIVOT_DEPTH_DOWNSHIFT[InvestigationDepth.DEEP] is InvestigationDepth.STANDARD
    assert PIVOT_DEPTH_DOWNSHIFT[InvestigationDepth.STANDARD] is InvestigationDepth.QUICK
    assert PIVOT_DEPTH_DOWNSHIFT[InvestigationDepth.QUICK] is InvestigationDepth.QUICK


def test_a_caller_may_lower_a_pivot_budget_but_not_raise_it() -> None:
    policy = PivotPolicy(mode=PivotMode.ENRICH, max_targets=1, max_remote_provider_runs=99)
    budget = policy.budget_for(InvestigationDepth.DEEP)
    assert budget.max_targets == 1
    assert budget.max_remote_provider_runs == 8


def test_a_budget_charges_only_what_it_was_told() -> None:
    budget = PivotBudget(max_targets=2, max_remote_provider_runs=5)
    charged = budget.charge(remote_runs=3)
    assert (charged.targets_used, charged.remote_runs_used) == (1, 3)
    assert charged.remote_remaining == 2
    assert not charged.exhausted
    assert charged.charge(remote_runs=2).exhausted


# --------------------------------------------------------------------------- #
# Limits
# --------------------------------------------------------------------------- #


def test_the_assertion_ceiling_truncates_and_counts() -> None:
    """Never a silent stop: an analyst reading a bounded edge needs to know how
    much did not fit."""
    graph, _ = graph_for(
        file_object(sha256=DIGEST_A), limits=GraphLimits(max_assertions_per_edge=2)
    )
    for index in range(6):
        graph.add_assertion(
            source_key=f"file:sha256:{DIGEST_A}",
            relationship_type=RelationshipType.CONTACTS,
            target_key="domain-name:evil.example",
            assertion=RelationshipAssertion(
                basis=RelationBasis.PROVIDER_REPORTED,
                transport_provider=f"p{index}",
                origin_provider=f"p{index}",
                source_family=f"family{index}",
                lineage_group_id=f"lg{index}",
            ),
        )
    edge = graph.edges[0]
    assert len(edge.assertions) == 2
    assert edge.assertions_truncated == 4
    assert graph.truncation.assertions_dropped == 4
    assert any(
        issue.issue_type is CorrelationIssueType.GRAPH_LIMIT_REACHED for issue in graph.issues
    )


def test_the_node_ceiling_reports_once_rather_than_per_item() -> None:
    graph, engine = graph_for(limits=GraphLimits(max_nodes=2))
    engine.ingest(
        envelope("one", objects=tuple(observable(f"host{index}.example") for index in range(20)))
    )
    assert graph.node_count == 2
    assert graph.truncation.nodes_dropped == 18
    limit_issues = [
        issue
        for issue in graph.issues
        if issue.issue_type is CorrelationIssueType.GRAPH_LIMIT_REACHED
    ]
    assert len(limit_issues) == 1


# --------------------------------------------------------------------------- #
# Serialization
# --------------------------------------------------------------------------- #


def test_the_graph_serializes_deterministically() -> None:
    """Two graphs built from the same facts must dump identically, so a diff
    between two runs means something changed rather than a dict reordered.

    The Task 3 object identity — a fresh UUID and creation timestamp per object —
    is excluded, because that is the model's own per-instance identity and not
    something correlation controls. What must be stable is the graph: which nodes
    exist, under which keys, with which provenance and which edges.
    """
    volatile = {"id", "created_at", "updated_at", "evidence_id"}

    def stable(dumped: dict[str, object]) -> dict[str, object]:
        """Drop per-instance identity: object UUIDs, timestamps, evidence ids.

        Those are pointers into one run's provider results, minted fresh each
        time. What has to be stable is the graph itself.
        """
        item = {key: value for key, value in dumped.items() if key not in volatile}
        obj = item.get("intel_object")
        if isinstance(obj, dict):
            item["intel_object"] = {key: value for key, value in obj.items() if key not in volatile}
        assertions = item.get("assertions")
        if isinstance(assertions, list):
            item["assertions"] = [
                {key: value for key, value in entry.items() if key not in volatile}
                for entry in assertions
                if isinstance(entry, dict)
            ]
        return item

    def build() -> object:
        graph, engine = graph_for(file_object(sha256=DIGEST_A))
        sample, domain = file_object(sha256=DIGEST_A), observable("evil.example")
        engine.ingest(
            envelope(
                "gti",
                source_family="google_ti",
                objects=(sample, domain),
                links=((sample, RelationshipType.CONTACTS, domain, "contacted_domains"),),
            )
        )
        engine.derive_structural_edges_for_graph()
        return (
            [stable(node.model_dump(mode="json")) for node in graph.nodes],
            [stable(edge.model_dump(mode="json")) for edge in graph.edges],
        )

    assert build() == build()


def test_nothing_serialized_carries_a_python_object_identity() -> None:
    graph, engine = graph_for(file_object(sha256=DIGEST_A))
    sample, domain = file_object(sha256=DIGEST_A), observable("evil.example")
    engine.ingest(
        envelope(
            "gti",
            objects=(sample, domain),
            links=((sample, RelationshipType.CONTACTS, domain, "contacted_domains"),),
        )
    )
    dumped = repr([node.model_dump(mode="json") for node in graph.nodes])
    assert "0x" not in dumped
    assert " object at " not in dumped


def test_the_metrics_sink_is_bounded_and_unfit_for_production() -> None:
    sink = InMemoryCorrelationMetricsSink(max_records=1)
    assert sink.is_production_ready is False
    with pytest.raises(ValueError, match="max_records"):
        InMemoryCorrelationMetricsSink(max_records=0)


def test_an_engine_derived_assertion_cannot_name_a_provider() -> None:
    """Validated rather than merely documented: the one rule that stops TI Recon's
    own parsing being counted as intelligence."""
    with pytest.raises(ValueError, match="names no provider"):
        RelationshipAssertion(
            basis=RelationBasis.ENGINE_DERIVED,
            transport_provider="gti",
            source_family="google_ti",
        )


def test_a_provider_assertion_must_say_who_made_it() -> None:
    with pytest.raises(ValueError, match="must name its transport provider"):
        RelationshipAssertion(basis=RelationBasis.PROVIDER_REPORTED)
