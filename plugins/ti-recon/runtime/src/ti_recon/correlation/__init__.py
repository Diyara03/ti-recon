"""Correlation graph, relationship lineage and controlled pivots (Task 14).

Takes what Task 13 learned about one observable and turns the objects and
relationships providers returned into a single, bounded, provenance-aware graph —
then decides which of the things it found are worth *considering* as further
enrichment.

It answers "what have we learned, which records refer to the same object, and what
might be worth asking about next". It does not answer "is this malicious": there
is no verdict, no confidence and no score anywhere in this package.

Four rules do most of the work:

* **Exact identity only.** Records merge when they are the same object. A shared
  ASN, /24, certificate issuer, malware family or fuzzy hash is not identity.
* **An edge aggregates assertions.** Two providers claiming the same relationship
  is one edge with two assertions, each keeping its own provenance and times.
* **No transitive inference.** A→B and B→C never produces A→C. Two samples
  contacting one address are not thereby related. Inference, if it is ever wanted,
  belongs in a layer that labels its output as inferred.
* **Discovery is not disclosure.** Finding a domain in a sandbox report does not
  authorise asking six third parties about it. Remote pivoting needs two explicit
  switches, is bounded by a shared budget, runs at a reduced depth, and stops one
  hop from the root.
"""

from ti_recon.correlation.engine import CorrelationEngine, IngestionSummary
from ti_recon.correlation.graph import EdgeKey, InvestigationGraph
from ti_recon.correlation.identity import (
    FileIdentityResolution,
    FileIdentityResolver,
    node_key_for,
)
from ti_recon.correlation.metrics import (
    CorrelationMetric,
    CorrelationMetricsSink,
    InMemoryCorrelationMetricsSink,
    NoOpCorrelationMetricsSink,
)
from ti_recon.correlation.models import (
    DEFAULT_GRAPH_LIMITS,
    CorrelationIssue,
    CorrelationIssueType,
    GraphEdge,
    GraphLimits,
    GraphNode,
    GraphTruncation,
    IdentityBasis,
    NodeOccurrence,
    PivotSafetyClass,
    RelationBasis,
    RelationshipAssertion,
)
from ti_recon.correlation.orchestrator import CorrelatedInvestigationOrchestrator
from ti_recon.correlation.pivots import (
    PIVOT_RANKING_FACTORS,
    PivotCandidate,
    PivotPlanner,
    is_sensitive_url,
    non_global_address,
)
from ti_recon.correlation.policy import (
    DEFAULT_PIVOT_BUDGETS,
    MAX_AUTOMATIC_PIVOT_HOP,
    PIVOT_DEPTH_DOWNSHIFT,
    PivotBudget,
    PivotMode,
    PivotPolicy,
    PivotSelectionReason,
    PivotSkipReason,
)
from ti_recon.correlation.relationships import (
    RELATIONSHIP_DEFINITIONS,
    PivotEligibility,
    RelationshipDefinition,
    definition_for,
)
from ti_recon.correlation.results import CorrelatedEnrichmentResult, PivotRun

__all__ = [
    "DEFAULT_GRAPH_LIMITS",
    "DEFAULT_PIVOT_BUDGETS",
    "MAX_AUTOMATIC_PIVOT_HOP",
    "PIVOT_DEPTH_DOWNSHIFT",
    "PIVOT_RANKING_FACTORS",
    "RELATIONSHIP_DEFINITIONS",
    "CorrelatedEnrichmentResult",
    "CorrelatedInvestigationOrchestrator",
    "CorrelationEngine",
    "CorrelationIssue",
    "CorrelationIssueType",
    "CorrelationMetric",
    "CorrelationMetricsSink",
    "EdgeKey",
    "FileIdentityResolution",
    "FileIdentityResolver",
    "GraphEdge",
    "GraphLimits",
    "GraphNode",
    "GraphTruncation",
    "IdentityBasis",
    "InMemoryCorrelationMetricsSink",
    "IngestionSummary",
    "InvestigationGraph",
    "NoOpCorrelationMetricsSink",
    "NodeOccurrence",
    "PivotBudget",
    "PivotCandidate",
    "PivotEligibility",
    "PivotMode",
    "PivotPlanner",
    "PivotPolicy",
    "PivotRun",
    "PivotSafetyClass",
    "PivotSelectionReason",
    "PivotSkipReason",
    "RelationBasis",
    "RelationshipAssertion",
    "RelationshipDefinition",
    "definition_for",
    "is_sensitive_url",
    "node_key_for",
    "non_global_address",
]
