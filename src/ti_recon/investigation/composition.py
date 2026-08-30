"""Building the default investigation orchestrator (Task 19).

The one place in this package that reaches the provider catalogues, and it does
so only through the composition roots the previous tasks already established:

* :func:`~ti_recon.planning.catalog.build_default_planning_registry` — which
  providers can be planned, what they cost and whether asking discloses anything;
* :func:`~ti_recon.reasoning.catalog.default_qualifiers` — each provider's pure
  translation of its own time and context fields;
* :func:`~ti_recon.reasoning.claims.registry.default_translators` — each
  provider's pure translation of its own directional evidence into propositions.

Reusing them rather than assembling a list here is the point. A second,
hand-written catalogue would drift: a provider added to the real one would keep
working everywhere except in a full investigation, and nothing would fail — the
run would simply be quietly narrower than every test suite believed.

The generic orchestrator stays provider-neutral. It receives an adapter registry
and an executor and never learns a name.
"""

from __future__ import annotations

from ti_recon.correlation.metrics import CorrelationMetricsSink
from ti_recon.correlation.models import DEFAULT_GRAPH_LIMITS, GraphLimits
from ti_recon.correlation.orchestrator import CorrelatedInvestigationOrchestrator
from ti_recon.execution.clock import Clock, SystemClock
from ti_recon.execution.executor import ProviderExecutor
from ti_recon.investigation.analysis import ReasoningEngines
from ti_recon.investigation.engine import InvestigationOrchestrator
from ti_recon.investigation.metrics import (
    InvestigationMetricsSink,
    NoOpInvestigationMetricsSink,
)
from ti_recon.planning.catalog import build_default_planning_registry
from ti_recon.planning.orchestrator import AdaptiveEnrichmentOrchestrator
from ti_recon.planning.planner import AdaptiveEnrichmentPlanner
from ti_recon.providers.registry import ProviderRegistry
from ti_recon.reasoning.catalog import default_qualifiers
from ti_recon.reasoning.claims.registry import default_translators
from ti_recon.reasoning.engine import TemporalContextEngine
from ti_recon.reasoning.false_positive.engine import FalsePositiveReasoningEngine
from ti_recon.reasoning.fusion.engine import EvidenceFusionEngine
from ti_recon.reasoning.readiness.engine import AssessmentReadinessEngine

__all__ = ["build_default_investigation_orchestrator", "build_default_reasoning_engines"]


def build_default_reasoning_engines() -> ReasoningEngines:
    """The four pure engines, wired to the shipped provider translations.

    Each engine keeps its own composition root — Task 15's qualifiers and
    Task 17's claim translators are the only places a provider is named in the
    reasoning layers, and both are reused here rather than re-derived.
    """
    return ReasoningEngines(
        temporal=TemporalContextEngine(qualifiers=default_qualifiers()),
        false_positive=FalsePositiveReasoningEngine(),
        fusion=EvidenceFusionEngine(translators=default_translators()),
        readiness=AssessmentReadinessEngine(),
    )


def build_default_investigation_orchestrator(
    *,
    registry: ProviderRegistry,
    executor: ProviderExecutor,
    clock: Clock | None = None,
    limits: GraphLimits = DEFAULT_GRAPH_LIMITS,
    metrics: InvestigationMetricsSink | None = None,
    correlation_metrics: CorrelationMetricsSink | None = None,
) -> InvestigationOrchestrator:
    """One orchestrator wired to the shipped catalogues.

    The adapter ``registry`` and the ``executor`` stay the caller's to build:
    adapters need clients and the executor needs credential, cache, quota and
    cooldown stores, and choosing those is a deployment decision rather than a
    property of the workflow.
    """
    return InvestigationOrchestrator(
        correlation=CorrelatedInvestigationOrchestrator(
            enrichment=AdaptiveEnrichmentOrchestrator(
                planner=AdaptiveEnrichmentPlanner(
                    registry=registry,
                    profiles=build_default_planning_registry(),
                ),
                executor=executor,
                registry=registry,
            ),
            limits=limits,
            metrics=correlation_metrics,
        ),
        engines=build_default_reasoning_engines(),
        clock=SystemClock() if clock is None else clock,
        metrics=NoOpInvestigationMetricsSink() if metrics is None else metrics,
    )
