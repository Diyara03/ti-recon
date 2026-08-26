"""Adaptive enrichment planning and orchestration (Task 13).

Answers **"what should TI Recon ask next?"** — and deliberately not "is this
malicious?".

Three layers, kept apart on purpose:

* **Planner** — chooses which provider to ask, for which capability, in what
  order, and when to stop. Deterministic, provider-neutral, no I/O.
* **Executor** (Task 6) — runs one provider safely: credentials, cache, retry,
  quota, cooldown, concurrency.
* **Fusion** (future) — decides what all the evidence means.

The planner reasons in **capabilities and source families**, never in provider
votes. Three abuse.ch datasets agreeing is one ecosystem agreeing with itself; a
second independent family saying the same thing is corroboration. Ranking them
differently is how enrichment avoids buying votes.

Two rules it will not break:

* **False-positive context never substitutes for threat intelligence.** A
  warninglist match explains evidence; it does not replace the need for any. A
  planner that stopped on one would systematically under-investigate anything
  hosted on shared infrastructure.
* **`GOALS_SATISFIED` means the requested coverage was collected**, not that the
  answer is known. Every :class:`StopReason` is operational, and there is
  deliberately no member meaning "confident enough".

Importing the catalogue
-----------------------

:mod:`ti_recon.planning.catalog` is **not** re-exported here, and must not be: it
imports every provider package, while every provider descriptor imports the
planning models from this package. Exporting it eagerly makes that a circular
import — as it did, immediately. Import it by module path when you want the
shipped registry::

    from ti_recon.planning.catalog import build_default_planning_registry

Scope boundaries: automatic planning is **passive only** — no submission,
detonation or rescan can enter a plan — and it enriches **the requested
observable only**. Providers return related objects; recursively enriching them
needs pivot-value judgement, graph deduplication and cycle prevention, and a task
of its own.
"""

from ti_recon.planning.goals import (
    DEPTH_ORDER,
    CapabilityGoal,
    GoalActivation,
    depth_at_least,
)
from ti_recon.planning.metrics import (
    InMemoryPlanningMetricsSink,
    NoOpPlanningMetricsSink,
    PlanningMetricsSink,
    PlanningRunMetric,
    ProviderSelectionMetric,
    ProviderSkipMetric,
)
from ti_recon.planning.models import (
    COST_ORDER,
    NOVELTY_ORDER,
    AdaptiveEnrichmentResult,
    CallCostClass,
    EnrichmentBudget,
    EnrichmentPlanningRequest,
    NoveltyClass,
    PlannedProviderCall,
    PlanningConstraints,
    PlanningDecision,
    ProviderAttempt,
    ProviderLocality,
    ProviderPlanningProfile,
    SelectionReason,
    SkippedCandidate,
    SkipReason,
    StopReason,
)
from ti_recon.planning.orchestrator import (
    MAX_PLANNING_ROUNDS,
    AdaptiveEnrichmentOrchestrator,
)
from ti_recon.planning.planner import AdaptiveEnrichmentPlanner, Candidate
from ti_recon.planning.policy import (
    DEFAULT_BUDGETS,
    DEFAULT_GOAL_TEMPLATES,
    EnrichmentPolicy,
    ProviderPlanningRegistry,
    UnknownProviderError,
)
from ti_recon.planning.ranking import (
    RANKING_FACTORS,
    candidate_key,
    selection_reason_for,
)
from ti_recon.planning.state import (
    BLOCKING_ERROR_CATEGORIES,
    COVERING_STATUSES,
    PARTIAL_STATUSES,
    PlanningState,
)

__all__ = [
    "BLOCKING_ERROR_CATEGORIES",
    "COST_ORDER",
    "COVERING_STATUSES",
    "DEFAULT_BUDGETS",
    "DEFAULT_GOAL_TEMPLATES",
    "DEPTH_ORDER",
    "MAX_PLANNING_ROUNDS",
    "NOVELTY_ORDER",
    "PARTIAL_STATUSES",
    "RANKING_FACTORS",
    "AdaptiveEnrichmentOrchestrator",
    "AdaptiveEnrichmentPlanner",
    "AdaptiveEnrichmentResult",
    "CallCostClass",
    "Candidate",
    "CapabilityGoal",
    "EnrichmentBudget",
    "EnrichmentPlanningRequest",
    "EnrichmentPolicy",
    "GoalActivation",
    "InMemoryPlanningMetricsSink",
    "NoOpPlanningMetricsSink",
    "NoveltyClass",
    "PlannedProviderCall",
    "PlanningConstraints",
    "PlanningDecision",
    "PlanningMetricsSink",
    "PlanningRunMetric",
    "PlanningState",
    "ProviderAttempt",
    "ProviderLocality",
    "ProviderPlanningProfile",
    "ProviderPlanningRegistry",
    "ProviderSelectionMetric",
    "ProviderSkipMetric",
    "SelectionReason",
    "SkipReason",
    "SkippedCandidate",
    "StopReason",
    "UnknownProviderError",
    "candidate_key",
    "depth_at_least",
    "selection_reason_for",
]
