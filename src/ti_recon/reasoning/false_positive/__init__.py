"""Deterministic false-positive and alternative-explanation reasoning (Task 16).

Takes what Task 15 qualified and asks the next question: **can that context
legitimately explain a specific piece of evidence, and what does the explanation
not cover?** It never decides the case -- no verdict, no confidence, no score, no
weight and no false-positive boolean.

Six rules do most of the work:

* **A false positive is a property of a detection, not of an IOC.** There is no
  ``is_false_positive`` on anything. Every finding names the evidence or
  relationship it concerns through a typed link, so "which claim was explained,
  and which was not" always has an answer.
* **Context alone explains nothing.** A warninglist hit on an address nobody has
  accused of anything is context. An explanation needs something to explain.
* **Scope is checked.** Host-level context produces a scope limitation and never
  an explanation: a fact about ``github.com`` is not a fact about a payload
  hosted on it.
* **Explaining, limiting and cautioning are different jobs.** Shared hosting
  affects attribution, current inactivity affects activity, a relayed finding
  affects independence, and a sandbox that ran nothing affects analysis quality.
  None of those is a candidate false positive, and only one role means "this may
  explain the detection".
* **Nothing propagates and nothing is rewritten.** Context on a pivot stays on
  the pivot, a relationship a sandbox watched stays observed, and no provider
  fact is mutated.
* **The engine names no provider.** Every discriminator is generic -- an effect,
  a class, a scope, a Task 15 signal -- and an AST test keeps it that way.
"""

from ti_recon.reasoning.false_positive.engine import FalsePositiveReasoningEngine
from ti_recon.reasoning.false_positive.index import DIRECTIONAL_EFFECTS, ReasoningIndex
from ti_recon.reasoning.false_positive.metrics import (
    InMemoryReasoningMetricsSink,
    NoOpReasoningMetricsSink,
    ReasoningMetric,
    ReasoningMetricsSink,
)
from ti_recon.reasoning.false_positive.models import (
    DoesNotEstablish,
    FindingLimitation,
    FindingLink,
    LinkRelation,
    LinkTarget,
    ReasonCode,
    ReasoningDimension,
    ReasoningFinding,
    ReasoningRole,
    finding_id_for,
)
from ti_recon.reasoning.false_positive.policy import (
    EXPLAINABLE_CONTEXT_SIGNALS,
    FALSE_POSITIVE_REASONING_POLICY_VERSION,
    HOST_SCOPED_CONTEXT_SIGNALS,
    REASON_BOUNDARIES,
    REASON_SEMANTICS,
    RULE_IDS,
    message_for,
)
from ti_recon.reasoning.false_positive.results import (
    FalsePositiveReasoningResult,
    ReasoningCoverage,
)
from ti_recon.reasoning.false_positive.rules import ALL_RULES, apply_rules

__all__ = [
    "ALL_RULES",
    "DIRECTIONAL_EFFECTS",
    "EXPLAINABLE_CONTEXT_SIGNALS",
    "FALSE_POSITIVE_REASONING_POLICY_VERSION",
    "HOST_SCOPED_CONTEXT_SIGNALS",
    "REASON_BOUNDARIES",
    "REASON_SEMANTICS",
    "RULE_IDS",
    "DoesNotEstablish",
    "FalsePositiveReasoningEngine",
    "FalsePositiveReasoningResult",
    "FindingLimitation",
    "FindingLink",
    "InMemoryReasoningMetricsSink",
    "LinkRelation",
    "LinkTarget",
    "NoOpReasoningMetricsSink",
    "ReasonCode",
    "ReasoningCoverage",
    "ReasoningDimension",
    "ReasoningFinding",
    "ReasoningIndex",
    "ReasoningMetric",
    "ReasoningMetricsSink",
    "ReasoningRole",
    "apply_rules",
    "finding_id_for",
    "message_for",
]
