"""Temporal evidence qualification and context reasoning (Task 15).

Takes what Tasks 5-14 collected and answers **"what does this piece of evidence
actually mean in time and context?"** — never "what is the verdict?". There is no
verdict, no confidence, no risk score, no evidence weight, no decay curve and no
false-positive flag anywhere in this package, and structural tests keep it that
way. Weighing what any of it is worth is the future fusion layer's job.

Six rules do most of the work:

* **A timestamp has a type.** ``last_analysis_date`` is a scan time,
  ``last_online`` is a serving time, ``analysis_start_time`` is a detonation
  time. Pouring them into one ``last_seen`` turns "we rescanned it yesterday"
  into "it attacked somebody yesterday". Query time is never observation time.
* **The clock is an argument.** Every run takes an explicit timezone-aware
  ``as_of``; nothing reads a wall clock, so the same inputs qualify identically
  forever.
* **Lifecycle belongs to the source.** URLhaus knows a URL is offline, ThreatFox
  knows its API holds six months, MISP's snapshot knows when it was built. TI
  Recon invents no generic freshness rule, because a phishing URL, a malware
  hash, a cloud address and a certificate do not share a lifetime.
* **Context explains; it never exonerates.** A warninglist match, a cloud range
  and GreyNoise's Business Services Intelligence are all context. None means
  safe, and no signal type exists that could be read that way.
* **Nothing propagates.** A cue attaches to the node, edge or finding it came
  from and stops. There is one edge-scoped rule and it reads exactly one edge.
* **Provider semantics stay provider-owned.** Each integration exposes a pure
  extractor; the evaluator names no vendor, and ``catalog.py`` is the only module
  here that may.
"""

from ti_recon.reasoning.catalog import default_qualifiers, qualified_provider_ids
from ti_recon.reasoning.context import direct_source_families, relayed_signals
from ti_recon.reasoning.cues import LIFECYCLE_CUES, SIGNAL_CUES, build_cues
from ti_recon.reasoning.engine import TemporalContextEngine
from ti_recon.reasoning.extraction import (
    ProviderQualification,
    ProviderQualifier,
    QualificationContext,
)
from ti_recon.reasoning.metrics import (
    InMemoryQualificationMetricsSink,
    NoOpQualificationMetricsSink,
    QualificationMetric,
    QualificationMetricsSink,
)
from ti_recon.reasoning.models import (
    INTERVAL_PAIRS,
    ContextSignal,
    ContextSignalType,
    CuePurpose,
    EvidenceRef,
    InterpretationCue,
    InterpretationCueType,
    SignalOrigin,
    SourceLifecycleState,
    SubjectKind,
    SubjectRef,
    TemporalFact,
    TemporalFactKind,
    TemporalIssue,
    TemporalIssueType,
    TemporalQualification,
    dataset_subject,
    edge_subject,
    observable_subject,
    report_subject,
)
from ti_recon.reasoning.policy import (
    CLOCK_SKEW_TOLERANCE,
    CONTEXT_POLICY_VERSION,
    WARNINGLIST_MAP_VERSION,
    WARNINGLIST_SIGNAL_MAP,
    signal_for_warninglist,
)
from ti_recon.reasoning.results import QualificationCoverage, TemporalContextResult
from ti_recon.reasoning.temporal import qualify_facts, require_utc

__all__ = [
    "CLOCK_SKEW_TOLERANCE",
    "CONTEXT_POLICY_VERSION",
    "INTERVAL_PAIRS",
    "LIFECYCLE_CUES",
    "SIGNAL_CUES",
    "WARNINGLIST_MAP_VERSION",
    "WARNINGLIST_SIGNAL_MAP",
    "ContextSignal",
    "ContextSignalType",
    "CuePurpose",
    "EvidenceRef",
    "InMemoryQualificationMetricsSink",
    "InterpretationCue",
    "InterpretationCueType",
    "NoOpQualificationMetricsSink",
    "ProviderQualification",
    "ProviderQualifier",
    "QualificationContext",
    "QualificationCoverage",
    "QualificationMetric",
    "QualificationMetricsSink",
    "SignalOrigin",
    "SourceLifecycleState",
    "SubjectKind",
    "SubjectRef",
    "TemporalContextEngine",
    "TemporalContextResult",
    "TemporalFact",
    "TemporalFactKind",
    "TemporalIssue",
    "TemporalIssueType",
    "TemporalQualification",
    "build_cues",
    "dataset_subject",
    "default_qualifiers",
    "direct_source_families",
    "edge_subject",
    "observable_subject",
    "qualified_provider_ids",
    "qualify_facts",
    "relayed_signals",
    "report_subject",
    "require_utc",
    "signal_for_warninglist",
]
