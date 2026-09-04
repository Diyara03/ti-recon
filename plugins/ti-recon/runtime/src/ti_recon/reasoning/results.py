"""What a qualification run returns (Task 15).

Deliberately not an assessment. There is no verdict, no confidence, no risk
score, no evidence weight and no false-positive flag anywhere in this module, and
a test walks the field names of every model in the package to prove it. What a
caller gets is structured facts about time, structured context, named cautions,
and an honest account of what was examined.

Coverage is a first-class part of that, for the reason it always is here:
"nothing was qualified" and "there was nothing to qualify" look identical without
it. A provider with no extractor is named rather than silently skipped, and a
missing timestamp is counted as coverage rather than reported as an error —
most providers time some claims and not others, and turning every absence into an
issue would bury the two cases that mean the data is actually wrong.
"""

from __future__ import annotations

from pydantic import Field

from ti_recon.models.base import FrozenTiReconModel, UtcDatetime
from ti_recon.reasoning.models import (
    ContextSignal,
    ContextSignalType,
    InterpretationCue,
    InterpretationCueType,
    TemporalIssue,
    TemporalQualification,
)

__all__ = ["QualificationCoverage", "TemporalContextResult"]


class QualificationCoverage(FrozenTiReconModel):
    """What this run actually looked at.

    Counts and provider ids only. Nothing here can hold an observable, a node
    key, an investigation id or a user.
    """

    provider_results_examined: int = Field(default=0, ge=0)
    evidence_items_examined: int = Field(default=0, ge=0)
    #: Evidence records that yielded at least one typed instant. The rest are not
    #: failures: a warninglist hit and a blocklist relay legitimately have no time.
    evidence_with_temporal_facts: int = Field(default=0, ge=0)
    relationship_assertions_examined: int = Field(default=0, ge=0)
    graph_nodes_examined: int = Field(default=0, ge=0)
    graph_edges_examined: int = Field(default=0, ge=0)
    temporal_facts_extracted: int = Field(default=0, ge=0)
    context_signals_generated: int = Field(default=0, ge=0)
    interpretation_cues_generated: int = Field(default=0, ge=0)
    temporal_issues: int = Field(default=0, ge=0)
    #: Providers whose results carried a partial view of the source's record.
    partial_provider_results: int = Field(default=0, ge=0)
    #: Local context datasets the provider itself reported as stale.
    stale_context_datasets: int = Field(default=0, ge=0)
    #: Extractors registered, and the ones that actually ran.
    qualifiers_available: tuple[str, ...] = ()
    qualifiers_used: tuple[str, ...] = ()
    #: Providers that answered but have no extractor. A blind spot, named.
    providers_without_qualifier: tuple[str, ...] = ()


class TemporalContextResult(FrozenTiReconModel):
    """One investigation, qualified in time and context at one explicit instant.

    ``evaluated_at`` is the ``as_of`` the caller supplied, not a wall-clock
    reading. Two runs over the same inputs at the same ``as_of`` produce the same
    result forever, which is what makes a stored qualification re-derivable and a
    disagreement between two runs mean something.
    """

    evaluated_at: UtcDatetime
    engine_version: str = Field(min_length=1, max_length=32)
    context_policy_version: str = Field(min_length=1, max_length=32)
    warninglist_map_version: str = Field(min_length=1, max_length=32)

    temporal_qualifications: tuple[TemporalQualification, ...] = ()
    context_signals: tuple[ContextSignal, ...] = ()
    interpretation_cues: tuple[InterpretationCue, ...] = ()
    temporal_issues: tuple[TemporalIssue, ...] = ()
    coverage: QualificationCoverage = QualificationCoverage()

    def signals_of(self, signal_type: ContextSignalType) -> tuple[ContextSignal, ...]:
        return tuple(item for item in self.context_signals if item.signal_type is signal_type)

    def cues_of(self, cue_type: InterpretationCueType) -> tuple[InterpretationCue, ...]:
        return tuple(item for item in self.interpretation_cues if item.cue_type is cue_type)

    def qualifications_for(self, subject_ref: str) -> tuple[TemporalQualification, ...]:
        return tuple(
            item for item in self.temporal_qualifications if item.fact.subject.ref == subject_ref
        )
