"""Turning facts and signals into named cautions (Task 15).

Every rule here reads structured input — an enum member, a boolean, a lifecycle
state — and never text. Nothing greps a description, a provider name, a tag or a
warninglist title. That is not fastidiousness: a rule keyed on ``"scanner" in
name`` would reclassify a list the day upstream reworded it, and provider-authored
text is attacker-influenced in several places already. A string that says "ignore
previous instructions" is inert data here, because no string is ever consulted.

What a cue is
-------------

A caution, addressed to whoever eventually weighs the evidence. Not a verdict,
not a confidence, not a weight and not a recommended action. "This malicious URL
is reported offline" is a cue; "therefore it is a false positive" is a
conclusion, and Task 15 does not draw conclusions.

What does not happen here
-------------------------

Context does not propagate. There is exactly one edge-scoped rule — a contact
with a public resolver — and it reads **one** edge and stops. There is no walk,
no closure and no inheritance: a file that contacted a domain that resolves to a
CDN does not acquire CDN context, because a chain of ordinary-looking links is
precisely how an unremarkable-looking conclusion gets built out of nothing.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any, Final

from ti_recon.correlation.graph import InvestigationGraph
from ti_recon.enums import EvidenceEffect, MatchScope, RelationshipType
from ti_recon.reasoning.models import (
    ContextSignal,
    ContextSignalType,
    CuePurpose,
    InterpretationCue,
    InterpretationCueType,
    SourceLifecycleState,
    TemporalFact,
    edge_subject,
)

__all__ = ["LIFECYCLE_CUES", "SIGNAL_CUES", "build_cues"]

#: Signal type -> the cue it raises and why. One deterministic rule each.
#:
#: Written as data so the whole vocabulary is readable in one place, and so a
#: test can assert that every cue this package can emit has a rule behind it.
SIGNAL_CUES: Final[dict[ContextSignalType, tuple[InterpretationCueType, CuePurpose]]] = {
    ContextSignalType.KNOWN_SCANNER: (
        InterpretationCueType.KNOWN_SCANNER_MAY_EXPLAIN_ACTIVITY,
        CuePurpose.FALSE_POSITIVE_CONTEXT,
    ),
    ContextSignalType.BUSINESS_SERVICE: (
        InterpretationCueType.BUSINESS_SERVICE_MAY_EXPLAIN_ACTIVITY,
        CuePurpose.FALSE_POSITIVE_CONTEXT,
    ),
    ContextSignalType.SHARED_CLOUD_OR_CDN: (
        InterpretationCueType.SHARED_INFRASTRUCTURE_ATTRIBUTION_CAUTION,
        CuePurpose.ATTRIBUTION_CAUTION,
    ),
    ContextSignalType.POPULAR_OR_COMMON_SERVICE: (
        InterpretationCueType.SHARED_INFRASTRUCTURE_ATTRIBUTION_CAUTION,
        CuePurpose.ATTRIBUTION_CAUTION,
    ),
    ContextSignalType.COMPROMISED_INFRASTRUCTURE: (
        InterpretationCueType.COMPROMISED_INFRASTRUCTURE_ATTRIBUTION_CAUTION,
        CuePurpose.ATTRIBUTION_CAUTION,
    ),
    ContextSignalType.TEST_ARTIFACT: (
        InterpretationCueType.TEST_ARTIFACT_CONTEXT,
        CuePurpose.FALSE_POSITIVE_CONTEXT,
    ),
    ContextSignalType.EMPTY_ARTIFACT: (
        InterpretationCueType.EMPTY_ARTIFACT_CONTEXT,
        CuePurpose.FALSE_POSITIVE_CONTEXT,
    ),
    ContextSignalType.HOST_COMPONENT_CONTEXT: (
        InterpretationCueType.HOST_CONTEXT_DOES_NOT_CLEAR_EXACT_URL,
        CuePurpose.SCOPE_CAUTION,
    ),
    ContextSignalType.SANDBOX_LOW_EXECUTION: (
        InterpretationCueType.SANDBOX_NEGATIVE_LOW_INFORMATION,
        CuePurpose.NEGATIVE_EVIDENCE_LIMITATION,
    ),
    ContextSignalType.SANDBOX_MEANINGFUL_EXECUTION: (
        InterpretationCueType.SANDBOX_NEGATIVE_WITH_MEANINGFUL_EXECUTION,
        CuePurpose.NEGATIVE_EVIDENCE_LIMITATION,
    ),
    ContextSignalType.SANDBOX_DIVERGENCE: (
        InterpretationCueType.SANDBOX_ENVIRONMENT_DIVERGENCE,
        CuePurpose.ANALYSIS_QUALITY,
    ),
    ContextSignalType.RELAYED_SOURCE: (
        InterpretationCueType.RELAYED_SOURCE_NOT_INDEPENDENT,
        CuePurpose.SOURCE_DEPENDENCE,
    ),
}

#: Source-stated lifecycle -> the temporal caution it raises.
LIFECYCLE_CUES: Final[dict[SourceLifecycleState, tuple[InterpretationCueType, CuePurpose]]] = {
    SourceLifecycleState.WITHIN_SOURCE_API_HORIZON: (
        InterpretationCueType.SOURCE_MANAGED_LIFECYCLE,
        CuePurpose.TEMPORAL_CAUTION,
    ),
    SourceLifecycleState.DATASET_STALE: (
        InterpretationCueType.STALE_CONTEXT_DATASET,
        CuePurpose.TEMPORAL_CAUTION,
    ),
}

#: Relationship types whose target being common infrastructure has an ordinary
#: explanation. Narrow on purpose: a sample *contacting* a resolver is routine,
#: while a URL *redirecting to* one would not be, and would deserve a look.
_CONTACT_TYPES: Final[frozenset[RelationshipType]] = frozenset({RelationshipType.CONTACTS})

#: Signals that make a contacted endpoint ordinary rather than interesting.
_COMMON_ENDPOINT_SIGNALS: Final[frozenset[ContextSignalType]] = frozenset(
    {ContextSignalType.PUBLIC_RESOLVER}
)


def build_cues(
    *,
    facts: Sequence[TemporalFact],
    signals: Sequence[ContextSignal],
    graph: InvestigationGraph | None = None,
) -> tuple[InterpretationCue, ...]:
    """Every cue the rules produce, deduplicated and deterministically ordered."""
    found: list[InterpretationCue] = []
    found.extend(_signal_cues(signals))
    found.extend(_lifecycle_cues(facts))
    found.extend(_inactive_malicious_cues(facts))
    if graph is not None:
        found.extend(_common_endpoint_cues(signals, graph))
    return _deduplicate(found)


def _signal_cues(signals: Iterable[ContextSignal]) -> list[InterpretationCue]:
    found: list[InterpretationCue] = []
    for signal in signals:
        mapped = SIGNAL_CUES.get(signal.signal_type)
        if mapped is None:
            # An uncategorized warninglist match is real information and no
            # caution in particular. Manufacturing one would be noise.
            continue
        cue_type, purpose = mapped
        detail: dict[str, Any] = {}
        if signal.source_key is not None:
            detail["source_key"] = signal.source_key[:200]
        if signal.host_component_only:
            detail["host_component_only"] = True
        if signal.signal_type is ContextSignalType.RELAYED_SOURCE:
            duplicated = signal.detail.get("direct_family_present")
            if isinstance(duplicated, bool):
                detail["direct_family_present"] = duplicated
        found.append(
            InterpretationCue(
                cue_type=cue_type,
                purpose=purpose,
                subject=signal.subject,
                match_scope=signal.match_scope,
                context_signal_refs=(signal.ref,),
                evidence_ids=(
                    (signal.evidence.evidence_id,) if signal.evidence is not None else ()
                ),
                detail=detail,
            )
        )
    return found


def _lifecycle_cues(facts: Iterable[TemporalFact]) -> list[InterpretationCue]:
    found: list[InterpretationCue] = []
    for fact in facts:
        if fact.lifecycle is None:
            continue
        mapped = LIFECYCLE_CUES.get(fact.lifecycle)
        if mapped is None:
            continue
        cue_type, purpose = mapped
        detail: dict[str, Any] = {"lifecycle": fact.lifecycle.value}
        if fact.detail is not None:
            detail["source_detail"] = fact.detail[:200]
        found.append(
            InterpretationCue(
                cue_type=cue_type,
                purpose=purpose,
                subject=fact.subject,
                match_scope=(
                    fact.evidence.match_scope if fact.evidence is not None else MatchScope.UNKNOWN
                ),
                temporal_fact_refs=(fact.ref,),
                evidence_ids=(fact.evidence.evidence_id,) if fact.evidence is not None else (),
                detail=detail,
            )
        )
    return found


def _inactive_malicious_cues(facts: Iterable[TemporalFact]) -> list[InterpretationCue]:
    """A directional finding whose source says the artifact is no longer serving.

    The cue that stops "offline" becoming "harmless". The evidence keeps its
    effect untouched — this reads it and never writes it — and what the cue adds
    is that the source's *current* state and its *historical* claim are two
    different facts that a fusion layer must handle separately.
    """
    found: list[InterpretationCue] = []
    for fact in facts:
        if fact.lifecycle is not SourceLifecycleState.INACTIVE_BY_SOURCE:
            continue
        if fact.evidence is None or fact.evidence.effect is not EvidenceEffect.SUPPORTS_MALICIOUS:
            continue
        found.append(
            InterpretationCue(
                cue_type=InterpretationCueType.HISTORICAL_MALICIOUS_CURRENTLY_INACTIVE,
                purpose=CuePurpose.TEMPORAL_CAUTION,
                subject=fact.subject,
                match_scope=fact.evidence.match_scope,
                temporal_fact_refs=(fact.ref,),
                evidence_ids=(fact.evidence.evidence_id,),
                detail={
                    "lifecycle": fact.lifecycle.value,
                    "last_instant_kind": fact.kind.value,
                    "source_family": (fact.source_family or "")[:200],
                },
            )
        )
    return found


def _common_endpoint_cues(
    signals: Sequence[ContextSignal], graph: InvestigationGraph
) -> list[InterpretationCue]:
    """A contact with common infrastructure may have an ordinary explanation.

    The one edge-scoped rule in Task 15, and deliberately the narrowest thing that
    could be useful: for each node carrying a public-resolver signal, each
    *directly incident* ``contacts`` edge gets a cue. One edge. No traversal, no
    second hop, and nothing added to or removed from the graph.

    What the cue does not say is as important as what it does. The relationship
    stays exactly as the sandbox observed it, the resolver does not become
    malicious for having been contacted, and the sample does not become benign
    for having contacted something ordinary.
    """
    keyed = {
        signal.subject.key: signal
        for signal in signals
        if signal.signal_type in _COMMON_ENDPOINT_SIGNALS
    }
    if not keyed:
        return []

    found: list[InterpretationCue] = []
    for node_key, signal in sorted(keyed.items()):
        if graph.node(node_key) is None:
            continue
        for edge in graph.incident_edges(node_key):
            if edge.relationship_type not in _CONTACT_TYPES or edge.target_key != node_key:
                continue
            found.append(
                InterpretationCue(
                    cue_type=InterpretationCueType.PUBLIC_SERVICE_MAY_EXPLAIN_CONTACT,
                    purpose=CuePurpose.FALSE_POSITIVE_CONTEXT,
                    subject=edge_subject(
                        edge.source_key, edge.relationship_type.value, edge.target_key
                    ),
                    match_scope=signal.match_scope,
                    context_signal_refs=(signal.ref,),
                    detail={
                        "endpoint_context": signal.signal_type.value,
                        "endpoint_node_key": node_key[:200],
                        # Observation basis is provenance, not significance: a
                        # watched connection is a better-grounded link, and still
                        # not an accusation against either endpoint.
                        "observation_bases": len({item.basis.value for item in edge.assertions}),
                    },
                )
            )
    return found


def _deduplicate(cues: Iterable[InterpretationCue]) -> tuple[InterpretationCue, ...]:
    """One caution per subject, merging the refs that justified it.

    Five cloud-range lists matching one address is one attribution caution with
    five signals behind it, not five cautions. Merging keeps the derivation
    complete without letting a well-covered value look like a pile of findings.
    """
    merged: dict[tuple[str, str, str], InterpretationCue] = {}
    for cue in cues:
        existing = merged.get(cue.key)
        if existing is None:
            merged[cue.key] = cue
            continue
        merged[cue.key] = existing.model_copy(
            update={
                "temporal_fact_refs": _union(existing.temporal_fact_refs, cue.temporal_fact_refs),
                "context_signal_refs": _union(
                    existing.context_signal_refs, cue.context_signal_refs
                ),
                "evidence_ids": _union(existing.evidence_ids, cue.evidence_ids),
            }
        )
    return tuple(merged[key] for key in sorted(merged))


def _union(left: tuple[str, ...], right: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(left) | set(right)))
