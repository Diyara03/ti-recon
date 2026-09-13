"""What a warninglist match and a snapshot's age mean (Task 15).

Two separate things, and conflating them is the mistake this module is shaped
around.

A **match** is about a value. "This address is in ``public-dns-v4``" is a fact
about the address, at the scope the match was made — and a warninglist match is
never a verdict in either direction. Task 11 already refuses to call it benign;
Task 15 keeps that refusal by turning each matched list into a
:class:`ContextSignal` whose category comes from a *versioned TI Recon mapping*
keyed on the exact slug, never on the list's name or description. A list TI Recon
has no category for still produces ``WARNINGLIST_MATCH`` with its slug attached,
which is the honest answer rather than a guess.

The **snapshot** is about the dataset. ``snapshot_generated_at`` is when the
local corpus was built, not when any entry in it was observed, and it becomes
``SNAPSHOT_GENERATED_AT`` on a dataset-scoped subject so it can never be mistaken
for a fact about the observable. Task 11 has already decided whether that
snapshot is stale against its own configured threshold, and that decision is
carried through as :attr:`SourceLifecycleState.DATASET_STALE` rather than
re-derived here — the provider owns its own staleness policy.

Scope is the third thing this module protects. A URL whose *host* matched a
popular-domain list gets a signal marked ``host_component_only`` at ``SAME_HOST``
scope. ``https://github.com/attacker/payload.exe`` matching ``github`` is a fact
about GitHub, and a layer that let it speak for the URL would wave through every
living-off-trusted-sites payload there is.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final

from ti_recon.enums import MatchScope
from ti_recon.models.evidence import Evidence
from ti_recon.providers.misp_warninglists.candidates import CandidateComponent
from ti_recon.providers.misp_warninglists.normalizer import (
    COVERAGE_CLAIM_TYPE,
    MATCHES_CLAIM_TYPE,
)
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.extraction import ProviderQualification, QualificationContext
from ti_recon.reasoning.models import (
    ContextSignal,
    ContextSignalType,
    EvidenceRef,
    SignalOrigin,
    SourceLifecycleState,
    TemporalFact,
    TemporalFactKind,
    dataset_subject,
)
from ti_recon.reasoning.policy import signal_for_warninglist

__all__ = ["DATASET_ID", "qualify"]

#: The dataset a snapshot fact is about. One local corpus, named once.
DATASET_ID: Final[str] = "warninglists"


def qualify(
    envelope: ProviderResultEnvelope, context: QualificationContext
) -> ProviderQualification:
    facts: list[TemporalFact] = []
    signals: list[ContextSignal] = []
    for evidence in envelope.evidence:
        if evidence.claim_type == MATCHES_CLAIM_TYPE:
            signals.extend(_match_signals(evidence, context))
        elif evidence.claim_type == COVERAGE_CLAIM_TYPE:
            facts.extend(_snapshot_fact(evidence, context))
    return ProviderQualification(temporal_facts=tuple(facts), context_signals=tuple(signals))


def _match_signals(evidence: Evidence, context: QualificationContext) -> list[ContextSignal]:
    """One signal per matched list, at that list's own match scope."""
    matches = evidence.attributes.get("matches")
    if not isinstance(matches, list):
        return []
    subject = context.subject_for(evidence.subject_object_id)
    reference = EvidenceRef.of(evidence)

    found: list[ContextSignal] = []
    for entry in matches:
        if not isinstance(entry, dict):
            continue
        slug = entry.get("list")
        if not isinstance(slug, str) or not slug:
            continue
        scope = _scope(entry.get("match_scope"), evidence.match_scope)
        host_only = entry.get("candidate_component") == CandidateComponent.URL_HOST.value
        detail: dict[str, Any] = {"list": slug[:200]}
        matcher = entry.get("matcher")
        if isinstance(matcher, str) and matcher:
            detail["matcher"] = matcher[:200]
        # The list's name and the entry that matched make the signal
        # reportable and checkable: "Reserved IPv4 (rfc5735), matched
        # 192.0.2.0/24" (Task 24 Phase 3). Bounded like every detail value.
        name = entry.get("list_name")
        if isinstance(name, str) and name:
            detail["list_name"] = name[:200]
        matched = entry.get("matched_entry")
        if isinstance(matched, str) and matched:
            detail["matched_entry"] = matched[:200]

        found.append(
            ContextSignal(
                signal_type=signal_for_warninglist(slug),
                subject=subject,
                # The category is TI Recon's versioned judgement about a slug the
                # provider stated. The *match* is the provider's; the *meaning*
                # is ours, and saying so is what makes the mapping auditable.
                origin=SignalOrigin.ENGINE_POLICY,
                match_scope=scope,
                host_component_only=host_only,
                transport_provider=evidence.transport_provider,
                origin_provider=evidence.origin_provider,
                source_family=evidence.source_family,
                lineage_group_id=evidence.lineage_group_id,
                evidence=reference,
                source_key=slug,
                source_partial=context.source_partial,
                detail=detail,
            )
        )
        if host_only:
            found.append(
                ContextSignal(
                    signal_type=ContextSignalType.HOST_COMPONENT_CONTEXT,
                    subject=subject,
                    origin=SignalOrigin.PROVIDER_REPORTED,
                    match_scope=scope,
                    host_component_only=True,
                    transport_provider=evidence.transport_provider,
                    origin_provider=evidence.origin_provider,
                    source_family=evidence.source_family,
                    lineage_group_id=evidence.lineage_group_id,
                    evidence=reference,
                    source_key=slug,
                    source_partial=context.source_partial,
                    detail=detail,
                )
            )
    return found


def _snapshot_fact(evidence: Evidence, context: QualificationContext) -> list[TemporalFact]:
    """When the local corpus was built, and whether the provider calls it stale."""
    raw = evidence.attributes.get("snapshot_generated_at")
    if not isinstance(raw, str) or not raw:
        return []
    try:
        instant = datetime.fromisoformat(raw)
    except ValueError:
        return []
    if instant.tzinfo is None:
        return []

    stale = evidence.attributes.get("snapshot_stale") is True
    commit = evidence.attributes.get("dataset_commit")
    return [
        TemporalFact(
            subject=dataset_subject(evidence.transport_provider, DATASET_ID),
            kind=TemporalFactKind.SNAPSHOT_GENERATED_AT,
            instant=instant,
            transport_provider=evidence.transport_provider,
            origin_provider=evidence.origin_provider,
            source_family=evidence.source_family,
            lineage_group_id=evidence.lineage_group_id,
            raw_field="snapshot_generated_at",
            # Task 11 decides staleness against its own threshold. Re-deriving it
            # here would be Task 15 inventing a freshness rule for somebody
            # else's dataset.
            lifecycle=(
                SourceLifecycleState.DATASET_STALE
                if stale
                else SourceLifecycleState.DATASET_CURRENT
            ),
            source_partial=context.source_partial,
            evidence=EvidenceRef.of(evidence),
            detail=f"commit={commit[:32]}" if isinstance(commit, str) else None,
        )
    ]


def _scope(raw: Any, fallback: MatchScope) -> MatchScope:
    if isinstance(raw, str):
        try:
            return MatchScope(raw)
        except ValueError:
            return fallback
    return fallback
