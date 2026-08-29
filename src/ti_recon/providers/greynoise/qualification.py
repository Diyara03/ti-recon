"""What GreyNoise's timestamps and Business Services Intelligence mean (Task 15).

Two things, and the second is the one that carries risk.

**Times.** GreyNoise's ``first_seen`` and ``last_seen`` are genuine observation
times: when its sensor fleet first and last saw this address doing something.
They become ``FIRST_OBSERVED`` and ``LAST_OBSERVED``, and only where GreyNoise
actually supplied them — an address that has never touched a sensor has no times,
and inventing any would turn "we have never seen it" into "we saw it".

The Business Services record's ``last_updated`` is different in kind and is
mapped differently. It is when GreyNoise last touched *its own record*, which is
housekeeping, not activity. ``SOURCE_RECORD_UPDATED_AT`` keeps it from being read
as a sighting.

**Business Services Intelligence.** BSI identifies common business-service
infrastructure — the successor to what used to be called RIOT. It is emphatically
**not a safe list and not an allow list**, and GreyNoise says so itself: a
Microsoft or Google range is common business infrastructure *and* a place attacks
come from, and BSI has no opinion about which. So it produces
:attr:`ContextSignalType.BUSINESS_SERVICE` and there is deliberately no signal
type it could produce that means safe, trusted or benign. Where another provider
has a directional finding about the same address, both survive: nothing here
cancels evidence.

The trust level GreyNoise assigns is carried as its own structured value and is
never turned into a TI Recon confidence. It is the provider's number, on the
provider's scale, and translating it would be inventing an engine judgement.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final

from ti_recon.models.evidence import Evidence
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.extraction import ProviderQualification, QualificationContext
from ti_recon.reasoning.models import (
    ContextSignal,
    ContextSignalType,
    EvidenceRef,
    SignalOrigin,
    TemporalFact,
    TemporalFactKind,
)

__all__ = ["BUSINESS_SERVICE_CLAIM_TYPE", "OBSERVATION_CLAIM_TYPES", "qualify"]

BUSINESS_SERVICE_CLAIM_TYPE: Final[str] = "greynoise_business_service"

#: Claim types whose first/last seen are sensor observations of the address.
#:
#: ``greynoise_not_observed`` is absent on purpose: it is the record that says
#: nothing was seen, and it carries no times to read.
OBSERVATION_CLAIM_TYPES: Final[frozenset[str]] = frozenset(
    {"greynoise_classification", "greynoise_scanner_observation"}
)


def qualify(
    envelope: ProviderResultEnvelope, context: QualificationContext
) -> ProviderQualification:
    facts: list[TemporalFact] = []
    signals: list[ContextSignal] = []
    for evidence in envelope.evidence:
        if evidence.claim_type in OBSERVATION_CLAIM_TYPES:
            facts.extend(_observation_facts(evidence, context))
        elif evidence.claim_type == BUSINESS_SERVICE_CLAIM_TYPE:
            facts.extend(_record_update_fact(evidence, context))
            signals.extend(_business_service_signal(evidence, context))
    return ProviderQualification(temporal_facts=tuple(facts), context_signals=tuple(signals))


def _observation_facts(evidence: Evidence, context: QualificationContext) -> list[TemporalFact]:
    subject = context.subject_for(evidence.subject_object_id)
    reference = EvidenceRef.of(evidence)
    found: list[TemporalFact] = []
    for kind, instant, raw in (
        (TemporalFactKind.FIRST_OBSERVED, evidence.first_seen, "first_seen"),
        (TemporalFactKind.LAST_OBSERVED, evidence.last_seen, "last_seen"),
    ):
        if instant is None:
            continue
        found.append(
            TemporalFact(
                subject=subject,
                kind=kind,
                instant=instant,
                transport_provider=evidence.transport_provider,
                origin_provider=evidence.origin_provider,
                source_family=evidence.source_family,
                lineage_group_id=evidence.lineage_group_id,
                raw_field=raw,
                source_partial=context.source_partial,
                evidence=reference,
                detail=f"claim={evidence.claim_type}"[:200],
            )
        )
    return found


def _record_update_fact(evidence: Evidence, context: QualificationContext) -> list[TemporalFact]:
    raw = evidence.attributes.get("last_updated")
    if not isinstance(raw, str) or not raw:
        return []
    try:
        instant = datetime.fromisoformat(raw)
    except ValueError:
        return []
    if instant.tzinfo is None:
        return []
    return [
        TemporalFact(
            subject=context.subject_for(evidence.subject_object_id),
            kind=TemporalFactKind.SOURCE_RECORD_UPDATED_AT,
            instant=instant,
            transport_provider=evidence.transport_provider,
            origin_provider=evidence.origin_provider,
            source_family=evidence.source_family,
            lineage_group_id=evidence.lineage_group_id,
            raw_field="business_service_intelligence.last_updated",
            source_partial=context.source_partial,
            evidence=EvidenceRef.of(evidence),
        )
    ]


def _business_service_signal(
    evidence: Evidence, context: QualificationContext
) -> list[ContextSignal]:
    if evidence.attributes.get("found") is not True:
        return []
    detail: dict[str, object] = {}
    for name in ("category", "trust_level"):
        value = evidence.attributes.get(name)
        if isinstance(value, str) and value:
            detail[name] = value[:200]
    return [
        ContextSignal(
            signal_type=ContextSignalType.BUSINESS_SERVICE,
            subject=context.subject_for(evidence.subject_object_id),
            origin=SignalOrigin.PROVIDER_REPORTED,
            match_scope=evidence.match_scope,
            transport_provider=evidence.transport_provider,
            origin_provider=evidence.origin_provider,
            source_family=evidence.source_family,
            lineage_group_id=evidence.lineage_group_id,
            evidence=EvidenceRef.of(evidence),
            source_key="business_service_intelligence",
            source_partial=context.source_partial,
            detail=detail,
        )
    ]
