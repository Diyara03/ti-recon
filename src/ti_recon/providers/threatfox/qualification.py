"""What ThreatFox's records mean in time (Task 15).

ThreatFox states two things about time and one about the platform, and the third
is the one everybody gets wrong.

``first_seen`` and ``last_seen`` are genuine observation times: when the
indicator was first and last seen being used. They become ``FIRST_OBSERVED`` and
``LAST_OBSERVED``.

The third is the **API horizon**. ThreatFox expires indicators from its API after
roughly six months — deliberately, to limit false positives on infrastructure
that changes hands, cloud addresses above all. So a record coming back means
"unexpired and present", which is a much weaker statement than "this
infrastructure is live". That is
:attr:`SourceLifecycleState.WITHIN_SOURCE_API_HORIZON`, and there is deliberately
no ``ACTIVE_NOW`` for it to be mistaken for.

The inverse is equally important and is why this module emits nothing at all for
an absence. "ThreatFox has no current record" is compatible with never having
been listed, with having been listed and expired, and with an indicator reported
an hour ago that has not propagated. Manufacturing an "expired" lifecycle out of
a miss would turn a coverage horizon into a claim about the world.
"""

from __future__ import annotations

from typing import Final

from ti_recon.models.evidence import Evidence
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
)

__all__ = ["DIRECTIONAL_CLAIM_TYPES", "HORIZON_ATTRIBUTE", "qualify"]

#: The claim types that carry ThreatFox's own observation times.
DIRECTIONAL_CLAIM_TYPES: Final[frozenset[str]] = frozenset(
    {"threatfox_ioc", "threatfox_hash_association"}
)

#: Where Task 10 publishes the API horizon. It sits on the coverage record rather
#: than on the finding, because it bounds what a *miss* covers as much as what a
#: hit means — so it is read once per result and applied to every fact.
HORIZON_ATTRIBUTE: Final[str] = "expiration_horizon_months"


def qualify(
    envelope: ProviderResultEnvelope, context: QualificationContext
) -> ProviderQualification:
    horizon = _horizon_months(envelope)
    facts: list[TemporalFact] = []
    signals: list[ContextSignal] = []
    for evidence in envelope.evidence:
        if evidence.claim_type not in DIRECTIONAL_CLAIM_TYPES:
            continue
        facts.extend(_observation_facts(evidence, context, horizon))
        signals.extend(_compromised_signal(evidence, context))
    return ProviderQualification(temporal_facts=tuple(facts), context_signals=tuple(signals))


def _observation_facts(
    evidence: Evidence, context: QualificationContext, horizon: int | None
) -> list[TemporalFact]:
    """ThreatFox's first/last seen, both inside its six-month API horizon."""
    subject = context.subject_for(evidence.subject_object_id)
    reference = EvidenceRef.of(evidence)
    detail = None if horizon is None else f"api_horizon_months={horizon}"

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
                # Present in the API, and nothing more. The record being
                # returned proves it has not expired, not that anything is live.
                lifecycle=SourceLifecycleState.WITHIN_SOURCE_API_HORIZON,
                source_partial=context.source_partial,
                evidence=reference,
                detail=detail,
            )
        )
    return found


def _compromised_signal(evidence: Evidence, context: QualificationContext) -> list[ContextSignal]:
    """``is_compromised`` — a fact about the victim, not about the indicator.

    ThreatFox saying the infrastructure is compromised legitimate hosting changes
    who owns the machine and what blocking it costs. It changes nothing about the
    evidence: a compromised host serving a payload is serving a payload.
    """
    if evidence.attributes.get("is_compromised") is not True:
        return []
    return [
        ContextSignal(
            signal_type=ContextSignalType.COMPROMISED_INFRASTRUCTURE,
            subject=context.subject_for(evidence.subject_object_id),
            origin=SignalOrigin.PROVIDER_REPORTED,
            match_scope=evidence.match_scope,
            transport_provider=evidence.transport_provider,
            origin_provider=evidence.origin_provider,
            source_family=evidence.source_family,
            lineage_group_id=evidence.lineage_group_id,
            evidence=EvidenceRef.of(evidence),
            source_key="is_compromised",
            source_partial=context.source_partial,
        )
    ]


def _horizon_months(envelope: ProviderResultEnvelope) -> int | None:
    """The horizon ThreatFox stated on this result, if it stated one."""
    for evidence in envelope.evidence:
        value = evidence.attributes.get(HORIZON_ATTRIBUTE)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None
