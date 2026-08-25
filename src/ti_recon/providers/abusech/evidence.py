"""Building abuse.ch evidence with honest provenance (Task 10).

Pure functions and small models, shared by the three adapters so that the
lineage rules are written once and cannot drift apart between them.

Two things live here that are easy to get wrong separately three times.

**Provenance defaults.** Every piece of evidence carries the platform as
transport *and* origin, and the abuse.ch family — but a per-platform lineage
group, so ThreatFox and URLhaus agreeing is visibly one ecosystem rather than
two witnesses. Callers do not pass these; they are the defaults, and overriding
them requires saying so.

**Relayed intelligence.** All three APIs repeat other people's findings, and the
temptation is to normalize each one into another malicious signal. That would
turn a single URLhaus response into "URLhaus says malicious, VirusTotal says
malicious, Spamhaus says malicious" — three votes from one request, two of them
belonging to sources TI Recon either already queries directly or has never
queried at all. :func:`relayed_summary` exists so the alternative is easy: one
bounded, direction-free record that says *which* third parties had something,
attributed to them rather than to abuse.ch.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from ti_recon.enums import EvidenceClass, EvidenceEffect, MatchScope
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.models.relationship import Relationship
from ti_recon.providers.abusech.family import (
    ABUSE_CH_SOURCE_FAMILY,
    lineage_group_for,
)
from ti_recon.providers.abusech.values import MAX_LABEL, string_list

__all__ = [
    "MAX_RELAYED_SOURCES",
    "AbuseChNormalization",
    "NormalizationContext",
    "build_evidence",
    "relayed_summary",
]

#: How many third-party source names one relayed summary may list. Bounded
#: because the list is provider-controlled and its value is qualitative: knowing
#: *that* a dozen vendors had something is the finding, not which twelve.
MAX_RELAYED_SOURCES: Final[int] = 20


@dataclass(frozen=True, slots=True)
class NormalizationContext:
    """Everything evidence needs that does not come from the response.

    ``now`` is passed in rather than read, so normalization stays a pure
    function and its timestamps are deterministic under test.

    ``match_scope`` says how precisely a claim applies to the observable that
    was submitted, and for these providers it does real work: a URLhaus host
    association is not the same claim as a URLhaus exact-URL match, and a
    ThreatFox ``ip:port`` record is about a service on an address rather than
    the address itself.
    """

    investigation_id: str
    subject_object_id: str
    now: datetime
    match_scope: MatchScope = MatchScope.EXACT_OBSERVABLE
    raw_reference_id: str | None = None

    def with_scope(self, match_scope: MatchScope) -> NormalizationContext:
        """The same context, narrowed to a different scope."""
        return NormalizationContext(
            investigation_id=self.investigation_id,
            subject_object_id=self.subject_object_id,
            now=self.now,
            match_scope=match_scope,
            raw_reference_id=self.raw_reference_id,
        )


class AbuseChNormalization(FrozenTiReconModel):
    """What one abuse.ch response normalized into.

    ``degraded`` means a block TI Recon recognizes was present but unreadable.
    The adapter turns that into a ``PARTIAL`` result: the evidence that *did*
    parse is still worth having.
    """

    evidence: tuple[Evidence, ...] = ()
    objects: tuple[IntelObject, ...] = ()
    relationships: tuple[Relationship, ...] = ()
    warnings: tuple[str, ...] = ()
    degraded: bool = False

    def merge(self, other: AbuseChNormalization) -> AbuseChNormalization:
        return AbuseChNormalization(
            evidence=self.evidence + other.evidence,
            objects=self.objects + other.objects,
            relationships=self.relationships + other.relationships,
            warnings=self.warnings + other.warnings,
            degraded=self.degraded or other.degraded,
        )


def build_evidence(
    context: NormalizationContext,
    *,
    provider_id: str,
    evidence_class: EvidenceClass,
    claim_type: str,
    effect: EvidenceEffect,
    attributes: dict[str, Any],
    observed_at: datetime | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    provider_confidence: float | None = None,
    origin_provider: str | None = None,
    source_family: str = ABUSE_CH_SOURCE_FAMILY,
    lineage_group_id: str | None = None,
) -> Evidence:
    """Build one piece of evidence with abuse.ch provenance.

    ``origin_provider`` and ``lineage_group_id`` default to the platform itself,
    which is right for everything it observed or curated. Relayed data overrides
    both — see :func:`relayed_summary`.

    ``provider_confidence`` is the provider's own number and nothing else.
    ThreatFox publishes a confidence level per IOC; recording it here keeps it
    where the model intends it to live, separate from the Admiralty grades TI
    Recon assigns and separate again from the confidence a future assessment
    layer computes. Those three are never collapsed, and an adapter sets exactly
    one of them.

    ``source_reliability`` and ``information_credibility`` are never set here:
    Admiralty grading is TI Recon policy, not a provider's to claim.
    """
    return Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=context.subject_object_id,
        evidence_class=evidence_class,
        claim_type=claim_type,
        effect=effect,
        transport_provider=provider_id,
        origin_provider=origin_provider or provider_id,
        source_family=source_family,
        provider_confidence=provider_confidence,
        match_scope=context.match_scope,
        observed_at=observed_at,
        first_seen=first_seen,
        last_seen=last_seen,
        retrieved_at=context.now,
        lineage_group_id=lineage_group_id or lineage_group_for(provider_id),
        attributes=attributes,
        raw_reference_id=context.raw_reference_id,
    )


def relayed_summary(
    context: NormalizationContext,
    *,
    provider_id: str,
    claim_type: str,
    origin_provider: str,
    source_family: str,
    sources: Sequence[str] = (),
    attributes: dict[str, Any] | None = None,
    observed_at: datetime | None = None,
) -> Evidence:
    """One bounded, direction-free record that a third party had something.

    This is the shape every relayed finding takes, and the constraints are the
    point rather than a limitation:

    * **It cannot carry a direction.** ``EvidenceClass.CONTEXT`` makes the model
      refuse one, so a relayed detection count can never become an extra
      malicious vote inside an abuse.ch response.
    * **It is attributed to whoever produced it.** ``origin_provider`` and
      ``source_family`` name the real source, so ``Evidence.is_relayed`` is true
      and a fusion layer can discount the overlap. A VirusTotal count repeated
      by URLhaus lands in the same family as a direct Google Threat Intelligence
      result, which is exactly what stops the two being counted twice.
    * **It summarizes rather than copies.** Source names and a few safe scalars,
      each bounded; never a nested vendor payload, never report text, never
      HTML. Task 10 is not a sandbox integration, and a relayed blob is how a
      future prompt-injection surface gets built by accident.
    """
    recorded: dict[str, Any] = {"relayed": True}
    names = string_list(list(sources), MAX_RELAYED_SOURCES, MAX_LABEL)
    if names:
        recorded["sources"] = names
        recorded["source_count"] = len(names)
    recorded.update(attributes or {})

    return build_evidence(
        context,
        provider_id=provider_id,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type=claim_type,
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=recorded,
        observed_at=observed_at,
        origin_provider=origin_provider,
        source_family=source_family,
        lineage_group_id=f"{source_family}:{origin_provider}",
    )
