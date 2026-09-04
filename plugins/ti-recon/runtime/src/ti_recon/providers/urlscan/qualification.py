"""What a urlscan scan's time means (Task 15).

Everything urlscan returns is a **point-in-time browser observation**. A scan
says: at this instant, a browser loaded this URL and saw these things. That is
``SCANNED_AT``, with :attr:`SourceLifecycleState.POINT_IN_TIME` beside it,
because the two claims a scan time cannot support are the two everybody reaches
for — "it is still malicious" and "it is clean now". A phishing kit that cloaks
by geography, a compromised page that was cleaned an hour later and a redirect
chain that has since changed all produce the same scan record.

The scan time is emitted once per scan, from the scan-observation record, rather
than once per piece of evidence. Task 8 stamps every record with the same
``document.scanned_at``, and repeating it five times would inflate the fact count
without adding a fact.

``tls_valid_from`` is a different kind again: it describes the certificate's
validity window, not the visit and not the page. It is emitted as ``VALID_FROM``
so nothing can mistake a certificate's start date for evidence about when the
site was serving.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final

from ti_recon.models.evidence import Evidence
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.extraction import ProviderQualification, QualificationContext
from ti_recon.reasoning.models import (
    EvidenceRef,
    SourceLifecycleState,
    TemporalFact,
    TemporalFactKind,
)

__all__ = ["PAGE_CONTEXT_CLAIM_TYPE", "SCAN_CLAIM_TYPE", "qualify"]

SCAN_CLAIM_TYPE: Final[str] = "urlscan_scan_observation"
PAGE_CONTEXT_CLAIM_TYPE: Final[str] = "urlscan_page_context"


def qualify(
    envelope: ProviderResultEnvelope, context: QualificationContext
) -> ProviderQualification:
    facts: list[TemporalFact] = []
    for evidence in envelope.evidence:
        if evidence.claim_type == SCAN_CLAIM_TYPE:
            fact = _scan_fact(evidence, context)
            if fact is not None:
                facts.append(fact)
        elif evidence.claim_type == PAGE_CONTEXT_CLAIM_TYPE:
            fact = _certificate_fact(evidence, context)
            if fact is not None:
                facts.append(fact)
    return ProviderQualification(temporal_facts=tuple(facts))


def _scan_fact(evidence: Evidence, context: QualificationContext) -> TemporalFact | None:
    if evidence.observed_at is None:
        return None
    scan_id = evidence.attributes.get("scan_id")
    return TemporalFact(
        subject=context.subject_for(evidence.subject_object_id),
        kind=TemporalFactKind.SCANNED_AT,
        instant=evidence.observed_at,
        transport_provider=evidence.transport_provider,
        origin_provider=evidence.origin_provider,
        source_family=evidence.source_family,
        lineage_group_id=evidence.lineage_group_id,
        raw_field="task.time",
        # One visit, one instant. No claim about before or after it.
        lifecycle=SourceLifecycleState.POINT_IN_TIME,
        source_partial=context.source_partial,
        evidence=EvidenceRef.of(evidence),
        detail=f"scan_id={scan_id}"[:200] if isinstance(scan_id, str) else None,
    )


def _certificate_fact(evidence: Evidence, context: QualificationContext) -> TemporalFact | None:
    """The served certificate's start date, kept apart from the visit.

    A certificate valid from 2024 says nothing about the page having served
    anything continuously since 2024 — a certificate's window describes the
    certificate, and hosts change what they present.
    """
    raw = evidence.attributes.get("tls_valid_from")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        instant = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if instant.tzinfo is None:
        return None
    return TemporalFact(
        subject=context.subject_for(evidence.subject_object_id),
        kind=TemporalFactKind.VALID_FROM,
        instant=instant,
        transport_provider=evidence.transport_provider,
        origin_provider=evidence.origin_provider,
        source_family=evidence.source_family,
        lineage_group_id=evidence.lineage_group_id,
        raw_field="page.tlsValidFrom",
        source_partial=context.source_partial,
        evidence=EvidenceRef.of(evidence),
    )
