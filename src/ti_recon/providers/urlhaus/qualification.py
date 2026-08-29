"""What URLhaus's records mean in time (Task 15).

URLhaus is the clearest case in the whole platform of a source that knows
something about *now*, and of why that must never be allowed to rewrite what it
knew about *then*.

Its ``url_status`` is explicit and three-valued: ``online`` (the URL is serving),
``offline`` (it is not), ``unknown`` (URLhaus could not tell). Those map onto
:class:`SourceLifecycleState` directly, because they are the source's own
statement about its own record — exactly the kind of lifecycle TI Recon will
carry and never invent.

The temptation this module exists to refuse is "offline, therefore harmless". A
URL that distributed malware in March and stopped in April distributed malware.
The evidence keeps its ``SUPPORTS_MALICIOUS`` effect untouched; what Task 15 adds
beside it is the current state, the last time it was confirmed serving, and a cue
saying the two are different facts.

The two instants are also different in kind. ``date_added`` is when the *dataset*
took the record — platform housekeeping — while ``last_online`` is a real
observation of the URL serving. Collapsing them into one "last seen" would make a
long-dead URL look recently active every time URLhaus re-imported it.
"""

from __future__ import annotations

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

__all__ = ["URL_STATUS_LIFECYCLE", "qualify"]

#: URLhaus's own status vocabulary, mapped to source-stated lifecycle.
#:
#: Nothing here maps to a benign or safe state, because URLhaus has no such
#: status and TI Recon must not manufacture one. ``offline`` says a URL stopped
#: serving; it says nothing about whether it was ever harmless.
URL_STATUS_LIFECYCLE: Final[dict[str, SourceLifecycleState]] = {
    "online": SourceLifecycleState.ACTIVE_BY_SOURCE,
    "offline": SourceLifecycleState.INACTIVE_BY_SOURCE,
    "unknown": SourceLifecycleState.STATUS_UNKNOWN,
}

#: Claim types whose ``first_seen`` is a dataset-addition time rather than an
#: observation. URLhaus records when *it* took a URL, not when the URL began.
_DATASET_CLAIMS: Final[frozenset[str]] = frozenset(
    {"urlhaus_malware_url", "urlhaus_host_malware_association"}
)


def qualify(
    envelope: ProviderResultEnvelope, context: QualificationContext
) -> ProviderQualification:
    facts: list[TemporalFact] = []
    for evidence in envelope.evidence:
        if evidence.claim_type in _DATASET_CLAIMS:
            facts.extend(_url_record_facts(evidence, context))
        elif evidence.claim_type == "urlhaus_payload_record":
            facts.extend(_payload_facts(evidence, context))
    return ProviderQualification(temporal_facts=tuple(facts))


def _url_record_facts(evidence: Evidence, context: QualificationContext) -> list[TemporalFact]:
    subject = context.subject_for(evidence.subject_object_id)
    reference = EvidenceRef.of(evidence)
    status = evidence.attributes.get("url_status")
    lifecycle = (
        URL_STATUS_LIFECYCLE.get(status.strip().lower()) if isinstance(status, str) else None
    )
    detail = None if not isinstance(status, str) else f"url_status={status.strip().lower()}"[:200]

    found: list[TemporalFact] = []
    if evidence.first_seen is not None:
        found.append(
            TemporalFact(
                subject=subject,
                kind=TemporalFactKind.ADDED_TO_DATASET_AT,
                instant=evidence.first_seen,
                transport_provider=evidence.transport_provider,
                origin_provider=evidence.origin_provider,
                source_family=evidence.source_family,
                lineage_group_id=evidence.lineage_group_id,
                raw_field="date_added",
                lifecycle=lifecycle,
                source_partial=context.source_partial,
                evidence=reference,
                detail=detail,
            )
        )
    if evidence.last_seen is not None:
        found.append(
            TemporalFact(
                subject=subject,
                kind=TemporalFactKind.LAST_ONLINE_AT,
                instant=evidence.last_seen,
                transport_provider=evidence.transport_provider,
                origin_provider=evidence.origin_provider,
                source_family=evidence.source_family,
                lineage_group_id=evidence.lineage_group_id,
                raw_field="last_online",
                lifecycle=lifecycle,
                source_partial=context.source_partial,
                evidence=reference,
                detail=detail,
            )
        )
    if not found and lifecycle is not None and evidence.observed_at is not None:
        # A record with a status and one usable instant still deserves to carry
        # the status somewhere a later layer will look.
        found.append(
            TemporalFact(
                subject=subject,
                kind=TemporalFactKind.ADDED_TO_DATASET_AT,
                instant=evidence.observed_at,
                transport_provider=evidence.transport_provider,
                origin_provider=evidence.origin_provider,
                source_family=evidence.source_family,
                lineage_group_id=evidence.lineage_group_id,
                raw_field="date_added",
                lifecycle=lifecycle,
                source_partial=context.source_partial,
                evidence=reference,
                detail=detail,
            )
        )
    return found


def _payload_facts(evidence: Evidence, context: QualificationContext) -> list[TemporalFact]:
    """When URLhaus first and last saw a tracked URL serving this file.

    Provenance rather than direction, matching how Task 10 already classifies the
    record: a URL that once served an installer and now serves an error page also
    produces one of these.
    """
    subject = context.subject_for(evidence.subject_object_id)
    reference = EvidenceRef.of(evidence)
    found: list[TemporalFact] = []
    for kind, instant, raw in (
        (TemporalFactKind.FIRST_OBSERVED, evidence.first_seen, "firstseen"),
        (TemporalFactKind.LAST_OBSERVED, evidence.last_seen, "lastseen"),
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
            )
        )
    return found
