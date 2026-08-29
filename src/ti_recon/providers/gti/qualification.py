"""What Google Threat Intelligence's timestamps mean (Task 15).

This module exists mostly for one distinction, and it is the distinction Task 15
was written to enforce.

``last_analysis_date`` is **when VirusTotal last analyzed the object**. It is a
scan time. It is not when the object was last observed doing anything, it is not
when a campaign was last active, and it is not a "last seen". A file uploaded in
2019 and rescanned this morning has a ``last_analysis_date`` of this morning and
has been nowhere near anybody since 2019.

Task 7 stores that instant in ``Evidence.last_seen``, because that is the field
the Task 3 model has for a claim's most recent instant, and Task 15 does not go
back and change it. What it does instead is refuse to read it generically: this
module knows which GTI claim types carry which *provider field*, and maps
``last_analysis_date`` to :attr:`TemporalFactKind.ANALYZED_AT` regardless of
which model field it happens to sit in. A generic evaluator reading ``last_seen``
off every provider would produce exactly the wrong answer here, which is why no
generic evaluator is allowed to read it at all.

The submission times are separate again. ``first_submission_date`` and
``last_submission_date`` say when somebody *gave* the object to VirusTotal. Three
different questions, three different kinds, none of them interchangeable.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final

from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.gti.descriptor import (
    GTI_ORIGIN_PROVIDER,
    GTI_PROVIDER_ID,
    GTI_SOURCE_FAMILY,
)
from ti_recon.providers.gti.normalizer import GTI_LINEAGE_GROUP, GTI_PROPERTY_NAMESPACE
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.extraction import ProviderQualification, QualificationContext
from ti_recon.reasoning.models import (
    EvidenceRef,
    SubjectRef,
    TemporalFact,
    TemporalFactKind,
    observable_subject,
)

__all__ = ["EVIDENCE_TIME_SEMANTICS", "OBJECT_TIME_SEMANTICS", "qualify"]

#: Per claim type, what each Task 3 time field on that evidence actually holds.
#:
#: The table is the whole point: a mapping from ``(claim type, model field)`` to
#: ``(kind, provider field name)``. Written out rather than inferred, so a wrong
#: mapping is a visible line of code instead of an invisible assumption, and the
#: provider's own field name travels onto every fact for anyone who wants to
#: argue with the judgement.
EVIDENCE_TIME_SEMANTICS: Final[dict[str, dict[str, tuple[TemporalFactKind, str]]]] = {
    "gti_assessment": {
        "last_seen": (TemporalFactKind.ANALYZED_AT, "last_analysis_date"),
    },
    "gti_analysis_stats": {
        "first_seen": (TemporalFactKind.FIRST_SUBMITTED, "first_submission_date"),
        "last_seen": (TemporalFactKind.ANALYZED_AT, "last_analysis_date"),
    },
    "gti_threat_severity": {
        "last_seen": (TemporalFactKind.ANALYZED_AT, "last_analysis_date"),
    },
}

#: GTI attributes Task 7 already keeps on the enriched object, as ISO-8601 UTC.
#:
#: Read here because they are the only place ``last_submission_date`` survives
#: normalization — no new request, no new endpoint, nothing added to the adapter.
OBJECT_TIME_SEMANTICS: Final[dict[str, TemporalFactKind]] = {
    "first_submission_date": TemporalFactKind.FIRST_SUBMITTED,
    "last_submission_date": TemporalFactKind.LAST_SUBMITTED,
    "last_analysis_date": TemporalFactKind.ANALYZED_AT,
}


def qualify(
    envelope: ProviderResultEnvelope, context: QualificationContext
) -> ProviderQualification:
    facts: list[TemporalFact] = []
    for evidence in envelope.evidence:
        semantics = EVIDENCE_TIME_SEMANTICS.get(evidence.claim_type)
        if semantics is None:
            continue
        subject = context.subject_for(evidence.subject_object_id)
        reference = EvidenceRef.of(evidence)
        for field_name, (kind, raw_field) in sorted(semantics.items()):
            instant = getattr(evidence, field_name, None)
            if not isinstance(instant, datetime):
                continue
            facts.append(
                TemporalFact(
                    subject=subject,
                    kind=kind,
                    instant=instant,
                    transport_provider=evidence.transport_provider,
                    origin_provider=evidence.origin_provider,
                    source_family=evidence.source_family,
                    lineage_group_id=evidence.lineage_group_id,
                    raw_field=raw_field,
                    source_partial=context.source_partial,
                    evidence=reference,
                )
            )

    for item in envelope.objects:
        facts.extend(_object_facts(item, context))
    return ProviderQualification(temporal_facts=tuple(facts))


def _object_facts(item: IntelObject, context: QualificationContext) -> list[TemporalFact]:
    """Submission and analysis times Task 7 attached to the enriched object."""
    namespace = item.properties.get(GTI_PROPERTY_NAMESPACE)
    if not isinstance(namespace, dict):
        return []
    subject = observable_subject(item.canonical_key)
    return [
        fact
        for name, kind in sorted(OBJECT_TIME_SEMANTICS.items())
        if (fact := _object_fact(namespace.get(name), name, kind, subject, context)) is not None
    ]


def _object_fact(
    raw: Any,
    name: str,
    kind: TemporalFactKind,
    subject: SubjectRef,
    context: QualificationContext,
) -> TemporalFact | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        instant = datetime.fromisoformat(raw)
    except ValueError:
        # Provider text stays inert. An unreadable instant costs one fact.
        return None
    if instant.tzinfo is None:
        return None
    return TemporalFact(
        subject=subject,
        kind=kind,
        instant=instant,
        transport_provider=GTI_PROVIDER_ID,
        origin_provider=GTI_ORIGIN_PROVIDER,
        source_family=GTI_SOURCE_FAMILY,
        lineage_group_id=GTI_LINEAGE_GROUP,
        raw_field=name,
        source_partial=context.source_partial,
    )
