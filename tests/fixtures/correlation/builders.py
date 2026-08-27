"""Building provider results without providers.

The correlation engine reads result envelopes, so a test needs envelopes rather
than API responses. These builders make one by hand so a test can say exactly what
two providers claimed and check what the graph did with it — including the cases
no fixture from a real provider produces, like two records that share an MD5 and
disagree on SHA-256.
"""

from __future__ import annotations

from datetime import datetime

from ti_recon.correlation.engine import CorrelationEngine
from ti_recon.correlation.graph import InvestigationGraph
from ti_recon.correlation.models import GraphLimits
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    ObjectClass,
    ProviderOperation,
    ProviderRunStatus,
    RelationshipType,
)
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.models.relationship import Relationship
from ti_recon.normalization import normalize_observable
from ti_recon.providers.result import ProviderResultEnvelope

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


def observable(value: str) -> IntelObject:
    """A fresh object for a value, with the identity the normalizer gives it."""
    return normalize_observable(value).intel_object


def file_object(**hashes: str) -> IntelObject:
    """A file carrying exactly the digests named, e.g. ``file_object(md5=..)``."""
    named = {
        {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}[key]: value
        for key, value in hashes.items()
    }
    strongest = named.get("SHA-256") or named.get("SHA-1") or next(iter(named.values()))
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=strongest,
        display_value=strongest,
        properties={"hashes": named},
    )


def envelope(
    provider: str,
    *,
    source_family: str | None = None,
    objects: tuple[IntelObject, ...] = (),
    links: tuple[tuple[IntelObject, RelationshipType, IntelObject, str], ...] = (),
    evidence_class: EvidenceClass = EvidenceClass.RELATIONSHIP,
    lineage_group_id: str = "",
    origin_provider: str | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    status: ProviderRunStatus = ProviderRunStatus.SUCCESS,
    with_evidence: bool = True,
    subject: IntelObject | None = None,
) -> ProviderResultEnvelope:
    """One provider result: some objects, some relationships, one evidence record.

    ``links`` entries are ``(source, relationship, target, raw provider name)``.
    """
    family = source_family or provider
    anchor = subject or (objects[0] if objects else None)
    evidence: tuple[Evidence, ...] = ()
    refs: tuple[str, ...] = ()
    if with_evidence and anchor is not None:
        record = Evidence(
            investigation_id="inv-1",
            subject_object_id=anchor.id,
            evidence_class=evidence_class,
            claim_type=f"{provider}_relationship",
            effect=EvidenceEffect.CONTEXT_ONLY,
            transport_provider=provider,
            origin_provider=origin_provider or provider,
            source_family=family,
            lineage_group_id=lineage_group_id or f"{family}:{provider}",
            first_seen=first_seen,
            last_seen=last_seen,
        )
        evidence, refs = (record,), (record.id,)

    relationships = tuple(
        Relationship(
            source_object_id=source.id,
            relationship_type=relationship,
            target_object_id=target.id,
            evidence_refs=refs or ("00000000-0000-4000-8000-000000000000",),
            raw_relationship_type=raw,
            first_seen=first_seen,
            last_seen=last_seen,
        )
        for source, relationship, target, raw in links
    )
    return ProviderResultEnvelope(
        provider=provider,
        operation=ProviderOperation.LOOKUP,
        status=status,
        adapter_version="1.0.0",
        api_version="v1",
        evidence=evidence,
        objects=objects,
        relationships=relationships,
    )


def graph_for(
    root: IntelObject | None = None, *, limits: GraphLimits | None = None
) -> tuple[InvestigationGraph, CorrelationEngine]:
    """An empty graph and its engine, with the root already placed."""
    graph = InvestigationGraph(
        investigation_id="inv-1",
        authenticated_user_id="analyst-a",
        limits=limits or GraphLimits(),
    )
    engine = CorrelationEngine(graph=graph)
    if root is not None:
        engine.add_root(root)
    return graph, engine
