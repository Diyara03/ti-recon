"""Context signals the engine derives for itself (Task 15).

Almost every context signal comes from a provider's own extractor. Two do not,
because they are properties of the *set* of results rather than of any one
provider, and no single integration can see them.

Relayed sources
---------------

``Evidence.is_relayed`` — transport and origin disagreeing — is already the
model's own statement that a finding reached TI Recon through somebody else. A
VirusTotal ratio arriving through URLhaus is VirusTotal's finding, URLhaus's
transport, and Tasks 3 and 10 have already recorded both. Reading it here is
generic in the strictest sense: this module tests two fields on a model, and
would behave identically for a provider that does not exist yet.

That matters because relayed findings are the sharpest way to inflate a picture.
A relayed VirusTotal count beside a direct Google Threat Intelligence result is
one upstream source appearing twice, and Task 15's job is to make the dependence
visible rather than to decide what it costs.

Warninglist matches for related objects
---------------------------------------

Nothing here walks the graph looking for context to spread. Context attaches to
the object it was stated about, and stops. The single edge-scoped rule lives in
:mod:`ti_recon.reasoning.cues`, reads exactly one edge, and produces a cue rather
than a signal — so there is no mechanism in this package by which a signal could
travel two hops even if somebody wanted it to.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from ti_recon.models.evidence import Evidence
from ti_recon.reasoning.extraction import QualificationContext
from ti_recon.reasoning.models import (
    ContextSignal,
    ContextSignalType,
    EvidenceRef,
    SignalOrigin,
)

__all__ = ["direct_source_families", "relayed_signals", "sort_signals"]


def direct_source_families(evidence: Iterable[Evidence]) -> frozenset[str]:
    """Families that answered TI Recon directly, rather than through a relay.

    The comparison set for source dependence: a relayed finding whose family also
    appears here is the same upstream source arriving twice.
    """
    return frozenset(item.source_family for item in evidence if not item.is_relayed)


def relayed_signals(
    evidence: Sequence[Evidence], context: QualificationContext
) -> tuple[ContextSignal, ...]:
    """One signal per relayed finding, naming who actually produced it."""
    direct = direct_source_families(evidence)
    found: list[ContextSignal] = []
    for item in evidence:
        if not item.is_relayed:
            continue
        found.append(
            ContextSignal(
                signal_type=ContextSignalType.RELAYED_SOURCE,
                subject=context.subject_for(item.subject_object_id),
                origin=SignalOrigin.ENGINE_POLICY,
                match_scope=item.match_scope,
                transport_provider=item.transport_provider,
                origin_provider=item.origin_provider,
                source_family=item.source_family,
                lineage_group_id=item.lineage_group_id,
                evidence=EvidenceRef.of(item),
                source_key=item.origin_provider,
                source_partial=context.source_partial,
                detail={
                    # Whether the same upstream family also answered directly, so
                    # a reader can tell "relayed" from "relayed *and duplicated*"
                    # without recomputing it.
                    "direct_family_present": item.source_family in direct,
                    "relayed_via": item.transport_provider[:200],
                },
            )
        )
    return tuple(found)


def sort_signals(signals: Iterable[ContextSignal]) -> tuple[ContextSignal, ...]:
    """Deterministic order, deduplicated by identity.

    Two providers stating the same context about the same value is one signal —
    the ref is derived from content, so this is a value comparison rather than an
    object one, and provider arrival order cannot change the outcome.
    """
    unique: dict[str, ContextSignal] = {}
    for signal in signals:
        unique.setdefault(signal.ref, signal)
    return tuple(unique[key] for key in sorted(unique))
