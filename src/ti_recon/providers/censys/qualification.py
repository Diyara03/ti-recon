"""What a Censys observation time means (Task 15).

Censys reports when it last observed an asset. That is a scan of infrastructure
at an instant, so it becomes ``LAST_OBSERVED`` with
:attr:`SourceLifecycleState.POINT_IN_TIME`: Censys saw these ports answering and
this software banner at that moment, and says nothing about the minute before or
after. An asset it has never reached has no observation time at all, and none is
manufactured — "Censys has not scanned this" is coverage, not a sighting and
certainly not an absence of exposure.

The certificate distinction §20 of the task description asks about is enforced
here by *omission*, which is worth stating explicitly. Task 9 keeps a
certificate's fingerprint, subject and issuer, and deliberately does **not**
normalize ``not_before``/``not_after``. So this module emits no ``VALID_FROM`` or
``VALID_UNTIL`` for Censys: there is nothing normalized to emit, and reading a
validity window out of a raw response would be a new provider behaviour rather
than a qualification of an existing one.

That omission is the safe side of the distinction anyway. A certificate valid
2024-2026 does not mean the host served it throughout — hosts rotate
certificates, and a validity window is a property of the certificate, never
evidence of continuous service.
"""

from __future__ import annotations

from typing import Final

from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.extraction import ProviderQualification, QualificationContext
from ti_recon.reasoning.models import (
    EvidenceRef,
    SourceLifecycleState,
    TemporalFact,
    TemporalFactKind,
)

__all__ = ["ASSET_OBSERVATION_CLAIM_TYPES", "qualify"]

#: The two records that carry Censys's own "when I last saw this asset".
#:
#: Only the asset-level ones. Every other Censys record repeats the same instant,
#: and emitting a dozen copies of one observation would look like a dozen
#: observations.
ASSET_OBSERVATION_CLAIM_TYPES: Final[frozenset[str]] = frozenset(
    {"censys_host_observation", "censys_web_property_observation"}
)


def qualify(
    envelope: ProviderResultEnvelope, context: QualificationContext
) -> ProviderQualification:
    facts: list[TemporalFact] = []
    for evidence in envelope.evidence:
        if evidence.claim_type not in ASSET_OBSERVATION_CLAIM_TYPES:
            continue
        if evidence.observed_at is None:
            continue
        facts.append(
            TemporalFact(
                subject=context.subject_for(evidence.subject_object_id),
                kind=TemporalFactKind.LAST_OBSERVED,
                instant=evidence.observed_at,
                transport_provider=evidence.transport_provider,
                origin_provider=evidence.origin_provider,
                source_family=evidence.source_family,
                lineage_group_id=evidence.lineage_group_id,
                raw_field="last_updated_at",
                lifecycle=SourceLifecycleState.POINT_IN_TIME,
                source_partial=context.source_partial,
                evidence=EvidenceRef.of(evidence),
            )
        )
    return ProviderQualification(temporal_facts=tuple(facts))
