"""What a URLhaus record actually asserts (Task 17A).

URLhaus tracks URLs somebody reported serving malware, and its exact-URL record
is the most specific claim in the abuse.ch family: *this artifact delivered
malware*. That is :attr:`ClaimSemantic.MALWARE_DISTRIBUTION`, and it is
materially stronger than a generic malicious reputation about the same string.

Scope is what keeps it honest. The host-association record is a claim about the
*host*, so it becomes a generic infrastructure association and carries the host
scope Task 10 already gave it. A payload record says a tracked URL once served
this file -- provenance rather than a verdict on the file -- so it maps to an
infrastructure association too rather than to sample identity.

Current state is not this module's business. A URL URLhaus reports offline
distributed malware; Task 15 records the current state and Task 16 says it does
not erase the history, and neither changes what the record asserts.
"""

from __future__ import annotations

from typing import Final

from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.claims.models import ClaimSemantic, NormalizedClaim, claim_from
from ti_recon.reasoning.claims.translation import ClaimTranslationContext, directional_evidence

__all__ = ["CLAIM_SEMANTICS", "translate"]

#: URLhaus's directional claim types, mapped to propositions.
CLAIM_SEMANTICS: Final[dict[str, ClaimSemantic]] = {
    # The exact artifact served malware. The specific one.
    "urlhaus_malware_url": ClaimSemantic.MALWARE_DISTRIBUTION,
    # Malware URLs exist on this host. About the host, and Task 10 already scoped
    # it that way.
    "urlhaus_host_malware_association": ClaimSemantic.THREAT_INFRASTRUCTURE_ASSOCIATION,
    # A tracked URL served this file. Provenance for the file, not identity.
    "urlhaus_payload_record": ClaimSemantic.THREAT_INFRASTRUCTURE_ASSOCIATION,
}


def translate(
    envelope: ProviderResultEnvelope, context: ClaimTranslationContext
) -> tuple[NormalizedClaim, ...]:
    return tuple(
        claim_from(
            evidence,
            policy_version=context.policy_version,
            semantic=CLAIM_SEMANTICS.get(
                evidence.claim_type, ClaimSemantic.UNCLASSIFIED_DIRECTIONAL
            ),
            subject_key=context.subject_key_for(evidence.subject_object_id),
            source_partial=context.source_partial,
        )
        for evidence in directional_evidence(envelope)
    )
