"""What a urlscan result actually asserts (Task 17A).

urlscan's own verdict is a curated reputation statement about a page it visited;
its engine aggregate and community votes are roll-ups of other people's opinions.
All three are directional, and the difference between them matters: one source
saying "malicious" and one source reporting that forty scanners said so are the
same *number* of sources.

So the aggregate and the votes become
:attr:`ClaimSemantic.AGGREGATED_REPUTATION`, which policy never treats as
corroboration and never counts. The counters remain on the evidence for an
analyst; nothing in fusion reads them.

Everything urlscan observes rather than judges -- the scan record, the redirect
chain, contacted infrastructure, served bodies -- is ``CONTEXT_ONLY`` in Task 8
and produces no claim. A page looking a certain way when a browser visited is a
point-in-time observation, and Task 15 already attached that qualification.
"""

from __future__ import annotations

from typing import Final

from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.claims.models import ClaimSemantic, NormalizedClaim, claim_from
from ti_recon.reasoning.claims.translation import ClaimTranslationContext, directional_evidence

__all__ = ["CLAIM_SEMANTICS", "translate"]

CLAIM_SEMANTICS: Final[dict[str, ClaimSemantic]] = {
    # urlscan's own judgement about the page.
    "urlscan_verdict": ClaimSemantic.MALICIOUS_REPUTATION,
    # Other people's opinions, relayed. One source.
    "urlscan_engine_aggregate": ClaimSemantic.AGGREGATED_REPUTATION,
    "urlscan_community_votes": ClaimSemantic.AGGREGATED_REPUTATION,
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
