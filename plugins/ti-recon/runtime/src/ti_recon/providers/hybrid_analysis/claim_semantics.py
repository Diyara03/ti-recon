"""What a sandbox report actually asserts (Task 17A).

A sandbox says what a sample did when somebody ran it, which is a claim about
behaviour rather than about reputation or hosting:
:attr:`ClaimSemantic.SANDBOX_CLASSIFICATION`.

Task 12 preserved the distinction between ``malicious`` and ``suspicious``
verdicts rather than flattening both into one direction, and this module keeps
that alive: a ``suspicious`` run becomes a *suspected* claim, which policy can
never treat as decisive. Losing that would let a hedged verdict carry the same
weight as a confident one.

Only the assessment record produces a claim. The behaviour record is
``CONTEXT_ONLY`` in Task 12 -- deliberately, because the direction was already
stated once and repeating it would be the same sandbox voting twice -- and a
report that never completed produces no verdict at all, so there is nothing here
to translate.

Execution quality is not read here. Whether a run observed anything is Task 15's
finding and Task 16's limitation, and fusion consumes both; re-deriving it would
put one provider's threshold in two places.
"""

from __future__ import annotations

from typing import Final

from ti_recon.providers.hybrid_analysis.normalizer import ASSESSMENT_CLAIM_TYPE
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.claims.models import (
    ClaimAssertionStrength,
    ClaimSemantic,
    NormalizedClaim,
    claim_from,
)
from ti_recon.reasoning.claims.translation import (
    ClaimTranslationContext,
    directional_evidence,
    text_attribute,
)
from ti_recon.sandbox.models import SandboxVerdict

__all__ = ["translate"]

#: Sandbox verdicts the platform states with a hedge.
_SUSPECTED: Final[frozenset[str]] = frozenset({SandboxVerdict.SUSPICIOUS.value})


def translate(
    envelope: ProviderResultEnvelope, context: ClaimTranslationContext
) -> tuple[NormalizedClaim, ...]:
    claims: list[NormalizedClaim] = []
    for evidence in directional_evidence(envelope):
        if evidence.claim_type != ASSESSMENT_CLAIM_TYPE:
            claims.append(
                claim_from(
                    evidence,
                    policy_version=context.policy_version,
                    semantic=ClaimSemantic.UNCLASSIFIED_DIRECTIONAL,
                    subject_key=context.subject_key_for(evidence.subject_object_id),
                    source_partial=context.source_partial,
                )
            )
            continue

        verdict = text_attribute(evidence.attributes, "sandbox_verdict")
        claims.append(
            claim_from(
                evidence,
                policy_version=context.policy_version,
                semantic=ClaimSemantic.SANDBOX_CLASSIFICATION,
                strength=(
                    ClaimAssertionStrength.SUSPECTED
                    if verdict in _SUSPECTED
                    else ClaimAssertionStrength.ASSERTED
                ),
                subject_key=context.subject_key_for(evidence.subject_object_id),
                source_partial=context.source_partial,
            )
        )
    return tuple(claims)
