"""What a GreyNoise classification actually asserts (Task 17A).

This is the translator Task 16 was missing.

GreyNoise classifies what an address *does on the internet*: whether it is
background scanning noise, and whose. Its claim is therefore about scanning
behaviour -- :attr:`ClaimSemantic.SCANNER_ACTIVITY` -- and that is a different
proposition from "this address serves command and control", even when both
concern the same address on the same day.

Task 16 could not draw that line. Both claims reach the generic layer as
``CURATED_THREAT_ASSERTION`` with ``SUPPORTS_MALICIOUS``, so scanner context
risked explaining away a C2 finding, and the explanation was deferred rather than
guessed. Naming the proposition here resolves it: the two claims now form
different propositions, corroborate nothing of each other's, and scanner context
can be matched against scanner claims alone.

Direction stays the provider's. GreyNoise's own ``classification`` already
decides malicious, suspicious or benign, and Task 9 already mapped that onto
``EvidenceEffect``; this module reads the raw value only to tell an asserted
claim from a suspected one.

Business Services Intelligence is absent from this module on purpose. It is
``CONTEXT_ONLY`` in Task 9 and explicitly not an allow list, so it is not a
directional claim and never becomes one.
"""

from __future__ import annotations

from typing import Final

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

__all__ = ["CLASSIFICATION_CLAIM", "translate"]

#: The one directional claim GreyNoise makes.
CLASSIFICATION_CLAIM: Final[str] = "greynoise_classification"

#: GreyNoise's own classification values that qualify rather than assert.
_SUSPECTED: Final[frozenset[str]] = frozenset({"suspicious"})


def translate(
    envelope: ProviderResultEnvelope, context: ClaimTranslationContext
) -> tuple[NormalizedClaim, ...]:
    claims: list[NormalizedClaim] = []
    for evidence in directional_evidence(envelope):
        if evidence.claim_type != CLASSIFICATION_CLAIM:
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

        raw = text_attribute(evidence.attributes, "raw_classification")
        claims.append(
            claim_from(
                evidence,
                policy_version=context.policy_version,
                # Scanning behaviour, whichever way the classification points.
                # A benign-classified scanner is still a claim about scanning.
                semantic=ClaimSemantic.SCANNER_ACTIVITY,
                strength=(
                    ClaimAssertionStrength.SUSPECTED
                    if raw in _SUSPECTED
                    else ClaimAssertionStrength.ASSERTED
                ),
                subject_key=context.subject_key_for(evidence.subject_object_id),
                source_partial=context.source_partial,
            )
        )
    return tuple(claims)
