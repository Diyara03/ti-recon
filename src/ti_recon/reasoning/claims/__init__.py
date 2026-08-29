"""Provider-neutral claim semantics (Task 17A).

Turns provider evidence into **propositions**: what each finding actually
asserts, in vocabulary no vendor owns. Fusion reasons over these rather than over
provider output, which is what lets a generic layer tell "this address scans the
internet" from "this address serves command and control" -- the distinction
Task 16 identified as missing and deferred rather than guess at.

A semantic names the dimension. ``EvidenceEffect`` names the direction. What
either is worth is fusion's decision. Evidence itself is never touched: a claim
is a view over one piece of it, and the provider's record stays authoritative.
"""

from ti_recon.reasoning.claims.models import (
    CLAIM_ID_LENGTH,
    OBJECT_SEMANTICS,
    ClaimAssertionStrength,
    ClaimPropositionKey,
    ClaimSemantic,
    NormalizedClaim,
    claim_from,
    claim_id_for,
)
from ti_recon.reasoning.claims.policy import (
    CLAIM_SEMANTICS_POLICY_VERSION,
    COMPATIBLE_SEMANTICS,
    NON_CORROBORATING_SEMANTICS,
    compatible,
)
from ti_recon.reasoning.claims.registry import (
    default_translators,
    translate_envelope,
    translated_provider_ids,
    unclassified_translation,
)
from ti_recon.reasoning.claims.translation import (
    ClaimTranslationContext,
    ClaimTranslator,
    directional_evidence,
)

__all__ = [
    "CLAIM_ID_LENGTH",
    "CLAIM_SEMANTICS_POLICY_VERSION",
    "COMPATIBLE_SEMANTICS",
    "NON_CORROBORATING_SEMANTICS",
    "OBJECT_SEMANTICS",
    "ClaimAssertionStrength",
    "ClaimPropositionKey",
    "ClaimSemantic",
    "ClaimTranslationContext",
    "ClaimTranslator",
    "NormalizedClaim",
    "claim_from",
    "claim_id_for",
    "compatible",
    "default_translators",
    "directional_evidence",
    "translate_envelope",
    "translated_provider_ids",
    "unclassified_translation",
]
