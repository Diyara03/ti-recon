"""What a ThreatFox record actually asserts (Task 17A).

ThreatFox publishes a structured ``threat_type`` alongside every indicator, and
that field is the reason Task 16's scanner-versus-C2 problem is solvable at all.
``botnet_cc`` and ``payload_delivery`` are documented platform values, not prose,
so a translator can map them to distinct propositions without reading a
description or guessing from a malware family name.

The mapping is deliberately short. A value this module does not recognise
becomes :attr:`ClaimSemantic.THREAT_INFRASTRUCTURE_ASSOCIATION` -- still a real
threat association, just not a claim about *which* role the infrastructure
played. Inventing a role from an unfamiliar string is exactly the guess that
would let a future ThreatFox vocabulary change quietly alter a verdict.
"""

from __future__ import annotations

from typing import Final

from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.claims.models import ClaimSemantic, NormalizedClaim, claim_from
from ti_recon.reasoning.claims.translation import (
    ClaimTranslationContext,
    directional_evidence,
    highlights_from,
    text_attribute,
)

__all__ = ["THREAT_TYPE_SEMANTICS", "translate"]

#: ThreatFox's own ``threat_type`` values, mapped to propositions.
#:
#: Exact keys only. These are the values the platform documents and the ones the
#: shipped fixtures carry; anything else falls through to the generic association
#: rather than being pattern-matched into a role it may not have.
THREAT_TYPE_SEMANTICS: Final[dict[str, ClaimSemantic]] = {
    "botnet_cc": ClaimSemantic.C2_ASSOCIATION,
    "payload_delivery": ClaimSemantic.MALWARE_DISTRIBUTION,
    "payload": ClaimSemantic.MALWARE_DISTRIBUTION,
}

#: The directional claim types this provider emits.
_IOC_CLAIM: Final[str] = "threatfox_ioc"
_HASH_CLAIM: Final[str] = "threatfox_hash_association"

#: What the report may quote about each claim, from named attributes only.
#:
#: For an address the record that matched is an ``ip:port`` IOC, and the
#: report has to be able to say so: which IOC matched, that it matched the
#: *host* component, which port, what ThreatFox called the threat and the
#: family. ``confidence_level`` is the contributor's own number, quoted and
#: never weighed (invariant 94b).
HIGHLIGHT_ATTRIBUTES: Final[dict[str, tuple[str, ...]]] = {
    _IOC_CLAIM: (
        "ioc",
        "ioc_type",
        "matched_component",
        "port",
        "threat_type",
        "malware_printable",
        "confidence_level",
        "is_compromised",
    ),
    _HASH_CLAIM: ("malware_printable", "threat_type", "matched_records"),
}


def translate(
    envelope: ProviderResultEnvelope, context: ClaimTranslationContext
) -> tuple[NormalizedClaim, ...]:
    claims: list[NormalizedClaim] = []
    for evidence in directional_evidence(envelope):
        if evidence.claim_type == _IOC_CLAIM:
            threat_type = text_attribute(evidence.attributes, "threat_type")
            semantic = THREAT_TYPE_SEMANTICS.get(
                threat_type or "", ClaimSemantic.THREAT_INFRASTRUCTURE_ASSOCIATION
            )
        elif evidence.claim_type == _HASH_CLAIM:
            # "This sample is tied to infrastructure ThreatFox tracks." An
            # association about the file, not a statement that the file is a
            # known vetted sample -- a different platform makes that claim.
            semantic = ClaimSemantic.THREAT_INFRASTRUCTURE_ASSOCIATION
        else:
            semantic = ClaimSemantic.UNCLASSIFIED_DIRECTIONAL

        claims.append(
            claim_from(
                evidence,
                policy_version=context.policy_version,
                semantic=semantic,
                subject_key=context.subject_key_for(evidence.subject_object_id),
                source_partial=context.source_partial,
                highlights=highlights_from(
                    evidence.attributes, HIGHLIGHT_ATTRIBUTES.get(evidence.claim_type, ())
                ),
            )
        )
    return tuple(claims)
