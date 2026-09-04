"""What a Google Threat Intelligence record actually asserts (Task 17A).

GTI is the broadest provider here and makes several genuinely different claims,
which is precisely why they must not collapse into one. Its curated verdict, its
Mandiant analyst determination, its actor and report associations, its sandbox
verdict and its aggregated engine counters are five different propositions that
happen to arrive from one API.

Two mappings matter more than the rest.

``gti_analysis_stats`` becomes :attr:`ClaimSemantic.AGGREGATED_REPUTATION` and
nothing stronger. It is a roll-up of other vendors' opinions -- one source
reporting many, not many sources -- so it can never be corroboration and its
counters are never votes. The numbers stay on the evidence for an analyst to
read; fusion reads the semantic.

The contributing factors are a **closed table** in Task 7's normalizer, with
exact claim types. Reading those exact strings here is provider-owned knowledge
in the provider's own package; a factor GTI adds later produces no claim until
somebody adds a row, which is the conservative direction to fail in.

Temporal semantics are absent from this module entirely. ``last_analysis_date``
is a scan time, Task 15 already said so, and fusion consumes Task 15 rather than
re-reading a timestamp.
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

__all__ = ["CLAIM_SEMANTICS", "VERDICT_SEMANTICS", "translate"]

#: GTI's own assessment verdicts, mapped to propositions.
#:
#: ``VERDICT_SUSPICIOUS`` keeps the malicious *direction* Task 7 gave it and
#: becomes a *suspected* claim, so a hedged verdict never carries the weight of a
#: confident one. ``VERDICT_UNDETECTED`` is deliberately absent: Task 7 makes it
#: context, because nothing flagging a file is not evidence of safety.
VERDICT_SEMANTICS: Final[dict[str, tuple[ClaimSemantic, ClaimAssertionStrength]]] = {
    "verdict_malicious": (ClaimSemantic.MALICIOUS_REPUTATION, ClaimAssertionStrength.ASSERTED),
    "verdict_suspicious": (ClaimSemantic.MALICIOUS_REPUTATION, ClaimAssertionStrength.SUSPECTED),
    "verdict_benign": (ClaimSemantic.BENIGN_REPUTATION, ClaimAssertionStrength.ASSERTED),
}

#: GTI's directional claim types, mapped to propositions. Exact keys, matching
#: Task 7's controlled contributing-factor table.
CLAIM_SEMANTICS: Final[dict[str, ClaimSemantic]] = {
    # A roll-up of other vendors. One source, however many opinions it holds.
    "gti_analysis_stats": ClaimSemantic.AGGREGATED_REPUTATION,
    # Curated human determinations.
    "gti.analyst_determination.malicious": ClaimSemantic.MALICIOUS_REPUTATION,
    "gti.analyst_determination.benign": ClaimSemantic.BENIGN_REPUTATION,
    "gti.legitimate_software": ClaimSemantic.BENIGN_REPUTATION,
    # Curated attribution to actors, campaigns and reporting.
    "gti.threat_actor_association": ClaimSemantic.THREAT_ACTOR_ASSOCIATION,
    "gti.threat_report_association": ClaimSemantic.THREAT_ACTOR_ASSOCIATION,
    "gti.malware_association": ClaimSemantic.THREAT_ACTOR_ASSOCIATION,
    "gti.osint_association": ClaimSemantic.THREAT_ACTOR_ASSOCIATION,
    # Behaviour GTI watched rather than a record it holds.
    "gti.sandbox_verdict.malicious": ClaimSemantic.SANDBOX_CLASSIFICATION,
    # Detections and infrastructure findings about the object.
    "gti.yara_match.malicious": ClaimSemantic.MALICIOUS_REPUTATION,
    "gti.dtm_alert": ClaimSemantic.MALICIOUS_REPUTATION,
    "gti.domain_hijack": ClaimSemantic.THREAT_INFRASTRUCTURE_ASSOCIATION,
}

_ASSESSMENT_CLAIM: Final[str] = "gti_assessment"


def translate(
    envelope: ProviderResultEnvelope, context: ClaimTranslationContext
) -> tuple[NormalizedClaim, ...]:
    claims: list[NormalizedClaim] = []
    for evidence in directional_evidence(envelope):
        strength = ClaimAssertionStrength.ASSERTED
        if evidence.claim_type == _ASSESSMENT_CLAIM:
            verdict = text_attribute(evidence.attributes, "verdict")
            semantic, strength = VERDICT_SEMANTICS.get(
                verdict or "",
                (ClaimSemantic.UNCLASSIFIED_DIRECTIONAL, ClaimAssertionStrength.ASSERTED),
            )
        else:
            semantic = CLAIM_SEMANTICS.get(
                evidence.claim_type, ClaimSemantic.UNCLASSIFIED_DIRECTIONAL
            )

        claims.append(
            claim_from(
                evidence,
                policy_version=context.policy_version,
                semantic=semantic,
                strength=strength,
                subject_key=context.subject_key_for(evidence.subject_object_id),
                source_partial=context.source_partial,
            )
        )
    return tuple(claims)
