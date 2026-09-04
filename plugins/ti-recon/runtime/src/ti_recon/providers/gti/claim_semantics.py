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

from collections.abc import Mapping
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
    highlights_from,
    text_attribute,
)

__all__ = [
    "ASSOCIATION_STRENGTHS",
    "CLAIM_SEMANTICS",
    "HIGHLIGHT_ATTRIBUTES",
    "SANDBOX_VERDICT_STRENGTHS",
    "VERDICT_SEMANTICS",
    "translate",
]

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
    # A sandbox's classification of what it watched -- the assessment's own
    # boolean factor, the file-level per-sandbox verdicts, and the behaviour
    # summary's aggregated verdict. Three records of one proposition from one
    # origin: fusion sees one claim, never three corroborations.
    "gti.sandbox_verdict.malicious": ClaimSemantic.SANDBOX_CLASSIFICATION,
    "gti.sandbox_verdicts": ClaimSemantic.SANDBOX_CLASSIFICATION,
    "gti.behavior.verdict": ClaimSemantic.SANDBOX_CLASSIFICATION,
    # Curated association relationships (Task 7 §11), one exact claim type per
    # relationship the normalizer emits. They surface only at DEEP, which is why
    # a STANDARD-only fixture never showed them unmapped.
    "gti.threat_association.malware-families": ClaimSemantic.THREAT_ACTOR_ASSOCIATION,
    "gti.threat_association.related-threat-actors": ClaimSemantic.THREAT_ACTOR_ASSOCIATION,
    "gti.threat_association.campaigns": ClaimSemantic.THREAT_ACTOR_ASSOCIATION,
    "gti.threat_association.related-reports": ClaimSemantic.THREAT_ACTOR_ASSOCIATION,
    "gti.threat_association.associations": ClaimSemantic.THREAT_ACTOR_ASSOCIATION,
    # Detections and infrastructure findings about the object.
    "gti.yara_match.malicious": ClaimSemantic.MALICIOUS_REPUTATION,
    "gti.dtm_alert": ClaimSemantic.MALICIOUS_REPUTATION,
    "gti.domain_hijack": ClaimSemantic.THREAT_INFRASTRUCTURE_ASSOCIATION,
}

_ASSESSMENT_CLAIM: Final[str] = "gti_assessment"

#: Claim types whose ``verdict`` attribute states how firmly the sandbox spoke.
#: ``malicious``/``asserted`` is a firm classification; ``suspicious`` and
#: ``suspected`` are hedged and stay weak, exactly as a hedged GTI verdict does.
_SANDBOX_CLAIMS: Final[frozenset[str]] = frozenset({"gti.sandbox_verdicts", "gti.behavior.verdict"})

#: How firmly each curated association asserts threat relevance.
#:
#: A family, actor or campaign attribution is GTI stating what this exact object
#: *is*. A report relationship says a report mentions it, and the generic
#: ``associations`` relationship says it sits in some collection -- both real,
#: both hedged: a report can discuss a decoy, and a collection can be anything
#: its author gathered. A hedged claim is never decisive and never corroborates
#: on its own.
ASSOCIATION_STRENGTHS: Final[Mapping[str, ClaimAssertionStrength]] = {
    "gti.threat_association.malware-families": ClaimAssertionStrength.ASSERTED,
    "gti.threat_association.related-threat-actors": ClaimAssertionStrength.ASSERTED,
    "gti.threat_association.campaigns": ClaimAssertionStrength.ASSERTED,
    "gti.threat_association.related-reports": ClaimAssertionStrength.SUSPECTED,
    "gti.threat_association.associations": ClaimAssertionStrength.SUSPECTED,
}
SANDBOX_VERDICT_STRENGTHS: Final[dict[str, ClaimAssertionStrength]] = {
    "malicious": ClaimAssertionStrength.ASSERTED,
    "asserted": ClaimAssertionStrength.ASSERTED,
    "suspicious": ClaimAssertionStrength.SUSPECTED,
    "suspected": ClaimAssertionStrength.SUSPECTED,
}

#: Which of a record's attributes are worth showing beside its claim, per claim
#: type. Provider knowledge, kept in the provider's package: the report never
#: reads a GTI attribute name, it prints the lines produced here.
HIGHLIGHT_ATTRIBUTES: Final[dict[str, tuple[str, ...]]] = {
    _ASSESSMENT_CLAIM: ("verdict", "severity", "threat_score", "description"),
    "gti_analysis_stats": ("malicious", "suspicious", "harmless", "undetected"),
    "gti.sandbox_verdicts": (
        "verdict",
        "malware_classification",
        "malicious_count",
        "suspicious_count",
        "harmless_count",
        "sandbox_count",
        "divergent",
    ),
    "gti.behavior.verdict": ("verdicts", "verdict_confidence", "highlights"),
    "gti.sandbox_verdict.malicious": ("factor",),
    "gti.threat_association.malware-families": ("relationship", "gti_collection_type", "name"),
    "gti.threat_association.related-threat-actors": ("relationship", "gti_collection_type", "name"),
    "gti.threat_association.campaigns": ("relationship", "gti_collection_type", "name"),
    "gti.threat_association.related-reports": ("relationship", "gti_collection_type", "name"),
    "gti.threat_association.associations": ("relationship", "gti_collection_type", "name"),
    "gti.analyst_determination.malicious": ("factor", "value"),
    "gti.analyst_determination.benign": ("factor", "value"),
    "gti.legitimate_software": ("factor", "value"),
    "gti.threat_actor_association": ("factor", "value"),
    "gti.threat_report_association": ("factor", "value"),
    "gti.malware_association": ("factor", "value"),
    "gti.osint_association": ("factor", "value"),
    "gti.yara_match.malicious": ("factor", "value"),
    "gti.dtm_alert": ("factor", "value"),
    "gti.domain_hijack": ("factor", "value"),
}


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
            if evidence.claim_type in _SANDBOX_CLAIMS:
                stated = text_attribute(evidence.attributes, "verdict")
                # A record whose verdict word this table does not know is a
                # hedged claim, never a firm one: the conservative direction.
                strength = SANDBOX_VERDICT_STRENGTHS.get(
                    stated or "", ClaimAssertionStrength.SUSPECTED
                )
            elif evidence.claim_type in ASSOCIATION_STRENGTHS:
                strength = ASSOCIATION_STRENGTHS[evidence.claim_type]

        claims.append(
            claim_from(
                evidence,
                policy_version=context.policy_version,
                semantic=semantic,
                strength=strength,
                subject_key=context.subject_key_for(evidence.subject_object_id),
                source_partial=context.source_partial,
                highlights=highlights_from(
                    evidence.attributes, HIGHLIGHT_ATTRIBUTES.get(evidence.claim_type, ())
                ),
            )
        )
    return tuple(claims)
