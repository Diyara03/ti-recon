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

**Scanning is not the direction.** ``noise: true`` says GreyNoise's sensors saw
the address scanning; ``classification`` says what GreyNoise concluded about
that behaviour. Only the second points anywhere -- an address observed scanning
with an ``unknown`` classification is context and makes no claim at all -- and
the highlights below quote both fields side by side so a reader of the report
never has to reconstruct which one the effect came from.

Business Services Intelligence is absent from this module on purpose. It is
``CONTEXT_ONLY`` in Task 9 and explicitly not an allow list, so it is not a
directional claim and never becomes one. What *is* quoted is whether the
provider supplied a Business Services state at all, because ``riot: false`` is
the absence of that context and an analyst should be able to see it was absent
rather than unreported.
"""

from __future__ import annotations

from typing import Final

from ti_recon.models.evidence import Evidence
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
    "ACCESS_PATH_HIGHLIGHT",
    "CLASSIFICATION_CLAIM",
    "COVERAGE_CLAIM",
    "HIGHLIGHT_ATTRIBUTES",
    "LAST_SEEN_HIGHLIGHT",
    "translate",
]

#: The one directional claim GreyNoise makes.
CLASSIFICATION_CLAIM: Final[str] = "greynoise_classification"

#: The context record saying which door answered and how much was read.
COVERAGE_CLAIM: Final[str] = "greynoise_coverage"

#: GreyNoise's own classification values that qualify rather than assert.
_SUSPECTED: Final[frozenset[str]] = frozenset({"suspicious"})

#: What the classification record says about itself, in the order an analyst
#: reads it: the provider's word, whether scanning was observed, whether a
#: Business Services entry exists, and who GreyNoise attributes the activity
#: to. Every one is a bounded scalar the normalizer already keeps; none is a
#: weight, and the classification is first because it is the only one the
#: effect was read from.
HIGHLIGHT_ATTRIBUTES: Final[tuple[str, ...]] = (
    "raw_classification",
    "observed_scanning",
    "known_business_service",
    "actor",
)

#: Label of the highlight line quoting the sensor fleet's last sighting.
LAST_SEEN_HIGHLIGHT: Final[str] = "last_seen"

#: Label of the highlight line naming the access path -- ``full`` or
#: ``community``, the adapter's own :class:`GreyNoiseAccessLevel` values --
#: that produced the answer. Read from the coverage record of the same
#: envelope: it is provenance of the claim, not a property of the address, and
#: it is the only way the access level reaches an analyst report.
ACCESS_PATH_HIGHLIGHT: Final[str] = "access_path"


def translate(
    envelope: ProviderResultEnvelope, context: ClaimTranslationContext
) -> tuple[NormalizedClaim, ...]:
    claims: list[NormalizedClaim] = []
    provenance = _access_path_highlights(envelope)
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
                highlights=(
                    *highlights_from(evidence.attributes, HIGHLIGHT_ATTRIBUTES),
                    *_last_seen_highlights(evidence),
                    *provenance,
                ),
            )
        )
    return tuple(claims)


def _last_seen_highlights(evidence: Evidence) -> tuple[str, ...]:
    """The provider's own last sighting, as one bounded line.

    Quoted from the evidence's ``last_seen`` -- the field Task 15 also reads as
    ``LAST_OBSERVED`` -- rather than from an attribute, so the report line and
    the temporal fact can never disagree about the instant.
    """
    if evidence.last_seen is None:
        return ()
    return (f"{LAST_SEEN_HIGHLIGHT}: {evidence.last_seen.strftime('%Y-%m-%dT%H:%M:%SZ')}",)


def _access_path_highlights(envelope: ProviderResultEnvelope) -> tuple[str, ...]:
    """Which door answered, from the envelope's own coverage record.

    The adapter records the access level on ``greynoise_coverage`` -- a
    ``CONTEXT`` record that never becomes a claim and therefore never reaches
    the report on its own. The classification claim from the same envelope is
    the answer that door produced, so the level is quoted beside it. Nothing
    is inferred: if the coverage record is absent or unreadable, no line is
    written.
    """
    for record in envelope.evidence:
        if record.claim_type != COVERAGE_CLAIM:
            continue
        level = text_attribute(record.attributes, "access_level")
        if level is not None:
            return (f"{ACCESS_PATH_HIGHLIGHT}: {level}",)
    return ()
