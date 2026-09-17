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

What the claim quotes
---------------------

Only a claim's ``highlights`` reach an analyst report, so a verdict that quotes
nothing arrives as "a sandbox classified this sample" and nothing else — not the
provider's own word, not the environments that disagreed, not the family it
named, not when it ran (Task 24, HA-03). The lines below are the provider's own
bounded statements about its own claim: the neutral verdict, the raw words it
used, which environment reported what, whether completed runs disagreed, the
family label it applied, how many runs it holds, and one line per run that was
actually read carrying that run's environment, detonation instant and how much
behaviour it produced.

Quotation, never weight. Fusion reads none of it, the threat score and AV count
are deliberately absent — they are not votes and printing them beside a verdict
invites them to be read as one — and a claim with no highlights is weighed
exactly the same as one with eight.
"""

from __future__ import annotations

from typing import Any, Final

from ti_recon.providers.hybrid_analysis.normalizer import (
    ASSESSMENT_CLAIM_TYPE,
    BEHAVIOUR_CLAIM_TYPE,
)
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.claims.models import (
    MAX_CLAIM_HIGHLIGHTS,
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
from ti_recon.sandbox.models import SandboxVerdict

__all__ = ["HIGHLIGHT_ATTRIBUTES", "RUN_HIGHLIGHT", "translate"]

#: Sandbox verdicts the platform states with a hedge.
_SUSPECTED: Final[frozenset[str]] = frozenset({SandboxVerdict.SUSPICIOUS.value})

#: What the assessment record says about itself, in the order an analyst needs
#: it: the conclusion, the provider's own wording, who disagreed, and what it
#: called the thing. ``threat_score`` and ``av_detect`` are deliberately absent.
HIGHLIGHT_ATTRIBUTES: Final[tuple[str, ...]] = (
    "sandbox_verdict",
    "raw_verdicts",
    "verdicts_by_environment",
    "divergent_verdicts",
    "provider_family_labels",
    "completed_report_count",
)

#: Label of the line describing one run that was actually read.
RUN_HIGHLIGHT: Final[str] = "run"

#: Behaviour counts quoted on a run line, with the words used to render them.
_RUN_COUNTS: Final[tuple[tuple[str, str], ...]] = (
    ("normalized_signatures", "signatures"),
    ("normalized_techniques", "techniques"),
    ("normalized_network", "network observations"),
)


def translate(
    envelope: ProviderResultEnvelope, context: ClaimTranslationContext
) -> tuple[NormalizedClaim, ...]:
    runs = _run_highlights(envelope)
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
                highlights=(
                    *highlights_from(evidence.attributes, HIGHLIGHT_ATTRIBUTES),
                    *runs,
                ),
            )
        )
    return tuple(claims)


def _run_highlights(envelope: ProviderResultEnvelope) -> tuple[str, ...]:
    """One line per run that was actually read, from the same envelope.

    Read from the behaviour records rather than the assessment, because the
    detonation instant and the behaviour counts belong to a single run and the
    assessment deliberately spans several. Absent record, absent line: nothing
    here invents a time, and a lookup whose budget bought no summary quotes no
    run.
    """
    found: list[str] = []
    for evidence in envelope.evidence:
        if evidence.claim_type != BEHAVIOUR_CLAIM_TYPE:
            continue
        parts: list[str] = []
        report_id = evidence.attributes.get("report_id")
        if isinstance(report_id, str) and report_id:
            # Named so two runs never render as one line, and so an analyst can
            # find the run this claim quotes.
            parts.append(report_id)
        environment = evidence.attributes.get("environment_id")
        if isinstance(environment, str) and environment:
            parts.append(f"environment={environment}")
        if evidence.observed_at is not None:
            parts.append(f"analyzed_at={evidence.observed_at.isoformat()}")
        parts.extend(_count_parts(evidence.attributes))
        if parts:
            found.append(f"{RUN_HIGHLIGHT}: {', '.join(parts)}")
    return tuple(found[:MAX_CLAIM_HIGHLIGHTS])


def _count_parts(attributes: Any) -> list[str]:
    """How much behaviour this run produced, as the provider counted it."""
    found: list[str] = []
    for name, word in _RUN_COUNTS:
        value = attributes.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            continue
        found.append(f"{value} {word}")
    return found
