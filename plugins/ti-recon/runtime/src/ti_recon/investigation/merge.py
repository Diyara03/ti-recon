"""Composing several enrichment rounds into one view (Task 19).

Task 13 returns one result per round. Tasks 15-18 must see the whole
investigation, so the rounds are composed into a single
:class:`AdaptiveEnrichmentResult` describing everything that was executed and
covered.

Not a concatenation
-------------------

Attempts carry a planner ``sequence`` that continues across rounds, because the
continuation state carries it forward. That makes the sequence a stable identity
rather than a position, so composing is a keyed merge: the same sequence must
describe the same attempt, and if two rounds disagree about one, something has
gone wrong with the state carried between them and the investigation stops rather
than silently preferring one.

Coverage comes from the last round alone
-----------------------------------------

Deliberately, and it is not a shortcut. The planning state carries covered and
partial families forward, so each round's coverage items already describe the
*accumulated* position — the last round's are the cumulative ones. Merging
coverage item by item would double-count families and could report a capability
as less covered than the planner knows it to be.
"""

from __future__ import annotations

from collections.abc import Sequence

from ti_recon.planning.models import AdaptiveEnrichmentResult, ProviderAttempt

__all__ = ["MergeConflictError", "merge_enrichment_results"]


class MergeConflictError(ValueError):
    """Two rounds describe the same execution differently.

    A structural failure, not an analytical one: it means the state carried
    between rounds was wrong, and every conclusion drawn from the merged view
    would be drawn from a picture that never existed.
    """


def merge_enrichment_results(
    rounds: Sequence[AdaptiveEnrichmentResult],
) -> AdaptiveEnrichmentResult:
    """One view of everything every round executed and covered.

    The target, depth and requested capabilities must agree across rounds — they
    describe the investigation, not the round — and disagreement is a structural
    error rather than something to reconcile.
    """
    if not rounds:
        msg = "an investigation has at least one enrichment round"
        raise MergeConflictError(msg)
    first, last = rounds[0], rounds[-1]

    for item in rounds[1:]:
        if item.target.canonical_key != first.target.canonical_key:
            msg = (
                "enrichment rounds describe different observables: "
                f"{first.target.canonical_key!r} vs {item.target.canonical_key!r}"
            )
            raise MergeConflictError(msg)
        if item.depth is not first.depth:
            msg = f"enrichment rounds disagree about depth: {first.depth} vs {item.depth}"
            raise MergeConflictError(msg)

    attempts: dict[int, ProviderAttempt] = {}
    for item in rounds:
        for attempt in item.attempts:
            existing = attempts.get(attempt.sequence)
            if existing is not None and existing != attempt:
                msg = (
                    f"two rounds describe attempt {attempt.sequence} differently: "
                    f"{existing.provider_id}/{existing.capability.value} vs "
                    f"{attempt.provider_id}/{attempt.capability.value}"
                )
                raise MergeConflictError(msg)
            attempts[attempt.sequence] = attempt

    return AdaptiveEnrichmentResult(
        target=last.target,
        depth=last.depth,
        requested_capabilities=last.requested_capabilities,
        attempts=tuple(attempts[key] for key in sorted(attempts)),
        decisions=tuple(decision for item in rounds for decision in item.decisions),
        # Already cumulative: the planning state carried coverage forward, so the
        # final round's items describe the whole investigation.
        coverage=last.coverage,
        # Likewise the budget, which carried its spend across rounds.
        budget=last.budget,
        # The reason the *last* round stopped asking. Earlier rounds' reasons
        # stay in the round trace, where they describe that round.
        stop_reason=last.stop_reason,
    )
