"""Which claims are genuinely separate sources (Task 17B).

The single most consequential question in fusion, and the one a naive engine gets
wrong by default. Five providers repeating one upstream feed is one observation
seen five times, and a system that counted it as five confirmations would be
confidently wrong in precisely the cases where an analyst most needs it not to be.

Grouping uses provenance Tasks 3 and 10 already recorded, in this order:

1. **Lineage.** ``lineage_group_id`` is the narrowest statement of "these came
   from one place". One provider rendering the same finding in its evidence, its
   related objects and a summary is one source, and Task 3 already said so.
2. **Originating source family.** ``source_family`` of whoever *produced* the
   information, not whoever transported it. This is what puts a VirusTotal ratio
   relayed through URLhaus in the same group as a direct GTI result, and what
   keeps three abuse.ch datasets from becoming three independent votes.

Note the deliberate asymmetry: two providers with different ids are *not*
assumed independent, but two different families are treated as potentially
independent unless lineage says otherwise. Independence has to be earned by
provenance; difference of vendor is not evidence of it.

Nothing is discarded
--------------------

Collapsing a group does not delete a claim. Every claim stays visible in the
trace with its own provenance; what collapses is only its ability to *corroborate*
something already counted. A relayed finding is a real finding.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence

from ti_recon.reasoning.claims.models import NormalizedClaim
from ti_recon.reasoning.fusion.models import IndependenceGroup, SupportBreadth

__all__ = ["breadth_of", "group_key_for", "independence_groups"]


def group_key_for(claim: NormalizedClaim) -> str:
    """The key that decides whether two claims are one source.

    Lineage wins where a provider stated one, because it is the narrower and
    more deliberate statement. Otherwise the originating family, which is what
    survives a relay.
    """
    if claim.lineage_group_id:
        return f"lineage:{claim.lineage_group_id}"
    return f"family:{claim.source_family}"


def independence_groups(claims: Iterable[NormalizedClaim]) -> tuple[IndependenceGroup, ...]:
    """Partition claims into groups that are not independent of one another.

    Deterministically ordered by key, so two runs that discovered the same
    claims in a different sequence produce identical groups.
    """
    buckets: dict[str, list[NormalizedClaim]] = defaultdict(list)
    for claim in claims:
        buckets[group_key_for(claim)].append(claim)

    return tuple(
        IndependenceGroup(
            group_key=key,
            source_family=sorted({item.source_family for item in members})[0],
            claim_ids=tuple(sorted(item.claim_id for item in members)),
            origin_providers=tuple(sorted({item.origin_provider for item in members})),
        )
        for key, members in sorted(buckets.items())
    )


def breadth_of(groups: Sequence[IndependenceGroup]) -> SupportBreadth:
    """How broadly a proposition is supported, as a category.

    A category rather than the number, because the number is the thing that must
    not become a tally. Policy asks "one source or several?", which is a question
    about provenance structure; it never asks "how many?", which is a question
    about votes.
    """
    if not groups:
        return SupportBreadth.NONE
    if len(groups) == 1:
        return SupportBreadth.ONE_INDEPENDENT_SOURCE
    return SupportBreadth.MULTIPLE_INDEPENDENT_SOURCES
