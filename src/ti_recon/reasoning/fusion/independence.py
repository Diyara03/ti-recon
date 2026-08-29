"""Which claims are genuinely separate sources (Task 17B).

The single most consequential question in fusion, and the one a naive engine gets
wrong by default. Five providers repeating one upstream feed is one observation
seen five times, and a system that counted it as five confirmations would be
confidently wrong in precisely the cases where an analyst most needs it not to be.

Grouping is by **originating source family** -- ``source_family``, which Task 10
sets to whoever *produced* the information rather than whoever transported it.
That single key does the whole job:

* it puts a VirusTotal ratio relayed through URLhaus in the same group as a
  direct GTI result, because Task 10 gives the relayed record the originator's
  family;
* it keeps ThreatFox, URLhaus and MalwareBazaar as one origin, because they are
  three datasets run by one organisation;
* it subsumes lineage, because ``lineage_group_id`` is always narrower than the
  family that contains it. Task 3 in fact *defaults* lineage to
  ``"{family}:{origin}"``, so keying on lineage first would have split two
  members of one family into two independent origins -- the exact inflation this
  module exists to prevent, arrived at by trying to be more precise.

Lineage is still carried on the group for traceability, and still separates
repeated renderings of one claim inside a family; it just does not decide
independence.

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

    The originating family, and nothing narrower. Two claims from one family are
    one origin however many vendor ids or lineage groups sit inside it, which is
    what rule C of the independence model requires.
    """
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
            lineage_group_ids=tuple(
                sorted({item.lineage_group_id for item in members if item.lineage_group_id})
            ),
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
