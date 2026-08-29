"""Which claims are genuinely separate sources (Task 17B).

The single most consequential question in fusion, and the one a naive engine gets
wrong by default. Five providers repeating one upstream feed is one observation
seen five times, and a system that counted it as five confirmations would be
confidently wrong in precisely the cases where an analyst most needs it not to be.

Dependence is a **relation**, so grouping is its transitive closure
-------------------------------------------------------------------

Three pieces of provenance each make two claims dependent, and any one of them
is enough:

* the same ``source_family`` -- three abuse.ch datasets are one organisation;
* the same ``origin_provider`` -- whoever actually produced the information,
  however many transports relayed it;
* the same ``lineage_group_id`` -- one provider's repeated renderings of one
  finding.

Those are *edges*, not a precedence order, and the difference matters. Picking
one key and partitioning by it loses every dependence the other two would have
found. A relay that crosses families is the case that exposes it: two claims can
carry different families while naming the same origin, and a family-only
partition calls them two independent confirmations when they are one source seen
twice.

So claims are unioned into connected components. If A shares a family with B and
B shares an origin with C, then A, B and C are one origin -- even though A and C
have nothing directly in common. Any single-key scheme would have counted C as
fresh corroboration.

> Two bugs live in this file's history, and both came from trying to be precise
> with one key. Keying on lineage first split one family into several origins,
> because Task 3 *defaults* ``lineage_group_id`` to ``"{family}:{origin}"``.
> Keying on family alone then missed cross-family relays. Neither is a rule that
> was too weak; both were rules that were too narrow.

Nothing is discarded
--------------------

Collapsing a component does not delete a claim. Every claim stays visible in the
trace with its own provenance and its own semantic -- two dependent sources can
still report a C2 association and a malware-distribution claim as two distinct
facts. What collapses is only the ability to *corroborate* something already
counted. A relayed finding is a real finding.

Note the deliberate asymmetry: independence has to be *earned* by provenance.
Two claims are joined the moment any one edge says they are dependent, and two
different vendor ids are never on their own evidence that they are not.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence

from ti_recon.reasoning.claims.models import NormalizedClaim
from ti_recon.reasoning.fusion.models import IndependenceGroup, SupportBreadth

__all__ = [
    "breadth_of",
    "dependence_keys_for",
    "independence_groups",
    "independence_index",
]


def dependence_keys_for(claim: NormalizedClaim) -> tuple[str, ...]:
    """Every provenance key that makes this claim dependent on another.

    Each key is an edge, not a ranking. A claim joins any component that shares
    any one of them, which is what stops a relay crossing a family boundary from
    reading as a second source.
    """
    keys = [f"family:{claim.source_family}", f"origin:{claim.origin_provider}"]
    if claim.lineage_group_id:
        keys.append(f"lineage:{claim.lineage_group_id}")
    return tuple(keys)


def independence_groups(claims: Iterable[NormalizedClaim]) -> tuple[IndependenceGroup, ...]:
    """Partition claims into components that are not independent of one another.

    A union-find over :func:`dependence_keys_for`, so dependence composes: sharing
    a family with one claim and an origin with another puts all three in one
    group. Deterministically ordered by key, so two runs that discovered the same
    claims in a different sequence produce identical groups.
    """
    parent: dict[str, str] = {}

    def find(key: str) -> str:
        parent.setdefault(key, key)
        root = key
        while parent[root] != root:
            root = parent[root]
        while parent[key] != root:  # path compression
            parent[key], key = root, parent[key]
        return root

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            # Lower key wins, so the representative never depends on input order.
            low, high = sorted((left_root, right_root))
            parent[high] = low

    ordered = list(claims)
    for claim in ordered:
        keys = dependence_keys_for(claim)
        for key in keys[1:]:
            union(keys[0], key)

    buckets: dict[str, list[NormalizedClaim]] = defaultdict(list)
    for claim in ordered:
        buckets[find(dependence_keys_for(claim)[0])].append(claim)

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


def independence_index(claims: Iterable[NormalizedClaim]) -> dict[str, str]:
    """Map each claim id to the key of the component it belongs to.

    The component is a property of the whole claim set rather than of one claim,
    because dependence composes: whether two claims are one source can depend on a
    third that links them. Callers asking "are these two independent?" must
    therefore resolve both through an index built over the same set.
    """
    return {
        claim_id: group.group_key
        for group in independence_groups(claims)
        for claim_id in group.claim_ids
    }


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
