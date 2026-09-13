"""Choosing what is worth asking about next (Task 14).

Correlation learns that a sample contacted a domain. This module decides whether
that domain is worth *considering* as a pivot, and Task 13 — not this module —
decides which providers would answer. Three separate decisions, kept separate on
purpose: conflating discovery with execution is how one submitted hash becomes
four hundred third-party queries.

Ranking is lexicographic
------------------------

No weighted score. There is no evidence for any set of weights over "directness"
and "fan-out", and a made-up formula produces a number that looks principled,
cannot be explained to an analyst, and shifts unpredictably when a provider starts
returning more objects. Instead the factors are compared in a fixed order, and any
decision can be explained by naming the first one that separated two candidates.

Notably absent from the ordering: how many source families asserted the
relationship. It is recorded and displayed, because two independent families
observing the same link is genuinely more interesting than one — but turning that
into rank here would be the first step towards "two providers agreed, therefore
malicious", which is a fusion judgement this layer must not make.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

from pydantic import Field

from ti_recon.correlation.graph import InvestigationGraph
from ti_recon.correlation.models import GraphEdge, GraphNode, PivotSafetyClass
from ti_recon.correlation.policy import (
    MAX_AUTOMATIC_PIVOT_HOP,
    PivotMode,
    PivotPolicy,
    PivotSelectionReason,
    PivotSkipReason,
)
from ti_recon.correlation.relationships import definition_for
from ti_recon.enums import IntelObjectType, RelationshipType
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.normalization.errors import NormalizationError
from ti_recon.security import SENSITIVE_KEY_PATTERN

__all__ = [
    "PIVOT_RANKING_FACTORS",
    "SAFETY_CLASS_ORDER",
    "PivotCandidate",
    "PivotPlanner",
    "is_sensitive_url",
    "non_global_address",
]

#: Object types a pivot can actually be submitted as. Anything else — an AS, a
#: certificate, a malware family — has no provider that takes it as a subject, so
#: it is a graph node and never a query.
PIVOTABLE_TYPES: Final[frozenset[IntelObjectType]] = frozenset(
    {
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.IPV6_ADDR,
        IntelObjectType.DOMAIN_NAME,
        IntelObjectType.URL,
        IntelObjectType.FILE,
    }
)

#: Directness order, most direct first. An artifact the investigation produced
#: outranks behaviour, which outranks shared infrastructure.
SAFETY_CLASS_ORDER: Final[dict[PivotSafetyClass, int]] = {
    PivotSafetyClass.DIRECT_ARTIFACT: 0,
    PivotSafetyClass.DIRECT_BEHAVIOR: 1,
    PivotSafetyClass.INFRASTRUCTURE_ASSOCIATION: 2,
    PivotSafetyClass.STRUCTURAL: 3,
    PivotSafetyClass.GENERIC_ASSOCIATION: 4,
}

#: The ranking, as data, so the documentation and the code cannot drift.
PIVOT_RANKING_FACTORS: Final[tuple[str, ...]] = (
    "explicitly_selected",
    "relationship_directness",
    "automatically_eligible",
    "not_previously_enriched",
    "supported_target_type",
    "relationship_fan_out",
    "distance_from_root",
    "node_key",
)


class PivotCandidate(FrozenTiReconModel):
    """A graph node that could be enriched, and everything behind that judgement."""

    target_node_key: str = Field(min_length=1, max_length=300)
    target_type: IntelObjectType
    #: The node this was reached from — the "why is this here" half of the trace.
    discovered_from_key: str = Field(min_length=1, max_length=300)
    edge_keys: tuple[str, ...] = ()
    relationship_types: tuple[RelationshipType, ...] = ()
    hop: int = Field(ge=0)
    safety_class: PivotSafetyClass
    #: Families that asserted the relationships reaching this node. Displayed,
    #: never ranked on, and never turned into confidence.
    source_families: tuple[str, ...] = ()
    fan_out: int = Field(default=0, ge=0)
    explicitly_selected: bool = False
    eligible_for_enrichment: bool = False
    selection_reason: PivotSelectionReason | None = None
    skip_reason: PivotSkipReason | None = None

    @property
    def sort_key(self) -> tuple[int, int, int, int, int, int, int, str]:
        """Lexicographic, every element "lower is better"."""
        return (
            0 if self.explicitly_selected else 1,
            SAFETY_CLASS_ORDER[self.safety_class],
            0 if self.eligible_for_enrichment else 1,
            0 if self.skip_reason is not PivotSkipReason.ALREADY_ENRICHED else 1,
            0 if self.target_type in PIVOTABLE_TYPES else 1,
            self.fan_out,
            self.hop,
            self.target_node_key,
        )


def is_canonical_observable(intel_object: IntelObject) -> bool:
    """Whether a provider-returned target is exactly what the normalizer would make of it.

    Related objects are built by provider normalizers from provider text, and
    several of them do less than the analyst-facing normalizer does: a domain
    kept in upper case, a URL with an unsupported scheme, a host carrying a
    port or an invisible character. Sending such a value to a third party would
    disclose something TI Recon would have refused from an analyst, and would
    fragment identity and cache keys. Fail closed: the value must normalize,
    to the same type, to the same canonical value.
    """
    try:
        normalized = normalize_observable(intel_object.canonical_value).intel_object
    except (NormalizationError, ValueError):
        return False
    return (
        normalized.object_type is intel_object.object_type
        and normalized.canonical_value == intel_object.canonical_value
    )


def non_global_address(intel_object: IntelObject) -> bool:
    """Whether this address must never be sent to a third party automatically.

    RFC1918, loopback, link-local, multicast, reserved, unspecified and
    documentation ranges. A sandbox routinely reports the analysis network's own
    addresses, and a customer's internal range is exactly the thing not to hand to
    an external service — the address is often more sensitive than the malware
    that touched it.

    ``is_global`` alone is not enough: a multicast address is not private, so a
    sandbox reporting 224.0.0.1 would sail straight past a single summary flag.
    Each property is therefore asked for explicitly.
    """
    if intel_object.object_type not in {IntelObjectType.IPV4_ADDR, IntelObjectType.IPV6_ADDR}:
        return False
    try:
        address = ipaddress.ip_address(intel_object.canonical_value)
    except ValueError:  # pragma: no cover - normalization already validated it
        # Unparseable is the safest possible thing to refuse to disclose.
        return True
    return (
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def is_sensitive_url(intel_object: IntelObject) -> bool:
    """Whether a URL carries material that must not be disclosed automatically.

    Userinfo, or a query parameter whose *name* looks like a credential. Only the
    name is inspected; the value is never read, logged or stored.

    The tempting fix — strip the query and look up what is left — is refused
    elsewhere by construction: that would be asking about a different observable
    and reporting the answer as though it were about this one. The host is a
    separate node and can be considered on its own merits.
    """
    if intel_object.object_type is not IntelObjectType.URL:
        return False
    parts = urlsplit(intel_object.canonical_value)
    if "@" in parts.netloc:
        return True
    return any(
        SENSITIVE_KEY_PATTERN.search(pair.split("=", 1)[0])
        for pair in parts.query.split("&")
        if pair
    )


@dataclass(frozen=True, slots=True)
class _Reach:
    """How a node was reached: the strongest relationship, and from where."""

    from_key: str
    edges: tuple[GraphEdge, ...]
    safety_class: PivotSafetyClass
    eligible: bool


class PivotPlanner:
    """Ranks graph nodes as pivot candidates. Performs no I/O of any kind."""

    def __init__(self, *, policy: PivotPolicy, max_candidates: int) -> None:
        self._policy = policy
        self._max_candidates = max_candidates

    def candidates(
        self, graph: InvestigationGraph, *, allow_remote_lookup: bool
    ) -> tuple[tuple[PivotCandidate, ...], int]:
        """Every considered node, ranked, plus how many the ceiling dropped.

        Skipped candidates are returned alongside selected ones: "why was this
        *not* followed" is the more common analyst question, and a candidate list
        that silently omitted its rejections would answer it with silence.
        """
        if self._policy.mode is PivotMode.NONE:
            return (), 0

        found: list[PivotCandidate] = []
        for node in graph.nodes:
            if node.is_root or node.node_key == graph.root_key:
                continue
            reach = self._reach_for(graph, node)
            if reach is None:
                continue
            found.append(
                self._candidate_for(graph, node, reach, allow_remote_lookup=allow_remote_lookup)
            )

        found.sort(key=lambda item: item.sort_key)
        dropped = max(0, len(found) - self._max_candidates)
        return tuple(found[: self._max_candidates]), dropped

    # ------------------------------------------------------------------ #
    # Reachability
    # ------------------------------------------------------------------ #

    def _reach_for(self, graph: InvestigationGraph, node: GraphNode) -> _Reach | None:
        """The most direct relationship reaching this node, if any.

        A node reached by several edges is still one candidate — the same domain
        named by three providers and two relationship kinds is one thing to ask
        about — and the strongest relationship decides its class.
        """
        edges = graph.incident_edges(node.node_key)
        if not edges:
            # A provider returned this object and never said how it relates to
            # anything. It is a real finding and stays visible as a candidate, with
            # the weakest class and no eligibility — the alternative, inventing a
            # `related-to` so the graph looks connected, would manufacture the very
            # justification for querying third parties about it.
            return _Reach(
                from_key=graph.root_key or node.node_key,
                edges=(),
                safety_class=PivotSafetyClass.GENERIC_ASSOCIATION,
                eligible=False,
            )
        best: tuple[int, GraphEdge] | None = None
        eligible = False
        for edge in edges:
            definition = definition_for(edge.relationship_type)
            if definition is None:  # pragma: no cover - unknown types never enter
                continue
            rank = SAFETY_CLASS_ORDER[definition.pivot_safety_class]
            if best is None or rank < best[0]:
                best = (rank, edge)
            # Eligibility is asked of the edge that *reaches* this node in the
            # direction the definition means. A file being dropped by something is
            # not a licence to go and ask about the parent.
            if definition.enrich_eligible and edge.target_key == node.node_key:
                eligible = True
        if best is None:  # pragma: no cover - defensive
            return None
        chosen = best[1]
        other = chosen.source_key if chosen.target_key == node.node_key else chosen.target_key
        definition = definition_for(chosen.relationship_type)
        assert definition is not None
        return _Reach(
            from_key=other,
            edges=edges,
            safety_class=definition.pivot_safety_class,
            eligible=eligible,
        )

    # ------------------------------------------------------------------ #
    # Judgement
    # ------------------------------------------------------------------ #

    def _candidate_for(
        self,
        graph: InvestigationGraph,
        node: GraphNode,
        reach: _Reach,
        *,
        allow_remote_lookup: bool,
    ) -> PivotCandidate:
        explicit = node.node_key in self._policy.explicit_targets
        families = tuple(
            sorted({family for edge in reach.edges for family in edge.asserting_source_families})
        )
        skip = self._skip_reason(
            graph, node, reach, explicit=explicit, allow_remote_lookup=allow_remote_lookup
        )
        return PivotCandidate(
            target_node_key=node.node_key,
            target_type=node.object_type,
            discovered_from_key=reach.from_key,
            edge_keys=tuple(
                sorted(
                    f"{edge.source_key}|{edge.relationship_type.value}|{edge.target_key}"
                    for edge in reach.edges
                )
            ),
            relationship_types=tuple(
                sorted(
                    {edge.relationship_type for edge in reach.edges}, key=lambda item: item.value
                )
            ),
            hop=node.discovered_at_hop,
            safety_class=reach.safety_class,
            source_families=families,
            fan_out=graph.fan_out(node.node_key),
            explicitly_selected=explicit,
            eligible_for_enrichment=skip is None,
            selection_reason=(
                self._selection_reason(reach, explicit=explicit) if skip is None else None
            ),
            skip_reason=skip,
        )

    def _skip_reason(
        self,
        graph: InvestigationGraph,
        node: GraphNode,
        reach: _Reach,
        *,
        explicit: bool,
        allow_remote_lookup: bool,
    ) -> PivotSkipReason | None:
        """Why this node will not be enriched, or ``None`` if it may be.

        Ordered so the reported reason is the one that actually decided it, and so
        the privacy rules are checked before anything an explicit selection could
        override — a caller naming a target does not make an internal address safe
        to disclose.
        """
        if node.object_type not in PIVOTABLE_TYPES:
            return PivotSkipReason.UNSUPPORTED_TARGET
        if not is_canonical_observable(node.intel_object):
            return PivotSkipReason.UNNORMALIZABLE_TARGET
        if non_global_address(node.intel_object):
            return PivotSkipReason.NON_GLOBAL_IP
        if is_sensitive_url(node.intel_object):
            return PivotSkipReason.SENSITIVE_URL
        if node.is_unlinked:
            return PivotSkipReason.UNLINKED_OBJECT
        if node.enriched:
            return PivotSkipReason.ALREADY_ENRICHED
        if node.discovered_at_hop >= MAX_AUTOMATIC_PIVOT_HOP + 1:
            return PivotSkipReason.HOP_LIMIT
        if self._policy.mode is not PivotMode.ENRICH:
            return PivotSkipReason.RECOMMEND_ONLY
        if not allow_remote_lookup or not self._policy.allow_remote_pivot_lookup:
            # Automatic pivoting is a remote-disclosure feature, so with it off
            # nothing is followed on its own. A target the caller named by hand
            # still runs, under a local-only constraint applied by Task 13's own
            # locality policy — no provider is named here.
            return None if explicit else PivotSkipReason.REMOTE_PIVOTS_DISABLED
        if explicit:
            return None
        if not reach.eligible:
            return PivotSkipReason.RELATION_NOT_ELIGIBLE
        if all(edge.is_engine_derived_only for edge in reach.edges):
            # Nothing but TI Recon's own parsing links this node to anything.
            # Deriving a host is not a reason to go and ask about it.
            return PivotSkipReason.RELATION_NOT_ELIGIBLE
        return None

    def _selection_reason(self, reach: _Reach, *, explicit: bool) -> PivotSelectionReason:
        if explicit:
            return PivotSelectionReason.EXPLICIT_SELECTION
        match reach.safety_class:
            case PivotSafetyClass.DIRECT_ARTIFACT:
                return PivotSelectionReason.DIRECT_ARTIFACT_RELATION
            case PivotSafetyClass.DIRECT_BEHAVIOR:
                return PivotSelectionReason.DIRECT_BEHAVIOR_RELATION
            case _:
                return PivotSelectionReason.ENRICHABLE_TARGET
