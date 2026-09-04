"""The investigation graph itself (Task 14).

Plain Python: two dicts and an adjacency index. No graph database — at
investigation scale the query patterns are "neighbours of a node" and "walk one
hop", both of which a dict answers instantly, and adopting Neo4j to do that would
buy an operational dependency and a second query language for nothing. Persistence,
when it arrives, can be PostgreSQL without any of the semantics here changing.

Everything is deterministic and bounded. Insertion order never affects identity,
iteration is sorted rather than insertion-ordered, and every collection has a
ceiling that reports what it dropped instead of silently stopping.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ti_recon.correlation.models import (
    DEFAULT_GRAPH_LIMITS,
    CorrelationIssue,
    CorrelationIssueType,
    GraphEdge,
    GraphLimits,
    GraphNode,
    GraphTruncation,
    NodeOccurrence,
    RelationshipAssertion,
)
from ti_recon.enums import RelationshipType

__all__ = ["EdgeKey", "InvestigationGraph"]

#: ``(source key, relationship type, target key)`` — provider-free by design.
EdgeKey = tuple[str, RelationshipType, str]


@dataclass
class InvestigationGraph:
    """One investigation's nodes, edges and assertions.

    Scoped to a user and an investigation, and deliberately not shared. Two
    analysts investigating the same domain produce the same canonical node keys
    and two entirely separate graphs: correlation is investigation knowledge, and
    letting one analyst's pivots warm another's graph would leak who is looking at
    what. Provider *caching* is Task 6's business and stays there.
    """

    investigation_id: str
    authenticated_user_id: str
    root_key: str | None = None
    limits: GraphLimits = DEFAULT_GRAPH_LIMITS

    _nodes: dict[str, GraphNode] = field(default_factory=dict)
    _edges: dict[EdgeKey, GraphEdge] = field(default_factory=dict)
    _out: dict[str, set[EdgeKey]] = field(default_factory=lambda: defaultdict(set))
    _in: dict[str, set[EdgeKey]] = field(default_factory=lambda: defaultdict(set))
    truncation: GraphTruncation = field(default_factory=GraphTruncation)
    issues: list[CorrelationIssue] = field(default_factory=list)
    #: Assertion dedupe keys already seen, per edge. What stops one provider's
    #: three renderings of one relationship becoming three corroborations.
    _assertion_keys: dict[EdgeKey, set[tuple[str, str, str, str, str]]] = field(
        default_factory=lambda: defaultdict(set)
    )
    assertions_deduplicated: int = 0

    # ------------------------------------------------------------------ #
    # Reading
    # ------------------------------------------------------------------ #

    @property
    def nodes(self) -> tuple[GraphNode, ...]:
        """Every node, ordered by key so two equal graphs serialize equal."""
        return tuple(self._nodes[key] for key in sorted(self._nodes))

    @property
    def edges(self) -> tuple[GraphEdge, ...]:
        return tuple(self._edges[key] for key in sorted(self._edges, key=_edge_sort_key))

    @property
    def root(self) -> GraphNode | None:
        return self._nodes.get(self.root_key) if self.root_key else None

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    @property
    def assertion_count(self) -> int:
        return sum(len(edge.assertions) for edge in self._edges.values())

    def node(self, node_key: str) -> GraphNode | None:
        return self._nodes.get(node_key)

    def edge(self, key: EdgeKey) -> GraphEdge | None:
        return self._edges.get(key)

    def edges_from(self, node_key: str) -> tuple[GraphEdge, ...]:
        return tuple(
            self._edges[key] for key in sorted(self._out.get(node_key, set()), key=_edge_sort_key)
        )

    def edges_into(self, node_key: str) -> tuple[GraphEdge, ...]:
        return tuple(
            self._edges[key] for key in sorted(self._in.get(node_key, set()), key=_edge_sort_key)
        )

    def incident_edges(self, node_key: str) -> tuple[GraphEdge, ...]:
        """Every edge touching a node, in either direction.

        Traversal is undirected even though storage is not: an analyst asking what
        a node is connected to does not care which way a provider happened to
        phrase it.
        """
        keys = self._out.get(node_key, set()) | self._in.get(node_key, set())
        return tuple(self._edges[key] for key in sorted(keys, key=_edge_sort_key))

    def neighbours(self, node_key: str) -> tuple[str, ...]:
        found = {
            other
            for edge in self.incident_edges(node_key)
            for other in (edge.source_key, edge.target_key)
            if other != node_key
        }
        return tuple(sorted(found))

    def fan_out(self, node_key: str) -> int:
        """How many distinct nodes this one links to.

        A pivot ranking input: a domain reached from a hub that touches two hundred
        others is a weaker lead than one reached from a node with two links.
        """
        return len(self.neighbours(node_key))

    # ------------------------------------------------------------------ #
    # Writing
    # ------------------------------------------------------------------ #

    def add_issue(self, issue: CorrelationIssue) -> None:
        self.issues.append(issue)

    def upsert_node(
        self,
        node: GraphNode,
        *,
        occurrence: NodeOccurrence | None = None,
    ) -> GraphNode | None:
        """Insert a node or fold a new sighting into an existing one.

        Returns ``None`` when the node ceiling refused it — never an exception, and
        never a silent no-op: the refusal is counted and recorded once.
        """
        existing = self._nodes.get(node.node_key)
        if existing is None:
            if len(self._nodes) >= self.limits.max_nodes:
                self._record_limit("nodes", node.node_key)
                return None
            merged = node
        else:
            merged = existing.model_copy(
                update={
                    # The earliest hop wins: a node found at hop 2 and again at
                    # hop 1 was reachable in one step, and pivot distance has to
                    # reflect the shortest path rather than the discovery order.
                    "discovered_at_hop": min(existing.discovered_at_hop, node.discovered_at_hop),
                    "is_root": existing.is_root or node.is_root,
                    "aliases": _merge_sorted(existing.aliases, node.aliases),
                    "enriched": existing.enriched or node.enriched,
                }
            )
        if occurrence is not None:
            merged = merged.model_copy(
                update={"occurrences": _merge_occurrences(merged.occurrences, occurrence)}
            )
        self._nodes[merged.node_key] = merged
        return merged

    def set_aliases(self, node_key: str, aliases: tuple[str, ...]) -> None:
        node = self._nodes.get(node_key)
        if node is not None:
            self._nodes[node_key] = node.model_copy(update={"aliases": aliases})

    def mark_enriched(self, node_key: str) -> None:
        node = self._nodes.get(node_key)
        if node is not None:
            self._nodes[node_key] = node.model_copy(update={"enriched": True})

    def add_assertion(
        self,
        *,
        source_key: str,
        relationship_type: RelationshipType,
        target_key: str,
        assertion: RelationshipAssertion,
    ) -> GraphEdge | None:
        """Attach an assertion to its semantic edge, creating the edge if needed.

        The edge key carries no provider, so two providers claiming the same thing
        meet on one edge. Deduplication happens per edge on the assertion's own
        key, so one provider's repeated renderings of a single relationship
        collapse while two providers' independent claims both survive.
        """
        key: EdgeKey = (source_key, relationship_type, target_key)
        edge = self._edges.get(key)
        if edge is None:
            if len(self._edges) >= self.limits.max_edges:
                self._record_limit("edges", f"{source_key} -> {target_key}")
                return None
            edge = GraphEdge(
                source_key=source_key, relationship_type=relationship_type, target_key=target_key
            )
            self._edges[key] = edge
            self._out[source_key].add(key)
            self._in[target_key].add(key)

        seen = self._assertion_keys[key]
        if assertion.dedupe_key in seen:
            self.assertions_deduplicated += 1
            return edge
        if (
            len(edge.assertions) >= self.limits.max_assertions_per_edge
            or self.assertion_count >= self.limits.max_assertions
        ):
            self._edges[key] = edge.model_copy(
                update={"assertions_truncated": edge.assertions_truncated + 1}
            )
            self.truncation = self.truncation.model_copy(
                update={"assertions_dropped": self.truncation.assertions_dropped + 1}
            )
            self._record_limit("assertions", f"{source_key} -> {target_key}")
            return self._edges[key]

        seen.add(assertion.dedupe_key)
        updated = edge.model_copy(update={"assertions": (*edge.assertions, assertion)})
        self._edges[key] = updated
        return updated

    # ------------------------------------------------------------------ #
    # Limits
    # ------------------------------------------------------------------ #

    def _record_limit(self, what: str, detail: str) -> None:
        """Count the drop, and say so once rather than once per dropped item."""
        if what == "nodes":
            self.truncation = self.truncation.model_copy(
                update={"nodes_dropped": self.truncation.nodes_dropped + 1}
            )
        elif what == "edges":
            self.truncation = self.truncation.model_copy(
                update={"edges_dropped": self.truncation.edges_dropped + 1}
            )
        already_reported = any(
            issue.issue_type is CorrelationIssueType.GRAPH_LIMIT_REACHED
            and issue.detail.startswith(what)
            for issue in self.issues
        )
        if already_reported:
            return
        self.issues.append(
            CorrelationIssue(
                issue_type=CorrelationIssueType.GRAPH_LIMIT_REACHED,
                detail=f"{what} ceiling reached; further items dropped",
                node_keys=(detail[:300],) if what == "nodes" else (),
            )
        )


def _edge_sort_key(key: EdgeKey) -> tuple[str, str, str]:
    return (key[0], key[1].value, key[2])


def _merge_sorted(existing: tuple[str, ...], incoming: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(existing) | set(incoming))) if incoming else existing


def _merge_occurrences(
    existing: tuple[NodeOccurrence, ...], incoming: NodeOccurrence
) -> tuple[NodeOccurrence, ...]:
    """Add a sighting, collapsing an exact repeat.

    An occurrence that stops being unlinked is upgraded in place: the provider
    that first returned a bare object and later related it did not sight it twice.
    """
    linked_now = not incoming.unlinked
    kept: list[NodeOccurrence] = []
    matched = False
    for item in existing:
        same = (
            item.provider_id == incoming.provider_id
            and item.source_family == incoming.source_family
            and item.lineage_group_id == incoming.lineage_group_id
            and item.hop == incoming.hop
        )
        if same:
            matched = True
            kept.append(
                item.model_copy(update={"unlinked": item.unlinked and not linked_now})
                if item.unlinked and linked_now
                else item
            )
        else:
            kept.append(item)
    if not matched:
        kept.append(incoming)
    return tuple(
        sorted(
            kept,
            key=lambda item: (
                item.hop,
                item.source_family,
                item.provider_id,
                item.lineage_group_id,
            ),
        )
    )
