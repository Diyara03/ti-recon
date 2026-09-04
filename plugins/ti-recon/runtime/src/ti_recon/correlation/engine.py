"""Turning provider results into graph knowledge (Task 14).

The engine reads only what providers stated explicitly: the objects and
relationships in a :class:`~ti_recon.providers.result.ProviderResultEnvelope`.
Nothing here parses evidence prose looking for indicators. A regex over a
description would invent relationships nobody asserted and attribute them to the
provider, and the failure mode is silent — a plausible edge with a real provider's
name on it. Where a provider knows something the graph needs, the fix is a small
change in that provider's normalizer to emit a relationship; the engine stays
provider-neutral, and a test reads the AST to keep it that way.

What ingestion does, in order
-----------------------------

1. place the enriched target as a node,
2. place the objects the providers returned,
3. resolve exact identity, merging files by digest,
4. validate each relationship against the canonical vocabulary,
5. flip a backwards relationship onto its canonical orientation,
6. fold its provenance onto the semantic edge as an assertion,
7. derive the one structural relationship TI Recon may state itself,
8. record what the ceilings refused.

Order independence
------------------

Feeding GTI, Hybrid Analysis and URLhaus in any sequence produces the same nodes,
the same edges and the same assertions. Identity comes from canonical keys rather
than arrival order, edge keys carry no provider, and assertion deduplication is by
value. The one thing that legitimately depends on order is the hop at which a node
was *discovered*, and even that keeps the minimum rather than the first.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ti_recon.correlation.graph import InvestigationGraph
from ti_recon.correlation.identity import FileIdentityResolver, node_key_for
from ti_recon.correlation.models import (
    CorrelationIssue,
    CorrelationIssueType,
    GraphNode,
    NodeOccurrence,
    RelationBasis,
    RelationshipAssertion,
)
from ti_recon.correlation.relationships import definition_for
from ti_recon.enums import EvidenceClass, IntelObjectType, RelationshipType
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.models.relationship import Relationship
from ti_recon.normalization import NormalizationError, normalize_domain, normalize_ip
from ti_recon.providers.result import ProviderResultEnvelope

__all__ = ["CorrelationEngine", "IngestionSummary"]

#: An evidence class that means the provider watched it happen.
#:
#: A live page load is `DIRECT_OBSERVATION`; a passive-DNS row, a curated dataset
#: entry and a relationship expansion are records somebody keeps. Both are
#: intelligence and they support different conclusions, so the graph keeps them
#: apart rather than calling everything "observed".
#:
#: The class is only *one* of the two ways a provider can say it watched
#: something. The other is `Relationship.directly_observed`, which a provider sets
#: on the link itself — necessary because the two properties are orthogonal: a
#: sandbox's contacted domain is `EvidenceClass.CONTEXT`, since it accuses nobody,
#: and simultaneously something the sandbox watched happen.
#:
#: Either signal earns `PROVIDER_OBSERVED`; neither leaves `PROVIDER_REPORTED`.
#: Both are things a provider must assert, so silence is never read as
#: observation: a 2019 database row cannot become an eyewitness account.
_OBSERVED_CLASSES: frozenset[EvidenceClass] = frozenset({EvidenceClass.DIRECT_OBSERVATION})


@dataclass(frozen=True, slots=True)
class IngestionSummary:
    """What one provider result added."""

    provider_id: str
    nodes_added: int = 0
    edges_added: int = 0
    assertions_added: int = 0
    identity_merges: int = 0
    issues: tuple[CorrelationIssue, ...] = ()


@dataclass
class CorrelationEngine:
    """Builds one investigation graph from provider results.

    Pure: no network, no credential, no adapter, no clock. Everything it needs
    arrives as an argument, which is also what makes the whole of Task 14 testable
    without a fixture server.
    """

    graph: InvestigationGraph
    _files: FileIdentityResolver = field(default_factory=FileIdentityResolver)

    def add_root(self, target: IntelObject) -> str:
        """Place the investigation's own observable, before anybody reports on it."""
        node_key = self._resolve_key(target)
        self.graph.upsert_node(
            GraphNode(
                node_key=node_key,
                intel_object=target,
                discovered_at_hop=0,
                is_root=True,
                aliases=self._files.aliases_for(node_key),
            )
        )
        if self.graph.root_key is None:
            self.graph.root_key = node_key
        self._derive_structural_edges(target, node_key, hop=0)
        return node_key

    def ingest(
        self,
        envelope: ProviderResultEnvelope,
        *,
        hop: int = 0,
        anchor_key: str | None = None,
    ) -> IngestionSummary:
        """Fold one provider result into the graph.

        ``anchor_key`` is the node this lookup was *about*. Several providers
        relate their findings to the observable without returning it among their
        objects — the subject is the request, not a discovery — so without the
        anchor every one of those relationships looks like it points at something
        absent, and the whole result would arrive as a pile of unlinked nodes.
        """
        before_nodes = self.graph.node_count
        before_edges = self.graph.edge_count
        before_assertions = self.graph.assertion_count
        issues: list[CorrelationIssue] = []
        merges = 0

        evidence_by_id = {item.id: item for item in envelope.evidence}
        # Object id (per-result UUID) -> canonical node key. Relationships address
        # objects by the ids minted inside this one envelope, so the mapping is
        # rebuilt per result and never leaks between them.
        keys: dict[str, str] = {}
        linked: set[str] = set()
        anchor = anchor_key if anchor_key is not None else self.graph.root_key
        if anchor is not None and self.graph.node(anchor) is not None:
            # Every id the provider's own evidence calls the subject resolves to
            # the node this lookup was about.
            for item in envelope.evidence:
                keys.setdefault(item.subject_object_id, anchor)

        for related in envelope.objects:
            key, merged, issue = self._place(related, envelope.provider, hop=hop)
            if issue is not None:
                issues.append(issue)
                self.graph.add_issue(issue)
            if key is None:
                continue
            keys[related.id] = key
            merges += int(merged)

        for relationship in envelope.relationships:
            issue = self._ingest_relationship(
                relationship, envelope, keys, evidence_by_id, linked, hop=hop
            )
            if issue is not None:
                issues.append(issue)
                self.graph.add_issue(issue)

        self._mark_unlinked(envelope, keys, linked, hop=hop)

        return IngestionSummary(
            provider_id=envelope.provider,
            nodes_added=self.graph.node_count - before_nodes,
            edges_added=self.graph.edge_count - before_edges,
            assertions_added=self.graph.assertion_count - before_assertions,
            identity_merges=merges,
            issues=tuple(issues),
        )

    # ------------------------------------------------------------------ #
    # Nodes
    # ------------------------------------------------------------------ #

    def _resolve_key(self, intel_object: IntelObject) -> str:
        resolution = self._files.resolve(intel_object)
        return resolution.node_key

    def _place(
        self, intel_object: IntelObject, provider_id: str, *, hop: int
    ) -> tuple[str | None, bool, CorrelationIssue | None]:
        """Insert a related object, resolving its identity first."""
        resolution = self._files.resolve(intel_object)
        node = GraphNode(
            node_key=resolution.node_key,
            intel_object=intel_object,
            identity_basis=resolution.basis,
            discovered_at_hop=hop,
            aliases=self._files.aliases_for(resolution.node_key),
        )
        placed = self.graph.upsert_node(node)
        if placed is None:
            return None, False, None
        # Aliases are refreshed after the merge so a node found by MD5 and later by
        # SHA-256 ends up knowing both, whichever arrived first.
        self.graph.set_aliases(resolution.node_key, self._files.aliases_for(resolution.node_key))
        return resolution.node_key, resolution.merged, resolution.issue

    def _mark_unlinked(
        self,
        envelope: ProviderResultEnvelope,
        keys: dict[str, str],
        linked: set[str],
        *,
        hop: int,
    ) -> None:
        """Record how each object was mentioned: with a relationship, or bare.

        An object a provider returned without saying how it relates to anything is
        graphed — throwing it away would lose a real finding — but it is marked,
        and an unlinked object is never automatically pivoted. Inventing a
        `related-to` edge to make the graph connected would fabricate a claim
        nobody made, and the fabrication would then look like grounds for querying
        third parties about it.
        """
        for object_id, node_key in keys.items():
            del object_id
            family = _source_family_for(envelope)
            self.graph.upsert_node(
                GraphNode(
                    node_key=node_key,
                    intel_object=self._object_for(node_key),
                    discovered_at_hop=hop,
                ),
                occurrence=NodeOccurrence(
                    provider_id=envelope.provider,
                    source_family=family,
                    lineage_group_id=_lineage_for(envelope),
                    hop=hop,
                    unlinked=node_key not in linked,
                ),
            )

    def _object_for(self, node_key: str) -> IntelObject:
        node = self.graph.node(node_key)
        if node is None:  # pragma: no cover - only reachable if a ceiling refused
            msg = f"no node for {node_key}"
            raise KeyError(msg)
        return node.intel_object

    # ------------------------------------------------------------------ #
    # Relationships
    # ------------------------------------------------------------------ #

    def _ingest_relationship(
        self,
        relationship: Relationship,
        envelope: ProviderResultEnvelope,
        keys: dict[str, str],
        evidence_by_id: dict[str, Evidence],
        linked: set[str],
        *,
        hop: int,
    ) -> CorrelationIssue | None:
        """Validate, orient and record one provider relationship."""
        source_key = keys.get(relationship.source_object_id)
        target_key = keys.get(relationship.target_object_id)
        if source_key is None or target_key is None:
            return CorrelationIssue(
                issue_type=CorrelationIssueType.DANGLING_RELATIONSHIP,
                detail=f"{relationship.relationship_type.value} references an absent object",
                provider_id=envelope.provider,
            )
        if source_key == target_key:
            # Two records that turned out to be one object. The relationship has
            # nothing left to say, and a self-loop would be an artifact of the
            # merge rather than something a provider claimed.
            linked.add(source_key)
            return None

        definition = definition_for(relationship.relationship_type)
        if definition is None:
            return CorrelationIssue(
                issue_type=CorrelationIssueType.UNKNOWN_RELATIONSHIP,
                detail=f"no canonical definition for {relationship.relationship_type.value}",
                node_keys=(source_key, target_key),
                provider_id=envelope.provider,
            )

        source_node, target_node = self.graph.node(source_key), self.graph.node(target_key)
        if source_node is None or target_node is None:  # pragma: no cover - ceiling only
            return None
        source_type, target_type = source_node.object_type, target_node.object_type

        if definition.accepts(source_type, target_type):
            oriented = (source_key, target_key)
        elif definition.accepts_inverted(source_type, target_type):
            # Written the other way round. Flipping it onto the canonical
            # orientation is what lets "URL served this file" and "file came from
            # this URL" be one edge with two assertions instead of two edges that
            # look like unrelated facts.
            oriented = (target_key, source_key)
        else:
            return CorrelationIssue(
                issue_type=CorrelationIssueType.ENDPOINT_TYPE_MISMATCH,
                detail=(
                    f"{relationship.relationship_type.value} does not relate "
                    f"{source_type.value} to {target_type.value}"
                ),
                node_keys=(source_key, target_key),
                provider_id=envelope.provider,
            )

        evidence = next(
            (evidence_by_id[ref] for ref in relationship.evidence_refs if ref in evidence_by_id),
            None,
        )
        assertion = self._assertion_for(relationship, evidence, envelope, hop=hop)
        self.graph.add_assertion(
            source_key=oriented[0],
            relationship_type=relationship.relationship_type,
            target_key=oriented[1],
            assertion=assertion,
        )
        linked.update(oriented)
        return None

    def _assertion_for(
        self,
        relationship: Relationship,
        evidence: Evidence | None,
        envelope: ProviderResultEnvelope,
        *,
        hop: int,
    ) -> RelationshipAssertion:
        """Build the assertion, taking provenance from the evidence behind it.

        The evidence is where lineage lives, so a relayed relationship keeps the
        origin of whoever produced it: a VirusTotal figure relayed through URLhaus
        is transported by urlhaus and originated by virustotal, and the graph must
        never let that read as URLhaus having seen it.
        """
        if evidence is None:
            # A relationship whose evidence did not travel with it. The transport
            # is still known — this envelope — but nothing may be assumed about
            # who originally produced it, so origin falls back to the transport
            # rather than being invented.
            return RelationshipAssertion(
                basis=(
                    RelationBasis.PROVIDER_OBSERVED
                    if relationship.directly_observed
                    else RelationBasis.PROVIDER_REPORTED
                ),
                transport_provider=envelope.provider,
                origin_provider=envelope.provider,
                source_family=envelope.provider,
                raw_relationship_type=relationship.raw_relationship_type,
                first_seen=relationship.first_seen,
                last_seen=relationship.last_seen,
                hop=hop,
            )
        observed = relationship.directly_observed or evidence.evidence_class in _OBSERVED_CLASSES
        return RelationshipAssertion(
            basis=(
                RelationBasis.PROVIDER_OBSERVED if observed else RelationBasis.PROVIDER_REPORTED
            ),
            transport_provider=evidence.transport_provider,
            origin_provider=evidence.origin_provider,
            source_family=evidence.source_family,
            lineage_group_id=evidence.lineage_group_id,
            raw_relationship_type=relationship.raw_relationship_type,
            first_seen=relationship.first_seen or evidence.first_seen,
            last_seen=relationship.last_seen or evidence.last_seen,
            observed_at=evidence.observed_at,
            evidence_id=evidence.id,
            hop=hop,
        )

    # ------------------------------------------------------------------ #
    # Structural relationships
    # ------------------------------------------------------------------ #

    def _derive_structural_edges(
        self, intel_object: IntelObject, node_key: str, *, hop: int
    ) -> None:
        """The one relationship TI Recon may state on its own: a URL's host.

        Parsed from the authority the URL already carries — no resolution, no DNS,
        no network. It lands on the same canonical edge a provider would assert,
        marked :attr:`RelationBasis.ENGINE_DERIVED` with no provider and no source
        family, so it can never be counted as somebody having observed something.
        """
        if intel_object.object_type is not IntelObjectType.URL:
            return
        host = _host_object(intel_object)
        if host is None:
            return
        host_key = node_key_for(host)
        if host_key == node_key:  # pragma: no cover - a URL is never its own host
            return
        placed = self.graph.upsert_node(
            GraphNode(intel_object=host, node_key=host_key, discovered_at_hop=hop)
        )
        if placed is None:
            return
        self.graph.add_assertion(
            source_key=host_key,
            relationship_type=RelationshipType.HOSTS,
            target_key=node_key,
            assertion=RelationshipAssertion(basis=RelationBasis.ENGINE_DERIVED, hop=hop),
        )

    def derive_structural_edges_for_graph(self) -> None:
        """Derive URL-host relationships for every URL currently in the graph.

        Run after ingestion so URLs a provider returned get the same structural
        treatment as the ones TI Recon was asked about.
        """
        for node in self.graph.nodes:
            if node.object_type is IntelObjectType.URL:
                self._derive_structural_edges(
                    node.intel_object, node.node_key, hop=node.discovered_at_hop
                )


def _host_object(url_object: IntelObject) -> IntelObject | None:
    """The host inside a URL, as a domain or address object.

    Parsed out of the canonical URL, never searched for: a path or a query string
    that happens to look like a hostname is not the authority, and a substring
    match is how a living-off-trusted-sites payload gets attributed to the wrong
    host.
    """
    remainder = url_object.canonical_value.split("://", 1)[-1]
    authority = remainder.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    authority = authority.rpartition("@")[2]
    if authority.startswith("["):
        host = authority[1:].partition("]")[0]
    else:
        host = authority.partition(":")[0]
    if not host:
        return None
    for parse in (normalize_ip, normalize_domain):
        try:
            return parse(host)
        except NormalizationError:
            continue
    return None


def _source_family_for(envelope: ProviderResultEnvelope) -> str:
    """The family this result belongs to, from its own evidence.

    Read from the evidence rather than assumed from the provider id, because three
    abuse.ch platforms share one family and a node occurrence that said otherwise
    would make one ecosystem look like three sources.
    """
    return next((item.source_family for item in envelope.evidence), envelope.provider)


def _lineage_for(envelope: ProviderResultEnvelope) -> str:
    return next((item.lineage_group_id for item in envelope.evidence), "")
