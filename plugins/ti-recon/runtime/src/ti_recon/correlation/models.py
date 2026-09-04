"""Investigation graph vocabulary (Task 14).

What this package builds is **one investigation's knowledge**, not a global
intelligence graph. It is scoped to a user and an investigation, held in memory,
and thrown away with the run. Two analysts looking at the same domain build two
graphs that never see each other.

Three ideas carry the design.

Identity is exact
-----------------

A node exists once per *observable identity*. Two records merge when they are the
same object, never when they resemble one another — not a shared ASN, a shared
/24, a shared certificate issuer, a shared malware family, a shared ssdeep. Those
are analytic signals and some of them are useful, but none of them is identity,
and a correlation engine that merges on resemblance produces a graph nobody can
audit.

An edge is a claim, not a fact
------------------------------

Two providers saying "this file contacted evil.example" is **one** semantic edge
carrying **two** assertions. Splitting them into two edges invents a second
relationship; collapsing them into one assertion loses a genuine independent
observation. :class:`GraphEdge` keeps the semantics and
:class:`RelationshipAssertion` keeps the provenance, and the source families that
asserted it stay visible for a later fusion layer to weigh — this layer weighs
nothing.

Derived is not observed
-----------------------

TI Recon can parse a URL and know its host. That is a real relationship and a
useful one, and it is *not* intelligence: it carries
:attr:`RelationBasis.ENGINE_DERIVED`, no provider and no source family, so it can
never be counted as somebody having observed something.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from pydantic import Field, model_validator

from ti_recon.enums import IntelObjectType, RelationshipType
from ti_recon.models.base import FrozenTiReconModel, UtcDatetime
from ti_recon.models.intel_object import IntelObject

__all__ = [
    "DEFAULT_GRAPH_LIMITS",
    "CorrelationIssue",
    "CorrelationIssueType",
    "GraphEdge",
    "GraphLimits",
    "GraphTruncation",
    "IdentityBasis",
    "NodeOccurrence",
    "PivotSafetyClass",
    "RelationBasis",
    "RelationshipAssertion",
]


class RelationBasis(StrEnum):
    """How a relationship came to be known.

    The distinction is not cosmetic. "A sandbox watched this sample resolve and
    connect" and "a passive-DNS aggregator holds a record saying these were once
    associated" support very different conclusions, and both differ from "TI Recon
    parsed the URL".
    """

    #: The provider observed it happen — sandbox execution, a live scan.
    PROVIDER_OBSERVED = "provider_observed"
    #: The provider holds a record of it. Passive DNS, historical hosting, a
    #: curated dataset entry. Real intelligence; not an eyewitness account.
    PROVIDER_REPORTED = "provider_reported"
    #: TI Recon derived it deterministically from the observable itself. Carries
    #: no provider and no source family, because nobody reported anything.
    ENGINE_DERIVED = "engine_derived"


class IdentityBasis(StrEnum):
    """Why two records were treated as the same object.

    Ordered from strongest to weakest, and never flattened: "these share a SHA-256"
    and "these share an MD5 and nothing contradicts it" are both merges, and only
    one of them would survive an adversary trying to force a collision.
    """

    #: Same canonical value for a non-file observable.
    CANONICAL_VALUE = "canonical_value"
    SHA256 = "sha256"
    SHA1 = "sha1"
    LEGACY_MD5 = "legacy_md5"
    #: A provider record that bound several digests to one sample.
    PROVIDER_MULTI_HASH_BINDING = "provider_multi_hash_binding"


class CorrelationIssueType(StrEnum):
    """A data-quality problem found while building the graph.

    Deliberately *not* :class:`~ti_recon.models.evidence.EvidenceConflict`, which
    relates two pieces of intelligence that disagree about the world. These are
    problems with the shape of the data: an object that cannot be identified, a
    relationship whose endpoints do not fit its meaning, a ceiling that was hit.
    Recording them as evidence conflicts would put plumbing failures in front of
    an analyst as though they were disagreements between sources.
    """

    #: Two records share a weaker hash but disagree on a stronger one.
    FILE_HASH_CONFLICT = "file_hash_conflict"
    #: A related object could not be turned into a node.
    INVALID_RELATED_OBJECT = "invalid_related_object"
    #: A relationship referenced an object that was not in the result.
    DANGLING_RELATIONSHIP = "dangling_relationship"
    #: The canonical vocabulary has no definition for this relationship type.
    UNKNOWN_RELATIONSHIP = "unknown_relationship"
    #: The endpoints do not match what the relationship means.
    ENDPOINT_TYPE_MISMATCH = "endpoint_type_mismatch"
    #: A ceiling stopped the graph growing.
    GRAPH_LIMIT_REACHED = "graph_limit_reached"


class PivotSafetyClass(StrEnum):
    """How directly a relationship ties its target to the investigation.

    A safety class says nothing about whether anything is malicious. It answers a
    narrower question: if TI Recon followed this link and asked third parties
    about what it found, would that be a defensible thing to have done
    automatically? A file dropped by the sample is squarely part of the
    investigation; a domain that once resolved to the same address is somebody
    else's neighbour.
    """

    #: An artifact this investigation directly produced or served.
    DIRECT_ARTIFACT = "direct_artifact"
    #: Behaviour attributed to the subject — contacted, redirected to.
    DIRECT_BEHAVIOR = "direct_behavior"
    #: Shared or historical infrastructure. Real, and frequently other people's.
    INFRASTRUCTURE_ASSOCIATION = "infrastructure_association"
    #: Derived from the observable's own structure.
    STRUCTURAL = "structural"
    #: An untyped or curated association with no artifact semantics.
    GENERIC_ASSOCIATION = "generic_association"


class NodeOccurrence(FrozenTiReconModel):
    """One provider result mentioning one node.

    Bounded provenance, not a copy of the evidence: the authoritative records stay
    in the provider result. What a node needs to be explainable is *who mentioned
    it, from which family, in which lineage group, and at which hop* — enough to
    answer "why is this here?" without turning the graph into a second evidence
    store.
    """

    provider_id: str = Field(min_length=1, max_length=64)
    source_family: str = Field(min_length=1, max_length=64)
    lineage_group_id: str = Field(default="", max_length=200)
    hop: int = Field(ge=0)
    #: ``True`` when the provider returned the object with no usable relationship.
    #: Such an object is graphed but never automatically pivoted: nobody said how
    #: it relates to anything.
    unlinked: bool = False


class RelationshipAssertion(FrozenTiReconModel):
    """One statement that a relationship exists.

    Provenance is carried exactly as Tasks 3-12 established it. ``transport`` is
    who handed TI Recon the record and ``origin`` is who produced it: when URLhaus
    relays a VirusTotal figure, transport is urlhaus and origin is virustotal, and
    the graph must never let that read as URLhaus having observed it.

    Times are per assertion for a reason. Two records of the same resolution, one
    from 2019 and one from 2026, are two observations — not evidence of a
    seven-year continuous association.
    """

    basis: RelationBasis
    #: Absent only for :attr:`RelationBasis.ENGINE_DERIVED`, which nobody reported.
    transport_provider: str | None = Field(default=None, min_length=1, max_length=64)
    origin_provider: str | None = Field(default=None, min_length=1, max_length=64)
    source_family: str | None = Field(default=None, min_length=1, max_length=64)
    lineage_group_id: str = Field(default="", max_length=200)
    #: The provider's own name for this relationship, kept so a canonical mapping
    #: can always be traced back and argued with.
    raw_relationship_type: str | None = Field(default=None, max_length=128)
    first_seen: UtcDatetime | None = None
    last_seen: UtcDatetime | None = None
    observed_at: UtcDatetime | None = None
    #: The evidence record behind this assertion, when the provider produced one.
    evidence_id: str | None = Field(default=None, max_length=64)
    hop: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _validate_assertion(self) -> RelationshipAssertion:
        derived = self.basis is RelationBasis.ENGINE_DERIVED
        named = self.transport_provider is not None or self.source_family is not None
        if derived and named:
            msg = "an engine-derived assertion names no provider and no source family"
            raise ValueError(msg)
        if not derived and (self.transport_provider is None or self.source_family is None):
            msg = "a provider assertion must name its transport provider and source family"
            raise ValueError(msg)
        if (
            self.first_seen is not None
            and self.last_seen is not None
            and self.last_seen < self.first_seen
        ):
            msg = "last_seen must not precede first_seen"
            raise ValueError(msg)
        return self

    @property
    def dedupe_key(self) -> tuple[str, str, str, str, str]:
        """What makes two assertions the same claim rather than two claims.

        One provider emitting a relationship in its evidence, in its related
        objects and again in a summary must not read as three corroborations. The
        lineage group is what ties those together, so it leads the key; the raw
        type is included because one provider genuinely can assert two different
        relationships between the same pair.
        """
        return (
            self.basis.value,
            self.source_family or "",
            self.lineage_group_id,
            self.origin_provider or "",
            self.raw_relationship_type or "",
        )


class GraphEdge(FrozenTiReconModel):
    """One semantic relationship, with every assertion that claimed it."""

    source_key: str = Field(min_length=1, max_length=300)
    relationship_type: RelationshipType
    target_key: str = Field(min_length=1, max_length=300)
    assertions: tuple[RelationshipAssertion, ...] = ()
    #: Assertions dropped because the assertion ceiling was reached.
    assertions_truncated: int = Field(default=0, ge=0)

    @property
    def key(self) -> tuple[str, RelationshipType, str]:
        """The semantic identity of the edge. Deliberately provider-free."""
        return (self.source_key, self.relationship_type, self.target_key)

    @property
    def asserting_source_families(self) -> tuple[str, ...]:
        """Families that asserted this relationship, sorted, deduplicated.

        Informational only. Two families is not twice the confidence of one, and
        nothing in this package turns the count into a number. Engine-derived
        assertions contribute nothing here, because TI Recon parsing a URL is not
        a source.
        """
        return tuple(sorted({item.source_family for item in self.assertions if item.source_family}))

    @property
    def is_engine_derived_only(self) -> bool:
        return bool(self.assertions) and all(
            item.basis is RelationBasis.ENGINE_DERIVED for item in self.assertions
        )

    @property
    def earliest_observed(self) -> UtcDatetime | None:
        """Earliest time any assertion mentions. **Display only.**

        With :attr:`latest_observed` this is a bounding box around separate
        observations, not a claim that the relationship existed throughout. A 2019
        resolution and a 2026 resolution do not make a seven-year association.
        """
        times = [item.first_seen or item.observed_at for item in self.assertions]
        present = [item for item in times if item is not None]
        return min(present) if present else None

    @property
    def latest_observed(self) -> UtcDatetime | None:
        """Latest time any assertion mentions. **Display only.** See above."""
        times = [item.last_seen or item.observed_at for item in self.assertions]
        present = [item for item in times if item is not None]
        return max(present) if present else None


#: The longest canonical key a node may carry. A key is derived from an
#: observable's canonical value, and a provider can return a related URL of any
#: length: one beyond this bound is refused as an ``INVALID_RELATED_OBJECT``
#: rather than rejected by the model, so a single over-long related object costs
#: one node and never the investigation.
MAX_NODE_KEY_LENGTH = 300


class GraphNode(FrozenTiReconModel):
    """One object in the investigation graph."""

    node_key: str = Field(min_length=1, max_length=MAX_NODE_KEY_LENGTH)
    intel_object: IntelObject
    #: Confirmed alternate identities for this node — today, a file's other
    #: digests. Only ever grown with non-conflicting values.
    aliases: tuple[str, ...] = ()
    identity_basis: IdentityBasis = IdentityBasis.CANONICAL_VALUE
    #: Shortest hop from the root at which this node was first seen.
    discovered_at_hop: int = Field(default=0, ge=0)
    occurrences: tuple[NodeOccurrence, ...] = ()
    is_root: bool = False
    #: ``True`` once this node's canonical value has been through Task 13.
    enriched: bool = False

    @property
    def object_type(self) -> IntelObjectType:
        return self.intel_object.object_type

    @property
    def source_families(self) -> tuple[str, ...]:
        return tuple(sorted({item.source_family for item in self.occurrences}))

    @property
    def is_unlinked(self) -> bool:
        """Whether every mention of this node came without a relationship."""
        return bool(self.occurrences) and all(item.unlinked for item in self.occurrences)


class CorrelationIssue(FrozenTiReconModel):
    """Something the graph could not do cleanly, recorded rather than swallowed."""

    issue_type: CorrelationIssueType
    detail: str = Field(max_length=300)
    #: Node keys the issue concerns. Canonical keys, never provider payloads.
    node_keys: tuple[str, ...] = ()
    provider_id: str | None = Field(default=None, max_length=64)


class GraphLimits(FrozenTiReconModel):
    """Safety ceilings on graph growth.

    Provider normalizers are bounded already; this is the final envelope, and it
    exists because "bounded per provider" times "several providers" times "pivots"
    is not bounded. None of these numbers is analytical — hitting one says nothing
    about the investigation except that it was large.
    """

    max_nodes: int = Field(default=1000, ge=1)
    max_edges: int = Field(default=2000, ge=1)
    max_assertions_per_edge: int = Field(default=50, ge=1)
    max_assertions: int = Field(default=5000, ge=1)
    max_pivot_candidates: int = Field(default=200, ge=1)


DEFAULT_GRAPH_LIMITS: Final[GraphLimits] = GraphLimits()


class GraphTruncation(FrozenTiReconModel):
    """What a ceiling stopped the graph from holding.

    Counted rather than merely flagged: an analyst reading a graph that stopped at
    a thousand nodes needs to know whether it dropped three or three thousand.
    """

    nodes_dropped: int = Field(default=0, ge=0)
    edges_dropped: int = Field(default=0, ge=0)
    assertions_dropped: int = Field(default=0, ge=0)
    pivot_candidates_dropped: int = Field(default=0, ge=0)

    @property
    def any_truncation(self) -> bool:
        return bool(
            self.nodes_dropped
            or self.edges_dropped
            or self.assertions_dropped
            or self.pivot_candidates_dropped
        )
