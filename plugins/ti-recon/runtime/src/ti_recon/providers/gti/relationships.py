"""GTI relationship policy (Task 7).

The verified relationship map, the depth profiles and the safety limits. No
relationship name is ever taken from user input: everything requested comes from
the tables here, so a caller cannot reach an arbitrary GTI endpoint by naming it.

Why relationships are rationed
------------------------------

A single GTI object can hang dozens of relationships off itself, several of them
unbounded. Pulling them all would spend an analyst's quota on data no
investigation asked for and turn one lookup into a slow, expensive fan-out. So
each depth gets an explicit allow-list, and three separate limits cap the
result: how many relationship types, how many results per type, and how many
related objects in total. Pagination is never exhausted — one page, bounded.

Descriptor-first, with a stated exception
-----------------------------------------

A relationship *descriptor* carries only a type and an id, and for most targets
that is the whole identity: a domain descriptor's id is the domain, a file
descriptor's id is its hash. Those are fetched as descriptors.

Two target shapes cannot be identified from a descriptor alone and are therefore
fetched as full objects:

* a **URL** descriptor's id is GTI's opaque base64 identifier, not the URL, and
  inventing a URL from it is impossible;
* a **resolution** object's id concatenates an address and a hostname, and the
  two are only reliably separable from its attributes.

Preferring descriptors is the rule; needing an attribute to know *what* the
target is, is the documented exception.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from pydantic import Field

from ti_recon.enums import (
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    RelationshipType,
)
from ti_recon.models.base import FrozenTiReconModel

__all__ = [
    "LIMITS_BY_DEPTH",
    "RELATIONSHIP_PLANS",
    "RELATIONSHIP_SPECS",
    "Direction",
    "GTIRelationshipDepth",
    "GTIRelationshipLimits",
    "GTIRelationshipSpec",
    "Retrieval",
    "TargetKind",
    "depth_for_investigation",
    "relationship_plan",
]


class GTIRelationshipDepth(StrEnum):
    """How much relationship expansion a lookup is allowed.

    Mirrors :class:`InvestigationDepth` rather than reusing it, so a change to
    GTI's profiles does not silently redefine what "deep" means everywhere else.
    """

    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


def depth_for_investigation(depth: InvestigationDepth) -> GTIRelationshipDepth:
    """The GTI profile for an investigation depth."""
    match depth:
        case InvestigationDepth.QUICK:
            return GTIRelationshipDepth.QUICK
        case InvestigationDepth.DEEP:
            return GTIRelationshipDepth.DEEP
        case _:
            return GTIRelationshipDepth.STANDARD


class TargetKind(StrEnum):
    """How a related item is turned into an :class:`IntelObject`."""

    #: The descriptor id *is* the object's value: a domain, an address, a hash.
    IDENTITY = "identity"
    #: A URL, whose value lives in the object's ``url`` attribute because the
    #: descriptor id is an opaque identifier.
    URL_OBJECT = "url_object"
    #: A GTI ``resolution``, whose address and hostname live in attributes
    #: because its id concatenates the two.
    RESOLUTION_OBJECT = "resolution_object"
    #: A high-level threat collection — malware family, actor, campaign, report.
    #: Its descriptor id is an internal collection identifier with no readable
    #: name, so a descriptor yields an association claim and only a DEEP
    #: expansion can name the thing.
    THREAT_OBJECT = "threat_object"


class Retrieval(StrEnum):
    """Which endpoint answers for a relationship."""

    DESCRIPTORS = "descriptors"
    OBJECTS = "objects"


class Direction(StrEnum):
    """Which end of the relationship the subject observable sits on.

    GTI names relationships from the subject's point of view, but TI Recon
    relationships are directed by *meaning*. ``communicating_files`` on a domain
    returns files, and the true statement is "that file contacted this domain" —
    so the related object is the source and the subject is the target.
    """

    #: subject -> related
    OUTBOUND = "outbound"
    #: related -> subject
    INBOUND = "inbound"


@dataclass(frozen=True, slots=True)
class GTIRelationshipSpec:
    """One verified GTI relationship and how to normalize it."""

    name: str
    relationship_type: RelationshipType
    target_kind: TargetKind
    direction: Direction = Direction.OUTBOUND
    #: Which intelligence capability this relationship serves. A lookup only
    #: requests relationships whose capability the caller actually asked for, so
    #: a reputation query does not quietly spend quota on a pivot graph.
    capability: ProviderCapability = ProviderCapability.RELATIONSHIPS
    #: True when an Enterprise/GTI entitlement gates the relationship, so a
    #: refusal reads as a plan limitation rather than a permission problem.
    entitlement_sensitive: bool = False

    @property
    def retrieval(self) -> Retrieval:
        """Descriptors unless the target's identity needs an attribute."""
        return (
            Retrieval.DESCRIPTORS
            if self.target_kind in {TargetKind.IDENTITY, TargetKind.THREAT_OBJECT}
            else Retrieval.OBJECTS
        )

    def retrieval_at(self, depth: GTIRelationshipDepth) -> Retrieval:
        """How to fetch this relationship at a given depth.

        Threat collections are the one depth-dependent case: STANDARD takes
        descriptors, which is enough to record *that* an association exists,
        while DEEP pays for the full object so the thing can actually be named.
        """
        if self.target_kind is TargetKind.THREAT_OBJECT:
            return (
                Retrieval.OBJECTS if depth is GTIRelationshipDepth.DEEP else Retrieval.DESCRIPTORS
            )
        return self.retrieval


#: Every relationship this integration knows how to normalize.
#:
#: Names come from the documented VT/GTI v3 relationship set. Anything not in
#: here is simply not requested — guessing an endpoint name would produce a 404
#: at best and an unintended query at worst.
RELATIONSHIP_SPECS: Final[dict[str, GTIRelationshipSpec]] = {
    # --- what a sample did ------------------------------------------------
    "contacted_domains": GTIRelationshipSpec(
        "contacted_domains", RelationshipType.CONTACTS, TargetKind.IDENTITY
    ),
    "contacted_ips": GTIRelationshipSpec(
        "contacted_ips", RelationshipType.CONTACTS, TargetKind.IDENTITY
    ),
    "contacted_urls": GTIRelationshipSpec(
        "contacted_urls", RelationshipType.CONTACTS, TargetKind.URL_OBJECT
    ),
    "dropped_files": GTIRelationshipSpec(
        "dropped_files", RelationshipType.DROPS, TargetKind.IDENTITY
    ),
    "embedded_domains": GTIRelationshipSpec(
        "embedded_domains", RelationshipType.CONTACTS, TargetKind.IDENTITY
    ),
    "embedded_ips": GTIRelationshipSpec(
        "embedded_ips", RelationshipType.CONTACTS, TargetKind.IDENTITY
    ),
    "embedded_urls": GTIRelationshipSpec(
        "embedded_urls", RelationshipType.CONTACTS, TargetKind.URL_OBJECT
    ),
    "itw_urls": GTIRelationshipSpec(
        "itw_urls", RelationshipType.DOWNLOADS, TargetKind.URL_OBJECT, Direction.INBOUND
    ),
    # --- where infrastructure points -------------------------------------
    "resolutions": GTIRelationshipSpec(
        "resolutions", RelationshipType.RESOLVES_TO, TargetKind.RESOLUTION_OBJECT
    ),
    "communicating_files": GTIRelationshipSpec(
        "communicating_files",
        RelationshipType.CONTACTS,
        TargetKind.IDENTITY,
        Direction.INBOUND,
    ),
    "downloaded_files": GTIRelationshipSpec(
        "downloaded_files", RelationshipType.DOWNLOADS, TargetKind.IDENTITY
    ),
    "referrer_files": GTIRelationshipSpec(
        "referrer_files",
        RelationshipType.CONTACTS,
        TargetKind.IDENTITY,
        Direction.INBOUND,
    ),
    "redirecting_urls": GTIRelationshipSpec(
        "redirecting_urls",
        RelationshipType.REDIRECTS_TO,
        TargetKind.URL_OBJECT,
        Direction.INBOUND,
    ),
    # --- curated threat attribution (Enterprise/GTI) ----------------------
    "malware_families": GTIRelationshipSpec(
        "malware_families",
        RelationshipType.ASSOCIATED_WITH_MALWARE,
        TargetKind.THREAT_OBJECT,
        capability=ProviderCapability.MALWARE_INTELLIGENCE,
        entitlement_sensitive=True,
    ),
    "associations": GTIRelationshipSpec(
        "associations",
        RelationshipType.RELATED_TO,
        TargetKind.THREAT_OBJECT,
        capability=ProviderCapability.THREAT_ASSOCIATIONS,
        entitlement_sensitive=True,
    ),
    "related_threat_actors": GTIRelationshipSpec(
        "related_threat_actors",
        RelationshipType.RELATED_TO,
        TargetKind.THREAT_OBJECT,
        capability=ProviderCapability.THREAT_ASSOCIATIONS,
        entitlement_sensitive=True,
    ),
    "related_reports": GTIRelationshipSpec(
        "related_reports",
        RelationshipType.RELATED_TO,
        TargetKind.THREAT_OBJECT,
        capability=ProviderCapability.THREAT_ASSOCIATIONS,
        entitlement_sensitive=True,
    ),
    "campaigns": GTIRelationshipSpec(
        "campaigns",
        RelationshipType.RELATED_TO,
        TargetKind.THREAT_OBJECT,
        capability=ProviderCapability.THREAT_ASSOCIATIONS,
        entitlement_sensitive=True,
    ),
}

#: Which relationships each depth requests, per observable type.
#:
#: STANDARD is the useful-and-cheap set the spec calls for; DEEP adds selected
#: extras and stays bounded by :data:`LIMITS_BY_DEPTH`. QUICK requests nothing:
#: relationships already inlined in the primary response are still normalized,
#: because those cost no additional call.
RELATIONSHIP_PLANS: Final[dict[IntelObjectType, dict[GTIRelationshipDepth, tuple[str, ...]]]] = {
    IntelObjectType.FILE: {
        GTIRelationshipDepth.QUICK: (),
        GTIRelationshipDepth.STANDARD: (
            "contacted_domains",
            "contacted_ips",
            "contacted_urls",
            "malware_families",
            "associations",
        ),
        GTIRelationshipDepth.DEEP: (
            "contacted_domains",
            "contacted_ips",
            "contacted_urls",
            "dropped_files",
            "embedded_domains",
            "itw_urls",
            "malware_families",
            "associations",
            "related_threat_actors",
            "related_reports",
            "campaigns",
        ),
    },
    IntelObjectType.DOMAIN_NAME: {
        GTIRelationshipDepth.QUICK: (),
        GTIRelationshipDepth.STANDARD: (
            "resolutions",
            "communicating_files",
            "associations",
        ),
        GTIRelationshipDepth.DEEP: (
            "resolutions",
            "communicating_files",
            "downloaded_files",
            "referrer_files",
            "associations",
            "related_threat_actors",
            "related_reports",
            "campaigns",
        ),
    },
    IntelObjectType.IPV4_ADDR: {
        GTIRelationshipDepth.QUICK: (),
        GTIRelationshipDepth.STANDARD: (
            "resolutions",
            "communicating_files",
            "associations",
        ),
        GTIRelationshipDepth.DEEP: (
            "resolutions",
            "communicating_files",
            "downloaded_files",
            "referrer_files",
            "associations",
            "related_threat_actors",
            "related_reports",
            "campaigns",
        ),
    },
    IntelObjectType.URL: {
        GTIRelationshipDepth.QUICK: (),
        GTIRelationshipDepth.STANDARD: (
            "downloaded_files",
            "communicating_files",
            "redirecting_urls",
            "associations",
        ),
        GTIRelationshipDepth.DEEP: (
            "downloaded_files",
            "communicating_files",
            "redirecting_urls",
            "contacted_domains",
            "contacted_ips",
            "associations",
            "related_threat_actors",
            "related_reports",
            "campaigns",
        ),
    },
}
RELATIONSHIP_PLANS[IntelObjectType.IPV6_ADDR] = RELATIONSHIP_PLANS[IntelObjectType.IPV4_ADDR]


class GTIRelationshipLimits(FrozenTiReconModel):
    """Safety caps on relationship expansion.

    These are TI Recon limits, not GTI API limits. They exist so one enrichment
    cannot spend an unbounded amount of an analyst's quota, and every one of them
    is configurable.
    """

    max_relationship_types: int = Field(ge=0, le=20)
    max_results_per_relationship: int = Field(ge=0, le=40)
    max_total_related_objects: int = Field(ge=0, le=200)

    #: Full threat collections are the most expensive thing to expand and the
    #: least useful in bulk, so they get their own much tighter cap. Five actor
    #: or campaign objects is context; fifty is a research project.
    max_threat_objects_per_relationship: int = Field(default=3, ge=0, le=20)

    @property
    def expands(self) -> bool:
        return (
            self.max_relationship_types > 0
            and self.max_results_per_relationship > 0
            and self.max_total_related_objects > 0
        )


#: Conservative defaults per depth.
LIMITS_BY_DEPTH: Final[dict[GTIRelationshipDepth, GTIRelationshipLimits]] = {
    GTIRelationshipDepth.QUICK: GTIRelationshipLimits(
        max_relationship_types=0,
        max_results_per_relationship=0,
        max_total_related_objects=0,
    ),
    GTIRelationshipDepth.STANDARD: GTIRelationshipLimits(
        max_relationship_types=5,
        max_results_per_relationship=5,
        max_total_related_objects=15,
        max_threat_objects_per_relationship=3,
    ),
    GTIRelationshipDepth.DEEP: GTIRelationshipLimits(
        max_relationship_types=10,
        max_results_per_relationship=10,
        max_total_related_objects=40,
        max_threat_objects_per_relationship=5,
    ),
}


def relationship_plan(
    object_type: IntelObjectType,
    depth: GTIRelationshipDepth,
    *,
    limits: GTIRelationshipLimits | None = None,
    capabilities: frozenset[ProviderCapability] | None = None,
) -> tuple[GTIRelationshipSpec, ...]:
    """The relationships to request, filtered and truncated.

    Returns specs rather than names, so a caller cannot request something the
    table does not describe. An unknown name in a plan is skipped rather than
    passed through — a typo must not become an API call.

    ``capabilities`` restricts the plan to what the request actually asked for.
    A reputation lookup should not quietly spend an analyst's quota building a
    pivot graph nobody wanted.
    """
    effective = LIMITS_BY_DEPTH[depth] if limits is None else limits
    if not effective.expands:
        return ()
    names = RELATIONSHIP_PLANS.get(object_type, {}).get(depth, ())
    specs = [
        spec
        for name in names
        if (spec := RELATIONSHIP_SPECS.get(name)) is not None
        and (capabilities is None or spec.capability in capabilities)
    ]
    return tuple(specs[: effective.max_relationship_types])
