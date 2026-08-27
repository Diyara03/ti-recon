"""Canonical relationship semantics (Task 14).

A provider-neutral statement of what each relationship in the Task 3 vocabulary
*means*: which kinds of object may sit at each end, which way round it is written,
how directly it ties its target to the investigation, and whether following it
automatically is a defensible thing to have done.

Only the relationships Tasks 7-12 actually emit are defined. Nine of the thirteen
`RelationshipType` members are in use; the rest are left undefined rather than
given speculative semantics, because a definition nobody produces is a rule
nobody has tested.

No provider is named here. Which provider field became which canonical
relationship is the provider's business and stays in its normalizer, recorded on
the assertion as ``raw_relationship_type`` so the mapping can always be traced.

Orientation
-----------

Providers describe the same fact from either end — urlscan reports a URL serving a
file, GTI reports a file downloaded in-the-wild from a URL. Written as two edges
those become two unrelated-looking facts, so each definition names one canonical
orientation and an assertion arriving the other way round is flipped onto the same
edge. Traversal can still go both ways; the *storage* is single-directional so the
assertions meet.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from pydantic import Field

from ti_recon.correlation.models import PivotSafetyClass
from ti_recon.enums import IntelObjectType, RelationshipType
from ti_recon.models.base import FrozenTiReconModel

__all__ = [
    "RELATIONSHIP_DEFINITIONS",
    "PivotEligibility",
    "RelationshipDefinition",
    "definition_for",
]

_HOSTS_TYPES: Final[frozenset[IntelObjectType]] = frozenset(
    {IntelObjectType.DOMAIN_NAME, IntelObjectType.IPV4_ADDR, IntelObjectType.IPV6_ADDR}
)
_ADDRESSABLE: Final[frozenset[IntelObjectType]] = _HOSTS_TYPES | {IntelObjectType.URL}


class PivotEligibility(StrEnum):
    """Whether following this relationship may spend somebody's quota.

    Separate from the safety class because the two answer different questions.
    The class says how directly the target belongs to the investigation; this says
    what TI Recon is allowed to *do* about it without being asked.
    """

    #: May be enriched automatically when pivoting is explicitly enabled.
    ENRICH_ELIGIBLE = "enrich_eligible"
    #: Surfaced to an analyst, never enriched on its own.
    RECOMMEND_ONLY = "recommend_only"
    #: Never followed automatically, whatever the mode.
    NEVER = "never"


class RelationshipDefinition(FrozenTiReconModel):
    """What one canonical relationship means."""

    canonical_type: RelationshipType
    allowed_source_types: frozenset[IntelObjectType]
    allowed_target_types: frozenset[IntelObjectType]
    pivot_safety_class: PivotSafetyClass
    eligibility: PivotEligibility
    #: How it reads in the other direction, for display and traversal.
    inverse_display_name: str = Field(min_length=1, max_length=64)
    description: str = Field(min_length=1, max_length=300)

    def accepts(self, source: IntelObjectType, target: IntelObjectType) -> bool:
        return source in self.allowed_source_types and target in self.allowed_target_types

    def accepts_inverted(self, source: IntelObjectType, target: IntelObjectType) -> bool:
        """Whether this pair fits the definition the other way round.

        Used to recognise a provider that wrote the relationship backwards, so its
        assertion lands on the canonical edge instead of creating a mirror.
        """
        return self.accepts(target, source)

    @property
    def enrich_eligible(self) -> bool:
        return self.eligibility is PivotEligibility.ENRICH_ELIGIBLE

    @property
    def never_pivot(self) -> bool:
        return self.eligibility is PivotEligibility.NEVER


#: Every relationship the shipped providers emit, and nothing else.
RELATIONSHIP_DEFINITIONS: Final[dict[RelationshipType, RelationshipDefinition]] = {
    RelationshipType.HOSTS: RelationshipDefinition(
        canonical_type=RelationshipType.HOSTS,
        allowed_source_types=_HOSTS_TYPES,
        allowed_target_types=frozenset({IntelObjectType.URL}),
        pivot_safety_class=PivotSafetyClass.STRUCTURAL,
        # A host is the URL's own authority, so it is nearly always already known
        # and rarely worth a query of its own; and a shared host serves a great
        # many URLs that have nothing to do with each other.
        eligibility=PivotEligibility.RECOMMEND_ONLY,
        inverse_display_name="has-host",
        description="the host a URL lives on, written host-first",
    ),
    RelationshipType.RESOLVES_TO: RelationshipDefinition(
        canonical_type=RelationshipType.RESOLVES_TO,
        allowed_source_types=frozenset({IntelObjectType.DOMAIN_NAME}),
        allowed_target_types=frozenset({IntelObjectType.IPV4_ADDR, IntelObjectType.IPV6_ADDR}),
        pivot_safety_class=PivotSafetyClass.INFRASTRUCTURE_ASSOCIATION,
        # Passive DNS explodes: one shared-hosting address answers for thousands of
        # unrelated names, and following resolutions automatically is how a single
        # observable becomes a survey of somebody else's customers.
        eligibility=PivotEligibility.RECOMMEND_ONLY,
        inverse_display_name="resolved-from",
        description="a name that resolved to an address, at some time",
    ),
    RelationshipType.REDIRECTS_TO: RelationshipDefinition(
        canonical_type=RelationshipType.REDIRECTS_TO,
        allowed_source_types=frozenset({IntelObjectType.URL}),
        allowed_target_types=frozenset({IntelObjectType.URL}),
        pivot_safety_class=PivotSafetyClass.DIRECT_BEHAVIOR,
        eligibility=PivotEligibility.ENRICH_ELIGIBLE,
        inverse_display_name="redirected-from",
        description="a URL that sent a visitor onwards to another URL",
    ),
    RelationshipType.CONTACTS: RelationshipDefinition(
        canonical_type=RelationshipType.CONTACTS,
        allowed_source_types=frozenset({IntelObjectType.FILE, IntelObjectType.URL}),
        allowed_target_types=_ADDRESSABLE,
        pivot_safety_class=PivotSafetyClass.DIRECT_BEHAVIOR,
        eligibility=PivotEligibility.ENRICH_ELIGIBLE,
        inverse_display_name="contacted-by",
        description="infrastructure a sample or page reached out to",
    ),
    RelationshipType.DOWNLOADS: RelationshipDefinition(
        canonical_type=RelationshipType.DOWNLOADS,
        allowed_source_types=_ADDRESSABLE,
        allowed_target_types=frozenset({IntelObjectType.FILE}),
        pivot_safety_class=PivotSafetyClass.DIRECT_ARTIFACT,
        eligibility=PivotEligibility.ENRICH_ELIGIBLE,
        inverse_display_name="served-by",
        description="a file served from a URL or host",
    ),
    RelationshipType.DROPS: RelationshipDefinition(
        canonical_type=RelationshipType.DROPS,
        allowed_source_types=frozenset({IntelObjectType.FILE}),
        allowed_target_types=frozenset({IntelObjectType.FILE}),
        pivot_safety_class=PivotSafetyClass.DIRECT_ARTIFACT,
        eligibility=PivotEligibility.ENRICH_ELIGIBLE,
        inverse_display_name="dropped-by",
        description="a file written or extracted by another file",
    ),
    RelationshipType.USES_CERTIFICATE: RelationshipDefinition(
        canonical_type=RelationshipType.USES_CERTIFICATE,
        allowed_source_types=_HOSTS_TYPES | {IntelObjectType.FILE},
        allowed_target_types=frozenset({IntelObjectType.X509_CERTIFICATE}),
        pivot_safety_class=PivotSafetyClass.INFRASTRUCTURE_ASSOCIATION,
        # No provider takes a certificate as a lookup subject today, so this is
        # unreachable as a pivot regardless; saying so here keeps the reason
        # semantic rather than accidental.
        eligibility=PivotEligibility.RECOMMEND_ONLY,
        inverse_display_name="certificate-of",
        description="a certificate served by a host or signing a file",
    ),
    RelationshipType.BELONGS_TO_ASN: RelationshipDefinition(
        canonical_type=RelationshipType.BELONGS_TO_ASN,
        allowed_source_types=_HOSTS_TYPES,
        allowed_target_types=frozenset({IntelObjectType.AUTONOMOUS_SYSTEM}),
        pivot_safety_class=PivotSafetyClass.INFRASTRUCTURE_ASSOCIATION,
        # An AS is an ownership fact about millions of addresses. It is context for
        # the node it hangs off, never a thing to go and investigate.
        eligibility=PivotEligibility.NEVER,
        inverse_display_name="announces",
        description="the autonomous system announcing an address",
    ),
    RelationshipType.ASSOCIATED_WITH_MALWARE: RelationshipDefinition(
        canonical_type=RelationshipType.ASSOCIATED_WITH_MALWARE,
        allowed_source_types=frozenset({IntelObjectType.FILE, IntelObjectType.URL} | _HOSTS_TYPES),
        allowed_target_types=frozenset({IntelObjectType.MALWARE}),
        pivot_safety_class=PivotSafetyClass.GENERIC_ASSOCIATION,
        # A malware family is a label, not an artifact. Following it would ask
        # providers about a name, which is a different product entirely.
        eligibility=PivotEligibility.NEVER,
        inverse_display_name="attributed-sample",
        description="a curated family attribution for an artifact",
    ),
    RelationshipType.RELATED_TO: RelationshipDefinition(
        canonical_type=RelationshipType.RELATED_TO,
        allowed_source_types=frozenset(IntelObjectType),
        allowed_target_types=frozenset(IntelObjectType),
        pivot_safety_class=PivotSafetyClass.GENERIC_ASSOCIATION,
        # Untyped by construction: whatever the provider meant, it did not say.
        # Automatically querying third parties about it cannot be justified.
        eligibility=PivotEligibility.NEVER,
        inverse_display_name="related-to",
        description="an association a provider stated without naming its kind",
    ),
}


def definition_for(relationship_type: RelationshipType) -> RelationshipDefinition | None:
    """The definition for a relationship, or ``None`` if the vocabulary has none.

    ``None`` is a real answer, not a failure to look: a relationship TI Recon
    cannot describe is recorded as an issue and kept out of the graph, rather than
    being given default semantics that would make it look understood.
    """
    return RELATIONSHIP_DEFINITIONS.get(relationship_type)
