"""Provider-neutral claim semantics (Task 17A).

Task 16 hit a wall and named it precisely: every ``claim_type`` in this
repository is provider-prefixed, so a generic layer could not tell a
scanner-reputation claim from a botnet-C2 claim. Both are
``CURATED_THREAT_ASSERTION`` with ``SUPPORTS_MALICIOUS``; only
``greynoise_classification`` versus ``threatfox_ioc`` separated them, and reading
that would have put a vendor name in the reasoning core.

This module is the seam that fixes it. A :class:`NormalizedClaim` says **what
proposition a piece of evidence supports**, in vocabulary no provider owns, and
fusion reasons over those instead of over provider output.

A semantic is not a verdict
---------------------------

:attr:`ClaimSemantic.C2_ASSOCIATION` says a source claims this address serves
command and control. It does not say the investigation is malicious.
:attr:`ClaimSemantic.SCANNER_ACTIVITY` says a source classified this address as
internet-scanning infrastructure; that is not benign either. The semantic names
the *dimension*, ``EvidenceEffect`` names the *direction*, and what either is
worth is fusion policy's decision — three separate things that this repository
has kept apart at every layer and keeps apart here.

A view, never a replacement
---------------------------

A claim is derived from an :class:`~ti_recon.models.evidence.Evidence` and holds
a reference to it. Evidence stays authoritative, unedited and unaware that this
layer exists. Nothing here copies a provider payload, and re-deriving claims from
the same evidence produces the same claims.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Final

from pydantic import Field, model_validator

from ti_recon.enums import EvidenceClass, EvidenceEffect, MatchScope
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.models.evidence import Evidence

__all__ = [
    "CLAIM_ID_LENGTH",
    "MAX_CLAIM_HIGHLIGHTS",
    "MAX_CLAIM_HIGHLIGHT_LENGTH",
    "MAX_CLAIM_QUALIFICATION_REASONS",
    "ClaimAssertionStrength",
    "ClaimPropositionKey",
    "ClaimQualification",
    "ClaimSemantic",
    "NormalizedClaim",
    "claim_id_for",
]


#: Length of a claim's derived record identity.
CLAIM_ID_LENGTH: Final[int] = 32

#: Bounds on the presentation highlights a claim may carry.
MAX_CLAIM_HIGHLIGHTS: Final[int] = 8
MAX_CLAIM_HIGHLIGHT_LENGTH: Final[int] = 160

#: Bound on the reason codes a qualification may carry.
MAX_CLAIM_QUALIFICATION_REASONS: Final[int] = 8


class ClaimSemantic(StrEnum):
    """What proposition a directional piece of evidence supports.

    Every member below is emitted by a shipped provider's translator over data
    that provider already normalizes. None is aspirational: a semantic nothing
    can set is a promise this layer does not keep, and a semantic set by guessing
    is worse than none at all.

    The vocabulary is deliberately shallow. It is not a CTI ontology; it is the
    smallest set of distinctions the current normalized data can honestly draw,
    and it grows only when a provider starts carrying structure that supports a
    new one.
    """

    # -- object identity ---------------------------------------------------- #
    #: A curated repository holds this exact file as a known malware sample.
    #: About the artifact itself, by cryptographic identity.
    MALWARE_SAMPLE_IDENTITY = "malware_sample_identity"

    # -- infrastructure roles ----------------------------------------------- #
    #: This artifact served or delivered malware.
    MALWARE_DISTRIBUTION = "malware_distribution"
    #: This address or name served command and control.
    C2_ASSOCIATION = "c2_association"
    #: A source ties this to malicious infrastructure without saying what role
    #: it played. Real, and less specific than the two above.
    THREAT_INFRASTRUCTURE_ASSOCIATION = "threat_infrastructure_association"
    #: A source associates this with a named actor, campaign or report.
    THREAT_ACTOR_ASSOCIATION = "threat_actor_association"

    # -- observed activity --------------------------------------------------- #
    #: A sensor network classified this address's internet-scanning behaviour.
    #: Deliberately its own dimension: scanning is not command and control, and
    #: collapsing the two is the exact error Task 16 refused to risk. The
    #: direction is the provider's *classification* of that behaviour --
    #: malicious, suspicious or benign -- never the fact that scanning was
    #: observed: an address seen scanning with an unknown classification is
    #: context and produces no claim of this semantic at all.
    SCANNER_ACTIVITY = "scanner_activity"
    #: A sandbox reached a verdict about what this sample did when run.
    SANDBOX_CLASSIFICATION = "sandbox_classification"

    # -- reputation ---------------------------------------------------------- #
    #: A provider's own curated reputation verdict.
    MALICIOUS_REPUTATION = "malicious_reputation"
    #: A provider's own curated benign verdict. Rare, and genuinely directional.
    BENIGN_REPUTATION = "benign_reputation"
    #: A roll-up of other parties' opinions. One source, however many opinions
    #: it aggregates -- which is why it can never be corroboration on its own.
    AGGREGATED_REPUTATION = "aggregated_reputation"

    # -- the honest fallback --------------------------------------------------- #
    #: Directional evidence whose proposition this layer cannot determine.
    #: Retained, visible, and never decisive. Guessing would be worse.
    UNCLASSIFIED_DIRECTIONAL = "unclassified_directional"


class ClaimAssertionStrength(StrEnum):
    """How firmly the source states its own claim.

    Providers distinguish "this is malicious" from "this looks suspicious", and
    Task 12 went to some trouble to preserve a sandbox's ``suspicious`` verdict
    separately from ``malicious``. Flattening both into one direction would throw
    that away, so the distinction rides here rather than multiplying the semantic
    vocabulary.
    """

    #: The source states the claim outright.
    ASSERTED = "asserted"
    #: The source qualifies it -- "suspicious" rather than "malicious".
    #: Never decisive, whatever the semantic.
    SUSPECTED = "suspected"


class ClaimQualification(StrEnum):
    """What a provider-owned test said about the basis behind an asserted claim.

    Source independence and evidence strength are different concepts. One
    origin can supply strong, direct, exact-observable evidence -- several of
    its own sandboxes classifying one sample malicious with stated confidence
    -- and one origin can supply a single hedged opinion. Both are "one source";
    they are not the same evidence. This field lets a translator say which,
    from the provider's own documented fields, under a versioned policy that
    lives in the provider package. Fusion reads only the enum: never a count,
    never a confidence, never a provider name.
    """

    #: The translator made no statement. The claim is weighed as its semantic,
    #: scope and strength alone allow.
    UNQUALIFIED = "unqualified"
    #: The source's own record met TI Recon's versioned consensus test for
    #: that provider -- owned by the provider package because it reads the
    #: provider's documented fields, never a threshold the vendor defined:
    #: enough evaluations, agreement, no contrary verdict, and adequate stated
    #: confidence. May let a semantic that is otherwise only corroborative
    #: decide alone.
    STRONG_DIRECT = "strong_direct"
    #: The record was tested and did not meet it -- too few evaluations,
    #: disagreement, a contrary verdict or insufficient confidence. The
    #: reasons say which. Weighed exactly like an unqualified claim.
    NOT_STRONG = "not_strong"


#: Semantics that describe a *relationship-independent* property of the object
#: itself rather than of surrounding infrastructure.
#:
#: Used by scope reasoning: a claim about what a file *is* survives host-level
#: context in a way a claim about hosting does not.
OBJECT_SEMANTICS: Final[frozenset[ClaimSemantic]] = frozenset(
    {
        ClaimSemantic.MALWARE_SAMPLE_IDENTITY,
        ClaimSemantic.SANDBOX_CLASSIFICATION,
    }
)


class ClaimPropositionKey(FrozenTiReconModel):
    """What makes two claims statements about the same thing.

    Deliberately provider-free. Two sources corroborate when they assert the same
    proposition about the same subject at the same scope -- not when they happen
    to be two different companies. Putting a provider in this key would make
    corroboration impossible by construction, which is the mirror image of
    counting providers as votes.

    Scope is part of identity because it has to be: "this host is associated with
    malware" and "this exact URL served malware" are different propositions, and
    a layer that merged them would let host-level suspicion vouch for an artifact.
    """

    subject_key: str = Field(min_length=1, max_length=700)
    semantic: ClaimSemantic
    scope: MatchScope
    #: For a relational proposition, the other endpoint. Empty otherwise.
    target_key: str = Field(default="", max_length=700)

    @property
    def ref(self) -> str:
        return "|".join((self.subject_key, self.semantic.value, self.scope.value, self.target_key))


class NormalizedClaim(FrozenTiReconModel):
    """One proposition, derived from one piece of evidence.

    A **view**: it references the evidence by id and copies only the provenance
    fusion needs. The evidence itself is untouched and remains the authority on
    what a provider actually said.
    """

    claim_id: str = Field(min_length=1, max_length=64)
    #: The evidence this claim reads. Never a copy of it.
    evidence_id: str = Field(min_length=1, max_length=200)

    semantic: ClaimSemantic
    strength: ClaimAssertionStrength = ClaimAssertionStrength.ASSERTED
    #: Direction, exactly as the provider stated it. Read-only, never recomputed.
    effect: EvidenceEffect
    evidence_class: EvidenceClass
    scope: MatchScope

    #: Canonical identity of what the claim is about.
    subject_key: str = Field(min_length=1, max_length=700)
    target_key: str = Field(default="", max_length=700)

    # -- provenance, carried verbatim from Task 3 -------------------------- #
    transport_provider: str = Field(min_length=1, max_length=64)
    origin_provider: str = Field(min_length=1, max_length=64)
    source_family: str = Field(min_length=1, max_length=64)
    lineage_group_id: str = Field(default="", max_length=200)

    #: ``True`` when the provider result behind this was incomplete.
    source_partial: bool = False
    #: Short, bounded statements of what the source actually said -- a verdict
    #: category, a confidence, a classification label, a rule title -- chosen by
    #: the provider's own translator from its own attributes. Presentation
    #: only: fusion never reads them, and a claim with none is weighed exactly
    #: like one with many. They exist so a report can say *why* without
    #: carrying the provider payload.
    highlights: tuple[str, ...] = Field(default=(), max_length=MAX_CLAIM_HIGHLIGHTS)
    #: What a provider-owned, versioned test said about the basis behind this
    #: claim. Fusion reads the enum alone; the reasons are stable codes for
    #: the report, never weighed.
    qualification: ClaimQualification = ClaimQualification.UNQUALIFIED
    qualification_reasons: tuple[str, ...] = Field(
        default=(), max_length=MAX_CLAIM_QUALIFICATION_REASONS
    )
    #: ``True`` when TI Recon derived this claim from graph structure rather than
    #: a provider stating it. Such a claim names its derivation rule and can
    #: never be presented as something a provider reported.
    engine_derived: bool = False
    derivation_rule_id: str | None = Field(default=None, max_length=128)
    #: Claims this one was derived from, for an engine-derived claim.
    derived_from_claim_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _validate_claim(self) -> NormalizedClaim:
        if self.engine_derived and not self.derivation_rule_id:
            msg = "an engine-derived claim must name the rule that derived it"
            raise ValueError(msg)
        if self.derivation_rule_id and not self.engine_derived:
            msg = "only an engine-derived claim carries a derivation rule"
            raise ValueError(msg)
        if self.effect is EvidenceEffect.CONTEXT_ONLY:
            msg = "a normalized claim is directional; context is not a claim"
            raise ValueError(msg)
        return self

    @property
    def proposition(self) -> ClaimPropositionKey:
        return ClaimPropositionKey(
            subject_key=self.subject_key,
            semantic=self.semantic,
            scope=self.scope,
            target_key=self.target_key,
        )

    @property
    def is_malicious_direction(self) -> bool:
        return self.effect is EvidenceEffect.SUPPORTS_MALICIOUS

    @property
    def is_relayed(self) -> bool:
        """Whether this reached TI Recon through somebody other than its author."""
        return self.transport_provider != self.origin_provider


def claim_id_for(
    *,
    policy_version: str,
    evidence_id: str,
    semantic: ClaimSemantic,
    subject_key: str,
    scope: MatchScope,
    target_key: str = "",
) -> str:
    """A claim's record identity, derived from what it says about which evidence.

    The policy version participates because a translation change alters what the
    claim *means*; reusing an old id for a new meaning would make two stored
    assessments look comparable when they are not.

    **Record identity, not a cross-run semantic one.** ``evidence_id`` is a UUID
    minted when the evidence was collected, so this id is deterministic for one
    serialized evidence set and differs across fresh collections of the same
    intelligence. The cross-run identity is
    :class:`ClaimPropositionKey` -- subject, semantic and scope -- which is what
    to compare when asking whether two runs concern the same claim.
    """
    material = "|".join(
        (policy_version, evidence_id, semantic.value, subject_key, scope.value, target_key)
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:CLAIM_ID_LENGTH]


def claim_from(
    evidence: Evidence,
    *,
    policy_version: str,
    semantic: ClaimSemantic,
    subject_key: str,
    strength: ClaimAssertionStrength = ClaimAssertionStrength.ASSERTED,
    target_key: str = "",
    source_partial: bool = False,
    highlights: tuple[str, ...] = (),
    qualification: ClaimQualification = ClaimQualification.UNQUALIFIED,
    qualification_reasons: tuple[str, ...] = (),
) -> NormalizedClaim:
    """Build a claim as a view over one piece of evidence.

    Every provenance field is copied verbatim rather than recomputed: direction,
    class, scope, transport, origin, family and lineage are the provider's and
    Task 3's, and this layer's job is to add a proposition beside them, not to
    reinterpret them.
    """
    return NormalizedClaim(
        claim_id=claim_id_for(
            policy_version=policy_version,
            evidence_id=evidence.id,
            semantic=semantic,
            subject_key=subject_key,
            scope=evidence.match_scope,
            target_key=target_key,
        ),
        evidence_id=evidence.id,
        semantic=semantic,
        strength=strength,
        effect=evidence.effect,
        evidence_class=evidence.evidence_class,
        scope=evidence.match_scope,
        subject_key=subject_key,
        target_key=target_key,
        transport_provider=evidence.transport_provider,
        origin_provider=evidence.origin_provider,
        source_family=evidence.source_family,
        lineage_group_id=evidence.lineage_group_id,
        source_partial=source_partial,
        highlights=tuple(item[:MAX_CLAIM_HIGHLIGHT_LENGTH] for item in highlights)[
            :MAX_CLAIM_HIGHLIGHTS
        ],
        qualification=qualification,
        qualification_reasons=tuple(item[:64] for item in qualification_reasons)[
            :MAX_CLAIM_QUALIFICATION_REASONS
        ],
    )
