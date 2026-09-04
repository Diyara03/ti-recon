"""Vocabulary for alternative-explanation reasoning (Task 16).

Task 15 said what each finding means in time and context. Task 16 asks the next
question and only the next question: **can that context legitimately explain a
specific piece of evidence, and what does the explanation not cover?**

It does not decide the case. There is no verdict, no confidence, no score, no
weight and -- the one that matters most here -- **no false-positive boolean**.

A false positive is a property of a detection, not of an IOC
------------------------------------------------------------

``ip.is_false_positive = True`` is the model this package exists to refuse. An
address is not permanently a false positive; a *particular claim about it* may
have an alternative explanation while another claim about the same address has
none. So every finding names what it applies to through a typed
:class:`FindingLink`, and a reader can always ask "which evidence does this
explain, and which evidence did nothing explain?".

Explaining, limiting, and cautioning are different jobs
-------------------------------------------------------

Most context is not a candidate false-positive explanation at all:

* a URL reported offline changes *current activity*, not whether it ever served
  malware;
* a shared CDN range changes *attribution*, not whether the traffic happened;
* a relayed finding changes *independence*, not whether the finding is real;
* a sandbox that ran nothing changes *analysis quality*, not the sample.

Filing all four under "potential false positive" because they are cautionary is
the failure this vocabulary is shaped to prevent, which is why
:class:`ReasoningRole` separates them and why only one role means "this may
explain the detection".

Nothing here is a conclusion
----------------------------

:class:`DoesNotEstablish` exists so a finding can state its own limits in
machine-readable form rather than in prose a later layer would have to parse.
"A public resolver may explain the contact" travels with "this does not
establish the object is benign", so the boundary survives being read by
something that did not write it.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any, Final

from pydantic import Field, field_validator, model_validator

from ti_recon.enums import MatchScope
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.reasoning.models import CONCLUSION_FIELD_PATTERN, MAX_DETAIL_LENGTH, SubjectRef

__all__ = [
    "FINDING_ID_LENGTH",
    "DoesNotEstablish",
    "FindingLimitation",
    "FindingLink",
    "LinkRelation",
    "LinkTarget",
    "ReasonCode",
    "ReasoningDimension",
    "ReasoningFinding",
    "ReasoningRole",
    "finding_id_for",
]


class ReasoningRole(StrEnum):
    """What kind of job a finding is doing.

    Seven roles, and only one of them -- :attr:`ALTERNATIVE_EXPLANATION` -- is a
    candidate false-positive explanation. The separation is the point: shared
    hosting, current inactivity, relayed sourcing and a sandbox that observed
    nothing are all cautionary, and none of them says a detection was wrong.
    Collapsing them into "potential false positive" because they all sound like
    doubt is exactly how a real detection gets waved through.
    """

    #: Context may explain why this detection or claim occurred.
    ALTERNATIVE_EXPLANATION = "alternative_explanation"
    #: The evidence is real; it is being read more broadly than it supports.
    INTERPRETATION_LIMITATION = "interpretation_limitation"
    #: Analysis conditions limit how much a negative result can carry.
    ANALYSIS_QUALITY_LIMITATION = "analysis_quality_limitation"
    #: Something malicious happened; who owns the infrastructure is a separate
    #: question, and the evidence does not answer it.
    ATTRIBUTION_CAUTION = "attribution_caution"
    #: Historical evidence and current state answer different questions.
    TEMPORAL_RELEVANCE = "temporal_relevance"
    #: Two findings that are not two independent sources.
    SOURCE_DEPENDENCE = "source_dependence"
    #: Facts point opposite ways and this layer may not pick a side.
    UNRESOLVED_TENSION = "unresolved_tension"


class ReasoningDimension(StrEnum):
    """Which question a finding is about.

    Evidence from different dimensions must never cancel. "This URL distributed
    malware" and "this URL is offline now" are both true and answer different
    questions; a layer that treated the second as refuting the first would delete
    a real finding. Carrying the dimension is what lets a later layer see that
    two statements are not in conflict at all.

    Every member is emitted by a rule in this package. There is deliberately no
    ``BEHAVIOR`` member: the generic evidence model carries no discriminator that
    separates a behavioural claim from any other curated assertion, so nothing
    could set it honestly, and an unused member would be a promise this layer
    does not keep.
    """

    #: What the object itself is.
    OBJECT_NATURE = "object_nature"
    #: What a link between two objects signifies.
    RELATIONSHIP_INTERPRETATION = "relationship_interpretation"
    #: Whether something is happening now.
    CURRENT_ACTIVITY = "current_activity"
    #: What the surrounding hosting or addressing implies.
    INFRASTRUCTURE_CONTEXT = "infrastructure_context"
    #: Who owns or controls the thing the evidence concerns.
    ATTRIBUTION = "attribution"
    #: How much the analysis behind a finding can support.
    ANALYSIS_QUALITY = "analysis_quality"
    #: Whether two findings are separate sources.
    SOURCE_INDEPENDENCE = "source_independence"


class ReasonCode(StrEnum):
    """The specific named reason, one per rule outcome.

    A closed vocabulary, so a later layer keys on an enum member rather than on a
    sentence. The human-readable message is derived *from* the code and is never
    the authoritative form.
    """

    # -- alternative explanations ------------------------------------------ #
    #: The object is a deliberate test artifact; detecting it is what a scanner
    #: is supposed to do rather than a mistake it made.
    EXPECTED_TEST_ARTIFACT_DETECTION = "expected_test_artifact_detection"
    #: The digest identifies an empty file, which has no content to be malicious
    #: and collects reputation from everything that ever produced one.
    EMPTY_ARTIFACT_MAY_EXPLAIN_REPUTATION_DETECTION = (
        "empty_artifact_may_explain_reputation_detection"
    )
    #: Contacting a public DNS resolver is what programs do.
    PUBLIC_RESOLVER_MAY_EXPLAIN_CONTACT = "public_resolver_may_explain_contact"
    #: Connecting to common business-service infrastructure is ordinary traffic.
    KNOWN_BUSINESS_SERVICE_MAY_EXPLAIN_CONNECTION = "known_business_service_may_explain_connection"

    # -- interpretation limitations ---------------------------------------- #
    #: Context about a URL's host says nothing about the exact artifact on it.
    HOST_CONTEXT_DOES_NOT_EXPLAIN_EXACT_URL = "host_context_does_not_explain_exact_url"
    #: Public internet intelligence does not identify a private-range asset.
    PUBLIC_INTELLIGENCE_SCOPE_MISMATCH = "public_intelligence_scope_mismatch"
    #: Scanner context cannot be matched to a claim without knowing what the
    #: claim asserts, and the generic evidence model does not say.
    SCANNER_CONTEXT_ALIGNMENT_NOT_ESTABLISHED = "scanner_context_alignment_not_established"

    # -- attribution cautions ---------------------------------------------- #
    #: Shared infrastructure has tenants who are not the actor.
    SHARED_INFRASTRUCTURE_LIMITS_ATTRIBUTION = "shared_infrastructure_limits_attribution"
    #: A compromised host has a victim, and the victim is not the attacker.
    COMPROMISED_INFRASTRUCTURE_SEPARATES_OWNER_FROM_ACTOR = (
        "compromised_infrastructure_separates_owner_from_actor"
    )

    # -- temporal relevance -------------------------------------------------- #
    #: Not serving now is not the same as never having served.
    CURRENT_INACTIVITY_DOES_NOT_ERASE_HISTORICAL_MALICIOUSNESS = (
        "current_inactivity_does_not_erase_historical_maliciousness"
    )

    # -- analysis quality ---------------------------------------------------- #
    #: Nothing ran, so nothing was learned in either direction.
    SANDBOX_NEGATIVE_NOT_INFORMATIVE_WITHOUT_EXECUTION = (
        "sandbox_negative_not_informative_without_execution"
    )
    #: Something ran and nothing malicious appeared. Better grounded than a run
    #: that executed nothing, and still not a verdict.
    SANDBOX_NEGATIVE_REMAINS_NON_VERDICT = "sandbox_negative_remains_non_verdict"
    #: Runs disagreed across environments, which is a property of the sample.
    SANDBOX_RESULT_ENVIRONMENT_DEPENDENT = "sandbox_result_environment_dependent"

    # -- source dependence --------------------------------------------------- #
    #: One upstream source arriving twice is one source.
    RELAYED_FINDINGS_NOT_INDEPENDENT = "relayed_findings_not_independent"

    # -- unresolved tension -------------------------------------------------- #
    #: Directional evidence points both ways about the same object.
    OPPOSING_DIRECTIONAL_EVIDENCE_UNRESOLVED = "opposing_directional_evidence_unresolved"


class DoesNotEstablish(StrEnum):
    """What a finding explicitly fails to prove.

    A finding's own boundary, in machine-readable form. "A public resolver may
    explain the contact" is only safe to publish beside "this does not establish
    the object is benign", and prose would put that guarantee somewhere a later
    layer has to parse rather than read.

    Every member names something the finding does **not** support. The word
    ``SAFE`` appears here in exactly that sense -- as a denial -- and nowhere in
    the role, dimension or reason vocabularies, which a test asserts.
    """

    #: The object under investigation is benign.
    OBJECT_BENIGN = "object_benign"
    #: The malicious evidence was wrong.
    MALICIOUS_EVIDENCE_FALSE = "malicious_evidence_false"
    #: The historical evidence was wrong.
    HISTORICAL_EVIDENCE_FALSE = "historical_evidence_false"
    #: The infrastructure is safe to allow or to stop looking at.
    INFRASTRUCTURE_SAFE = "infrastructure_safe"
    #: The findings corroborate one another independently.
    INDEPENDENT_CORROBORATION = "independent_corroboration"


class FindingLimitation(StrEnum):
    """A caveat about the finding's own inputs, rather than about the evidence.

    Kept apart from :class:`DoesNotEstablish`, which says what the finding cannot
    conclude. This says how much the finding's *own* support is worth.
    """

    #: The context this finding leans on came from a dataset its provider
    #: reported as stale. The explanation stands and its footing is softer;
    #: saying so is better than silently discounting it with a number nobody
    #: could defend.
    SUPPORTING_CONTEXT_DATASET_STALE = "supporting_context_dataset_stale"
    #: The provider result behind the supporting context was itself partial.
    SUPPORTING_RESULT_PARTIAL = "supporting_result_partial"


class LinkRelation(StrEnum):
    """How a finding relates to the thing it points at.

    Typed rather than an untyped bag of ids: "explains" and "opposes" are the two
    most important distinctions in this package, and an array called
    ``evidence_refs`` would hide which was which.
    """

    #: This context may account for why that evidence exists.
    EXPLAINS = "explains"
    #: This narrows how that evidence should be read, without explaining it.
    QUALIFIES = "qualifies"
    #: This bounds what that evidence can be used for.
    LIMITS = "limits"
    #: That evidence points the other way and is not explained here.
    OPPOSES = "opposes"
    #: Two things that are not independent of one another.
    DEPENDENT_WITH = "dependent_with"
    #: Something that supports this finding without being its subject.
    SUPPORTED_BY = "supported_by"


class LinkTarget(StrEnum):
    """What sort of thing a link points at."""

    EVIDENCE = "evidence"
    RELATIONSHIP = "relationship"
    CONTEXT_SIGNAL = "context_signal"
    INTERPRETATION_CUE = "interpretation_cue"
    TEMPORAL_FACT = "temporal_fact"


class FindingLink(FrozenTiReconModel):
    """One typed pointer from a finding to what it concerns.

    ``ref`` is whatever deterministic identity the target already has -- an
    evidence id, a Task 15 signal or fact ref, a graph edge key. Nothing here
    mints a new identity for something that already had one, and nothing stores a
    Python object.
    """

    relation: LinkRelation
    target: LinkTarget
    ref: str = Field(min_length=1, max_length=900)


class ReasoningFinding(FrozenTiReconModel):
    """One deterministic interpretation, with its working shown.

    Carries no verdict, no confidence, no weight and no false-positive flag. What
    it carries is a named reason, the scope it applies at, typed links to the
    evidence and context it concerns, and an explicit statement of what it does
    not establish.
    """

    #: Content-derived, so the same inputs produce the same identity forever and
    #: two runs can be diffed. Never a random UUID: a semantic finding whose id
    #: changed on every run could not be stored, compared or referenced.
    finding_id: str = Field(min_length=1, max_length=64)
    rule_id: str = Field(min_length=1, max_length=128)
    policy_version: str = Field(min_length=1, max_length=32)

    role: ReasoningRole
    dimension: ReasoningDimension
    reason_code: ReasonCode

    subject: SubjectRef
    #: How precisely this applies. A host-scoped finding never speaks for an
    #: exact URL, and carrying the scope keeps that checkable rather than
    #: implied.
    match_scope: MatchScope = MatchScope.UNKNOWN

    links: tuple[FindingLink, ...] = ()
    does_not_establish: tuple[DoesNotEstablish, ...] = ()
    limitations: tuple[FindingLimitation, ...] = ()

    #: Rendered from ``reason_code`` and structured parameters by a fixed
    #: template. Presentation only -- the enum members above are authoritative,
    #: and no rule ever reads this string back.
    message: str = Field(default="", max_length=600)
    detail: dict[str, Any] = Field(default_factory=dict)

    @field_validator("detail")
    @classmethod
    def _check_detail(cls, value: dict[str, Any]) -> dict[str, Any]:
        for key, item in value.items():
            if CONCLUSION_FIELD_PATTERN.search(key):
                msg = f"Task 16 detail must not carry a conclusion field: {key!r}"
                raise ValueError(msg)
            if isinstance(item, bool | int | float):
                continue
            if isinstance(item, str) and len(item) <= MAX_DETAIL_LENGTH:
                continue
            msg = f"detail value for {key!r} must be a short scalar"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _require_a_target(self) -> ReasoningFinding:
        """Every finding says what it is about.

        A finding with no links would be "this object has false-positive
        context" -- precisely the shapeless output this package exists to avoid,
        and useless to a layer that has to ask which evidence was explained.
        """
        if not self.links:
            msg = "a reasoning finding must link to the evidence or relationship it concerns"
            raise ValueError(msg)
        return self

    @property
    def explained_evidence_ids(self) -> tuple[str, ...]:
        """Evidence this finding claims to account for.

        Only :attr:`LinkRelation.EXPLAINS`, and only from an
        :attr:`ReasoningRole.ALTERNATIVE_EXPLANATION`. A limitation that
        *qualifies* evidence has not explained it, and letting the two blur is
        how unexplained malicious evidence disappears from a summary.
        """
        if self.role is not ReasoningRole.ALTERNATIVE_EXPLANATION:
            return ()
        return tuple(
            sorted(
                item.ref
                for item in self.links
                if item.relation is LinkRelation.EXPLAINS and item.target is LinkTarget.EVIDENCE
            )
        )

    @property
    def opposing_evidence_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                item.ref
                for item in self.links
                if item.relation is LinkRelation.OPPOSES and item.target is LinkTarget.EVIDENCE
            )
        )


#: Length of a finding's content-derived identity. Long enough that two distinct
#: findings colliding is not a practical concern, short enough to read in a diff.
FINDING_ID_LENGTH: Final[int] = 32


def finding_id_for(
    *,
    policy_version: str,
    rule_id: str,
    subject: SubjectRef,
    match_scope: MatchScope,
    link_refs: tuple[str, ...],
) -> str:
    """A finding's stable identity, derived from what it says.

    Sorted link refs, so two runs that discovered the same links in a different
    order produce one identity rather than two. The policy version is part of the
    key on purpose: a rule change that alters what a finding means should produce
    a *different* finding rather than quietly reusing an old id.
    """
    material = "".join(
        (policy_version, rule_id, subject.ref, match_scope.value, *sorted(link_refs))
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:FINDING_ID_LENGTH]
