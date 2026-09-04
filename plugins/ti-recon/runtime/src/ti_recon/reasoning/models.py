"""Temporal and context qualification vocabulary (Task 15).

What this package answers is **"what does this piece of evidence actually mean
in time and context?"** — never "what is the verdict?". There is no verdict, no
confidence, no risk score, no evidence weight and no false-positive boolean
anywhere in Task 15, and a test asserts that by reading the field names of every
model defined here.

Five ideas carry the design.

A timestamp has a type
----------------------

"2026-03-01" is not a fact until somebody says *which question it answers*.
VirusTotal's ``last_analysis_date`` is when a file was last scanned; URLhaus's
``last_online`` is when a URL last served a payload; a sandbox's
``analysis_start_time`` is when somebody detonated a sample. Pouring all three
into one ``last_seen`` field turns "we rescanned it yesterday" into "it attacked
somebody yesterday", which is the single most common way a freshness heuristic
lies. Every instant here therefore carries a :class:`TemporalFactKind`, and the
provider's own field name beside it.

The clock is an argument
------------------------

Age is computed against an explicit ``as_of`` handed to the engine. Nothing here
reads a wall clock, so two runs over the same inputs at the same ``as_of``
produce the same output forever, and a stored result stays re-derivable.

Lifecycle belongs to the source
-------------------------------

URLhaus knows whether a URL is serving right now. ThreatFox knows that its API
holds roughly six months. MISP's snapshot knows when it was generated. Those are
:class:`SourceLifecycleState` values, stated by whoever is entitled to state
them. TI Recon invents no generic "older than thirty days is stale" rule, because
a phishing URL, a malware hash, a cloud address and a certificate do not share a
lifetime and never will.

Context explains; it never exonerates
-------------------------------------

A :class:`ContextSignal` says "this value is in a public-resolver list", "this
address is common business-service infrastructure", "the provider says this host
is compromised". None of those means benign, and the vocabulary deliberately has
no member that could be read that way — no ``SAFE``, no ``TRUSTED``, no
``BENIGN_CONTEXT``. A cloud range hosts attacks, a CDN serves malware, and a
warninglist can be stale.

Nothing propagates
------------------

A cue is attached to the node, edge or piece of evidence it was derived from, and
to nothing else. Context does not travel along edges: a file that contacted a
public resolver does not become "public resolver adjacent", and the resolver does
not become malicious. The one edge-scoped rule in this package reads a single
edge and stops.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Final

from pydantic import Field, field_validator, model_validator

from ti_recon.correlation.models import RelationBasis
from ti_recon.enums import EvidenceClass, EvidenceEffect, MatchScope
from ti_recon.models.base import FrozenTiReconModel, UtcDatetime
from ti_recon.models.evidence import Evidence

__all__ = [
    "CONCLUSION_FIELD_PATTERN",
    "ContextSignal",
    "ContextSignalType",
    "CuePurpose",
    "EvidenceRef",
    "InterpretationCue",
    "InterpretationCueType",
    "SignalOrigin",
    "SourceLifecycleState",
    "SubjectKind",
    "SubjectRef",
    "TemporalFact",
    "TemporalFactKind",
    "TemporalIssue",
    "TemporalIssueType",
    "TemporalQualification",
    "dataset_subject",
    "edge_subject",
    "observable_subject",
    "report_subject",
]

#: Names Task 15 must never carry, checked wherever this layer accepts a
#: free-form structured detail.
#:
#: Qualification hands the future fusion layer facts to weigh. The moment a cue
#: could carry ``risk_score`` or ``is_false_positive``, something downstream would
#: read it instead of doing the weighing, and the layering would be gone without
#: anybody deciding to remove it.
CONCLUSION_FIELD_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?:^|_)(?:verdict|risk|malicious_score|benign_score|decay|weight|"
    r"confidence|false_positive|is_benign|is_safe)(?:$|_)",
    re.IGNORECASE,
)

#: Longest string a structured detail value may hold. Details are vocabulary and
#: small identifiers, never provider prose.
MAX_DETAIL_LENGTH: Final[int] = 200


class TemporalFactKind(StrEnum):
    """Which of the five time questions an instant answers.

    The five questions, and why they are not interchangeable:

    1. **When did a source receive the object?** ``FIRST_SUBMITTED`` /
       ``LAST_SUBMITTED``. Somebody uploaded a file. It says nothing about when
       the file was used against anyone.
    2. **When did a source analyze it?** ``ANALYZED_AT`` / ``SCANNED_AT``. A
       rescan today does not make an indicator active today.
    3. **When was activity observed?** ``FIRST_OBSERVED`` / ``LAST_OBSERVED`` /
       ``LAST_ONLINE_AT`` / the relationship pair. This is the only family that
       is about the threat rather than about the platform.
    4. **What does the source say is true now?** Carried as
       :class:`SourceLifecycleState` beside the instant, not as an instant.
    5. **How fresh is the dataset?** ``SNAPSHOT_GENERATED_AT`` and
       ``ADDED_TO_DATASET_AT``, which describe the corpus rather than the world.

    Every member below is emitted by a real extractor over data a shipped
    provider already normalizes. None is speculative.
    """

    #: Earliest activity the source attributes to the observable.
    FIRST_OBSERVED = "first_observed"
    #: Most recent activity the source attributes to the observable.
    LAST_OBSERVED = "last_observed"
    #: When the observable first reached the platform's collection.
    FIRST_SUBMITTED = "first_submitted"
    #: When it most recently reached the platform's collection.
    LAST_SUBMITTED = "last_submitted"
    #: When the platform last ran its own analysis. **Not** an observation.
    ANALYZED_AT = "analyzed_at"
    #: When a web scan visited the page. A point-in-time browser observation.
    SCANNED_AT = "scanned_at"
    #: When a curated dataset added the record.
    ADDED_TO_DATASET_AT = "added_to_dataset_at"
    #: When a URL was last confirmed serving. Only meaningful beside a status.
    LAST_ONLINE_AT = "last_online_at"
    #: When the source last touched its own record. Housekeeping, not activity.
    SOURCE_RECORD_UPDATED_AT = "source_record_updated_at"
    #: Start of a certificate's validity window.
    VALID_FROM = "valid_from"
    #: End of a certificate's validity window.
    VALID_UNTIL = "valid_until"
    #: When a local dataset snapshot was built.
    SNAPSHOT_GENERATED_AT = "snapshot_generated_at"
    #: Earliest time an assertion gives for one relationship.
    RELATIONSHIP_FIRST_OBSERVED = "relationship_first_observed"
    #: Latest time an assertion gives for one relationship.
    RELATIONSHIP_LAST_OBSERVED = "relationship_last_observed"


#: Interval semantics, expressed as pairs rather than as a range type.
#:
#: A fact is always an instant. An interval is two facts about one subject from
#: one source, and the only thing the engine does with the pairing is check that
#: the start does not follow the end. Modelling ranges directly would have meant
#: inventing a start for every provider that reports only a "last seen", and
#: pretending an observation window existed where the source stated a point.
INTERVAL_PAIRS: Final[dict[TemporalFactKind, TemporalFactKind]] = {
    TemporalFactKind.FIRST_OBSERVED: TemporalFactKind.LAST_OBSERVED,
    TemporalFactKind.FIRST_SUBMITTED: TemporalFactKind.LAST_SUBMITTED,
    TemporalFactKind.VALID_FROM: TemporalFactKind.VALID_UNTIL,
    TemporalFactKind.RELATIONSHIP_FIRST_OBSERVED: TemporalFactKind.RELATIONSHIP_LAST_OBSERVED,
}


class SourceLifecycleState(StrEnum):
    """What the *source* says about the record's current standing.

    Deliberately qualitative and deliberately source-owned. There is no
    ``SAFE``, no ``BENIGN`` and no ``TRUSTED``, and there is no
    ``ACTIVE_NOW``: a record coming back from an API proves the API holds it,
    not that the infrastructure is live.
    """

    #: The source explicitly says the artifact is serving/active right now.
    ACTIVE_BY_SOURCE = "active_by_source"
    #: The source explicitly says it is not serving right now. History, not
    #: absolution: a URL that distributed malware last month still did.
    INACTIVE_BY_SOURCE = "inactive_by_source"
    #: The source was asked and could not say.
    STATUS_UNKNOWN = "status_unknown"
    #: The record is inside the source's retention horizon and nothing more.
    #: ThreatFox drops indicators from its API after roughly six months, so a
    #: returned record means "unexpired", never "currently active".
    WITHIN_SOURCE_API_HORIZON = "within_source_api_horizon"
    #: A single observation at one instant, with no claim about before or after.
    POINT_IN_TIME = "point_in_time"
    #: A local dataset older than its configured staleness threshold.
    DATASET_STALE = "dataset_stale"
    #: A local dataset inside its threshold. Still a snapshot, not a live feed.
    DATASET_CURRENT = "dataset_current"


class TemporalIssueType(StrEnum):
    """A temporal statement that cannot be taken at face value.

    Deliberately two members. A missing timestamp is *coverage* — most providers
    report a time for some claims and not others, and turning every absence into
    an issue would bury the two cases that genuinely mean the data is wrong.
    """

    #: An instant after ``as_of`` by more than the clock-skew tolerance.
    FUTURE_TIMESTAMP = "future_timestamp"
    #: An interval whose start follows its end. Never repaired by swapping.
    INVALID_INTERVAL = "invalid_interval"


class ContextSignalType(StrEnum):
    """Structured context that bears on how evidence should be read.

    A signal is **not** evidence: it makes no claim about the world that a
    provider did not already make, and it points in no direction. Every member
    is a caveat or an explanation, and none of them means safe. There is
    deliberately no ``BENIGN_CONTEXT``, no ``SAFE_IP`` and no
    ``TRUSTED_DOMAIN``: a cloud range hosts attacks, a CDN serves malware, a
    popular domain has a malicious path on it, and an EICAR hash is a test
    artifact rather than an ordinary benign file.
    """

    #: A warninglist matched and TI Recon has no semantic mapping for it.
    WARNINGLIST_MATCH = "warninglist_match"
    #: Mapped known internet-scanning infrastructure.
    KNOWN_SCANNER = "known_scanner"
    #: Mapped public DNS resolver infrastructure.
    PUBLIC_RESOLVER = "public_resolver"
    #: Mapped private, reserved, documentation or special-use range.
    PRIVATE_OR_SPECIAL_USE = "private_or_special_use"
    #: Mapped shared cloud, CDN or shared-hosting infrastructure.
    SHARED_CLOUD_OR_CDN = "shared_cloud_or_cdn"
    #: Mapped popular or commonly-visited service.
    POPULAR_OR_COMMON_SERVICE = "popular_or_common_service"
    #: Common business-service infrastructure a provider identified. Not an
    #: allow list, and never a reason to discount a directional finding.
    BUSINESS_SERVICE = "business_service"
    #: A deliberate test artifact — EICAR and friends.
    TEST_ARTIFACT = "test_artifact"
    #: The digest of an empty file, which identifies nothing in particular.
    EMPTY_ARTIFACT = "empty_artifact"
    #: The source says the malicious activity sits on compromised legitimate
    #: infrastructure. Changes attribution and blocking, never the direction.
    COMPROMISED_INFRASTRUCTURE = "compromised_infrastructure"
    #: The context applies to a component of the observable, not the observable.
    HOST_COMPONENT_CONTEXT = "host_component_context"
    #: A completed sandbox run in which nothing was observed executing.
    SANDBOX_LOW_EXECUTION = "sandbox_low_execution"
    #: A completed sandbox run in which execution genuinely happened.
    SANDBOX_MEANINGFUL_EXECUTION = "sandbox_meaningful_execution"
    #: Completed sandbox runs that disagreed across environments.
    SANDBOX_DIVERGENCE = "sandbox_divergence"
    #: A finding that reached TI Recon through a third party.
    RELAYED_SOURCE = "relayed_source"


class SignalOrigin(StrEnum):
    """Who decided this signal applies.

    Kept because the two are audited differently. A provider-stated signal is
    only as good as the provider; an engine-policy signal is only as good as the
    versioned mapping that produced it, and that mapping is TI Recon's to defend.
    """

    #: The provider stated the structured fact directly.
    PROVIDER_REPORTED = "provider_reported"
    #: A versioned TI Recon mapping turned a provider fact into a category.
    ENGINE_POLICY = "engine_policy"


class CuePurpose(StrEnum):
    """What kind of care a cue is asking a later layer to take.

    Not a polarity and not a weight. "This is shared infrastructure" is neither
    positive nor negative evidence; it is a reason to be careful about who owns
    what, and a reason a block has a victim.
    """

    #: What a timestamp does and does not establish.
    TEMPORAL_CAUTION = "temporal_caution"
    #: Context that may explain a finding without refuting it.
    FALSE_POSITIVE_CONTEXT = "false_positive_context"
    #: Ownership or actor attribution is harder than it looks here.
    ATTRIBUTION_CAUTION = "attribution_caution"
    #: The context applies to something narrower than the observable.
    SCOPE_CAUTION = "scope_caution"
    #: How much an absence of findings is actually worth.
    NEGATIVE_EVIDENCE_LIMITATION = "negative_evidence_limitation"
    #: Two findings that are not two independent sources.
    SOURCE_DEPENDENCE = "source_dependence"
    #: How much the analysis behind a finding can support.
    ANALYSIS_QUALITY = "analysis_quality"


class InterpretationCueType(StrEnum):
    """A named caution, addressed to whoever eventually weighs the evidence.

    Each member is produced by exactly one deterministic rule over structured
    inputs. None of them is a conclusion, and none of them can be turned into
    one without a later layer deciding to.
    """

    #: A malicious artifact the source says is not currently serving.
    HISTORICAL_MALICIOUS_CURRENTLY_INACTIVE = "historical_malicious_currently_inactive"
    #: The source manages this record's visibility on its own horizon.
    SOURCE_MANAGED_LIFECYCLE = "source_managed_lifecycle"
    #: Host-level context, on an observable that is not the host.
    HOST_CONTEXT_DOES_NOT_CLEAR_EXACT_URL = "host_context_does_not_clear_exact_url"
    #: Shared infrastructure complicates ownership and broad blocking.
    SHARED_INFRASTRUCTURE_ATTRIBUTION_CAUTION = "shared_infrastructure_attribution_caution"
    #: Observed traffic may be consistent with known internet scanning.
    KNOWN_SCANNER_MAY_EXPLAIN_ACTIVITY = "known_scanner_may_explain_activity"
    #: A contact with common infrastructure may have an ordinary explanation.
    PUBLIC_SERVICE_MAY_EXPLAIN_CONTACT = "public_service_may_explain_contact"
    #: Common business-service infrastructure may explain observed activity.
    BUSINESS_SERVICE_MAY_EXPLAIN_ACTIVITY = "business_service_may_explain_activity"
    #: Malicious activity on somebody else's compromised host.
    COMPROMISED_INFRASTRUCTURE_ATTRIBUTION_CAUTION = (
        "compromised_infrastructure_attribution_caution"
    )
    #: A deliberate test artifact rather than an incident.
    TEST_ARTIFACT_CONTEXT = "test_artifact_context"
    #: An empty-file digest, which identifies no particular content.
    EMPTY_ARTIFACT_CONTEXT = "empty_artifact_context"
    #: A sandbox negative from a run in which nothing executed.
    SANDBOX_NEGATIVE_LOW_INFORMATION = "sandbox_negative_low_information"
    #: A sandbox negative from a run in which execution was observed.
    SANDBOX_NEGATIVE_WITH_MEANINGFUL_EXECUTION = "sandbox_negative_with_meaningful_execution"
    #: Completed runs disagreed. Environment-dependent behaviour, not a defect.
    SANDBOX_ENVIRONMENT_DIVERGENCE = "sandbox_environment_divergence"
    #: A relayed finding is not a second source.
    RELAYED_SOURCE_NOT_INDEPENDENT = "relayed_source_not_independent"
    #: The local context dataset is older than its staleness threshold.
    STALE_CONTEXT_DATASET = "stale_context_dataset"


class SubjectKind(StrEnum):
    """What a qualification is about."""

    #: A graph node, keyed by its canonical observable key.
    OBSERVABLE = "observable"
    #: One semantic graph edge.
    RELATIONSHIP = "relationship"
    #: One sandbox run.
    SANDBOX_REPORT = "sandbox_report"
    #: A local dataset a provider read.
    CONTEXT_DATASET = "context_dataset"


class SubjectRef(FrozenTiReconModel):
    """A deterministic pointer to what a qualification concerns.

    A string key rather than a Python reference, so a result serializes, sorts
    and compares the same way on every run. Node keys are the canonical
    correlation keys, so a Task 15 result joins straight onto a Task 14 graph.
    """

    kind: SubjectKind
    key: str = Field(min_length=1, max_length=700)

    @property
    def ref(self) -> str:
        return f"{self.kind.value}:{self.key}"


def observable_subject(node_key: str) -> SubjectRef:
    return SubjectRef(kind=SubjectKind.OBSERVABLE, key=node_key)


def edge_subject(source_key: str, relationship_type: str, target_key: str) -> SubjectRef:
    """The subject for one semantic edge, keyed exactly as the graph keys it."""
    return SubjectRef(
        kind=SubjectKind.RELATIONSHIP,
        key=f"{source_key}|{relationship_type}|{target_key}",
    )


def report_subject(provider_id: str, report_id: str) -> SubjectRef:
    return SubjectRef(kind=SubjectKind.SANDBOX_REPORT, key=f"{provider_id}:{report_id}")


def dataset_subject(provider_id: str, dataset_id: str) -> SubjectRef:
    return SubjectRef(kind=SubjectKind.CONTEXT_DATASET, key=f"{provider_id}:{dataset_id}")


class EvidenceRef(FrozenTiReconModel):
    """Provenance of the evidence a qualification came from, copied not moved.

    Task 15 never mutates a piece of evidence. It records enough of one to
    explain a cue — which provider transported it, who originated it, which
    family and lineage group it belongs to, how precisely it applies, and which
    way it already points — and leaves the authoritative record untouched.

    ``effect`` is carried **read-only**. It is what lets a cue say "this
    malicious finding concerns a URL the source reports offline" without
    anything here being able to change the finding's direction.
    """

    evidence_id: str = Field(min_length=1, max_length=200)
    claim_type: str = Field(min_length=1, max_length=128)
    transport_provider: str = Field(min_length=1, max_length=64)
    origin_provider: str = Field(min_length=1, max_length=64)
    source_family: str = Field(min_length=1, max_length=64)
    lineage_group_id: str = Field(default="", max_length=200)
    evidence_class: EvidenceClass
    effect: EvidenceEffect
    match_scope: MatchScope = MatchScope.UNKNOWN
    relayed: bool = False

    @classmethod
    def of(cls, evidence: Evidence) -> EvidenceRef:
        return cls(
            evidence_id=evidence.id,
            claim_type=evidence.claim_type,
            transport_provider=evidence.transport_provider,
            origin_provider=evidence.origin_provider,
            source_family=evidence.source_family,
            lineage_group_id=evidence.lineage_group_id,
            evidence_class=evidence.evidence_class,
            effect=evidence.effect,
            match_scope=evidence.match_scope,
            relayed=evidence.is_relayed,
        )


def _validate_detail(value: dict[str, Any]) -> dict[str, Any]:
    """Structured detail only: short scalars, and never a conclusion."""
    for key, item in value.items():
        if CONCLUSION_FIELD_PATTERN.search(key):
            msg = f"Task 15 detail must not carry a conclusion field: {key!r}"
            raise ValueError(msg)
        if isinstance(item, bool | int | float):
            continue
        if isinstance(item, str):
            if len(item) > MAX_DETAIL_LENGTH:
                msg = f"detail value for {key!r} exceeds {MAX_DETAIL_LENGTH} characters"
                raise ValueError(msg)
            continue
        msg = f"detail value for {key!r} must be a short scalar"
        raise ValueError(msg)
    return value


class TemporalFact(FrozenTiReconModel):
    """One typed instant, exactly as a source stated it.

    Never repaired and never invented. A future timestamp stays in the future, an
    inverted interval keeps both endpoints, and no instant is ever manufactured
    from a request time, a cache time or an enrichment time — those are system
    metadata, and letting one become a ``last_seen`` would make every lookup look
    like fresh activity.
    """

    subject: SubjectRef
    kind: TemporalFactKind
    instant: UtcDatetime

    transport_provider: str | None = Field(default=None, min_length=1, max_length=64)
    origin_provider: str | None = Field(default=None, min_length=1, max_length=64)
    source_family: str | None = Field(default=None, min_length=1, max_length=64)
    lineage_group_id: str = Field(default="", max_length=200)

    #: The provider's own field name, so a mapping can always be argued with.
    raw_field: str | None = Field(default=None, max_length=128)
    #: What the source says about the record's standing, when it says anything.
    lifecycle: SourceLifecycleState | None = None
    #: ``True`` when the provider result this came from was itself partial.
    source_partial: bool = False
    #: How a relationship was learned, for facts read off a graph assertion.
    relation_basis: RelationBasis | None = None
    #: The evidence record behind this fact, when one produced it.
    evidence: EvidenceRef | None = None
    #: A bounded discriminator — a report id, an environment, a list slug.
    detail: str | None = Field(default=None, max_length=MAX_DETAIL_LENGTH)

    #: Deterministic identity, so a cue can point at a fact without an object
    #: reference. Derived from content, set once, never a memory address.
    ref: str = Field(default="", max_length=900)

    @model_validator(mode="after")
    def _derive_ref(self) -> TemporalFact:
        if not self.ref:
            object.__setattr__(
                self,
                "ref",
                "|".join(
                    (
                        self.subject.ref,
                        self.kind.value,
                        self.instant.isoformat(),
                        self.origin_provider or "",
                        self.raw_field or "",
                        self.detail or "",
                    )
                )[:900],
            )
        return self


class TemporalQualification(FrozenTiReconModel):
    """A fact plus what it is worth relative to one explicit ``as_of``.

    Age is exact and unlabelled. There is no ``fresh``, no ``stale`` and no
    ``old``, because a two-year-old malware hash and a two-year-old cloud address
    are not comparably aged and no single threshold describes both. Where a
    *source* defines a lifecycle, it is on the fact; where it does not, a later
    layer gets the number and decides.
    """

    fact: TemporalFact
    #: Absent whenever an issue made the arithmetic meaningless.
    age_seconds: float | None = Field(default=None, ge=0.0)
    age_days: float | None = Field(default=None, ge=0.0)
    issue_types: tuple[TemporalIssueType, ...] = ()


class ContextSignal(FrozenTiReconModel):
    """Structured context relevant to reading evidence. Never evidence itself.

    Carries enough provenance to answer the four questions a later layer will
    ask: what it is about, who said so, which family and lineage that belongs to,
    and how precisely it applies. It carries no provider payload — a signal is a
    category and a key, not a copy of a response.
    """

    signal_type: ContextSignalType
    subject: SubjectRef
    origin: SignalOrigin
    match_scope: MatchScope = MatchScope.UNKNOWN
    #: ``True`` when the context is about a component of the observable — a
    #: URL's host — rather than the observable itself.
    host_component_only: bool = False

    transport_provider: str | None = Field(default=None, min_length=1, max_length=64)
    origin_provider: str | None = Field(default=None, min_length=1, max_length=64)
    source_family: str | None = Field(default=None, min_length=1, max_length=64)
    lineage_group_id: str = Field(default="", max_length=200)

    evidence: EvidenceRef | None = None
    #: The exact structured key behind the signal: a warninglist slug, a report
    #: id. Never a provider description and never matched prose.
    source_key: str | None = Field(default=None, max_length=200)
    source_partial: bool = False
    detail: dict[str, Any] = Field(default_factory=dict)

    ref: str = Field(default="", max_length=900)

    @field_validator("detail")
    @classmethod
    def _check_detail(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_detail(value)

    @model_validator(mode="after")
    def _derive_ref(self) -> ContextSignal:
        if not self.ref:
            object.__setattr__(
                self,
                "ref",
                "|".join(
                    (
                        self.subject.ref,
                        self.signal_type.value,
                        self.origin_provider or "",
                        self.source_key or "",
                        self.match_scope.value,
                    )
                )[:900],
            )
        return self


class InterpretationCue(FrozenTiReconModel):
    """A named caution about how to read something, with its working shown.

    Deliberately has no verdict, no confidence, no weight and no recommended
    action. A cue says "this malicious URL is reported offline" or "this negative
    sandbox run observed no execution"; what either is *worth* is the fusion
    layer's decision, and a cue that pre-empted it would be a verdict wearing a
    different name.
    """

    cue_type: InterpretationCueType
    purpose: CuePurpose
    subject: SubjectRef
    #: How precisely the cue applies. A host-scoped cue never speaks for an
    #: exact URL, and carrying the scope is what keeps that checkable.
    match_scope: MatchScope = MatchScope.UNKNOWN
    #: Refs into this result's own facts and signals — the cue's derivation.
    temporal_fact_refs: tuple[str, ...] = ()
    context_signal_refs: tuple[str, ...] = ()
    #: Evidence ids the cue concerns. Read-only: nothing here edits evidence.
    evidence_ids: tuple[str, ...] = ()
    detail: dict[str, Any] = Field(default_factory=dict)

    @field_validator("detail")
    @classmethod
    def _check_detail(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_detail(value)

    @property
    def key(self) -> tuple[str, str, str]:
        """What makes two cues the same caution rather than two cautions."""
        return (self.cue_type.value, self.subject.ref, self.purpose.value)


class TemporalIssue(FrozenTiReconModel):
    """A temporal statement that cannot be read literally.

    Recorded rather than repaired. Swapping an inverted interval or clamping a
    future timestamp would hand a later layer a clean number that the source
    never stated, and the correction would be invisible.
    """

    issue_type: TemporalIssueType
    subject: SubjectRef
    kind: TemporalFactKind
    #: Short vocabulary, never provider prose.
    detail: str = Field(default="", max_length=300)
    fact_refs: tuple[str, ...] = ()
