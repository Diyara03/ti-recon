"""The deterministic rules (Task 16).

Fifteen rules, each keyed on structured inputs only: a Task 15 signal type, an
``EvidenceEffect``, a ``MatchScope``, a ``SourceLifecycleState``, a graph
relationship type. Nothing reads a description, a provider name, a tag or a
claim type, and no rule can be influenced by a string a provider chose.

That last point is not fastidiousness. Every ``claim_type`` in this repository is
provider-prefixed -- ``urlhaus_malware_url``, ``threatfox_ioc``,
``greynoise_classification`` -- so a rule that keyed on one would embed a vendor
in the generic engine, and the boundary test reading this file's AST would catch
it. The consequence is real and is documented where it bites: see
``_known_scanner``.

Two things every rule obeys
---------------------------

**Context alone explains nothing.** Every rule that could produce an alternative
explanation first requires something *to* explain -- directional evidence, or an
explicit relationship whose significance is in question. A warninglist hit on an
address nobody has accused of anything is context, and stays context.

**Scope is checked, never assumed.** An explanation about an object must come
from context about that object. Host-level context produces a scope limitation
and never an explanation, and the check is a field comparison rather than a
comment.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from ti_recon.correlation.models import GraphEdge
from ti_recon.enums import EvidenceEffect, MatchScope, RelationshipType
from ti_recon.models.evidence import Evidence
from ti_recon.reasoning.false_positive.index import ReasoningIndex, edge_ref
from ti_recon.reasoning.false_positive.models import (
    FindingLimitation,
    FindingLink,
    LinkRelation,
    LinkTarget,
    ReasonCode,
    ReasoningFinding,
    finding_id_for,
)
from ti_recon.reasoning.false_positive.policy import (
    EXPLAINABLE_CONTEXT_SIGNALS,
    FALSE_POSITIVE_REASONING_POLICY_VERSION,
    HOST_SCOPED_CONTEXT_SIGNALS,
    REASON_BOUNDARIES,
    REASON_SEMANTICS,
    RULE_IDS,
    message_for,
)
from ti_recon.reasoning.models import (
    ContextSignal,
    ContextSignalType,
    SourceLifecycleState,
    SubjectRef,
    observable_subject,
)

__all__ = ["ALL_RULES", "apply_rules"]

#: Relationship types whose significance common-infrastructure context can speak
#: to.
#:
#: Narrow on purpose. A sample *contacting* a resolver is routine; a URL
#: *redirecting to* one would not be, and would deserve a look rather than an
#: explanation.
_CONTACT_TYPES: frozenset[RelationshipType] = frozenset({RelationshipType.CONTACTS})

#: Context that limits attribution without touching the finding itself.
_SHARED_INFRASTRUCTURE_SIGNALS: frozenset[ContextSignalType] = frozenset(
    {ContextSignalType.SHARED_CLOUD_OR_CDN, ContextSignalType.POPULAR_OR_COMMON_SERVICE}
)


def _finding(
    *,
    rule_key: str,
    reason: ReasonCode,
    subject: SubjectRef,
    match_scope: MatchScope,
    links: Sequence[FindingLink],
    limitations: Sequence[FindingLimitation] = (),
    message_parameters: dict[str, object] | None = None,
    detail: dict[str, object] | None = None,
) -> ReasoningFinding:
    """Assemble one finding from the policy tables.

    Role, dimension and boundaries all come from :mod:`policy` rather than from
    the rule body, so a rule decides only *whether* it fires and never what its
    output is allowed to mean.
    """
    role, dimension = REASON_SEMANTICS[reason]
    ordered = tuple(
        sorted(links, key=lambda item: (item.relation.value, item.target.value, item.ref))
    )
    return ReasoningFinding(
        finding_id=finding_id_for(
            policy_version=FALSE_POSITIVE_REASONING_POLICY_VERSION,
            rule_id=RULE_IDS[rule_key],
            subject=subject,
            match_scope=match_scope,
            link_refs=tuple(item.ref for item in ordered),
        ),
        rule_id=RULE_IDS[rule_key],
        policy_version=FALSE_POSITIVE_REASONING_POLICY_VERSION,
        role=role,
        dimension=dimension,
        reason_code=reason,
        subject=subject,
        match_scope=match_scope,
        links=ordered,
        does_not_establish=REASON_BOUNDARIES[reason],
        limitations=tuple(sorted(set(limitations), key=lambda item: item.value)),
        message=message_for(reason, **(message_parameters or {})),
        detail=dict(sorted((detail or {}).items())),
    )


def _evidence_links(evidence: Iterable[Evidence], relation: LinkRelation) -> list[FindingLink]:
    return [
        FindingLink(relation=relation, target=LinkTarget.EVIDENCE, ref=item.id) for item in evidence
    ]


def _signal_links(
    signals: Iterable[ContextSignal], relation: LinkRelation = LinkRelation.SUPPORTED_BY
) -> list[FindingLink]:
    return [
        FindingLink(relation=relation, target=LinkTarget.CONTEXT_SIGNAL, ref=item.ref)
        for item in signals
    ]


def _stale(index: ReasoningIndex, signals: Iterable[ContextSignal]) -> list[FindingLimitation]:
    """Caveats about the support *this* finding leans on.

    A stale warninglist snapshot does not delete an explanation -- the list was
    right about EICAR last month and still is -- but a reader deserves to know
    the footing, and a numerical penalty would be a made-up number standing in
    for a fact that is already available.

    Scoped to the finding's own supporting signals, and that scoping is the point.
    Staleness belongs to the dataset that is stale: one provider shipping an old
    snapshot says nothing about a second provider's compromised-host report, and
    a run-level flag would stamp "supporting context dataset stale" onto findings
    that never touched the stale corpus -- a caveat pointing at the wrong
    evidence, which is worse than none.
    """
    supporting = tuple(signals)
    found: list[FindingLimitation] = []
    if index.stale_context_families and any(
        (item.source_family or item.transport_provider) in index.stale_context_families
        for item in supporting
    ):
        found.append(FindingLimitation.SUPPORTING_CONTEXT_DATASET_STALE)
    if any(item.source_partial for item in supporting):
        found.append(FindingLimitation.SUPPORTING_RESULT_PARTIAL)
    return found


# --------------------------------------------------------------------------- #
# Object-scope alternative explanations
# --------------------------------------------------------------------------- #


def _object_nature_explanations(index: ReasoningIndex) -> list[ReasoningFinding]:
    """A test artifact or an empty file may account for a detection about it.

    The two strongest alternative explanations available, and the only two that
    speak about the object itself. Both require **exact-scope** context and
    **same-subject** malicious evidence: a detection somewhere else is not
    explained by what this artifact is.

    Directly-observed behaviour is deliberately not explained. If a sandbox
    watched the same file do something, "it is a test artifact" does not account
    for that, and the evidence is carried as opposing rather than quietly folded
    into the explanation.
    """
    found: list[ReasoningFinding] = []
    for subject_ref in index.subject_refs():
        malicious = index.malicious_at_scope(subject_ref, MatchScope.EXACT_OBSERVABLE)
        if not malicious:
            # Nothing to explain. Context on its own is context, and inventing
            # an explanation for a detection nobody made is how this layer would
            # start manufacturing doubt.
            continue

        explained = [item for item in malicious if not _is_direct_observation(item)]
        opposing = [item for item in malicious if _is_direct_observation(item)]
        if not explained:
            continue

        for signal_type, reason in sorted(
            EXPLAINABLE_CONTEXT_SIGNALS.items(), key=lambda pair: pair[0].value
        ):
            signals = index.exact_scope_signals(subject_ref, signal_type)
            if not signals:
                continue

            support = index.signals(subject_ref, ContextSignalType.SANDBOX_MEANINGFUL_EXECUTION)
            links = [
                *_evidence_links(explained, LinkRelation.EXPLAINS),
                *_evidence_links(opposing, LinkRelation.OPPOSES),
                *_signal_links(signals),
                *_signal_links(support),
            ]
            found.append(
                _finding(
                    rule_key=(
                        "test_artifact"
                        if signal_type is ContextSignalType.TEST_ARTIFACT
                        else "empty_artifact"
                    ),
                    reason=reason,
                    subject=_subject_of(index, subject_ref),
                    match_scope=MatchScope.EXACT_OBSERVABLE,
                    links=links,
                    limitations=_stale(index, signals),
                    message_parameters={
                        "source_key": signals[0].source_key or "",
                        "explained": len(explained),
                    },
                    detail={
                        "explained_evidence": len(explained),
                        "opposing_evidence": len(opposing),
                        "supporting_signals": len(signals) + len(support),
                    },
                )
            )
    return found


# --------------------------------------------------------------------------- #
# Relationship-scope alternative explanations
# --------------------------------------------------------------------------- #


def _relationship_explanations(index: ReasoningIndex) -> list[ReasoningFinding]:
    """A contact with common infrastructure may have an ordinary explanation.

    Scoped to the **edge**, never to either endpoint. That is the whole point: a
    sample that resolved a name contacted a resolver, which says something about
    what the contact is worth and nothing whatever about the sample. The
    relationship itself is untouched -- a link a sandbox watched happen stays
    ``PROVIDER_OBSERVED``, because Task 16 interprets observations rather than
    rewriting them.
    """
    found: list[ReasoningFinding] = []
    for edge in index.edges:
        if edge.relationship_type not in _CONTACT_TYPES:
            continue
        target_ref = observable_subject(edge.target_key).ref

        for signal_type, rule_key, reason in (
            (
                ContextSignalType.PUBLIC_RESOLVER,
                "public_resolver",
                ReasonCode.PUBLIC_RESOLVER_MAY_EXPLAIN_CONTACT,
            ),
            (
                ContextSignalType.BUSINESS_SERVICE,
                "business_service",
                ReasonCode.KNOWN_BUSINESS_SERVICE_MAY_EXPLAIN_CONNECTION,
            ),
        ):
            signals = index.signals(target_ref, signal_type)
            if not signals:
                continue
            if index.malicious_at_scope(target_ref):
                # Somebody has accused this endpoint of something specific, and
                # "it is a common service" does not account for that. Explaining
                # the contact anyway would use ordinariness to wave past a real
                # finding about the thing being contacted.
                continue

            found.append(
                _finding(
                    rule_key=rule_key,
                    reason=reason,
                    subject=_edge_subject(edge),
                    match_scope=MatchScope.EXACT_OBSERVABLE,
                    links=[
                        FindingLink(
                            relation=LinkRelation.EXPLAINS,
                            target=LinkTarget.RELATIONSHIP,
                            ref=edge_ref(edge),
                        ),
                        *_signal_links(signals),
                    ],
                    limitations=_stale(index, signals),
                    detail={
                        "relationship_type": edge.relationship_type.value,
                        "endpoint_context": signal_type.value,
                        # Observation basis travels as provenance. A watched
                        # connection is better grounded than a database row, and
                        # is still not an accusation against either endpoint.
                        "observation_bases": len({item.basis.value for item in edge.assertions}),
                    },
                )
            )
    return found


# --------------------------------------------------------------------------- #
# Interpretation limitations
# --------------------------------------------------------------------------- #


def _host_context_limitation(index: ReasoningIndex) -> list[ReasoningFinding]:
    """Host-level context never accounts for an exact artifact.

    ``https://github.com/attacker/payload.exe`` matching a popular-domain list is
    a fact about GitHub. Emitting an explanation here would clear the exact URL
    on the strength of its hosting, which is how every living-off-trusted-sites
    payload gets waved through -- so the finding *limits* the context and leaves
    the malicious evidence explicitly unexplained.
    """
    found: list[ReasoningFinding] = []
    for subject_ref in index.subject_refs():
        malicious = index.malicious_at_scope(subject_ref, MatchScope.EXACT_OBSERVABLE)
        if not malicious:
            continue
        host_signals = [
            item
            for item in index.host_scoped_signals(subject_ref)
            if item.signal_type in HOST_SCOPED_CONTEXT_SIGNALS
        ]
        if not host_signals:
            continue

        found.append(
            _finding(
                rule_key="host_context",
                reason=ReasonCode.HOST_CONTEXT_DOES_NOT_EXPLAIN_EXACT_URL,
                subject=_subject_of(index, subject_ref),
                match_scope=MatchScope.SAME_HOST,
                links=[
                    # QUALIFIES, never EXPLAINS. The distinction is what keeps
                    # this evidence in the unexplained set where Task 17 needs
                    # to see it.
                    *_evidence_links(malicious, LinkRelation.QUALIFIES),
                    *_signal_links(host_signals, LinkRelation.LIMITS),
                ],
                limitations=_stale(index, host_signals),
                message_parameters={"explained": len(malicious)},
                detail={
                    "unexplained_exact_evidence": len(malicious),
                    "host_signals": len(host_signals),
                },
            )
        )
    return found


def _private_address_limitation(index: ReasoningIndex) -> list[ReasoningFinding]:
    """Public intelligence does not identify a private-range asset.

    Reputation for ``10.0.0.5`` describes somebody else's ``10.0.0.5``. The claim
    is not wrong; it is about a different machine, and this says so without
    calling anything benign.
    """
    found: list[ReasoningFinding] = []
    for subject_ref in index.subject_refs():
        signals = index.signals(subject_ref, ContextSignalType.PRIVATE_OR_SPECIAL_USE)
        if not signals:
            continue
        directional = tuple(
            item
            for item in index.evidence_by_subject.get(subject_ref, ())
            if item.effect in {EvidenceEffect.SUPPORTS_MALICIOUS, EvidenceEffect.SUPPORTS_BENIGN}
        )
        if not directional:
            continue

        found.append(
            _finding(
                rule_key="private_address",
                reason=ReasonCode.PUBLIC_INTELLIGENCE_SCOPE_MISMATCH,
                subject=_subject_of(index, subject_ref),
                match_scope=MatchScope.EXACT_OBSERVABLE,
                links=[
                    *_evidence_links(directional, LinkRelation.QUALIFIES),
                    *_signal_links(signals, LinkRelation.LIMITS),
                ],
                limitations=_stale(index, signals),
                message_parameters={"explained": len(directional)},
                detail={"qualified_evidence": len(directional)},
            )
        )
    return found


def _known_scanner(index: ReasoningIndex) -> list[ReasoningFinding]:
    """Scanner context, and the reason it cannot explain anything here yet.

    Known scanning infrastructure could legitimately account for a
    *scanning-reputation* claim. It must never account for a botnet-C2 or
    malware-delivery claim merely because both concern one address.

    Telling those apart needs to know what a claim asserts, and the generic
    evidence model does not carry that: a scanner classification and a C2
    indicator are both ``CURATED_THREAT_ASSERTION`` with ``SUPPORTS_MALICIOUS``,
    and the only field that separates them is a provider-prefixed ``claim_type``
    this layer may not read. So the honest output is a limitation saying the
    alignment is unknown, and the explanation waits for a generic claim-kind seam
    that does not exist. Guessing would be the single most dangerous rule in the
    package.
    """
    found: list[ReasoningFinding] = []
    for subject_ref in index.subject_refs():
        signals = index.signals(subject_ref, ContextSignalType.KNOWN_SCANNER)
        if not signals:
            continue
        malicious = index.malicious_at_scope(subject_ref)
        if not malicious:
            continue

        found.append(
            _finding(
                rule_key="known_scanner",
                reason=ReasonCode.SCANNER_CONTEXT_ALIGNMENT_NOT_ESTABLISHED,
                subject=_subject_of(index, subject_ref),
                match_scope=MatchScope.EXACT_OBSERVABLE,
                links=[
                    *_evidence_links(malicious, LinkRelation.QUALIFIES),
                    *_signal_links(signals, LinkRelation.LIMITS),
                ],
                limitations=_stale(index, signals),
                message_parameters={"explained": len(malicious)},
                detail={"unexplained_evidence": len(malicious)},
            )
        )
    return found


# --------------------------------------------------------------------------- #
# Attribution cautions
# --------------------------------------------------------------------------- #


def _attribution_cautions(index: ReasoningIndex) -> list[ReasoningFinding]:
    """Who owns the infrastructure is not who ran the campaign.

    Both rules here leave the malicious evidence completely intact and say
    something about a different question. Shared hosting means a block has
    bystanders; a compromised host means the owner is a victim. Neither is a
    reason to doubt that the activity happened, and filing either as a
    potential false positive would be the most consequential mistake this
    package could make.
    """
    found: list[ReasoningFinding] = []
    for subject_ref in index.subject_refs():
        malicious = index.malicious_at_scope(subject_ref)
        if not malicious:
            continue

        shared = [
            item
            for item in index.signals_by_subject.get(subject_ref, ())
            if item.signal_type in _SHARED_INFRASTRUCTURE_SIGNALS and not item.host_component_only
        ]
        if shared:
            found.append(
                _finding(
                    rule_key="shared_infrastructure",
                    reason=ReasonCode.SHARED_INFRASTRUCTURE_LIMITS_ATTRIBUTION,
                    subject=_subject_of(index, subject_ref),
                    match_scope=MatchScope.EXACT_OBSERVABLE,
                    links=[
                        *_evidence_links(malicious, LinkRelation.QUALIFIES),
                        *_signal_links(shared),
                    ],
                    limitations=_stale(index, shared),
                    message_parameters={"explained": len(malicious)},
                    detail={"qualified_evidence": len(malicious)},
                )
            )

        compromised = index.signals(subject_ref, ContextSignalType.COMPROMISED_INFRASTRUCTURE)
        if compromised:
            found.append(
                _finding(
                    rule_key="compromised_infrastructure",
                    reason=ReasonCode.COMPROMISED_INFRASTRUCTURE_SEPARATES_OWNER_FROM_ACTOR,
                    subject=_subject_of(index, subject_ref),
                    match_scope=MatchScope.EXACT_OBSERVABLE,
                    links=[
                        *_evidence_links(malicious, LinkRelation.QUALIFIES),
                        *_signal_links(compromised),
                    ],
                    limitations=_stale(index, compromised),
                    message_parameters={"explained": len(malicious)},
                    detail={"qualified_evidence": len(malicious)},
                )
            )
    return found


# --------------------------------------------------------------------------- #
# Temporal relevance
# --------------------------------------------------------------------------- #


def _temporal_relevance(index: ReasoningIndex) -> list[ReasoningFinding]:
    """Not serving now is not the same as never having served.

    A ``TEMPORAL_RELEVANCE`` finding rather than an explanation, and the
    difference is the entire rule. A URL that distributed malware in March and
    stopped in April distributed malware; the source's current state answers a
    different question and is filed under a different dimension so nothing can
    read the two as being in conflict.
    """
    found: list[ReasoningFinding] = []
    for subject_ref in index.subject_refs():
        inactive = index.lifecycle_qualifications(
            subject_ref, SourceLifecycleState.INACTIVE_BY_SOURCE
        )
        historical = [
            item
            for item in inactive
            if item.fact.evidence is not None
            and item.fact.evidence.effect is EvidenceEffect.SUPPORTS_MALICIOUS
        ]
        if not historical:
            continue

        evidence_ids = sorted({item.fact.evidence.evidence_id for item in historical})  # type: ignore[union-attr]
        found.append(
            _finding(
                rule_key="inactive_by_source",
                reason=(ReasonCode.CURRENT_INACTIVITY_DOES_NOT_ERASE_HISTORICAL_MALICIOUSNESS),
                subject=_subject_of(index, subject_ref),
                match_scope=MatchScope.EXACT_OBSERVABLE,
                links=[
                    *[
                        FindingLink(
                            relation=LinkRelation.QUALIFIES,
                            target=LinkTarget.EVIDENCE,
                            ref=item,
                        )
                        for item in evidence_ids
                    ],
                    *[
                        FindingLink(
                            relation=LinkRelation.SUPPORTED_BY,
                            target=LinkTarget.TEMPORAL_FACT,
                            ref=item.fact.ref,
                        )
                        for item in historical
                    ],
                ],
                message_parameters={"explained": len(evidence_ids)},
                detail={
                    "lifecycle": SourceLifecycleState.INACTIVE_BY_SOURCE.value,
                    "historical_evidence": len(evidence_ids),
                },
            )
        )
    return found


# --------------------------------------------------------------------------- #
# Analysis quality
# --------------------------------------------------------------------------- #


def _sandbox_quality(index: ReasoningIndex) -> list[ReasoningFinding]:
    """How much a sandbox run can carry.

    Three signals, three findings, and none of them is an explanation. A run that
    executed nothing supports no conclusion in either direction; a run that did
    execute is better grounded and still one environment; runs that disagreed
    describe environment-dependent malware. All three exist so a later layer
    cannot read "nothing malicious observed" as evidence of safety.
    """
    found: list[ReasoningFinding] = []
    for signal_type, rule_key, reason in (
        (
            ContextSignalType.SANDBOX_LOW_EXECUTION,
            "sandbox_low_execution",
            ReasonCode.SANDBOX_NEGATIVE_NOT_INFORMATIVE_WITHOUT_EXECUTION,
        ),
        (
            ContextSignalType.SANDBOX_MEANINGFUL_EXECUTION,
            "sandbox_meaningful_execution",
            ReasonCode.SANDBOX_NEGATIVE_REMAINS_NON_VERDICT,
        ),
        (
            ContextSignalType.SANDBOX_DIVERGENCE,
            "sandbox_divergence",
            ReasonCode.SANDBOX_RESULT_ENVIRONMENT_DEPENDENT,
        ),
    ):
        for subject_ref in index.subject_refs():
            signals = index.signals(subject_ref, signal_type)
            if not signals:
                continue
            found.append(
                _finding(
                    rule_key=rule_key,
                    reason=reason,
                    subject=signals[0].subject,
                    match_scope=signals[0].match_scope,
                    links=[
                        *_signal_links(signals, LinkRelation.QUALIFIES),
                        *[
                            FindingLink(
                                relation=LinkRelation.QUALIFIES,
                                target=LinkTarget.EVIDENCE,
                                ref=item.evidence.evidence_id,
                            )
                            for item in signals
                            if item.evidence is not None
                        ],
                    ],
                    detail={"sandbox_signals": len(signals)},
                )
            )
    return found


# --------------------------------------------------------------------------- #
# Source dependence
# --------------------------------------------------------------------------- #


def _source_dependence(index: ReasoningIndex) -> list[ReasoningFinding]:
    """A relayed finding is real, and it is not a second source.

    ``DEPENDENT_WITH`` rather than ``OPPOSES`` or ``LIMITS``: the finding is not
    doubted and not diminished. What the link says is that counting it beside the
    direct result from the same upstream family would inflate one source into
    two, which is the specific arithmetic Task 17 must not do.
    """
    found: list[ReasoningFinding] = []
    for subject_ref in index.subject_refs():
        for signal in index.signals(subject_ref, ContextSignalType.RELAYED_SOURCE):
            if signal.evidence is None:
                continue
            found.append(
                _finding(
                    rule_key="relayed_source",
                    reason=ReasonCode.RELAYED_FINDINGS_NOT_INDEPENDENT,
                    subject=signal.subject,
                    match_scope=signal.match_scope,
                    links=[
                        FindingLink(
                            relation=LinkRelation.DEPENDENT_WITH,
                            target=LinkTarget.EVIDENCE,
                            ref=signal.evidence.evidence_id,
                        ),
                        *_signal_links((signal,)),
                    ],
                    message_parameters={
                        "transport": signal.transport_provider or "",
                        "origin": signal.origin_provider or "",
                    },
                    detail={
                        # The family, not a provider count. Two members of one
                        # family agreeing is one family agreeing with itself, and
                        # nothing here turns that into a number.
                        "source_family": (signal.source_family or "")[:200],
                        "origin_provider": (signal.origin_provider or "")[:200],
                        "direct_family_present": bool(
                            signal.detail.get("direct_family_present", False)
                        ),
                    },
                )
            )
    return found


# --------------------------------------------------------------------------- #
# Unresolved tension
# --------------------------------------------------------------------------- #


def _unresolved_tension(index: ReasoningIndex) -> list[ReasoningFinding]:
    """Evidence pointing both ways about one object, left that way.

    No vote, no balance, no winner. Both sides are linked -- the malicious side as
    ``QUALIFIES`` and the benign side as ``OPPOSES`` -- so Task 17 receives the
    disagreement intact rather than a number that hid it.
    """
    found: list[ReasoningFinding] = []
    for subject_ref in index.subject_refs():
        malicious = index.directional(subject_ref, EvidenceEffect.SUPPORTS_MALICIOUS)
        benign = index.directional(subject_ref, EvidenceEffect.SUPPORTS_BENIGN)
        if not (malicious and benign):
            continue

        found.append(
            _finding(
                rule_key="opposing_evidence",
                reason=ReasonCode.OPPOSING_DIRECTIONAL_EVIDENCE_UNRESOLVED,
                subject=_subject_of(index, subject_ref),
                match_scope=MatchScope.EXACT_OBSERVABLE,
                links=[
                    *_evidence_links(malicious, LinkRelation.QUALIFIES),
                    *_evidence_links(benign, LinkRelation.OPPOSES),
                ],
                message_parameters={"malicious": len(malicious), "benign": len(benign)},
                detail={
                    "malicious_evidence": len(malicious),
                    "benign_evidence": len(benign),
                    "source_families": len({item.source_family for item in (*malicious, *benign)}),
                },
            )
        )
    return found


# --------------------------------------------------------------------------- #
# Composition
# --------------------------------------------------------------------------- #

#: Every rule, in a fixed order.
#:
#: The order does not affect the result -- output is sorted and findings carry
#: content-derived ids -- but a fixed list is what lets a test assert that every
#: rule id in the policy has a body behind it.
ALL_RULES: tuple[tuple[str, object], ...] = (
    ("object_nature", _object_nature_explanations),
    ("relationship", _relationship_explanations),
    ("host_context", _host_context_limitation),
    ("private_address", _private_address_limitation),
    ("known_scanner", _known_scanner),
    ("attribution", _attribution_cautions),
    ("temporal", _temporal_relevance),
    ("sandbox", _sandbox_quality),
    ("source_dependence", _source_dependence),
    ("unresolved_tension", _unresolved_tension),
)


def apply_rules(index: ReasoningIndex) -> tuple[ReasoningFinding, ...]:
    """Run every rule and return findings in a deterministic order.

    Deduplicated by ``finding_id``, which is content-derived, so two rules
    reaching the same conclusion about the same subject from the same support
    produce one finding rather than two.
    """
    produced: dict[str, ReasoningFinding] = {}
    for _, rule in ALL_RULES:
        for finding in rule(index):  # type: ignore[operator]
            produced.setdefault(finding.finding_id, finding)
    return tuple(
        sorted(
            produced.values(),
            key=lambda item: (
                item.role.value,
                item.reason_code.value,
                item.subject.ref,
                item.finding_id,
            ),
        )
    )


def _subject_of(index: ReasoningIndex, subject_ref: str) -> SubjectRef:
    """Recover the SubjectRef behind a ref string, from whichever index has it."""
    for signals in (index.signals_by_subject.get(subject_ref), ()):
        if signals:
            return signals[0].subject
    for cues in (index.cues_by_subject.get(subject_ref), ()):
        if cues:
            return cues[0].subject
    for items in (index.temporal_by_subject.get(subject_ref), ()):
        if items:
            return items[0].fact.subject
    for evidence in index.evidence_by_subject.get(subject_ref, ()):
        found = index.subject_by_evidence.get(evidence.id)
        if found is not None:
            return found
    # Only reachable for a ref nothing indexed, which cannot happen for a ref
    # this module obtained from the index itself.
    return observable_subject(subject_ref.partition(":")[2] or subject_ref)


def _edge_subject(edge: GraphEdge) -> SubjectRef:
    from ti_recon.reasoning.models import edge_subject as build

    return build(edge.source_key, edge.relationship_type.value, edge.target_key)


def _is_direct_observation(evidence: Evidence) -> bool:
    """Whether a provider watched this rather than holding a record of it.

    The generic discriminator that lets an object-nature explanation keep its
    hands off behaviour: "this is a test artifact" accounts for a scanner
    flagging it, and accounts for nothing a sandbox watched the file actually do.
    """
    from ti_recon.enums import EvidenceClass

    return evidence.evidence_class is EvidenceClass.DIRECT_OBSERVATION
