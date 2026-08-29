"""Malformed provider data, and the paths a happy fixture never reaches.

One invariant runs through the whole file: **bad provider data costs one fact,
never the lookup**. Every provider value Task 15 reads is provider-controlled and
several are attacker-influenced — a certificate subject, a scan title, a
submitted filename — so an unparseable instant, a wrong type or a missing key
drops that one item and leaves the rest of the qualification intact.

The other half covers subject resolution: what a fact attaches to when the
evidence's object id is not in the graph, and what it attaches to when even the
root is unknown.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from fixtures.reasoning import (
    AS_OF,
    gti_file_envelope,
    observable,
    sandbox_envelope,
    urlhaus_payload_envelope,
    urlhaus_url_envelope,
    urlscan_scan_envelope,
)
from ti_recon.correlation import CorrelationEngine, InvestigationGraph
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    MatchScope,
    ProviderOperation,
    ProviderRunStatus,
    RelationshipType,
)
from ti_recon.models.evidence import Evidence
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning import (
    ContextSignal,
    ContextSignalType,
    CuePurpose,
    InterpretationCue,
    InterpretationCueType,
    ProviderQualification,
    QualificationContext,
    SignalOrigin,
    SourceLifecycleState,
    TemporalContextEngine,
    TemporalFactKind,
    build_cues,
    edge_subject,
    observable_subject,
)


def qualify(*envelopes: ProviderResultEnvelope) -> object:
    return TemporalContextEngine().evaluate(as_of=AS_OF, results=envelopes)


def kinds(result: object) -> set[TemporalFactKind]:
    return {item.fact.kind for item in result.temporal_qualifications}  # type: ignore[attr-defined]


def _submitted_facts(result: object) -> int:
    return len(
        [
            item
            for item in result.temporal_qualifications  # type: ignore[attr-defined]
            if item.fact.kind is TemporalFactKind.FIRST_SUBMITTED
        ]
    )


# --------------------------------------------------------------------------- #
# Unparseable instants cost one fact
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("broken", ["not-a-date", "", "2026-13-45T99:00:00Z", "12345"])
def test_a_gti_object_timestamp_that_will_not_parse_costs_one_fact(broken: str) -> None:
    """Task 7 writes these as ISO-8601 strings. A malformed one is dropped and
    the rest of the object still qualifies."""
    envelope = gti_file_envelope()
    enriched = envelope.objects[0]
    namespace = dict(enriched.properties["gti"])
    namespace["first_submission_date"] = broken
    patched = envelope.model_copy(
        update={
            "objects": (
                enriched.model_copy(
                    update={"properties": {**enriched.properties, "gti": namespace}}
                ),
            )
        }
    )

    # The scan time still lands; exactly the object-derived submission fact is
    # gone. Task 7 also carries a submission time on gti_analysis_stats, which is
    # a separate reading and is unaffected — hence a count rather than an
    # emptiness assertion.
    assert TemporalFactKind.ANALYZED_AT in kinds(qualify(patched))
    assert _submitted_facts(qualify(patched)) == _submitted_facts(qualify(envelope)) - 1


def test_a_naive_gti_timestamp_is_dropped_rather_than_assumed_utc() -> None:
    """Assuming a zone would silently shift the age by hours."""
    envelope = gti_file_envelope()
    enriched = envelope.objects[0]
    namespace = dict(enriched.properties["gti"])
    namespace["last_submission_date"] = "2026-05-06T07:00:00"  # no offset
    patched = envelope.model_copy(
        update={
            "objects": (
                enriched.model_copy(
                    update={"properties": {**enriched.properties, "gti": namespace}}
                ),
            )
        }
    )
    # LAST_SUBMITTED comes only from the object, so it disappears entirely.
    assert TemporalFactKind.LAST_SUBMITTED not in kinds(qualify(patched))


def test_a_urlscan_certificate_start_that_will_not_parse_costs_one_fact() -> None:
    envelope = urlscan_scan_envelope()
    context = _patched_attributes(envelope, "urlscan_page_context", tls_valid_from="whenever")
    result = qualify(context)
    assert TemporalFactKind.SCANNED_AT in kinds(result)
    assert TemporalFactKind.VALID_FROM not in kinds(result)


def test_a_sandbox_certificate_window_that_will_not_parse_costs_one_fact() -> None:
    envelope = sandbox_envelope()
    behaviour = next(
        item for item in envelope.evidence if item.claim_type == "hybrid_analysis_sandbox_behaviour"
    )
    certificates = [{"sha1_fingerprint": "a" * 40, "valid_from": "nope", "valid_until": ""}]
    patched = _patched_attributes(envelope, behaviour.claim_type, certificates=certificates)
    result = qualify(patched)
    assert TemporalFactKind.ANALYZED_AT in kinds(result)
    assert not ({TemporalFactKind.VALID_FROM, TemporalFactKind.VALID_UNTIL} & kinds(result))


def test_a_misp_snapshot_time_that_will_not_parse_costs_the_dataset_fact_only() -> None:
    """The warninglist *matches* are unaffected: a bad manifest date says nothing
    about whether a list matched."""
    from ti_recon.providers.misp_warninglists.qualification import qualify as misp_qualify

    envelope = _misp_envelope(snapshot_generated_at="sometime last year")
    produced = misp_qualify(envelope, QualificationContext.build(objects=envelope.objects))
    assert produced.temporal_facts == ()
    assert [item.signal_type for item in produced.context_signals] == [
        ContextSignalType.PUBLIC_RESOLVER
    ]


def test_a_misp_match_scope_the_engine_does_not_know_falls_back_to_the_evidence() -> None:
    """Upstream vocabulary is not TI Recon's to guess at. An unrecognized scope
    uses the scope the provider already put on the record."""
    from ti_recon.providers.misp_warninglists.qualification import qualify as misp_qualify

    envelope = _misp_envelope(match_scope="something_new")
    produced = misp_qualify(envelope, QualificationContext.build(objects=envelope.objects))
    assert produced.context_signals[0].match_scope is MatchScope.EXACT_OBSERVABLE


def test_a_misp_match_record_without_a_slug_is_skipped() -> None:
    from ti_recon.providers.misp_warninglists.qualification import qualify as misp_qualify

    envelope = _misp_envelope(matches=[{"matcher": "cidr"}, "not-a-record"])
    produced = misp_qualify(envelope, QualificationContext.build(objects=envelope.objects))
    assert produced.context_signals == ()


# --------------------------------------------------------------------------- #
# URLhaus paths a single happy fixture does not reach
# --------------------------------------------------------------------------- #


def test_a_urlhaus_payload_record_contributes_provenance_times() -> None:
    """A tracked URL served this file, first and last seen. Provenance, not a
    direction — matching how Task 10 already classifies the record."""
    envelope = urlhaus_payload_envelope()
    assert any(item.claim_type == "urlhaus_payload_record" for item in envelope.evidence)

    result = qualify(envelope)
    payload_facts = [
        item.fact
        for item in result.temporal_qualifications  # type: ignore[attr-defined]
        if item.fact.raw_field in {"firstseen", "lastseen"}
    ]
    assert payload_facts
    # Provenance carries no lifecycle: URLhaus states none for a payload record.
    assert all(item.lifecycle is None for item in payload_facts)


def test_a_urlhaus_record_with_only_a_status_still_carries_the_status() -> None:
    """A record URLhaus timed with one instant should not lose its current state
    just because the pair is incomplete."""
    from ti_recon.providers.urlhaus.qualification import qualify as urlhaus_qualify

    evidence = Evidence(
        investigation_id="inv-1",
        subject_object_id="obj-1",
        evidence_class=EvidenceClass.CURATED_THREAT_ASSERTION,
        claim_type="urlhaus_malware_url",
        effect=EvidenceEffect.SUPPORTS_MALICIOUS,
        transport_provider="urlhaus",
        origin_provider="urlhaus",
        source_family="abuse_ch",
        observed_at=datetime(2026, 4, 1, tzinfo=UTC),
        attributes={"url_status": "unknown"},
    )
    produced = urlhaus_qualify(_envelope("urlhaus", evidence), QualificationContext())

    assert len(produced.temporal_facts) == 1
    assert produced.temporal_facts[0].lifecycle is SourceLifecycleState.STATUS_UNKNOWN
    assert produced.temporal_facts[0].kind is TemporalFactKind.ADDED_TO_DATASET_AT


def test_a_urlhaus_status_the_engine_does_not_know_yields_no_lifecycle() -> None:
    """A new status word is not guessed at. The instants still land."""
    result = qualify(urlhaus_url_envelope(url_status="quarantined"))
    assert all(
        item.fact.lifecycle is None
        for item in result.temporal_qualifications  # type: ignore[attr-defined]
    )
    assert TemporalFactKind.LAST_ONLINE_AT in kinds(result)


# --------------------------------------------------------------------------- #
# Sandbox states that contribute nothing
# --------------------------------------------------------------------------- #


def test_an_errored_sandbox_run_produces_no_execution_signal() -> None:
    """A failed detonation has no behavioural content. Letting it look like a
    quiet run is how an infrastructure failure becomes a clean bill of health."""
    from ti_recon.providers.hybrid_analysis.qualification import qualify as sandbox_qualify

    envelope = _sandbox_pair(state="ERROR", verdict="no specific threat")
    produced = sandbox_qualify(envelope, QualificationContext())
    assert produced.context_signals == ()


def test_a_sandbox_state_the_engine_does_not_know_produces_no_signal() -> None:
    from ti_recon.providers.hybrid_analysis.qualification import qualify as sandbox_qualify

    envelope = _sandbox_pair(state="MYSTERY", verdict="no specific threat")
    assert sandbox_qualify(envelope, QualificationContext()).context_signals == ()


def test_a_malicious_sandbox_run_needs_no_qualification_of_its_silence() -> None:
    """It is not a negative, so there is nothing to say about how informative
    its absence of findings was."""
    from ti_recon.providers.hybrid_analysis.qualification import qualify as sandbox_qualify

    envelope = _sandbox_pair(state="SUCCESS", verdict="malicious")
    assert sandbox_qualify(envelope, QualificationContext()).context_signals == ()


def test_a_behaviour_record_with_no_report_id_falls_back_to_the_sample() -> None:
    from ti_recon.providers.hybrid_analysis.qualification import qualify as sandbox_qualify

    behaviour = Evidence(
        investigation_id="inv-1",
        subject_object_id="obj-1",
        evidence_class=EvidenceClass.CONTEXT,
        claim_type="hybrid_analysis_sandbox_behaviour",
        effect=EvidenceEffect.CONTEXT_ONLY,
        transport_provider="hybrid_analysis",
        origin_provider="hybrid_analysis",
        source_family="hybrid_analysis",
        attributes={"analysis_started_at": "2026-07-30T08:00:00+00:00", "state": "SUCCESS"},
    )
    context = QualificationContext(node_keys={"obj-1": "file:sha256:" + "a" * 64})
    produced = sandbox_qualify(_envelope("hybrid_analysis", behaviour), context)
    assert produced.temporal_facts[0].subject.key == "file:sha256:" + "a" * 64


# --------------------------------------------------------------------------- #
# Subject resolution
# --------------------------------------------------------------------------- #


def test_an_unresolvable_subject_falls_back_to_the_root_then_to_the_id() -> None:
    """Never a fabricated key. An adapter anchoring a claim to the run's target
    resolves to the root; with no root even that is unavailable, and the honest
    answer is the id itself."""
    target = observable("evil.example")
    with_root = QualificationContext.build(root=target)
    assert with_root.subject_for("unknown-id") == observable_subject(target.canonical_key)
    assert with_root.subject_for(None) == observable_subject(target.canonical_key)

    bare = QualificationContext()
    assert bare.subject_for("unknown-id") == observable_subject("unknown-id")
    assert bare.subject_for(None) == observable_subject("unknown")


def test_two_provider_qualifications_merge_without_losing_either() -> None:
    left = ProviderQualification(context_signals=(_signal(ContextSignalType.KNOWN_SCANNER),))
    right = ProviderQualification(context_signals=(_signal(ContextSignalType.PUBLIC_RESOLVER),))
    merged = left.merge(right)
    assert len(merged.context_signals) == 2
    assert merged.temporal_facts == ()


# --------------------------------------------------------------------------- #
# Cue rules at their edges
# --------------------------------------------------------------------------- #


def test_a_resolver_signal_for_a_node_outside_the_graph_raises_no_edge_cue() -> None:
    """The rule reads the graph; a value the graph never held has no edge."""
    graph = InvestigationGraph(investigation_id="inv-1", authenticated_user_id="analyst-a")
    CorrelationEngine(graph=graph).add_root(observable("evil.example"))

    cues = build_cues(
        facts=(),
        signals=(_signal(ContextSignalType.PUBLIC_RESOLVER, key="ipv4-addr:8.8.8.8"),),
        graph=graph,
    )
    assert not [
        item
        for item in cues
        if item.cue_type is InterpretationCueType.PUBLIC_SERVICE_MAY_EXPLAIN_CONTACT
    ]


def test_an_unmapped_warninglist_signal_raises_no_cue() -> None:
    """A warninglist matched and TI Recon has no category for it. That is real
    information and no caution in particular; manufacturing one would be noise."""
    cues = build_cues(facts=(), signals=(_signal(ContextSignalType.WARNINGLIST_MATCH),))
    assert cues == ()


def test_several_shared_infrastructure_signals_merge_into_one_caution() -> None:
    """Five cloud-range lists matching one address is one attribution caution
    with five signals behind it, not five findings."""
    signals = tuple(
        _signal(ContextSignalType.SHARED_CLOUD_OR_CDN, source_key=f"list-{index}")
        for index in range(5)
    )
    cues = build_cues(facts=(), signals=signals)
    assert len(cues) == 1
    assert len(cues[0].context_signal_refs) == 5


def test_a_cue_subject_and_purpose_are_what_make_two_cautions_distinct() -> None:
    cue = InterpretationCue(
        cue_type=InterpretationCueType.TEST_ARTIFACT_CONTEXT,
        purpose=CuePurpose.FALSE_POSITIVE_CONTEXT,
        subject=observable_subject("file:md5:" + "a" * 32),
    )
    assert cue.key == (
        "test_artifact_context",
        "observable:file:md5:" + "a" * 32,
        "false_positive_context",
    )


def test_an_edge_subject_reads_back_as_the_graph_keyed_it() -> None:
    subject = edge_subject("file:sha256:" + "a" * 64, "contacts", "ipv4-addr:8.8.8.8")
    assert subject.key == "file:sha256:" + "a" * 64 + "|contacts|ipv4-addr:8.8.8.8"
    assert subject.ref.startswith("relationship:")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _signal(
    signal_type: ContextSignalType,
    *,
    key: str = "domain-name:evil.example",
    source_key: str = "a-list",
) -> ContextSignal:
    return ContextSignal(
        signal_type=signal_type,
        subject=observable_subject(key),
        origin=SignalOrigin.ENGINE_POLICY,
        match_scope=MatchScope.EXACT_OBSERVABLE,
        transport_provider="p",
        origin_provider="p",
        source_family="f",
        source_key=source_key,
    )


def _envelope(provider: str, *evidence: Evidence) -> ProviderResultEnvelope:
    return ProviderResultEnvelope(
        provider=provider,
        operation=ProviderOperation.LOOKUP,
        status=ProviderRunStatus.SUCCESS,
        adapter_version="1.0.0",
        api_version="v1",
        evidence=evidence,
    )


def _patched_attributes(
    envelope: ProviderResultEnvelope, claim_type: str, **attributes: object
) -> ProviderResultEnvelope:
    """Rewrite one evidence record's attributes, leaving the rest alone."""
    updated = tuple(
        item.model_copy(update={"attributes": {**item.attributes, **attributes}})
        if item.claim_type == claim_type
        else item
        for item in envelope.evidence
    )
    return envelope.model_copy(update={"evidence": updated})


def _misp_envelope(
    *,
    snapshot_generated_at: str = "2026-08-25T15:51:11.436932+00:00",
    match_scope: str = "exact_observable",
    matches: list[object] | None = None,
) -> ProviderResultEnvelope:
    """A warninglist result shaped exactly as Task 11 emits one."""
    common = {
        "investigation_id": "inv-1",
        "subject_object_id": "obj-1",
        "evidence_class": EvidenceClass.CONTEXT,
        "effect": EvidenceEffect.CONTEXT_ONLY,
        "transport_provider": "misp_warninglists",
        "origin_provider": "misp_warninglists",
        "source_family": "misp",
        "match_scope": MatchScope.EXACT_OBSERVABLE,
    }
    return _envelope(
        "misp_warninglists",
        Evidence(
            claim_type="misp_warninglist_matches",
            attributes={
                "matches": matches
                if matches is not None
                else [
                    {
                        "list": "public-dns-v4",
                        "matcher": "cidr",
                        "match_scope": match_scope,
                        "candidate_component": "observable",
                    }
                ]
            },
            **common,  # type: ignore[arg-type]
        ),
        Evidence(
            claim_type="misp_warninglist_coverage",
            attributes={
                "snapshot_generated_at": snapshot_generated_at,
                "snapshot_stale": False,
                "dataset_commit": "84f0610aaf3b32159285c9b85510d0f415ea6b27",
            },
            **common,  # type: ignore[arg-type]
        ),
    )


def _sandbox_pair(*, state: str, verdict: str) -> ProviderResultEnvelope:
    """An assessment record and a behaviour record that agree on the report id."""
    common = {
        "investigation_id": "inv-1",
        "subject_object_id": "obj-1",
        "effect": EvidenceEffect.CONTEXT_ONLY,
        "transport_provider": "hybrid_analysis",
        "origin_provider": "hybrid_analysis",
        "source_family": "hybrid_analysis",
    }
    return _envelope(
        "hybrid_analysis",
        Evidence(
            evidence_class=EvidenceClass.CONTEXT,
            claim_type="hybrid_analysis_sandbox_assessment",
            attributes={
                "reports": [{"report_id": "job-1:120", "verdict": verdict, "state": state}],
                "divergent_verdicts": False,
            },
            **common,  # type: ignore[arg-type]
        ),
        Evidence(
            evidence_class=EvidenceClass.CONTEXT,
            claim_type="hybrid_analysis_sandbox_behaviour",
            attributes={
                "report_id": "job-1:120",
                "state": state,
                "observed_execution": False,
                "analysis_started_at": "2026-07-30T08:00:00+00:00",
            },
            **common,  # type: ignore[arg-type]
        ),
    )


def test_the_relationship_vocabulary_is_still_the_one_the_cue_rule_expects() -> None:
    """The edge rule keys on RelationshipType.CONTACTS. If Task 14 ever renamed
    it, the rule would silently stop firing rather than fail."""
    assert RelationshipType.CONTACTS.value == "contacts"
