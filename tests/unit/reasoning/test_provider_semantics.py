"""What each provider's timestamps actually mean (Task 15).

Driven through the **real adapters** against the existing payload fixtures, so a
claim type renamed in Task 7-12 breaks these loudly instead of leaving them
passing against evidence that no longer exists.

Each test here pins one semantic distinction that a naive freshness layer gets
wrong, and several of them assert a *negative* — that a particular kind was not
produced — because the failure mode is always an over-reading rather than a
missing fact.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fixtures.reasoning import (
    AS_OF,
    gti_file_envelope,
    malwarebazaar_envelope,
    sandbox_envelope,
    threatfox_absent_envelope,
    threatfox_compromised_envelope,
    threatfox_ip_envelope,
    urlhaus_url_envelope,
    urlscan_scan_envelope,
)
from ti_recon.enums import EvidenceEffect, ProviderRunStatus
from ti_recon.reasoning import (
    ContextSignalType,
    InterpretationCueType,
    SourceLifecycleState,
    TemporalContextEngine,
    TemporalFactKind,
)
from ti_recon.reasoning.results import TemporalContextResult


def qualify(*envelopes: object, as_of: datetime = AS_OF) -> TemporalContextResult:
    return TemporalContextEngine().evaluate(as_of=as_of, results=envelopes)  # type: ignore[arg-type]


def kinds(result: TemporalContextResult) -> set[TemporalFactKind]:
    return {item.fact.kind for item in result.temporal_qualifications}


def facts_of(result: TemporalContextResult, kind: TemporalFactKind) -> list[object]:
    return [item.fact for item in result.temporal_qualifications if item.fact.kind is kind]


# --------------------------------------------------------------------------- #
# GTI: an analysis is not an observation
# --------------------------------------------------------------------------- #


def test_gti_last_analysis_date_is_an_analysis_time_and_never_an_observation() -> None:
    """The single most important mapping in Task 15.

    ``last_analysis_date`` is when VirusTotal last *scanned* the object. A file
    uploaded in 2019 and rescanned this morning has a ``last_analysis_date`` of
    this morning and has been nowhere near anybody since 2019. Task 7 stores that
    instant in ``Evidence.last_seen`` because that is the field the Task 3 model
    has for a claim's most recent instant — so a generic reader taking
    ``last_seen`` at face value would be exactly wrong here, which is why no
    generic reader is allowed to take it.
    """
    analysed = datetime(2026, 8, 20, 9, 30, tzinfo=UTC)
    submitted = datetime(2019, 4, 1, 8, 0, tzinfo=UTC)
    resubmitted = datetime(2025, 5, 6, 7, 0, tzinfo=UTC)
    result = qualify(
        gti_file_envelope(
            extra_attributes={
                "last_analysis_date": int(analysed.timestamp()),
                "first_submission_date": int(submitted.timestamp()),
                "last_submission_date": int(resubmitted.timestamp()),
            }
        )
    )

    analysed_facts = facts_of(result, TemporalFactKind.ANALYZED_AT)
    assert analysed_facts
    # Every one of them is a scan time, whichever GTI block carried it. The
    # ``threat_severity`` block states its own ``last_analysis_date``, which is a
    # second genuine scan instant rather than a stray value — so the assertion is
    # on the *kind* and the provider field name, not on there being exactly one.
    assert {item.raw_field for item in analysed_facts} == {"last_analysis_date"}
    assert analysed in {item.instant for item in analysed_facts}

    # The regression this whole layer exists to prevent: a scan time must never
    # become an observation of activity, in any of its spellings.
    assert TemporalFactKind.LAST_OBSERVED not in kinds(result)
    assert TemporalFactKind.LAST_ONLINE_AT not in kinds(result)
    assert TemporalFactKind.FIRST_OBSERVED not in kinds(result)

    # Submission is a third question again, and keeps its own two kinds.
    assert {item.instant for item in facts_of(result, TemporalFactKind.FIRST_SUBMITTED)} == {
        submitted
    }
    assert {item.instant for item in facts_of(result, TemporalFactKind.LAST_SUBMITTED)} == {
        resubmitted
    }


def test_a_gti_rescan_today_of_a_2019_file_ages_the_submission_not_the_scan() -> None:
    """Reading the two numbers apart is the whole point: the file is seven years
    old and the opinion about it is nine days old."""
    analysed = AS_OF - timedelta(days=9)
    submitted = AS_OF - timedelta(days=2555)
    result = qualify(
        gti_file_envelope(
            extra_attributes={
                "last_analysis_date": int(analysed.timestamp()),
                "first_submission_date": int(submitted.timestamp()),
            }
        )
    )
    ages = {
        item.fact.kind: item.age_days
        for item in result.temporal_qualifications
        if item.age_days is not None
    }
    assert ages[TemporalFactKind.ANALYZED_AT] == 9.0
    assert ages[TemporalFactKind.FIRST_SUBMITTED] == 2555.0


def test_gti_produces_no_lifecycle_because_it_states_none() -> None:
    """GTI says nothing about whether anything is currently active, so Task 15
    attaches no lifecycle rather than inferring one from a fresh rescan."""
    result = qualify(gti_file_envelope())
    assert all(item.fact.lifecycle is None for item in result.temporal_qualifications)


# --------------------------------------------------------------------------- #
# URLhaus: offline is history, not absolution
# --------------------------------------------------------------------------- #


def test_an_offline_urlhaus_url_keeps_its_malicious_evidence_and_gains_a_cue() -> None:
    """The canonical Task 15 example.

    URLhaus says this exact URL distributed malware and says it is not serving
    now. Both are true. The evidence keeps ``SUPPORTS_MALICIOUS`` untouched, the
    current state is recorded as a source-stated lifecycle, the last-online
    instant keeps its own kind, and a cue says the two are different facts.
    """
    last_online = datetime(2026, 6, 20, 8, 0, tzinfo=UTC)
    envelope = urlhaus_url_envelope()  # the shipped fixture is offline on purpose
    record = next(item for item in envelope.evidence if item.claim_type == "urlhaus_malware_url")
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS

    result = qualify(envelope)

    online = facts_of(result, TemporalFactKind.LAST_ONLINE_AT)
    assert online and online[0].instant == last_online  # type: ignore[attr-defined]
    assert online[0].lifecycle is SourceLifecycleState.INACTIVE_BY_SOURCE  # type: ignore[attr-defined]
    assert result.cues_of(InterpretationCueType.HISTORICAL_MALICIOUS_CURRENTLY_INACTIVE)

    # Nothing was rewritten, and nothing became benign.
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert _no_benign(result)


def test_an_online_urlhaus_url_is_active_by_source_and_raises_no_history_cue() -> None:
    result = qualify(urlhaus_url_envelope(url_status="online"))
    added = facts_of(result, TemporalFactKind.ADDED_TO_DATASET_AT)
    assert added and added[0].lifecycle is SourceLifecycleState.ACTIVE_BY_SOURCE  # type: ignore[attr-defined]
    assert not result.cues_of(InterpretationCueType.HISTORICAL_MALICIOUS_CURRENTLY_INACTIVE)


def test_urlhaus_date_added_is_a_dataset_time_not_an_observation() -> None:
    """When URLhaus took the record, not when the URL began serving."""
    result = qualify(urlhaus_url_envelope())
    added = facts_of(result, TemporalFactKind.ADDED_TO_DATASET_AT)
    assert added and added[0].raw_field == "date_added"  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# ThreatFox: a horizon is not a heartbeat
# --------------------------------------------------------------------------- #


def test_a_current_threatfox_record_is_within_the_api_horizon_and_not_active_now() -> None:
    """ThreatFox drops indicators after roughly six months, so a returned record
    means "unexpired" and nothing stronger."""
    result = qualify(threatfox_ip_envelope())

    assert {TemporalFactKind.FIRST_OBSERVED, TemporalFactKind.LAST_OBSERVED} <= kinds(result)
    lifecycles = {item.fact.lifecycle for item in result.temporal_qualifications}
    assert SourceLifecycleState.WITHIN_SOURCE_API_HORIZON in lifecycles
    assert SourceLifecycleState.ACTIVE_BY_SOURCE not in lifecycles

    horizons = [
        item.fact.detail
        for item in result.temporal_qualifications
        if item.fact.detail and item.fact.detail.startswith("api_horizon_months=")
    ]
    assert horizons == ["api_horizon_months=6", "api_horizon_months=6"]
    assert result.cues_of(InterpretationCueType.SOURCE_MANAGED_LIFECYCLE)


def test_the_lifecycle_vocabulary_has_no_way_to_say_active_now() -> None:
    """Structural, not incidental: there is no member to reach for."""
    names = {item.value for item in SourceLifecycleState}
    assert "active_now" not in names
    assert not {item for item in names if "safe" in item or "benign" in item or "trust" in item}


def test_threatfox_no_data_invents_no_expiry_and_no_times() -> None:
    """An absence is compatible with never-listed, expired, and reported an hour
    ago. Task 15 manufactures none of the three."""
    envelope = threatfox_absent_envelope()
    assert envelope.status is ProviderRunStatus.NO_DATA

    result = qualify(envelope)
    assert result.temporal_qualifications == ()
    assert not [
        item
        for item in result.interpretation_cues
        if item.cue_type is InterpretationCueType.SOURCE_MANAGED_LIFECYCLE
    ]
    assert _no_benign(result)


def test_threatfox_compromised_infrastructure_cautions_without_weakening_evidence() -> None:
    """Malicious activity on somebody else's hacked host is still malicious
    activity. What changes is attribution and what a block costs."""
    envelope = threatfox_compromised_envelope()
    record = next(item for item in envelope.evidence if item.claim_type == "threatfox_ioc")
    assert record.attributes["is_compromised"] is True
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS

    result = qualify(envelope)
    assert result.signals_of(ContextSignalType.COMPROMISED_INFRASTRUCTURE)
    assert result.cues_of(InterpretationCueType.COMPROMISED_INFRASTRUCTURE_ATTRIBUTION_CAUTION)
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS


# --------------------------------------------------------------------------- #
# MalwareBazaar: a hash does not decay
# --------------------------------------------------------------------------- #


def test_an_old_malwarebazaar_sample_ages_exactly_and_expires_never() -> None:
    """Exact age, no decay, no expiry. Cryptographic file identity does not
    change tenant the way a cloud address does: if those bytes were ransomware in
    2023, they are the same bytes now."""
    envelope = malwarebazaar_envelope(
        first_seen="2023-01-02 03:04:05", last_seen="2023-02-03 04:05:06"
    )
    record = next(
        item for item in envelope.evidence if item.claim_type == "malwarebazaar_sample_record"
    )
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS

    result = qualify(envelope)
    last = [
        item
        for item in result.temporal_qualifications
        if item.fact.kind is TemporalFactKind.LAST_OBSERVED
    ]
    assert last
    expected = (AS_OF - datetime(2023, 2, 3, 4, 5, 6, tzinfo=UTC)).total_seconds()
    assert last[0].age_seconds == expected
    assert last[0].age_days == expected / 86_400.0

    # No lifecycle at all: MalwareBazaar states none, so none is invented.
    assert all(item.fact.lifecycle is None for item in result.temporal_qualifications)
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert _no_benign(result)


# --------------------------------------------------------------------------- #
# urlscan: a scan is a moment
# --------------------------------------------------------------------------- #


def test_a_urlscan_scan_is_a_point_in_time_observation_with_an_exact_age() -> None:
    """ "This page looked like this when the browser visited" — not "it still
    does", and not "it is clean now"."""
    scanned = datetime(2026, 6, 1, 7, 8, 9, tzinfo=UTC)
    result = qualify(urlscan_scan_envelope(scanned.strftime("%Y-%m-%dT%H:%M:%S.000Z")))

    scans = [
        item
        for item in result.temporal_qualifications
        if item.fact.kind is TemporalFactKind.SCANNED_AT
    ]
    assert len(scans) == 1
    assert scans[0].fact.instant == scanned
    assert scans[0].fact.lifecycle is SourceLifecycleState.POINT_IN_TIME
    assert scans[0].fact.raw_field == "task.time"
    assert scans[0].age_seconds == (AS_OF - scanned).total_seconds()

    # No claim about the page now, in either direction, and no invented decay.
    assert TemporalFactKind.LAST_OBSERVED not in kinds(result)
    assert _no_benign(result)


def test_one_scan_produces_one_scan_time_however_many_records_it_stamped() -> None:
    """Task 8 stamps every record with the same scan instant. Emitting one fact
    per record would make one visit look like nine observations."""
    result = qualify(urlscan_scan_envelope())
    assert len(facts_of(result, TemporalFactKind.SCANNED_AT)) == 1


# --------------------------------------------------------------------------- #
# Hybrid Analysis: a detonation time is a detonation time
# --------------------------------------------------------------------------- #


def test_a_sandbox_analysis_time_is_an_analysis_time_at_report_scope() -> None:
    """One instant per run, on the run rather than on the sample. Different
    environments detonate at different times and stay separate facts."""
    result = qualify(sandbox_envelope())
    analysed = facts_of(result, TemporalFactKind.ANALYZED_AT)
    assert analysed
    assert all(item.raw_field == "analysis_start_time" for item in analysed)  # type: ignore[attr-defined]
    assert all(item.subject.kind.value == "sandbox_report" for item in analysed)  # type: ignore[attr-defined]
    # Never re-labelled as something about the file itself.
    assert not ({TemporalFactKind.FIRST_OBSERVED, TemporalFactKind.LAST_OBSERVED} & kinds(result))


def _no_benign(result: TemporalContextResult) -> bool:
    """Nothing in a qualification may read as evidence of safety."""
    dumped = result.model_dump_json().lower()
    return not any(
        word in dumped
        for word in ("supports_benign", '"safe"', "likely_benign", "is_false_positive")
    )


def test_a_far_future_gap_between_as_of_values_only_moves_the_age() -> None:
    """Changing only ``as_of`` changes only time-dependent output."""
    envelope = malwarebazaar_envelope()
    early = qualify(envelope, as_of=AS_OF)
    later = qualify(envelope, as_of=AS_OF + timedelta(days=10))

    assert [item.fact for item in early.temporal_qualifications] == [
        item.fact for item in later.temporal_qualifications
    ]
    assert early.context_signals == later.context_signals
    assert early.interpretation_cues == later.interpretation_cues
    for before, after in zip(
        early.temporal_qualifications, later.temporal_qualifications, strict=True
    ):
        assert after.age_seconds == before.age_seconds + 10 * 86_400.0
