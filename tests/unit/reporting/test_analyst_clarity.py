"""What a report says about how it was collected (Task 22 correction).

Live use surfaced a class of misreading the verdict tests never covered: not
"what did the engine conclude", but "what actually happened to get there". A
source nobody could reach read as a source that answered; a cached answer read
as a fresh query; a stored credential read as a working one; a preserved
disagreement read as a resolved one.

Each of those is a sentence an analyst would act on, and each is a property of
the *record* rather than of the assessment — so these tests run whole
investigations through the real engines and assert what the projection says
about the collection behind them.

Every case here is deterministic. The fixtures script provider answers and let
Tasks 13 through 19 do the rest, so a passing test means the real chain produced
the state, not that a report object was hand-filled with it.
"""

from __future__ import annotations

import pytest

from fixtures.reporting import (
    cached_report,
    conflicted_report,
    inconclusive_report,
    malicious_report,
    unconfigured_report,
)
from ti_recon.enums import Verdict
from ti_recon.reasoning.readiness.models import ReadinessStatus
from ti_recon.reporting import render_text
from ti_recon.reporting.text import COVERAGE_MEANING, STATUS_MEANING, VERDICT_MEANING

# --------------------------------------------------------------------------- #
# A — a source nobody could reach
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_an_unreachable_source_is_recorded_as_never_contacted() -> None:
    """``NOT_CONFIGURED`` is the absence of a check, not the result of one.

    The three claims it must not support: that the source was contacted, that it
    was contacted and failed, and that it was contacted and knew nothing. All
    three are things a reader supplies for themselves if the record does not say
    otherwise, and each would change what the coverage appears to have covered.
    """
    _, report = await unconfigured_report()

    checks = {item.provider_id: item for item in report.source_checks.items}
    assert checks, "the attempt is recorded even though nothing was contacted"
    entry = checks["repo"]
    assert entry.status == "not_configured"
    assert entry.called_provider is False
    assert entry.cache_hit is False
    assert entry.produced_evidence is False


@pytest.mark.asyncio
async def test_an_unconfigured_source_is_a_coverage_gap_and_not_a_verdict() -> None:
    """The absence is charged to coverage, and to nothing else.

    A missing credential is a fact about setup. It is not adverse evidence, not
    exculpatory evidence, and not an authorization failure — the investigation
    completes and reports what it could not reach.
    """
    _, report = await unconfigured_report()

    assert report.assessment.verdict is Verdict.INCONCLUSIVE
    assert report.assessment_basis.items == ()
    assert report.opposing_evidence.items == ()

    gaps = {item.capability: item for item in report.gaps.items}
    assert "reputation" in gaps
    assert gaps["reputation"].gap_type == "not_configured"
    # Every capability the unconfigured source's one call carried is typed by
    # what actually happened -- not_configured -- never "not attempted"
    # (Task 24 Phase 3).
    assert {item.gap_type for item in report.gaps.items} == {"not_configured"}


@pytest.mark.asyncio
async def test_the_rendered_unconfigured_line_says_it_was_not_checked() -> None:
    """A bare status beside a provider name reads as an outage.

    ``repo / reputation: not_configured`` is accurate and unhelpful; a reader
    who does not already know the vocabulary will take it for a source that was
    down. The gloss is what makes the line self-explanatory.
    """
    _, report = await unconfigured_report()
    rendered = render_text(report)

    assert "not checked; no credential is available for this account" in rendered
    for forbidden in ("offline", "unreachable", "rejected"):
        assert forbidden not in rendered.lower(), forbidden


@pytest.mark.asyncio
async def test_the_report_never_tells_anyone_how_to_supply_a_credential() -> None:
    """Setup advice is deployment-specific and does not belong in a result.

    The report is rendered identically for a local analyst and a hosted one, so
    any instruction it carried would be wrong for one of them. The deployment
    profile says it once, in the MCP server's own instructions, where it can
    differ.
    """
    _, report = await unconfigured_report()
    rendered = render_text(report).lower()

    # Instructional forms only. ``not_configured`` is a machine value the report
    # must keep, and a bare "configure" substring would forbid it.
    for forbidden in (
        "api key",
        "environment variable",
        ".env",
        "reconnect",
        "restart",
        "paste",
        "configure it",
        "configure the",
        "set up",
        "self-service",
    ):
        assert forbidden not in rendered, forbidden


# --------------------------------------------------------------------------- #
# B — a source that answered and held nothing
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_completed_empty_check_is_distinguishable_from_an_unreachable_one() -> None:
    """The two states that look alike in a summary and mean opposite things.

    One source was asked and had nothing; the other was never asked. Collapsing
    them lets an unattempted check pass for an exhausted one, which is how an
    investigation looks more thorough than it was.
    """
    _, empty = await inconclusive_report()
    _, unreachable = await unconfigured_report()

    asked = {item.status for item in empty.source_checks.items}
    assert asked == {"no_data"}
    assert all(item.called_provider for item in empty.source_checks.items)

    unasked = {item.status for item in unreachable.source_checks.items}
    assert unasked == {"not_configured"}
    assert not any(item.called_provider for item in unreachable.source_checks.items)


@pytest.mark.asyncio
async def test_a_completed_empty_check_is_never_benign_evidence() -> None:
    """ "Nothing known" is also true of every threat nobody has caught yet."""
    _, report = await inconclusive_report()

    assert report.assessment.verdict is Verdict.INCONCLUSIVE
    assert report.assessment_basis.items == ()
    rendered = render_text(report)
    assert "checked; held nothing applicable (not evidence of safety)" in rendered


# --------------------------------------------------------------------------- #
# C — a cached answer
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_cached_check_is_recorded_as_completed_without_a_request() -> None:
    """Both halves are true and neither alone is.

    The check completed and the assessment stands on it; the source was not
    contacted for this run. A reader told only the first over-reports the
    disclosure, and one told only the second under-reports the evidence.
    """
    _, report = await cached_report()

    entry = next(item for item in report.source_checks.items if item.provider_id == "repo")
    assert entry.cache_hit is True
    assert entry.called_provider is False
    assert entry.status == "success"
    assert entry.produced_evidence is True
    # The cached answer carried the verdict exactly as a fresh one would.
    assert report.assessment.verdict is Verdict.MALICIOUS


@pytest.mark.asyncio
async def test_a_cached_result_reaches_the_same_assessment_as_a_fresh_one() -> None:
    """Caching is an execution concern and changes no conclusion.

    Asserted because the correction touched how a cache hit is *described*: the
    wording may say it was reused, and the analysis it fed must be identical.
    """
    _, fresh = await malicious_report()
    _, cached = await cached_report()

    assert cached.assessment.verdict == fresh.assessment.verdict
    assert cached.assessment.confidence == fresh.assessment.confidence
    assert cached.assessment.verdict_rule_id == fresh.assessment.verdict_rule_id
    assert cached.readiness.status == fresh.readiness.status


@pytest.mark.asyncio
async def test_the_rendered_cached_line_does_not_claim_a_new_request() -> None:
    """Said on the line itself, where the status is read."""
    _, report = await cached_report()
    rendered = render_text(report)

    assert "[cached; source not contacted again]" in rendered


# --------------------------------------------------------------------------- #
# H — a disagreement nobody resolved
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_a_conflict_is_preserved_rather_than_resolved() -> None:
    """Two independent origins, opposite directions, one proposition.

    Nothing is averaged and nothing wins. The disagreement is recorded, the
    surviving support decides the verdict, and the confidence band is held down
    by a named cap rather than by an arithmetic adjustment nobody could explain.
    """
    _, report = await conflicted_report()

    assert report.conflicts.total == 1
    conflict = report.conflicts.items[0]
    assert conflict.malicious_claim_ids and conflict.benign_claim_ids
    assert set(conflict.malicious_source_families) != set(conflict.benign_source_families)

    assert report.assessment.verdict is Verdict.SUSPICIOUS
    assert report.assessment.confidence == "low"
    assert report.assessment.confidence_caps


@pytest.mark.asyncio
async def test_supporting_and_opposing_channels_stay_distinct_under_conflict() -> None:
    """The section a claim lands in is the engine's own disposition.

    Under one heading meaning "why", the benign assertion would read as a reason
    the object was called suspicious — the exact inversion this split exists to
    prevent.
    """
    _, report = await conflicted_report()

    assert report.assessment_basis.total == 1
    assert report.opposing_evidence.total == 1
    basis = report.assessment_basis.items[0]
    opposing = report.opposing_evidence.items[0]

    assert basis.effect != opposing.effect
    assert basis.claim_id != opposing.claim_id
    # Every item carries its Task 17 role in either section, so a machine reader
    # never has to infer a disposition from which list it arrived in.
    assert basis.role and opposing.role
    assert basis.decision_role and opposing.decision_role


@pytest.mark.asyncio
async def test_the_rendered_conflict_is_shown_under_its_own_heading() -> None:
    """Visible as a disagreement, not folded into the basis."""
    _, report = await conflicted_report()
    rendered = render_text(report)

    assert "Unresolved disagreement" in rendered
    assert "Evidence against this assessment" in rendered
    assert "Confidence limited by:" in rendered


# --------------------------------------------------------------------------- #
# The plain-language layer adds words and changes nothing
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "verdict"),
    [
        (malicious_report, Verdict.MALICIOUS),
        (conflicted_report, Verdict.SUSPICIOUS),
        (inconclusive_report, Verdict.INCONCLUSIVE),
        (unconfigured_report, Verdict.INCONCLUSIVE),
        (cached_report, Verdict.MALICIOUS),
    ],
    ids=["malicious", "conflict", "inconclusive", "unconfigured", "cached"],
)
async def test_every_verdict_is_rendered_with_the_machine_value_and_a_sentence(
    case, verdict: Verdict
) -> None:
    """A reader gets both, and the machine value is never replaced.

    The sentence is presentation. Removing the spelling in favour of prose would
    make the text renderer disagree with the JSON contract about what the engine
    said, which is worse than the ambiguity it was meant to fix.
    """
    _, report = await case()
    rendered = render_text(report)

    assert report.assessment.verdict is verdict
    assert f"Verdict: {verdict.value.upper()}" in rendered
    # And a sentence follows it, indented under the value it explains.
    body = rendered.split(f"Verdict: {verdict.value.upper()}\n", 1)[1]
    assert body.startswith("    ")


def test_every_verdict_and_coverage_value_has_a_sentence() -> None:
    """A value with no sentence is a value a reader has to already understand.

    The renderer looks these up rather than indexing them, so a missing entry
    degrades to silence instead of a traceback — which is the right failure for
    a renderer and the wrong one for the contract. Asserted against the enums
    themselves, so adding a verdict or a readiness state fails here rather than
    shipping one member quietly less legible than its neighbours.
    """
    assert set(VERDICT_MEANING) == {item.value for item in Verdict}
    assert set(COVERAGE_MEANING) == {item.value for item in ReadinessStatus}


def test_no_verdict_or_coverage_sentence_recommends_an_action() -> None:
    """The renderer states an assessment and never what to do about it.

    Adding plain English is exactly where advice creeps in: "likely benign" is
    one short step from "safe to allow", and a MALICIOUS verdict on shared or
    compromised infrastructure makes blocking actively harmful. That decision
    needs asset criticality and response policy this engine has no access to.

    Matched on the recommending *constructions* rather than on bare verbs,
    because these sentences deliberately deny some of them — "not an
    allowlisting decision" is the opposite of advice, and forbidding the word
    would forbid the denial that does the work.
    """
    advice = (
        "safe to ",
        "should block",
        "should allow",
        "should be blocked",
        "can be blocked",
        "recommend",
        "take action",
        "you can safely",
        "no action",
        "close the alert",
        "declare an incident",
    )
    for sentence in (
        *VERDICT_MEANING.values(),
        *COVERAGE_MEANING.values(),
        *STATUS_MEANING.values(),
    ):
        lowered = sentence.lower()
        for phrase in advice:
            assert phrase not in lowered, f"{phrase!r} in {sentence!r}"


def test_the_status_glosses_cover_the_statuses_that_mislead() -> None:
    """Three that a reader turns into an outage or into reassurance.

    Not every status: ``success``, ``error`` and ``quota_exceeded`` say what
    they mean, and a gloss on every line would bury the ones that need one.
    """
    assert set(STATUS_MEANING) == {"not_configured", "no_data", "not_supported", "partial"}
    assert "not checked" in STATUS_MEANING["not_configured"]
    assert "not evidence of safety" in STATUS_MEANING["no_data"]
