"""Which reports get fetched, and why (Task 12).

Selection is where API cost is decided. A hash with forty detonations must still
cost at most three requests, and the two summaries read must be the two most
worth reading — which is not the same as the two most malicious.
"""

from __future__ import annotations

import pytest

from ti_recon.enums import InvestigationDepth
from ti_recon.sandbox import (
    DEPTH_SUMMARY_BUDGET,
    MAX_SUMMARIES_PER_LOOKUP,
    SELECTION_STRATEGY,
    SandboxEnvironment,
    SandboxReportRef,
    SandboxReportState,
    SandboxVerdict,
    select_reports,
)


def ref(
    report_id: str,
    *,
    verdict: SandboxVerdict = SandboxVerdict.MALICIOUS,
    state: SandboxReportState = SandboxReportState.SUCCESS,
    environment: str = "140",
) -> SandboxReportRef:
    return SandboxReportRef(
        report_id=report_id,
        environment=SandboxEnvironment(environment_id=environment),
        state=state,
        verdict=verdict,
    )


# --------------------------------------------------------------------------- #
# Budgets
# --------------------------------------------------------------------------- #


def test_quick_fetches_no_summary() -> None:
    """Its answer is the report index: how many runs, where, with what verdicts."""
    selection = select_reports((ref("r1"), ref("r2")), InvestigationDepth.QUICK)
    assert selection.selected == ()
    assert selection.budget == 0


def test_standard_fetches_exactly_one() -> None:
    selection = select_reports((ref("r1"), ref("r2"), ref("r3")), InvestigationDepth.STANDARD)
    assert selection.selected_count == 1


def test_deep_fetches_at_most_two() -> None:
    selection = select_reports(
        tuple(ref(f"r{index}", environment=str(index)) for index in range(10)),
        InvestigationDepth.DEEP,
    )
    assert selection.selected_count == 2


def test_a_hundred_reports_still_cost_two_summaries() -> None:
    """The property that keeps a well-studied hash from exhausting an allowance."""
    reports = tuple(ref(f"r{index:03d}", environment=str(index % 5)) for index in range(100))
    selection = select_reports(reports, InvestigationDepth.DEEP)
    assert selection.selected_count == 2
    assert selection.skipped_over_budget == 98


def test_the_ceiling_is_absolute() -> None:
    assert max(DEPTH_SUMMARY_BUDGET.values()) <= MAX_SUMMARIES_PER_LOOKUP
    assert MAX_SUMMARIES_PER_LOOKUP == 2


def test_no_reports_selects_nothing() -> None:
    assert select_reports((), InvestigationDepth.DEEP).selected == ()


# --------------------------------------------------------------------------- #
# Only completed runs are candidates
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "state",
    [SandboxReportState.ERROR, SandboxReportState.IN_QUEUE, SandboxReportState.IN_PROGRESS],
)
def test_an_incomplete_report_is_never_fetched(state: SandboxReportState) -> None:
    """Summarising it would spend a request to re-learn what the index said."""
    selection = select_reports(
        (ref("bad", state=state), ref("good", verdict=SandboxVerdict.NO_VERDICT)),
        InvestigationDepth.STANDARD,
    )
    assert [item.report_id for item in selection.selected] == ["good"]
    assert selection.skipped_incomplete == 1


def test_a_failed_report_is_not_preferred_over_a_weaker_completed_one() -> None:
    """Even when the failed one claims to be malicious, which providers do emit."""
    selection = select_reports(
        (
            ref("failed", verdict=SandboxVerdict.MALICIOUS, state=SandboxReportState.ERROR),
            ref("ok", verdict=SandboxVerdict.NO_SPECIFIC_THREAT),
        ),
        InvestigationDepth.STANDARD,
    )
    assert [item.report_id for item in selection.selected] == ["ok"]


def test_nothing_completed_means_nothing_fetched() -> None:
    selection = select_reports(
        (ref("a", state=SandboxReportState.ERROR), ref("b", state=SandboxReportState.ERROR)),
        InvestigationDepth.DEEP,
    )
    assert selection.selected == ()
    assert selection.skipped_incomplete == 2


# --------------------------------------------------------------------------- #
# The primary pick is the strongest completed verdict
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("stronger", "weaker"),
    [
        (SandboxVerdict.MALICIOUS, SandboxVerdict.SUSPICIOUS),
        (SandboxVerdict.SUSPICIOUS, SandboxVerdict.NO_SPECIFIC_THREAT),
        (SandboxVerdict.NO_SPECIFIC_THREAT, SandboxVerdict.NO_VERDICT),
    ],
)
def test_the_stronger_verdict_leads(stronger: SandboxVerdict, weaker: SandboxVerdict) -> None:
    selection = select_reports(
        (
            ref("weak", verdict=weaker, environment="1"),
            ref("strong", verdict=stronger, environment="2"),
        ),
        InvestigationDepth.STANDARD,
    )
    assert selection.selected[0].report_id == "strong"


def test_selection_is_deterministic_regardless_of_input_order() -> None:
    """The same index must always produce the same requests, or a cached answer
    stops meaning anything."""
    reports = (
        ref("r-b", environment="120"),
        ref("r-a", environment="120"),
        ref("r-c", environment="110"),
    )
    first = select_reports(reports, InvestigationDepth.DEEP)
    second = select_reports(tuple(reversed(reports)), InvestigationDepth.DEEP)
    assert [item.report_id for item in first.selected] == [
        item.report_id for item in second.selected
    ]


def test_ties_break_on_environment_then_report_id() -> None:
    selection = select_reports(
        (
            ref("z", environment="110"),
            ref("a", environment="110"),
            ref("m", environment="100"),
        ),
        InvestigationDepth.STANDARD,
    )
    assert selection.selected[0].report_id == "m"


def test_the_strategy_is_named_for_coverage() -> None:
    """So a result can say how one of forty reports came to be the one read."""
    selection = select_reports((ref("r1"),), InvestigationDepth.STANDARD)
    assert selection.strategy == SELECTION_STRATEGY
    assert "verdict" in selection.strategy


# --------------------------------------------------------------------------- #
# The second pick contrasts rather than confirms
# --------------------------------------------------------------------------- #


def test_deep_prefers_a_disagreeing_verdict() -> None:
    """The environment-dependence signal, which a second malicious run lacks."""
    selection = select_reports(
        (
            ref("mal-a", verdict=SandboxVerdict.MALICIOUS, environment="140"),
            ref("mal-b", verdict=SandboxVerdict.MALICIOUS, environment="141"),
            ref("clean", verdict=SandboxVerdict.NO_SPECIFIC_THREAT, environment="120"),
        ),
        InvestigationDepth.DEEP,
    )
    chosen = {item.report_id for item in selection.selected}
    assert chosen == {"mal-a", "clean"}
    assert selection.contrasting is True


def test_deep_falls_back_to_a_different_environment() -> None:
    """Same verdict everywhere still says the behaviour reproduces elsewhere."""
    selection = select_reports(
        (
            ref("a", environment="140"),
            ref("b", environment="120"),
        ),
        InvestigationDepth.DEEP,
    )
    assert {item.report_id for item in selection.selected} == {"a", "b"}
    assert selection.contrasting is False


def test_deep_declines_a_duplicate_second_report() -> None:
    """Identical verdict *and* environment is a request spent on a duplicate."""
    selection = select_reports(
        (
            ref("a", environment="140"),
            ref("b", environment="140"),
        ),
        InvestigationDepth.DEEP,
    )
    assert selection.selected_count == 1


def test_deep_with_one_report_fetches_one() -> None:
    selection = select_reports((ref("only"),), InvestigationDepth.DEEP)
    assert selection.selected_count == 1


def test_selection_never_claims_recency() -> None:
    """A hash search carries no analysis timestamp, so "latest" is unavailable.

    Asserted on the model rather than in prose: if a timestamp is added to
    `SandboxReportRef` later, this test fails and the selection strategy — which
    would then be able to honour recency — gets revisited deliberately.
    """
    assert "analysis" not in str(SandboxReportRef.model_fields.keys())
    assert "time" not in str(SandboxReportRef.model_fields.keys())
    assert "newest" not in SELECTION_STRATEGY
    assert "latest" not in SELECTION_STRATEGY
