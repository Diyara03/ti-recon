"""Choosing which sandbox reports are worth fetching (Task 12).

A hash can have dozens of detonations. Each detailed summary is a separate
metered request, and a restricted Hybrid Analysis key allows roughly five
requests a minute — so "fetch them all" is not a strategy, it is an outage.

This module answers one question: given an index of runs and a depth, which *at
most two* are worth spending requests on?

What is deliberately not used: recency
--------------------------------------

The obvious selection rule is "take the newest report", and it is not available.
A hash search returns report identity, environment, state and verdict — **not an
analysis timestamp**. Ordering by report id would be ordering by an opaque
string, and calling the result "latest" would be a claim the data does not
support. Inventing that ordering is worse than not having it: an analyst who
believes they are reading the newest run will interpret an old one as current.

So selection is by *verdict strength* and, at DEEP, by *behavioural contrast* —
both of which the index actually reports — with a deterministic tiebreak so the
same index always yields the same choice.

Why contrast rather than confirmation
-------------------------------------

At DEEP the second report is chosen to **disagree** with the first where
possible: a different verdict, or failing that a different environment. Fetching
a second malicious run tells an analyst almost nothing they did not already know
from the first. Fetching the Windows 7 run that saw nothing, next to the Windows
11 run that saw credential theft, tells them the sample is environment-dependent
— which is how targeted malware behaves and exactly what a false-positive review
needs to see.
"""

from __future__ import annotations

from typing import Final

from pydantic import Field

from ti_recon.enums import InvestigationDepth
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.sandbox.models import SandboxReportRef, verdict_rank

__all__ = [
    "DEPTH_SUMMARY_BUDGET",
    "MAX_SUMMARIES_PER_LOOKUP",
    "SELECTION_STRATEGY",
    "ReportSelection",
    "select_reports",
]

#: How many detailed summaries each depth may fetch.
#:
#: One request per summary, on top of the single index request every depth makes.
#: So the physical maximum per lookup is 1, 2 and 3 requests — chosen to sit
#: under a restricted key's ~5/minute allowance with room for the retry the
#: execution layer might add.
DEPTH_SUMMARY_BUDGET: Final[dict[InvestigationDepth, int]] = {
    InvestigationDepth.QUICK: 0,
    InvestigationDepth.STANDARD: 1,
    InvestigationDepth.DEEP: 2,
}

#: Absolute ceiling regardless of depth or configuration. A future planner may
#: lower a budget; nothing raises it past here without changing this constant.
MAX_SUMMARIES_PER_LOOKUP: Final[int] = 2

#: Named so coverage can state how the reports were chosen rather than leaving an
#: analyst to guess why one of forty runs was read.
SELECTION_STRATEGY: Final[str] = "strongest_completed_verdict_then_contrast"


class ReportSelection(FrozenTiReconModel):
    """Which reports to fetch, and what was skipped to get there."""

    selected: tuple[SandboxReportRef, ...] = ()
    strategy: str = Field(default=SELECTION_STRATEGY, max_length=64)
    #: Runs that were never candidates because they had not completed.
    skipped_incomplete: int = Field(default=0, ge=0)
    #: Completed runs left unfetched because the budget ran out.
    skipped_over_budget: int = Field(default=0, ge=0)
    budget: int = Field(default=0, ge=0)

    @property
    def selected_count(self) -> int:
        return len(self.selected)

    @property
    def contrasting(self) -> bool:
        """Whether the selection deliberately covers disagreeing runs."""
        return len({item.verdict for item in self.selected}) > 1


def select_reports(
    reports: tuple[SandboxReportRef, ...], depth: InvestigationDepth
) -> ReportSelection:
    """Pick at most :data:`MAX_SUMMARIES_PER_LOOKUP` reports to summarize.

    Only completed runs are candidates: a failed or queued report has nothing to
    summarize, so fetching one would spend an allowance to re-learn what the
    index already said.

    The first pick is the strongest verdict. The second, at DEEP only, prefers a
    *different verdict* over a different environment over anything else — see the
    module docstring for why contrast beats confirmation.

    Deterministic throughout: ties break on environment identity then report id,
    so the same index always produces the same requests and a cached answer stays
    meaningful.
    """
    budget = min(DEPTH_SUMMARY_BUDGET.get(depth, 1), MAX_SUMMARIES_PER_LOOKUP)
    candidates = [item for item in reports if item.is_selectable]
    incomplete = len(reports) - len(candidates)

    if budget == 0 or not candidates:
        return ReportSelection(
            selected=(),
            skipped_incomplete=incomplete,
            skipped_over_budget=len(candidates) if budget == 0 else 0,
            budget=budget,
        )

    ordered = sorted(candidates, key=_primary_key)
    selected = [ordered[0]]

    if budget > 1:
        contrast = _pick_contrast(ordered[0], ordered[1:])
        if contrast is not None:
            selected.append(contrast)

    return ReportSelection(
        selected=tuple(selected),
        skipped_incomplete=incomplete,
        skipped_over_budget=max(0, len(candidates) - len(selected)),
        budget=budget,
    )


def _primary_key(ref: SandboxReportRef) -> tuple[int, str, str]:
    """Strongest verdict first, then a stable deterministic tiebreak."""
    return (-verdict_rank(ref.verdict), ref.environment.identity, ref.report_id)


def _pick_contrast(
    primary: SandboxReportRef, remaining: list[SandboxReportRef]
) -> SandboxReportRef | None:
    """The most analytically useful second report, or ``None``.

    Preference order, each already sorted deterministically:

    1. a different verdict — the environment-dependence signal;
    2. the same verdict from a different environment — weaker, but still says
       the behaviour reproduces somewhere else;
    3. nothing. A second report identical in verdict *and* environment to the
       first is a request spent on a duplicate.
    """
    for item in remaining:
        if item.verdict is not primary.verdict:
            return item
    for item in remaining:
        if item.environment.identity != primary.environment.identity:
            return item
    return None
