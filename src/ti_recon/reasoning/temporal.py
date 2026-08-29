"""Turning stated instants into age, against one explicit ``as_of`` (Task 15).

The whole module is a pure function of ``(facts, as_of)``. Nothing reads a wall
clock, so a qualification computed today can be recomputed identically in a year,
and a test can assert an exact age instead of a tolerance.

What it computes
----------------

Exact elapsed time, and nothing else. There is no ``fresh``, no ``stale``, no
``recent`` and no decay curve, because different threat-intelligence artifacts do
not age alike: a phishing URL is worthless in a week, a malware SHA-256 is not,
a cloud address changes tenant, a certificate expires on a date it announces, and
a sandbox report describes a moment that will never recur. A single invented
half-life would be wrong for all five while looking principled. Where a *source*
defines a lifecycle, the source's word is carried; where it does not, a later
layer gets the number.

What it refuses to do
---------------------

Repair anything. A timestamp after ``as_of`` keeps its value and gets an issue
rather than a clamp, and its age is left unset — an "age" of zero would read as
"observed just now", which is precisely the wrong reading. An interval whose
start follows its end keeps both endpoints: swapping them would invent an
observation window the source never described.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime

from ti_recon.reasoning.models import (
    INTERVAL_PAIRS,
    TemporalFact,
    TemporalFactKind,
    TemporalIssue,
    TemporalIssueType,
    TemporalQualification,
)
from ti_recon.reasoning.policy import CLOCK_SKEW_TOLERANCE

__all__ = [
    "FORWARD_LOOKING_KINDS",
    "SECONDS_PER_DAY",
    "TemporalEvaluation",
    "qualify_facts",
    "require_utc",
]

SECONDS_PER_DAY: float = 86_400.0

#: Kinds whose instant is *supposed* to sit in the future.
#:
#: A certificate's ``not_after`` is a future date on every certificate that has
#: not expired, so reporting it as a future-timestamp problem would file an issue
#: against ordinary correct data — and once a result is full of those, the two
#: cases that mean the data is genuinely wrong stop being visible.
#:
#: Such a fact is also not *aged* while it is still ahead: "this expires in four
#: months" is time remaining, which is a different quantity from elapsed time and
#: is left for a later layer to compute rather than smuggled into ``age_seconds``.
#: Once the instant has passed, the ordinary age applies and means what it says:
#: how long ago the certificate expired.
FORWARD_LOOKING_KINDS: frozenset[TemporalFactKind] = frozenset({TemporalFactKind.VALID_UNTIL})


def require_utc(as_of: datetime) -> datetime:
    """Reject a naive ``as_of`` and normalize an aware one to UTC.

    Rejected rather than assumed, exactly as Task 3 rejects naive provider
    timestamps. Guessing the local zone would shift every age in the result by
    hours, and the mistake would be invisible: the numbers would still look
    plausible.
    """
    if as_of.tzinfo is None or as_of.tzinfo.utcoffset(as_of) is None:
        msg = "as_of must be timezone-aware; temporal qualification has no default clock"
        raise ValueError(msg)
    return as_of.astimezone(UTC)


class TemporalEvaluation:
    """The qualifications and issues one evaluation produced."""

    __slots__ = ("issues", "qualifications")

    def __init__(
        self,
        qualifications: tuple[TemporalQualification, ...],
        issues: tuple[TemporalIssue, ...],
    ) -> None:
        self.qualifications = qualifications
        self.issues = issues


def qualify_facts(facts: Iterable[TemporalFact], *, as_of: datetime) -> TemporalEvaluation:
    """Age every fact and record the ones that cannot be taken literally.

    Deterministic in both content and order: the output is sorted by a key made
    only of the facts themselves, so shuffling the input — which happens whenever
    providers answer in a different sequence — cannot change the result.
    """
    moment = require_utc(as_of)
    ordered = sorted(facts, key=_fact_sort_key)

    issues: list[TemporalIssue] = []
    issues.extend(_interval_issues(ordered))
    invalid_refs = {ref for issue in issues for ref in issue.fact_refs}

    qualifications: list[TemporalQualification] = []
    for fact in ordered:
        kinds: list[TemporalIssueType] = []
        if fact.ref in invalid_refs:
            kinds.append(TemporalIssueType.INVALID_INTERVAL)

        delta = (moment - fact.instant).total_seconds()
        age_seconds: float | None
        if delta < 0 and fact.kind in FORWARD_LOOKING_KINDS:
            # Not yet reached, and not a problem. No age, no issue.
            age_seconds = None
        elif delta < -CLOCK_SKEW_TOLERANCE.total_seconds():
            # Beyond ordinary skew. The instant is preserved and left unaged: a
            # clamped zero would read as "observed just now".
            kinds.append(TemporalIssueType.FUTURE_TIMESTAMP)
            issues.append(
                TemporalIssue(
                    issue_type=TemporalIssueType.FUTURE_TIMESTAMP,
                    subject=fact.subject,
                    kind=fact.kind,
                    detail=f"instant is {abs(delta):.0f}s after as_of",
                    fact_refs=(fact.ref,),
                )
            )
            age_seconds = None
        else:
            # Inside the tolerance a small negative is a clock difference rather
            # than a claim about the future, so it floors at zero silently.
            age_seconds = max(0.0, delta)

        qualifications.append(
            TemporalQualification(
                fact=fact,
                age_seconds=age_seconds,
                age_days=None if age_seconds is None else age_seconds / SECONDS_PER_DAY,
                issue_types=tuple(sorted(set(kinds), key=lambda item: item.value)),
            )
        )

    return TemporalEvaluation(
        qualifications=tuple(qualifications),
        issues=tuple(sorted(issues, key=_issue_sort_key)),
    )


def _interval_issues(facts: Sequence[TemporalFact]) -> list[TemporalIssue]:
    """Intervals whose start follows their end.

    An interval is two facts about the same subject, from the same origin, with
    the same discriminator — a certificate's validity, a record's first and last
    seen. Pairing on origin matters: two providers reporting first-seen and
    last-seen for one object are describing two separate observations, and
    treating them as one window would manufacture a disagreement out of two
    perfectly consistent records.
    """
    indexed: dict[tuple[str, str, str, str], TemporalFact] = {}
    for fact in facts:
        indexed.setdefault(
            (
                fact.subject.ref,
                fact.origin_provider or "",
                fact.detail or "",
                fact.kind.value,
            ),
            fact,
        )

    found: list[TemporalIssue] = []
    for start_kind, end_kind in INTERVAL_PAIRS.items():
        for key, start in indexed.items():
            if key[3] != start_kind.value:
                continue
            end = indexed.get((key[0], key[1], key[2], end_kind.value))
            if end is None or end.instant >= start.instant:
                continue
            found.append(
                TemporalIssue(
                    issue_type=TemporalIssueType.INVALID_INTERVAL,
                    subject=start.subject,
                    kind=start_kind,
                    detail=f"{start_kind.value} follows {end_kind.value}",
                    fact_refs=tuple(sorted((start.ref, end.ref))),
                )
            )
    return found


def _fact_sort_key(fact: TemporalFact) -> tuple[str, str, str, str, str, str]:
    return (
        fact.subject.ref,
        fact.kind.value,
        fact.instant.isoformat(),
        fact.source_family or "",
        fact.origin_provider or "",
        fact.ref,
    )


def _issue_sort_key(issue: TemporalIssue) -> tuple[str, str, str, str]:
    return (
        issue.issue_type.value,
        issue.subject.ref,
        issue.kind.value,
        "|".join(issue.fact_refs),
    )
