"""Material gaps and the information they call for (Task 18).

A gap is not "a capability that did not run". It is a capability that did not run
*and whose absence leaves something about this assessment unsettled*. The
difference is the whole point: a catalogue full of unused providers is normal,
and reporting each one as a deficiency would bury the one that mattered.

Gaps name capabilities, never providers
---------------------------------------

A gap says ``FILE_BEHAVIOR coverage was not obtained``. It does not say which
integration could have obtained it, because that is Task 13's decision, made
later and with the catalogue and the budget in front of it. The provider ids that
were *observed* to fail are carried alongside for the trace, and no rule reads
them.

Outlook is deliberately hedged
------------------------------

``MAY_ADDRESS_MATERIAL_GAP`` says an applicable requirement is unfulfilled and a
path exists. It does not say the verdict would change, because that is unknowable
until the check runs -- and a layer that predicted outcomes would be inventing the
evidence it is complaining about not having.
"""

from __future__ import annotations

from collections.abc import Sequence

from ti_recon.reasoning.readiness.models import (
    GapOutlook,
    GapType,
    InformationNeed,
    ReadinessGap,
    RequirementEvaluation,
    gap_id_for,
)
from ti_recon.reasoning.readiness.policy import (
    BASIS_RATIONALE,
    TERMINAL_GAP_TYPES,
)

__all__ = ["gaps_from_evaluations", "information_needs_from_gaps", "outlook_for"]


def outlook_for(gap_type: GapType) -> GapOutlook:
    """Whether enrichment could still address a gap of this kind.

    Only the terminal categories close the door: a capability nothing implements,
    and evidence that could not be attributed. Everything else -- unconfigured,
    out of quota, unavailable, never attempted, budget-limited -- describes a
    path that exists and is currently unusable, which a later run may find open.
    """
    if gap_type in TERMINAL_GAP_TYPES:
        return GapOutlook.NO_REMAINING_PATH
    return GapOutlook.MAY_ADDRESS_MATERIAL_GAP


def gaps_from_evaluations(
    evaluations: Sequence[RequirementEvaluation], *, policy_version: str
) -> tuple[ReadinessGap, ...]:
    """One gap per unmet requirement that actually bears on the assessment.

    Ordered by capability so two runs over the same investigation produce the
    same list, and so a diff between two runs means something.
    """
    found: list[ReadinessGap] = []
    for evaluation in evaluations:
        if not evaluation.material or evaluation.gap_type is None:
            continue
        requirement = evaluation.requirement
        found.append(
            ReadinessGap(
                gap_id=gap_id_for(
                    policy_version=policy_version,
                    requirement_id=requirement.requirement_id,
                    gap_type=evaluation.gap_type,
                ),
                requirement_id=requirement.requirement_id,
                gap_type=evaluation.gap_type,
                capability=requirement.capability,
                criticality=requirement.criticality,
                outlook=outlook_for(evaluation.gap_type),
                observed_sources=tuple(sorted({check.provider_id for check in evaluation.checks})),
                detail=(
                    f"{requirement.capability.value} coverage was not obtained "
                    f"({evaluation.gap_type.value})"
                ),
            )
        )
    return tuple(sorted(found, key=lambda item: item.capability.value if item.capability else ""))


def information_needs_from_gaps(gaps: Sequence[ReadinessGap]) -> tuple[InformationNeed, ...]:
    """What would be worth obtaining, stated as capabilities.

    Not a plan, not a request and not a recommendation about the observable.
    Task 19 may hand these to Task 13, which knows who could serve them; until
    then they are a statement of what this investigation still lacks.
    """
    seen: dict[str, InformationNeed] = {}
    for gap in gaps:
        if gap.capability is None or gap.outlook is GapOutlook.NO_REMAINING_PATH:
            continue
        seen.setdefault(
            gap.capability.value,
            InformationNeed(
                capability=gap.capability,
                criticality=gap.criticality,
                reason=BASIS_RATIONALE["planner_goal"],
                outlook=gap.outlook,
            ),
        )
    return tuple(seen[key] for key in sorted(seen))
