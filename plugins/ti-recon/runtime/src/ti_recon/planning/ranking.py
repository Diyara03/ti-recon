"""How candidates are ordered (Task 13).

**Lexicographic, and deliberately so.** There is no weighted score here — no
``0.37 * reputation - 0.21 * cost`` — because there is no evidence for any such
constant, and inventing one would produce a number that looks principled, cannot
be explained to an analyst, and changes behaviour unpredictably when a provider
is added.

A lexicographic order has three properties that matter more than expressiveness:
it is deterministic, every decision can be explained by naming the first factor
that separated two candidates, and a test can pin it.

The order
---------

Compared in this sequence, first difference wins:

1. **Explicitly requested capability.** A caller who named a capability gets it
   before the defaults, rather than after the budget has gone on baseline work.
2. **Local before remote.** A local provider discloses nothing and spends no
   remote allowance, so there is never a reason to defer one. This ranks above
   the goal urgency below it precisely because it is free — collecting cheap
   context first cannot delay anything.
3. **Required, unsatisfied goal.** Learning something required beats deepening
   something optional.
4. **Baseline before specialized.** A goal that is eligible from the start comes
   before a follow-up that had to wait for one. Asking what a file *did* before
   knowing whether anyone has ever seen it is the wrong order, and it spends the
   expensive request first.
5. **Novelty.** New capability, then new source family, then a new dataset in a
   family already consulted. Buying a *kind* of answer nobody has beats buying
   the same answer from someone else, which beats buying it from the same house
   again.
6. **Cheaper cost class.**
7. **Higher profile priority.** A tie-break between providers a policy considers
   equally suitable, not a quality score.
8. **Provider id, then capability.** The final tie-breaks, so the order is total
   and stable rather than incidentally determined by iteration order — two
   capabilities of the same provider must not depend on how goals happened to be
   listed.

Nothing here reads a provider name, and no factor is a judgement about how good a
provider is.
"""

from __future__ import annotations

from ti_recon.enums import ProviderCapability
from ti_recon.planning.models import (
    COST_ORDER,
    NOVELTY_ORDER,
    NoveltyClass,
    ProviderPlanningProfile,
    SelectionReason,
)

__all__ = ["RANKING_FACTORS", "CandidateKey", "candidate_key", "selection_reason_for"]

#: The ordering, as data, so documentation and tests read the same list.
RANKING_FACTORS: tuple[str, ...] = (
    "explicit_capability",
    "local_before_remote",
    "required_unsatisfied_goal",
    "baseline_before_specialized",
    "novelty",
    "cost_class",
    "profile_priority",
    "provider_id",
    "capability",
)

#: The sort key: every element is "lower is better".
CandidateKey = tuple[int, int, int, int, int, int, int, str, str]


def candidate_key(
    *,
    profile: ProviderPlanningProfile,
    capability: ProviderCapability,
    novelty: NoveltyClass,
    explicitly_requested: bool,
    goal_required_and_unsatisfied: bool,
    specialized: bool,
) -> CandidateKey:
    """The lexicographic sort key for one candidate.

    Booleans are inverted so that ``sorted`` puts the preferred candidate first
    without anybody having to remember a reverse flag per field — the kind of
    detail that silently inverts a ranking during a refactor.
    """
    return (
        0 if explicitly_requested else 1,
        0 if profile.is_local else 1,
        0 if goal_required_and_unsatisfied else 1,
        1 if specialized else 0,
        NOVELTY_ORDER[novelty],
        COST_ORDER[profile.cost_for(capability)],
        -profile.priority,
        profile.provider_id,
        capability.value,
    )


def selection_reason_for(
    *,
    profile: ProviderPlanningProfile,
    novelty: NoveltyClass,
    explicitly_requested: bool,
    specialized: bool,
) -> SelectionReason:
    """The stable code explaining why this candidate won.

    Derived from the same facts the ranking used, so an explanation can never
    disagree with the decision it describes.
    """
    if explicitly_requested:
        return SelectionReason.EXPLICIT_CAPABILITY
    if profile.is_local:
        return SelectionReason.LOCAL_CONTEXT
    if specialized:
        return SelectionReason.SPECIALIZED_FOLLOWUP
    if novelty is NoveltyClass.NEW_CAPABILITY:
        return SelectionReason.MISSING_CAPABILITY
    if novelty is NoveltyClass.NEW_SOURCE_FAMILY:
        return SelectionReason.NEW_SOURCE_FAMILY
    return SelectionReason.NEW_DATASET
