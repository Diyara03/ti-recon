"""Turning readiness into a request for more information (Task 19).

Task 18 says what is missing and whether anything could still address it. This
module turns that into something Task 13 can plan against — and refuses to
invent one where Task 18 named no capability.

Only Task 18 decides
--------------------

A continuation happens when readiness is ``NEEDS_MORE_DATA`` *and* continuation
is ``MORE_DATA_AVAILABLE``. Not when the verdict is suspicious, not when it is
inconclusive, not when a provider failed and not when a sandbox is missing. Those
are all reasons a person might feel the investigation is unfinished, and Task 18
has already weighed every one of them against what the assessment actually rests
on. Re-deciding here would be a second opinion formed with less information.

Capabilities, never providers
-----------------------------

A directive names ``FILE_BEHAVIOR``, never a sandbox. Choosing who can serve a
capability needs the catalogue, the credentials, the cost class and the ranking —
all of which Task 13 has. A workflow that picked the provider would be a second
planner with a worse view, and the first thing it would break is the budget.
"""

from __future__ import annotations

from ti_recon.enums import ProviderCapability
from ti_recon.investigation.models import ContinuationDirective
from ti_recon.reasoning.fusion.independence import independence_groups
from ti_recon.reasoning.fusion.results import FusionResult
from ti_recon.reasoning.readiness.models import (
    ContinuationState,
    GapOutlook,
    GapType,
    ReadinessStatus,
)
from ti_recon.reasoning.readiness.results import AssessmentReadinessResult

__all__ = [
    "benign_basis_families",
    "directives_for",
    "wants_continuation",
]


def wants_continuation(readiness: AssessmentReadinessResult) -> bool:
    """Whether Task 18 asked for more, in the only way that counts.

    Both axes, because either alone means something else. Inadequate coverage
    with nothing left to try is not a request for more data — it is a finished
    search with an open question, and querying anyway would spend budget on
    sources readiness has already ruled out.
    """
    return (
        readiness.readiness_status is ReadinessStatus.NEEDS_MORE_DATA
        and readiness.continuation_state is ContinuationState.MORE_DATA_AVAILABLE
    )


def benign_basis_families(fusion: FusionResult) -> frozenset[str]:
    """Source families dependent on the benign claims' information origin.

    A planning *hint* for the case where readiness wants an adverse search
    independent of whatever asserted the object was benign. Task 17's grouping
    supplies the families already known to share that origin, so the planner can
    prefer something else.

    It is not a claim of independence. Family is the only provenance knowable
    before a call, and a source that looks unrelated can turn out to relay the
    very origin it was meant to challenge. Whether the answer really was
    independent is settled afterwards by Task 17, from the provenance the
    response carried — and if it was not, readiness will say the challenge is
    still missing.
    """
    benign = [claim for claim in fusion.normalized_claims if not claim.is_malicious_direction]
    if not benign:
        return frozenset()
    benign_ids = {claim.claim_id for claim in benign}
    by_id = {claim.claim_id: claim for claim in fusion.normalized_claims}
    return frozenset(
        by_id[claim_id].source_family
        for group in independence_groups(fusion.normalized_claims)
        if benign_ids & set(group.claim_ids)
        for claim_id in group.claim_ids
    )


def directives_for(
    readiness: AssessmentReadinessResult,
    fusion: FusionResult,
    *,
    admissible: frozenset[ProviderCapability] | None = None,
) -> tuple[ContinuationDirective, ...]:
    """What to ask Task 13 for next, or nothing.

    Built from Task 18's own information needs, which are already scoped to
    material gaps at the requested depth and already exclude anything with no
    remaining path. Needs whose gap is terminal — a capability nothing
    implements, evidence nobody could attribute — produce no directive, because
    there is no request that would address them.

    ``admissible`` is the capability envelope Task 13 admitted for this root at
    the requested depth, frozen before any directive existed. A need naming
    something outside it produces no directive: readiness describes what would
    help, and it does not get to decide that a QUICK investigation should have
    been a DEEP one. Filtering here rather than in the planner keeps the reason
    visible — the workflow records that a remaining path named nothing it was
    allowed to ask for, instead of issuing a directive that plans nothing.

    A capability some provider already answered is *not* filtered here. Whether
    another source could add anything is Task 13's question: it holds the
    per-provider record of what has been asked, the ranking and the remaining
    budget, and a capability answered by one family may still be exactly what a
    second, independent one should be asked for. Pre-empting that here would
    make the requirement unmeetable by deciding, without the catalogue, that
    nobody else could help.

    Returning empty when readiness asked for more is a real outcome, not a
    failure to try: the workflow records it and stops rather than inventing a
    capability to go and fetch.
    """
    avoid = benign_basis_families(fusion)
    found: list[ContinuationDirective] = []
    for need in readiness.information_needs:
        if need.outlook is not GapOutlook.MAY_ADDRESS_MATERIAL_GAP:
            continue
        if admissible is not None and need.capability not in admissible:
            continue
        gap = next(
            (item for item in readiness.gaps if item.capability is need.capability),
            None,
        )
        if gap is None:
            continue
        found.append(
            ContinuationDirective(
                requirement_id=gap.requirement_id,
                capability=need.capability,
                criticality=need.criticality,
                reason=need.reason,
                # Only the need that asked for independence carries the hint.
                # Every other material need wants the *information*, and whether
                # its source shares an origin with something that called the
                # object benign has no bearing on that: a sandbox report is worth
                # the same whoever else has spoken. Attaching the families to
                # every directive would record a constraint nobody asked for, and
                # would be the first thing a future planner seam read as one.
                avoid_source_families=(
                    avoid if gap.gap_type is GapType.INDEPENDENT_CHALLENGE_MISSING else frozenset()
                ),
            )
        )
    return tuple(sorted(found, key=lambda item: item.capability.value))
