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

from collections.abc import Sequence

from ti_recon.investigation.models import ContinuationDirective
from ti_recon.reasoning.fusion.independence import independence_groups
from ti_recon.reasoning.fusion.results import FusionResult
from ti_recon.reasoning.readiness.models import (
    ContinuationState,
    GapOutlook,
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
    attempted_capabilities: Sequence[str] = (),
) -> tuple[ContinuationDirective, ...]:
    """What to ask Task 13 for next, or nothing.

    Built from Task 18's own information needs, which are already scoped to
    material gaps at the requested depth and already exclude anything with no
    remaining path. Needs whose gap is terminal — a capability nothing
    implements, evidence nobody could attribute — produce no directive, because
    there is no request that would address them.

    Returning empty when readiness asked for more is a real outcome, not a
    failure to try: the workflow records it and stops rather than inventing a
    capability to go and fetch.
    """
    avoid = benign_basis_families(fusion)
    already = set(attempted_capabilities)
    found: list[ContinuationDirective] = []
    for need in readiness.information_needs:
        if need.outlook is not GapOutlook.MAY_ADDRESS_MATERIAL_GAP:
            continue
        if need.capability.value in already:
            continue
        requirement_id = next(
            (gap.requirement_id for gap in readiness.gaps if gap.capability is need.capability),
            "",
        )
        if not requirement_id:
            continue
        found.append(
            ContinuationDirective(
                requirement_id=requirement_id,
                capability=need.capability,
                criticality=need.criticality,
                reason=need.reason,
                avoid_source_families=avoid,
            )
        )
    return tuple(sorted(found, key=lambda item: item.capability.value))
