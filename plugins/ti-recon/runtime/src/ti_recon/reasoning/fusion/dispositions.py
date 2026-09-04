"""Reading Task 16's findings exactly (Task 17C).

Task 16 draws a distinction this module exists to preserve: only an
``ALTERNATIVE_EXPLANATION`` finding, through an ``EXPLAINS`` link to a piece of
evidence, means "there is a plausible alternative reason this detection fired".
Everything else it produces is a caution about how to *read* evidence, not a
suggestion the evidence was wrong.

Getting that wrong would be the most expensive bug in the system. An attribution
caution says a compromised host has a victim; a temporal note says a malicious
URL stopped serving; a source-dependence finding says two results are one source;
an analysis-quality limitation says a sandbox ran nothing. Treating any of them
as an explanation would quietly clear real malicious evidence, and the resulting
verdict would look thoroughly reasoned.

So the check here is narrow and literal: role is ``ALTERNATIVE_EXPLANATION``,
relation is ``EXPLAINS``, target is ``EVIDENCE``. Nothing else counts, and a test
walks every other role to prove none of them can.

Explained is not false
----------------------

A claim marked :attr:`ClaimDisposition.EXPLAINED_BY_ALTERNATIVE` is still a real
provider finding. Nothing rewrites it, deletes it or marks the source wrong. What
changes is only that the verdict did not rest on it -- and the contribution trace
says exactly that, so an analyst can see the detection, the explanation, and the
decision side by side.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from ti_recon.reasoning.claims.models import NormalizedClaim
from ti_recon.reasoning.false_positive.models import (
    LinkRelation,
    LinkTarget,
    ReasoningFinding,
    ReasoningRole,
)
from ti_recon.reasoning.fusion.models import ClaimDisposition

__all__ = [
    "DependencyIndex",
    "explained_evidence_ids",
    "findings_touching",
    "limiting_findings",
]


def explained_evidence_ids(findings: Iterable[ReasoningFinding]) -> frozenset[str]:
    """Evidence a Task 16 alternative explanation specifically accounts for.

    The only path by which a claim leaves the unexplained set. Three conditions,
    all required: the finding must be an alternative explanation, the link must
    be ``EXPLAINS``, and it must point at evidence rather than at a relationship.

    The relationship case matters. Task 16's public-resolver rule explains a
    *contact* and deliberately links to the edge, not to any evidence about the
    file that made it -- so a routine DNS lookup can never end up accounting for a
    malicious classification.
    """
    found: set[str] = set()
    for finding in findings:
        if finding.role is not ReasoningRole.ALTERNATIVE_EXPLANATION:
            continue
        for link in finding.links:
            if link.relation is LinkRelation.EXPLAINS and link.target is LinkTarget.EVIDENCE:
                found.add(link.ref)
    return frozenset(found)


def limiting_findings(findings: Iterable[ReasoningFinding]) -> dict[str, tuple[str, ...]]:
    """Evidence id -> ids of findings that qualify it without explaining it.

    Attribution cautions, scope limitations, temporal notes, analysis-quality
    limitations and source-dependence findings all land here. They shape
    confidence and the rationale; they never remove support.
    """
    found: dict[str, set[str]] = {}
    for finding in findings:
        if finding.role is ReasoningRole.ALTERNATIVE_EXPLANATION:
            continue
        for link in finding.links:
            if link.target is not LinkTarget.EVIDENCE:
                continue
            found.setdefault(link.ref, set()).add(finding.finding_id)
    return {key: tuple(sorted(value)) for key, value in sorted(found.items())}


def findings_touching(findings: Iterable[ReasoningFinding], evidence_id: str) -> tuple[str, ...]:
    """Every Task 16 finding that mentions one piece of evidence, in any role."""
    return tuple(
        sorted(
            finding.finding_id
            for finding in findings
            if any(link.ref == evidence_id for link in finding.links)
        )
    )


class DependencyIndex:
    """Which claims are already counted, as fusion walks a proposition.

    Independence is a property of a *set* of claims, so a claim is a dependent
    duplicate only relative to what has already been credited. This keeps that
    state explicit rather than implied by iteration order, and the ordering it
    walks is the deterministic one the caller supplies.
    """

    __slots__ = ("_seen",)

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def is_duplicate(self, group_key: str) -> bool:
        return group_key in self._seen

    def credit(self, group_key: str) -> None:
        self._seen.add(group_key)


def dispositions_for(
    claims: Sequence[NormalizedClaim],
    *,
    explained: frozenset[str],
    limited: dict[str, tuple[str, ...]],
    opposed_claim_ids: frozenset[str],
    duplicate_claim_ids: frozenset[str],
) -> dict[str, ClaimDisposition]:
    """One disposition per claim, in a fixed precedence.

    Precedence matters and is deliberate:

    1. **Explained** wins. A claim a Task 16 alternative explanation accounts for
       is not support, whatever else is true of it.
    2. **Dependent duplicate** next. Real, and already counted.
    3. **Opposed** next. Something on the same proposition points the other way.
    4. **Qualified only** when a Task 16 finding narrowed it without explaining
       it -- still support.
    5. **Unexplained** otherwise. The default, and the one that carries a verdict.
    """
    found: dict[str, ClaimDisposition] = {}
    for claim in claims:
        if claim.evidence_id in explained:
            found[claim.claim_id] = ClaimDisposition.EXPLAINED_BY_ALTERNATIVE
        elif claim.claim_id in duplicate_claim_ids:
            found[claim.claim_id] = ClaimDisposition.DEPENDENT_DUPLICATE
        elif claim.claim_id in opposed_claim_ids:
            found[claim.claim_id] = ClaimDisposition.OPPOSED
        elif limited.get(claim.evidence_id):
            found[claim.claim_id] = ClaimDisposition.QUALIFIED_ONLY
        else:
            found[claim.claim_id] = ClaimDisposition.UNEXPLAINED
    return found
