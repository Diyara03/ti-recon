"""The capability coverage ledger (Task 18).

Turns what actually executed into per-capability facts, keeping two things apart
that a naive ledger collapses:

* **whether the check happened** -- :class:`CheckCompletion`;
* **what it returned** -- :class:`InformationYield`.

A source that answered "nothing known about this" completed its check and
yielded ``NO_DATA``. That is strictly more coverage than a source that was never
configured, and it is not one atom of evidence that the observable is safe. Every
rule in this module exists to keep those three states -- answered-with-nothing,
never-asked, and answered-with-something -- distinguishable.

Aggregation is at the capability, never the provider
----------------------------------------------------

Three sources may serve one capability. If one is unconfigured, one is out of
quota and the third answered, the capability is covered: the requirement asked
for information, not for a quorum. The failures stay in the trace because hiding
them would make the investigation look tidier than it was, but they do not create
a gap.

Independence follows Task 17
----------------------------

Where breadth matters, families are grouped exactly as fusion groups them, so
three datasets run by one organisation are one origin. Nothing here counts
provider ids.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence

from ti_recon.enums import CoverageStatus, ProviderCapability, ProviderRunStatus
from ti_recon.models.coverage import CoverageItem
from ti_recon.planning.models import ProviderAttempt, ProviderLocality
from ti_recon.reasoning.claims.models import NormalizedClaim
from ti_recon.reasoning.readiness.models import (
    CheckCompletion,
    InformationYield,
    SourceCheck,
)
from ti_recon.reasoning.readiness.policy import CAPABILITY_ANSWERED_BY_SEMANTIC

__all__ = [
    "STATUS_COMPLETION",
    "capability_checks",
    "checks_for",
    "completion_for",
    "directional_capabilities_by_provider",
    "independent_families",
    "secondary_yield_for",
    "worst_completion",
    "yield_for",
]

#: Provider id -> the capabilities its directional claims demonstrably answered.
AttributedCapabilities = Mapping[str, frozenset[ProviderCapability]]

#: Every provider status, mapped on purpose. There is no default branch: a new
#: status must be classified deliberately, because silently defaulting one to
#: "complete" would report an unasked question as an answered one, and
#: defaulting to "blocked" would invent a gap that never existed.
STATUS_COMPLETION: dict[ProviderRunStatus, CheckCompletion] = {
    # The source answered. NO_DATA is an answer: it completed the check and
    # simply held nothing, which is the distinction this whole layer turns on.
    ProviderRunStatus.SUCCESS: CheckCompletion.COMPLETE,
    ProviderRunStatus.NO_DATA: CheckCompletion.COMPLETE,
    # The source answered incompletely.
    # Reduced evidence -- *if* any came back. Task 6 documents that an adapter
    # may also raise ``PARTIAL_RESULT`` when it could not retrieve enough to
    # build an envelope at all, so this entry is the optimistic case and
    # `completion_for` refines it from what the attempt actually produced.
    ProviderRunStatus.PARTIAL: CheckCompletion.PARTIAL,
    # The credential is valid and the account's plan does not cover this data.
    # It reaches an attempt only through the executor's error path, where the
    # envelope is None -- so nothing was retrieved and no coverage was obtained.
    # A source exists and cannot currently be used, which is BLOCKED.
    ProviderRunStatus.PLAN_LIMITED: CheckCompletion.BLOCKED,
    # The source could not be used. Each stays distinguishable in `raw_status`
    # so the gap can name the real cause without a category per status.
    ProviderRunStatus.NOT_CONFIGURED: CheckCompletion.BLOCKED,
    ProviderRunStatus.QUOTA_EXCEEDED: CheckCompletion.BLOCKED,
    ProviderRunStatus.TEMPORARILY_UNAVAILABLE: CheckCompletion.BLOCKED,
    ProviderRunStatus.ERROR: CheckCompletion.BLOCKED,
    # This source cannot answer this question about this observable. Not a
    # failure and not a gap: another source may serve the capability, and if
    # none can, that is a catalogue fact recorded separately.
    ProviderRunStatus.NOT_SUPPORTED: CheckCompletion.OUT_OF_SCOPE,
}

#: Ordered worst-to-best, so aggregating many attempts into one answer is a
#: max rather than a pile of conditionals.
_COMPLETION_ORDER: dict[CheckCompletion, int] = {
    CheckCompletion.NOT_ATTEMPTED: 0,
    CheckCompletion.OUT_OF_SCOPE: 1,
    CheckCompletion.BLOCKED: 2,
    CheckCompletion.PARTIAL: 3,
    CheckCompletion.COMPLETE: 4,
}

_YIELD_ORDER: dict[InformationYield, int] = {
    InformationYield.NONE: 0,
    # A check carries UNATTRIBUTED when it stands for a capability the attempt
    # *carried* beside its primary: the call completed, and what that
    # capability got back is not retained per capability (Task 24 Phase 3).
    InformationYield.UNATTRIBUTED: 1,
    InformationYield.NO_DATA: 2,
    InformationYield.CONTEXT_ONLY: 3,
    InformationYield.DIRECTIONAL: 4,
}


#: The completions under which an attempt can have returned information at
#: all. A blocked, out-of-scope or unattempted check returned nothing, so it
#: may not borrow a yield from another call.
_YIELDING_COMPLETIONS: frozenset[CheckCompletion] = frozenset(
    {CheckCompletion.COMPLETE, CheckCompletion.PARTIAL}
)


def completion_for(attempt: ProviderAttempt) -> CheckCompletion:
    """How far one attempt got, from the status *and* what it produced.

    A single status-to-completion table is not enough for ``PARTIAL``. Task 6
    records that a partial result is "usually an envelope carrying reduced
    evidence, but an adapter may also raise ``PARTIAL_RESULT`` when it could not
    retrieve enough to build one" -- and those are different facts. The first
    partially covered the capability; the second covered none of it, and
    crediting it as a partial check would report coverage that does not exist.

    So the table gives the status's meaning and this refines it with the
    execution record. Nothing else needs refining: every other status is
    unambiguous about whether an answer came back.
    """
    completion = STATUS_COMPLETION[attempt.status]
    if completion is CheckCompletion.PARTIAL and not attempt.produced_evidence:
        return CheckCompletion.BLOCKED
    return completion


def yield_for(
    attempt: ProviderAttempt, *, directional_providers: frozenset[str]
) -> InformationYield:
    """What one attempt actually returned.

    ``NO_DATA`` is read from the provider's own status rather than inferred from
    an absence of evidence, so "the source said it has nothing" never blurs into
    "we did not look". Directionality is read from whether a claim reached the
    assessment layer, which is Task 17's judgement rather than a fresh one.

    Only an attempt that completed *and produced evidence* can have yielded
    anything. The directional-provider set is keyed by provider, because a
    claim does not record which call produced it; before Task 24 that let a
    ``NOT_SUPPORTED`` behaviour query inherit ``DIRECTIONAL`` from the same
    provider's reputation answer -- a refusal rendered as a finding. A refused,
    unconfigured, errored or empty-handed attempt yields ``NONE`` whatever the
    provider's other calls returned. What remains is the case of two
    *completed, evidence-producing* calls to one provider, where a
    context-only answer still reads ``DIRECTIONAL`` because the record cannot
    say which call produced the claim. That is a retention limit of the
    per-attempt record -- this function cannot return ``UNATTRIBUTED``, which
    the capability ledger reserves for a call it has no attempt for at all.
    """
    if attempt.status is ProviderRunStatus.NO_DATA:
        return InformationYield.NO_DATA
    if completion_for(attempt) not in _YIELDING_COMPLETIONS or not attempt.produced_evidence:
        return InformationYield.NONE
    if attempt.provider_id in directional_providers:
        return InformationYield.DIRECTIONAL
    return InformationYield.CONTEXT_ONLY


def directional_provider_ids(claims: Iterable[NormalizedClaim]) -> frozenset[str]:
    """Providers whose answers became directional claims.

    Transport rather than origin: this asks which *execution* produced something
    directional, which is what a coverage ledger is about. Independence is a
    separate question and is answered with Task 17's grouping.
    """
    return frozenset(claim.transport_provider for claim in claims)


def directional_capabilities_by_provider(
    claims: Iterable[NormalizedClaim],
) -> dict[str, frozenset[ProviderCapability]]:
    """Per transport provider, the capabilities its claims demonstrably answered.

    Read from :data:`CAPABILITY_ANSWERED_BY_SEMANTIC`, so a claim attributes a
    yield only where its own proposition names exactly one capability. Keyed
    by transport like :func:`directional_provider_ids`, and for the same
    reason: this is about which execution produced the claim.
    """
    found: dict[str, set[ProviderCapability]] = defaultdict(set)
    for claim in claims:
        answered = CAPABILITY_ANSWERED_BY_SEMANTIC.get(claim.semantic)
        if answered is not None:
            found[claim.transport_provider].add(answered)
    return {provider: frozenset(items) for provider, items in found.items()}


def secondary_yield_for(
    attempt: ProviderAttempt,
    capability: ProviderCapability,
    *,
    attributed_capabilities: AttributedCapabilities,
) -> InformationYield:
    """What one attempt returned for a capability it carried beside its primary.

    Completion is the call's -- the provider was asked, and refused or answered
    for the whole bundle -- so a call that did not complete yields ``NONE``.
    A call that completed yields ``UNATTRIBUTED`` by default, because Task 13
    retains what came back per *call* and not per capability. The one
    exception is deterministic: where a directional claim this same provider
    produced has a semantic that names this capability and no other
    (:data:`CAPABILITY_ANSWERED_BY_SEMANTIC`), the claim *is* the answer to
    this question, and the yield is ``DIRECTIONAL`` -- the same judgement the
    primary's yield already reads from Task 17. Never ``CONTEXT_ONLY`` or
    ``NO_DATA`` for a secondary: the record holds no context-only evidence
    keyed to a capability, and a bundled call's ``NO_DATA`` is not retained
    per question either (Task 24 scanner-context validation, GN-FINDING-03).
    """
    completion = completion_for(attempt)
    if completion not in _YIELDING_COMPLETIONS:
        return InformationYield.NONE
    if attempt.produced_evidence and capability in attributed_capabilities.get(
        attempt.provider_id, frozenset()
    ):
        return InformationYield.DIRECTIONAL
    return InformationYield.UNATTRIBUTED


def checks_for(
    attempts: Iterable[ProviderAttempt],
    *,
    directional_providers: frozenset[str],
    capability: ProviderCapability | None = None,
    attributed_capabilities: AttributedCapabilities | None = None,
) -> tuple[SourceCheck, ...]:
    """One :class:`SourceCheck` per attempt, deterministically ordered.

    ``capability`` is the ledger bucket the checks are being built for. For
    the attempt's primary capability the yield is read from the attempt; for
    another capability the same call *carried*, the yield comes from
    :func:`secondary_yield_for` -- ``NONE`` if the call did not complete,
    ``DIRECTIONAL`` where a claim's own semantic names this capability, and
    otherwise ``UNATTRIBUTED``, because what that capability got back is not
    retained per capability. Never ``CONTEXT_ONLY`` or ``NO_DATA`` for a
    secondary: those would assert content the record cannot support.
    """
    attributed = {} if attributed_capabilities is None else attributed_capabilities
    found: list[SourceCheck] = []
    for attempt in attempts:
        bucket = attempt.capability if capability is None else capability
        if bucket is attempt.capability:
            yielded = yield_for(attempt, directional_providers=directional_providers)
        else:
            yielded = secondary_yield_for(attempt, bucket, attributed_capabilities=attributed)
        found.append(
            SourceCheck(
                provider_id=attempt.provider_id,
                source_family=attempt.source_family,
                capability=bucket,
                raw_status=attempt.status.value,
                completion=completion_for(attempt),
                information_yield=yielded,
                # A cache hit or a coalesced request is information that was
                # available; readiness asks whether it was, not whether a socket
                # was opened for it.
                served_without_call=not attempt.called_provider,
                local_source=attempt.locality is ProviderLocality.LOCAL,
            )
        )
    return tuple(
        sorted(found, key=lambda item: (item.capability.value, item.provider_id, item.raw_status))
    )


def capability_checks(
    attempts: Sequence[ProviderAttempt],
    *,
    directional_providers: frozenset[str],
    attributed_capabilities: AttributedCapabilities | None = None,
) -> dict[ProviderCapability, tuple[SourceCheck, ...]]:
    """The ledger: every attempt grouped under every capability it carried.

    One call bundling several questions is one attempt in the trace and one
    check under each of those questions: the provider was asked all of them,
    and a refusal, an outage or an unconfigured credential refused all of
    them. Keying on the primary alone typed the others "not attempted" when
    the provider had in fact answered NOT_CONFIGURED (Task 24 Phase 3).

    ``attributed_capabilities`` is :func:`directional_capabilities_by_provider`
    over the claims that reached the assessment: it lets a secondary bucket
    read ``DIRECTIONAL`` where a claim's semantic demonstrably answers it, and
    nothing else.
    """
    buckets: dict[ProviderCapability, list[ProviderAttempt]] = defaultdict(list)
    for attempt in attempts:
        for carried in attempt.capabilities:
            buckets[carried].append(attempt)
    return {
        capability: checks_for(
            items,
            directional_providers=directional_providers,
            capability=capability,
            attributed_capabilities=attributed_capabilities,
        )
        for capability, items in buckets.items()
    }


def worst_completion(checks: Sequence[SourceCheck]) -> CheckCompletion:
    """The *best* result any source achieved for this capability.

    Named for the question it answers rather than the arithmetic: one source
    completing the check covers the capability however many others failed, so
    aggregation takes the maximum. Requiring every provider to succeed would be
    the quorum this layer explicitly refuses.
    """
    if not checks:
        return CheckCompletion.NOT_ATTEMPTED
    return max(checks, key=lambda item: _COMPLETION_ORDER[item.completion]).completion


def best_yield(checks: Sequence[SourceCheck]) -> InformationYield:
    """The most informative thing any source returned for this capability."""
    if not checks:
        return InformationYield.NONE
    return max(checks, key=lambda item: _YIELD_ORDER[item.information_yield]).information_yield


def independent_families(checks: Sequence[SourceCheck]) -> tuple[str, ...]:
    """Originating families that completed a check, deduplicated.

    Family rather than provider, so three datasets from one organisation answer
    once. This is the same conservatism Task 17 applies to corroboration, for the
    same reason: a number going up is not information arriving.
    """
    return tuple(
        sorted(
            {
                check.source_family
                for check in checks
                if check.completion in {CheckCompletion.COMPLETE, CheckCompletion.PARTIAL}
            }
        )
    )


def capability_coverage_items(
    items: Iterable[CoverageItem],
) -> dict[ProviderCapability, CoverageItem]:
    """Task 13's own coverage statement, addressed by capability."""
    return {item.capability: item for item in items}


#: What Task 13's own per-capability coverage statement means for completion.
#:
#: This is the *authoritative* record for whether a capability was answered,
#: because one provider execution can answer several. Task 13 bundles compatible
#: goals into a single request and credits every capability the response
#: ``answered_capabilities`` names — but it records one ``ProviderAttempt``
#: carrying only the call's *primary* capability. So the attempts describe what
#: was executed, and the coverage items describe what was covered, and for a
#: bundled call those are deliberately not the same set.
_COVERAGE_COMPLETION: dict[CoverageStatus, CheckCompletion] = {
    CoverageStatus.COVERED: CheckCompletion.COMPLETE,
    CoverageStatus.PARTIAL: CheckCompletion.PARTIAL,
    CoverageStatus.NOT_COVERED: CheckCompletion.NOT_ATTEMPTED,
    CoverageStatus.NOT_APPLICABLE: CheckCompletion.OUT_OF_SCOPE,
}


def coverage_completion(item: CoverageItem | None) -> CheckCompletion:
    """How far Task 13 says this capability got, independent of who ran.

    Reading it is what stops readiness demanding a second call for a capability
    the planner deliberately answered with one request. ``NOT_COVERED`` maps to
    ``NOT_ATTEMPTED`` so it never *raises* a completion — the attempts remain
    the place where a blocked or partial execution is recognised.
    """
    if item is None:
        return CheckCompletion.NOT_ATTEMPTED
    return _COVERAGE_COMPLETION[item.status]


def has_no_eligible_source(item: CoverageItem | None) -> bool:
    """Whether nothing registered could have served this capability at all.

    Structural rather than textual: the planner records the providers it
    considered, so an empty set with uncovered status means the catalogue has no
    path, not that a path failed. Reading the human-readable reason string would
    make this brittle the moment somebody rewords it.
    """
    return (
        item is not None
        and item.status is CoverageStatus.NOT_COVERED
        and not item.providers_considered
    )
