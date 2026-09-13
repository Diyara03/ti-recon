"""Turning warninglist matches into evidence (Task 11).

One rule governs this entire module, and it has no exceptions.

**Every warninglist hit is ``EvidenceClass.CONTEXT`` with
``EvidenceEffect.CONTEXT_ONLY``.** Never ``SUPPORTS_BENIGN``, never
``SUPPORTS_MALICIOUS``.

A warninglist match means: *this value has characteristics that may explain,
qualify or de-prioritise other evidence.* It does not mean the value is safe. A
cloud range hosts malicious infrastructure daily. A CDN serves malware. A popular
domain has a malicious path on it right now. A legitimate scanner still trips
alerts. An EICAR hash is a test artifact, which is a specific thing rather than
an ordinary benign file. And a warninglist can simply be stale — upstream has
carried infrastructure later found to be hosting attacks.

So this provider contributes context and stops. Deciding what a
``SUPPORTS_MALICIOUS`` ThreatFox record plus an Azure-range hit adds up to is
false-positive reasoning, it belongs to the future fusion layer, and an adapter
that pre-empted it would be overwriting a provider's fact with a guess.

One finding, not one per list
-----------------------------

``8.8.8.8`` matches ``public-dns-v4`` and ``vpn-ipv4``; ``example.com`` matches
``rfc6761`` and every popularity ranking in the profile. That is one contextual
observation with several supporting records, not two or seventeen independent
opinions — so it becomes a single ``misp_warninglist_matches`` evidence record
carrying bounded per-list detail, plus a coverage record. Emitting one Evidence
per list would let a single curated dataset outvote genuinely independent
intelligence purely by being thorough.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from pydantic import Field

from ti_recon.enums import EvidenceClass, EvidenceEffect, MatchScope
from ti_recon.models.base import FrozenTiReconModel, utc_now
from ti_recon.models.evidence import Evidence
from ti_recon.providers.misp_warninglists.candidates import (
    CandidateComponent,
    WarningListCandidate,
)
from ti_recon.providers.misp_warninglists.descriptor import (
    MISP_WARNINGLISTS_ORIGIN_PROVIDER,
    MISP_WARNINGLISTS_PROVIDER_ID,
    MISP_WARNINGLISTS_SOURCE_FAMILY,
    lineage_group_for_dataset,
)
from ti_recon.providers.misp_warninglists.loader import WarningListIndex
from ti_recon.providers.misp_warninglists.matchers import ListMatch
from ti_recon.providers.misp_warninglists.models import SnapshotManifest
from ti_recon.providers.misp_warninglists.snapshot import WarningListSnapshot

__all__ = [
    "COVERAGE_CLAIM_TYPE",
    "MATCHES_CLAIM_TYPE",
    "NO_MATCH_CLAIM_TYPE",
    "NormalizationContext",
    "normalize_coverage",
    "normalize_matches",
    "normalize_no_match",
]

MATCHES_CLAIM_TYPE = "misp_warninglist_matches"
NO_MATCH_CLAIM_TYPE = "misp_warninglist_no_match"
COVERAGE_CLAIM_TYPE = "misp_warninglist_coverage"


class NormalizationContext(FrozenTiReconModel):
    """What every record from one lookup shares."""

    investigation_id: str = Field(min_length=1, max_length=200)
    subject_object_id: str = Field(min_length=1, max_length=200)
    dataset_fingerprint: str = Field(min_length=1, max_length=64)

    @property
    def lineage_group_id(self) -> str:
        return lineage_group_for_dataset(self.dataset_fingerprint)


def _evidence(
    context: NormalizationContext,
    *,
    claim_type: str,
    attributes: dict[str, Any],
    match_scope: MatchScope,
) -> Evidence:
    """Build one context record.

    Every caller gets ``CONTEXT`` / ``CONTEXT_ONLY``: the class and the effect are
    not parameters, because there is no warninglist finding that should carry a
    direction. ``EvidenceClass.CONTEXT`` also makes the Task 3 model enforce it —
    a context claim cannot be given a direction even by a future edit here.

    No Admiralty grading and no ``provider_confidence``. How much a warninglist
    hit is worth is TI Recon policy, and an adapter asserting it would be
    smuggling in the judgement this provider exists not to make.
    """
    return Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=context.subject_object_id,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type=claim_type,
        effect=EvidenceEffect.CONTEXT_ONLY,
        transport_provider=MISP_WARNINGLISTS_PROVIDER_ID,
        origin_provider=MISP_WARNINGLISTS_ORIGIN_PROVIDER,
        source_family=MISP_WARNINGLISTS_SOURCE_FAMILY,
        match_scope=match_scope,
        lineage_group_id=context.lineage_group_id,
        attributes=attributes,
        observed_at=utc_now(),
    )


def _match_record(match: ListMatch, index: WarningListIndex) -> dict[str, Any]:
    """One list's detail, bounded.

    The matched entry is kept because it is what makes the finding checkable —
    "matched ``10.0.0.0/8``" is reviewable in a way "matched rfc1918" is not.
    One entry, never the list: a match record is evidence, not a copy of the
    dataset.

    There is no ``category`` field. MISP's runtime database exposes categories
    like ``false_positive`` and ``known``, but the raw upstream schema does not,
    so putting one here would mean inventing provenance for a value nothing in
    this provider depends on.
    """
    compiled = next((item for item in index.lists if item.slug == match.slug), None)
    record: dict[str, Any] = {
        "list": match.slug,
        "matcher": match.method,
        "matched_entry": match.entry,
        "candidate_attribute_type": match.candidate.misp_attribute_type,
        "candidate_component": match.candidate.component.value,
        "match_scope": match.candidate.match_scope.value,
    }
    if match.candidate.algorithm is not None:
        record["matched_by_hash"] = match.candidate.algorithm
    if compiled is not None:
        if compiled.name:
            record["list_name"] = compiled.name
        record["list_entry_count"] = compiled.entry_count
        record["matching_attributes"] = (
            "*" if compiled.attribute_types is None else sorted(compiled.attribute_types)
        )
    return record


def normalize_matches(
    context: NormalizationContext,
    matches: tuple[ListMatch, ...],
    index: WarningListIndex,
    *,
    max_records: int,
) -> Evidence:
    """One context record for every list that matched.

    ``match_scope`` is the narrowest scope among the matches, which is how the
    URL case stays honest. A URL whose *host* matched a popular-domain list gets
    ``SAME_HOST``: the context is about the host, and claiming
    ``EXACT_OBSERVABLE`` would say the artifact itself is common when only its
    hosting is. ``host_component_only`` states it outright, so nothing downstream
    has to infer it from a scope enum.
    """
    ordered = sorted(matches, key=lambda item: (item.candidate.is_component, item.slug))
    kept = ordered[:max_records]
    components = {item.candidate.component for item in ordered}
    scopes = {item.candidate.match_scope for item in ordered}
    attributes: dict[str, Any] = {
        "matches": [_match_record(item, index) for item in kept],
        "matched_lists": sorted({item.slug for item in ordered}),
        "total_matches": len(ordered),
        "normalized_matches": len(kept),
        "truncated": len(ordered) > len(kept),
        # True when *every* match came from a derived component rather than the
        # artifact. The living-off-trusted-sites case, named explicitly.
        "host_component_only": components == {CandidateComponent.URL_HOST},
        "matched_components": sorted(item.value for item in components),
    }
    return _evidence(
        context,
        claim_type=MATCHES_CLAIM_TYPE,
        attributes=attributes,
        match_scope=_narrowest(scopes),
    )


def normalize_no_match(context: NormalizationContext) -> Evidence:
    """Record that the configured lists were checked and none matched.

    Says one thing and nothing more: no selected list in this snapshot matched.
    Not benign, not clean, not trusted, not safe. Most values an analyst submits
    are in no warninglist at all — that is the normal case for a targeted attack
    and equally the normal case for an ordinary corporate host — so reading it as
    reassurance would invert its meaning.

    The attribute is named ``matched`` rather than anything resembling a verdict,
    and the coverage record beside it says exactly which lists that covers.
    """
    return _evidence(
        context,
        claim_type=NO_MATCH_CLAIM_TYPE,
        attributes={
            "matched": False,
            "means_benign": False,
        },
        match_scope=MatchScope.EXACT_OBSERVABLE,
    )


def normalize_coverage(
    context: NormalizationContext,
    *,
    snapshot: WarningListSnapshot,
    index: WarningListIndex,
    candidates: tuple[WarningListCandidate, ...],
    profile_id: str,
    profile_fingerprint: str,
    depth: str,
    total_matches: int,
    normalized_matches: int,
    stale_after: timedelta,
    partial_reason: str | None,
) -> Evidence:
    """What was actually checked, and what was not.

    The record that makes a clean result interpretable. Without it, "no
    warninglist matched" and "the dataset excluded the lists that would have
    matched" look identical.

    Reports both kinds of absence separately, because they are different
    situations: lists the **snapshot** never contained, which need a rebuild, and
    lists the **profile** excluded, which need a configuration change.
    """
    manifest: SnapshotManifest = snapshot.manifest
    attribute_types = frozenset(item.misp_attribute_type for item in candidates)
    applicable = index.applicable(attribute_types)
    unusable = index.unusable_for(attribute_types)
    unsupported = index.unsupported_applicable(attribute_types)
    age = snapshot.age()
    diagnostics = index.diagnostics

    attributes: dict[str, Any] = {
        "dataset_commit": manifest.upstream_commit,
        "dataset_fingerprint": manifest.dataset_fingerprint,
        "dataset_license": manifest.license,
        "snapshot_generated_at": manifest.generated_at.isoformat(),
        "snapshot_age_days": round(age.total_seconds() / 86400.0, 2),
        "snapshot_stale": age > stale_after,
        "snapshot_stale_after_days": round(stale_after.total_seconds() / 86400.0, 2),
        "profile_id": profile_id,
        "profile_fingerprint": profile_fingerprint,
        "depth": depth,
        # Everything that bounds what "no match" covers.
        "snapshot_lists": manifest.list_count,
        "snapshot_entries": manifest.entry_count,
        "loaded_lists": len(index.lists),
        "loaded_entries": index.entry_count,
        "profile_excluded_lists": len(index.profile_excluded),
        "snapshot_omitted_lists": len(index.snapshot_omitted),
        "applicable_lists": len(applicable),
        "applicable_entries": sum(item.entry_count for item in applicable),
        "checked_lists": len(applicable) - len(unsupported),
        "candidate_attribute_types": sorted(attribute_types),
        "matcher_types_available": sorted({item.matcher for item in applicable}),
        "unsupported_applicable_lists": len(unsupported),
        "unusable_applicable_lists": len(unusable),
        "invalid_entry_count": diagnostics.invalid_entry_count,
        "invalid_cidr_count": diagnostics.invalid_cidr_count,
        "invalid_regex_count": diagnostics.invalid_regex_count,
        "unmatchable_entry_count": diagnostics.unmatchable_entry_count,
        "malformed_list_count": diagnostics.malformed_list_count,
        "total_matches": total_matches,
        "normalized_matches": normalized_matches,
        "truncated": total_matches > normalized_matches,
        # Never implied, always stated. The profile and the snapshot both leave
        # lists out by design, so this is false whenever either did.
        "all_lists_checked": (
            not index.profile_excluded
            and not index.snapshot_omitted
            and not unsupported
            and not unusable
        ),
    }
    if partial_reason is not None:
        attributes["partial_reason"] = partial_reason
    if index.profile_excluded:
        attributes["profile_excluded_sample"] = sorted(
            item.slug for item in index.profile_excluded
        )[:20]
    if unsupported:
        attributes["unsupported_applicable_sample"] = sorted(item.slug for item in unsupported)[:20]
    return _evidence(
        context,
        claim_type=COVERAGE_CLAIM_TYPE,
        attributes=attributes,
        match_scope=MatchScope.EXACT_OBSERVABLE,
    )


def _narrowest(scopes: set[MatchScope]) -> MatchScope:
    """The least specific scope present.

    Deliberately pessimistic. If any part of this finding is only about the
    host, the finding as a whole is reported at host scope: overstating precision
    is the failure that turns a hosting fact into a statement about an artifact.
    """
    if not scopes:
        return MatchScope.EXACT_OBSERVABLE
    if MatchScope.SAME_HOST in scopes:
        return MatchScope.SAME_HOST
    return MatchScope.EXACT_OBSERVABLE
