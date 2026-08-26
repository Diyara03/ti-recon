"""Building a queryable index from a snapshot and a profile (Task 11).

Loading happens once, at adapter construction. A lookup then runs against an
immutable in-memory index: no file is opened, no path is resolved and nothing is
parsed while an investigation is in flight.

What a load costs, measured
---------------------------

Against the pinned snapshot and the default ``core`` profile: 123 lists,
304,266 entries, about 34 MB of retained heap, ~1.7 s cold. Selecting an
unbounded profile over an unbounded snapshot instead costs about 510 MB — which
is why the profile layer exists and why its default is what it is.

The saving is not only memory. A profile decides from the *manifest*, so an
excluded list is never read off disk or parsed at all; the transient cost of
discarding a million-entry JSON document is avoided rather than paid and freed.

Applicability, and what "partial" honestly means
-----------------------------------------------

The index records which lists could not be evaluated, and per matcher which
attribute types they would have applied to. That is what lets partiality be
*candidate-aware*: a malformed phone-number regex list is irrelevant to an IPv4
lookup and must not degrade it, while an unusable CIDR list is exactly what an
IPv4 lookup needs to know about. Coverage is computed per lookup from the
candidates in hand, not once at load time.
"""

from __future__ import annotations

from pydantic import ConfigDict, Field

from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.misp_warninglists.candidates import WarningListCandidate
from ti_recon.providers.misp_warninglists.matchers import (
    MATCHER_SUPPORT,
    CompiledList,
    ListMatch,
    compile_list,
)
from ti_recon.providers.misp_warninglists.models import (
    ListOmissionReason,
    LoadDiagnostics,
    SnapshotListRecord,
)
from ti_recon.providers.misp_warninglists.profile import ProfileSelection
from ti_recon.providers.misp_warninglists.snapshot import (
    SnapshotError,
    WarningListSnapshot,
)

__all__ = ["UnusableList", "WarningListIndex", "build_index"]


class UnusableList(FrozenTiReconModel):
    """A list that was selected but cannot be evaluated.

    Carries the attribute types it *would* have covered, which is the whole
    point: without them, "one list failed to load" cannot be turned into an
    honest statement about any particular lookup.
    """

    slug: str = Field(min_length=1, max_length=200)
    matcher: str = Field(min_length=1, max_length=32)
    reason: str = Field(min_length=1, max_length=64)
    #: ``None`` means it declared no ``matching_attributes``, so it would have
    #: applied to every candidate — the worst case for coverage.
    attribute_types: frozenset[str] | None = None
    entry_count: int = Field(default=0, ge=0)

    def affects(self, attribute_types: frozenset[str]) -> bool:
        """Whether losing this list matters to a lookup over ``attribute_types``."""
        if self.attribute_types is None:
            return True
        return bool(self.attribute_types & attribute_types)


class WarningListIndex(FrozenTiReconModel):
    """An immutable, queryable set of compiled warninglists."""

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    lists: tuple[CompiledList, ...] = ()
    unusable: tuple[UnusableList, ...] = ()
    profile_excluded: tuple[ListOmissionReason, ...] = ()
    snapshot_omitted: tuple[ListOmissionReason, ...] = ()
    diagnostics: LoadDiagnostics = LoadDiagnostics()
    profile_identity: str = ""
    entry_count: int = Field(default=0, ge=0)

    def applicable(self, attribute_types: frozenset[str]) -> tuple[CompiledList, ...]:
        """The lists that may judge candidates of these attribute types.

        This is the ``matching_attributes`` gate, applied before a single value
        is compared. It is not an optimization — it is the semantics: a list that
        does not declare a candidate's attribute type has no opinion about it.
        """
        return tuple(
            item
            for item in self.lists
            if item.attribute_types is None or item.attribute_types & attribute_types
        )

    def unusable_for(self, attribute_types: frozenset[str]) -> tuple[UnusableList, ...]:
        """Lists that failed to load *and* would have applied to this lookup."""
        return tuple(item for item in self.unusable if item.affects(attribute_types))

    def unsupported_applicable(self, attribute_types: frozenset[str]) -> tuple[CompiledList, ...]:
        """Loaded lists whose matcher this build will not run for this lookup.

        Today this is only ``regex``, and against the pinned snapshot it is
        always empty because both regex lists target email and phone attributes.
        A future snapshot that adds a regex list about domains would land here
        and make a domain lookup ``PARTIAL`` — visibly, rather than by quietly
        skipping it.
        """
        return tuple(
            item
            for item in self.applicable(attribute_types)
            if not MATCHER_SUPPORT.get(item.matcher, False)
        )

    def match(self, candidates: tuple[WarningListCandidate, ...]) -> tuple[ListMatch, ...]:
        """Every list that matches, at most once per list.

        Deduplication is the reason this loop is written by list rather than by
        candidate. A domain is offered as both ``domain`` and ``hostname``; a
        file offers three digests. One list matching through two of them is one
        contextual fact about one artifact, and emitting it twice would let a
        single dataset look like corroboration.

        The first matching candidate wins, and candidates arrive in a
        deterministic order, so the retained match is stable across runs. Where
        an observable-level candidate and a derived component both match, the
        observable-level one is preferred: it is the more precise claim.
        """
        attribute_types = frozenset(item.misp_attribute_type for item in candidates)
        ordered = sorted(candidates, key=lambda item: (item.is_component, item.misp_attribute_type))
        matches: list[ListMatch] = []
        for compiled in self.applicable(attribute_types):
            for candidate in ordered:
                if not compiled.applies_to(candidate.misp_attribute_type):
                    continue
                found = compiled.match(candidate)
                if found is not None:
                    matches.append(found)
                    break
        return tuple(matches)

    def __repr__(self) -> str:
        return (
            f"<WarningListIndex lists={len(self.lists)} entries={self.entry_count} "
            f"unusable={len(self.unusable)}>"
        )


def build_index(snapshot: WarningListSnapshot, selection: ProfileSelection) -> WarningListIndex:
    """Compile every list the profile selected.

    One list failing never fails the load. An unreadable or checksum-mismatched
    file, an entry set that compiles to nothing — each becomes an
    :class:`UnusableList` with the attribute types it would have covered, and the
    rest of the dataset loads. The alternative, refusing the whole index because
    one of 123 lists is broken, would turn a small upstream defect into total
    loss of a capability.
    """
    manifest = snapshot.manifest
    selected = set(selection.selected)
    compiled: list[CompiledList] = []
    unusable: list[UnusableList] = []
    diagnostics = manifest.diagnostics
    entries = 0

    for record in manifest.lists:
        if record.slug not in selected:
            continue
        result, note = _compile_record(snapshot, record)
        diagnostics = diagnostics.merge(note)
        if result is None:
            unusable.append(
                UnusableList(
                    slug=record.slug,
                    matcher=record.matcher,
                    reason="unusable",
                    attribute_types=(
                        None
                        if record.matching_attributes is None
                        else frozenset(record.matching_attributes)
                    ),
                    entry_count=record.entry_count,
                )
            )
            continue
        compiled.append(result)
        entries += result.entry_count

    return WarningListIndex(
        lists=tuple(compiled),
        unusable=tuple(unusable),
        profile_excluded=selection.excluded,
        snapshot_omitted=manifest.omitted,
        diagnostics=diagnostics,
        profile_identity=selection.identity(),
        entry_count=entries,
    )


def _compile_record(
    snapshot: WarningListSnapshot, record: SnapshotListRecord
) -> tuple[CompiledList | None, LoadDiagnostics]:
    """Read and compile one list, converting any failure into a diagnostic."""
    try:
        raw = snapshot.read_list(record)
    except SnapshotError:
        return None, LoadDiagnostics(malformed_list_count=1, notes=(f"{record.slug}: unreadable",))
    except ValueError:
        # Schema validation failed: the file is JSON but not a warninglist.
        return None, LoadDiagnostics(
            malformed_list_count=1, notes=(f"{record.slug}: schema invalid",)
        )
    return compile_list(record.slug, raw)
