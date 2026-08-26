"""Which warninglists a lookup actually checks (Task 11).

A profile is the answer to "what does this result cover?", and it exists because
the honest answer is never "all of them".

The measured reason
-------------------

The pinned upstream snapshot holds 143 lists and 5,214,898 entries. Twenty of
those lists hold 4,910,632 of the entries — million-row popularity rankings and
a bulk Windows binary-hash set — and the popularity ones are nested subsets of
each other: ``example.com`` appears in thirteen Cloudflare tiers plus Tranco,
CrUX, Majestic and Moz. Loading all of them costs about 510 MB of retained heap
to learn one fact sixteen times.

Bounding the snapshot to lists of at most 100,000 entries, and dropping the
redundant popularity tiers while keeping one, gives 123 lists and 304,266
entries for about 34 MB — the same *kinds* of context at 6% of the data. So that
is the default, and the numbers rather than the intuition are what chose it.

Exclusion is never silent
-------------------------

Two different kinds of absence, kept apart because they mean different things:

* a list the **snapshot** never contained, recorded in its manifest, which cannot
  be re-enabled without rebuilding;
* a list the **profile** excluded, which can.

Both travel into coverage. Nothing here may produce a result that reads as "all
MISP warninglists checked".
"""

from __future__ import annotations

import hashlib
from typing import Final

from pydantic import Field, model_validator

from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.misp_warninglists.models import (
    ListOmissionReason,
    SnapshotManifest,
)

__all__ = [
    "CORE_PROFILE_ID",
    "DEFAULT_MAX_LIST_ENTRIES",
    "FULL_PROFILE_ID",
    "REDUNDANT_POPULARITY_TIERS",
    "RETAINED_POPULARITY_TIERS",
    "ProfileSelection",
    "WarningListProfile",
    "core_profile",
    "full_profile",
]

CORE_PROFILE_ID: Final[str] = "core"
FULL_PROFILE_ID: Final[str] = "full"

#: Entry ceiling for the default profile, from the measured distribution: the
#: eight lists above it hold 94% of all entries between them.
DEFAULT_MAX_LIST_ENTRIES: Final[int] = 100_000

#: Popularity rankings that are nested subsets of, or near-duplicates of, a tier
#: this profile keeps. Excluded by name rather than by size because the problem
#: is duplication, not scale: thirteen Cloudflare tiers answer "is this domain
#: popular?" thirteen times.
REDUNDANT_POPULARITY_TIERS: Final[frozenset[str]] = frozenset(
    {
        "cloudflare-top50k",
        "cloudflare-top20k",
        "cloudflare-top5k",
        "cloudflare-top2k",
        "cloudflare-top1k",
        "cloudflare-top200",
        "cisco_top20k",
        "cisco_top5k",
        "tranco10k",
        "majestic_million",
        "alexa",
        "moz-top500",
    }
)

#: The popularity tiers the default profile keeps: two independently produced
#: rankings at ten thousand entries each. Enough to say "this is a commonly
#: visited domain" from more than one source, cheap enough not to notice.
RETAINED_POPULARITY_TIERS: Final[frozenset[str]] = frozenset({"cloudflare-top10k", "cisco_top10k"})

#: Reasons a profile leaves a list out. Short, stable strings: they end up in
#: coverage, so they are vocabulary rather than prose.
_REASON_OVERSIZED: Final[str] = "oversized"
_REASON_REDUNDANT: Final[str] = "redundant_popularity_tier"
_REASON_NOT_INCLUDED: Final[str] = "not_in_include_list"
_REASON_EXCLUDED: Final[str] = "explicitly_excluded"


class WarningListProfile(FrozenTiReconModel):
    """Which lists in a snapshot a lookup is allowed to consult.

    ``include`` is an allow-list when non-empty: nothing outside it is loaded,
    whatever the other settings say. ``exclude`` always wins over ``include``, so
    a configuration cannot accidentally re-enable something it also forbade.
    """

    profile_id: str = Field(default=CORE_PROFILE_ID, min_length=1, max_length=64)

    #: Empty means "every list in the snapshot, subject to the rules below".
    include: frozenset[str] = frozenset()
    exclude: frozenset[str] = frozenset()

    #: ``None`` means no ceiling.
    max_list_entries: int | None = Field(default=DEFAULT_MAX_LIST_ENTRIES, ge=1)
    #: Named tiers to drop for duplication rather than size.
    drop_redundant_tiers: frozenset[str] = frozenset()

    @model_validator(mode="after")
    def _validate_profile(self) -> WarningListProfile:
        overlap = self.include & self.exclude
        if overlap:
            msg = f"lists cannot be both included and excluded: {sorted(overlap)}"
            raise ValueError(msg)
        return self

    def select(self, manifest: SnapshotManifest) -> ProfileSelection:
        """Split a snapshot's lists into what this profile checks and what it drops.

        Deterministic and ordered, because the result feeds a fingerprint: two
        runs of the same profile over the same snapshot must produce byte-identical
        selections or a cache key built from them would be meaningless.
        """
        selected: list[str] = []
        excluded: list[ListOmissionReason] = []
        for record in sorted(manifest.lists, key=lambda item: item.slug):
            reason = self._reason_to_exclude(record.slug, record.entry_count)
            if reason is None:
                selected.append(record.slug)
            else:
                excluded.append(
                    ListOmissionReason(
                        slug=record.slug, reason=reason, entry_count=record.entry_count
                    )
                )
        unknown = sorted(
            slug for slug in (self.include | self.exclude) if slug not in set(manifest.slugs)
        )
        return ProfileSelection(
            profile=self,
            selected=tuple(selected),
            excluded=tuple(excluded),
            unknown_slugs=tuple(unknown),
            snapshot_fingerprint=manifest.dataset_fingerprint,
        )

    def _reason_to_exclude(self, slug: str, entry_count: int) -> str | None:
        if slug in self.exclude:
            return _REASON_EXCLUDED
        if self.include and slug not in self.include:
            return _REASON_NOT_INCLUDED
        if slug in self.drop_redundant_tiers:
            return _REASON_REDUNDANT
        if self.max_list_entries is not None and entry_count > self.max_list_entries:
            return _REASON_OVERSIZED
        return None

    def fingerprint(self) -> str:
        """A stable digest of every setting that changes what gets checked.

        Included in the cache discriminator. Two profiles that select different
        lists must not be able to share a cached answer, and the only way to
        guarantee that without enumerating a snapshot is to hash the settings.
        """
        parts = (
            f"profile={self.profile_id}",
            f"include={','.join(sorted(self.include))}",
            f"exclude={','.join(sorted(self.exclude))}",
            f"max_entries={self.max_list_entries if self.max_list_entries is not None else '-'}",
            f"drop_tiers={','.join(sorted(self.drop_redundant_tiers))}",
        )
        return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


class ProfileSelection(FrozenTiReconModel):
    """The outcome of applying a profile to one snapshot."""

    profile: WarningListProfile
    selected: tuple[str, ...]
    excluded: tuple[ListOmissionReason, ...]
    #: Slugs named by the profile that the snapshot does not contain. A
    #: configuration error worth reporting rather than a silent no-op: an
    #: operator who misspells an include gets an empty profile otherwise.
    unknown_slugs: tuple[str, ...] = ()
    snapshot_fingerprint: str = ""

    @property
    def selected_count(self) -> int:
        return len(self.selected)

    @property
    def excluded_count(self) -> int:
        return len(self.excluded)

    def identity(self) -> str:
        """The cache discriminator: this profile, over this exact dataset.

        Both halves are load-bearing. The snapshot fingerprint alone would serve
        one profile's answers to another; the profile fingerprint alone would
        serve yesterday's data after a refresh.
        """
        return f"{self.profile.fingerprint()[:32]}:{self.snapshot_fingerprint[:32]}"


def core_profile() -> WarningListProfile:
    """The default: every list except the oversized and the duplicated.

    123 of 143 lists and 304,266 of 5,214,898 entries on the pinned snapshot.
    """
    return WarningListProfile(
        profile_id=CORE_PROFILE_ID,
        max_list_entries=DEFAULT_MAX_LIST_ENTRIES,
        drop_redundant_tiers=REDUNDANT_POPULARITY_TIERS - RETAINED_POPULARITY_TIERS,
    )


def full_profile() -> WarningListProfile:
    """Everything the snapshot contains, with no ceiling.

    Available, not recommended, and only as complete as the snapshot it reads:
    the shipped snapshot is itself bounded at build time, and its manifest says
    what it omitted. Against an unbounded snapshot this profile costs roughly
    510 MB of retained heap.
    """
    return WarningListProfile(profile_id=FULL_PROFILE_ID, max_list_entries=None)
