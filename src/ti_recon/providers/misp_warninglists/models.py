"""The MISP warninglist data model (Task 11).

Two layers, deliberately separate.

:class:`RawWarningList` is the **upstream** schema, modelled faithfully and
nothing more. The official ``schema.json`` sets ``additionalProperties: false``
over exactly six fields, so this model does the same: anything else in a list
file is a shape change worth refusing rather than guessing at.

Everything else here is TI Recon's own: what a snapshot records about where its
data came from, and what a load produced. Those are ours to design, and they are
kept apart from the upstream model so a future upstream schema change touches one
class rather than the whole package.

What is *not* modelled
----------------------

**There is no category field.** MISP's own runtime database and its Feedback
service expose categories such as ``false_positive`` and ``known``, and it is
tempting to infer one from a list's name or description. The raw upstream schema
has no such field, so inferring one would be inventing provenance — and it would
buy nothing here, because every warninglist hit is ``CONTEXT_ONLY`` regardless
(see :mod:`ti_recon.providers.misp_warninglists.normalizer`). A category appears
in this model only if a snapshot source ever supplies one authoritatively.
"""

from __future__ import annotations

from typing import Final

from pydantic import ConfigDict, Field, field_validator

from ti_recon.models.base import FrozenTiReconModel, UtcDatetime

__all__ = [
    "ALL_ATTRIBUTES",
    "MAX_ENTRY_LENGTH",
    "MAX_LIST_ENTRIES",
    "RAW_MATCHER_TYPES",
    "ListOmissionReason",
    "LoadDiagnostics",
    "RawWarningList",
    "SnapshotListRecord",
    "SnapshotManifest",
    "WarningListMatcher",
]

#: The five matcher types the official schema permits. Anything else is a schema
#: change, not a value to guess at.
RAW_MATCHER_TYPES: Final[frozenset[str]] = frozenset(
    {"string", "substring", "hostname", "cidr", "regex"}
)

#: What an absent ``matching_attributes`` means: the list applies to every MISP
#: attribute type. Represented explicitly rather than as ``None`` scattered
#: through the matching code, because "applies to everything" is a decision and
#: deserves a name.
ALL_ATTRIBUTES: Final[str] = "*"

#: Bounds on what a single list may contain. The pinned upstream snapshot's
#: longest entry is 191 characters and its largest list is a million entries;
#: these caps are far above both, and exist so a corrupted or hostile file cannot
#: exhaust memory during a load.
MAX_ENTRY_LENGTH: Final[int] = 2048
MAX_LIST_ENTRIES: Final[int] = 2_000_000


class WarningListMatcher(FrozenTiReconModel):
    """One matcher type, and whether this build can evaluate it.

    ``supported`` is not a statement about the matcher being implemented in the
    abstract — it is whether *this* package will run it against a candidate. The
    distinction matters for ``regex``: the pinned snapshot's regex lists target
    email and phone attributes, so they are recognized, recorded, and never
    executed. See :mod:`ti_recon.providers.misp_warninglists.matchers`.
    """

    matcher: str = Field(min_length=1, max_length=32)
    supported: bool


class RawWarningList(FrozenTiReconModel):
    """One upstream ``list.json``, exactly as the official schema defines it.

    Six fields, five of them required. ``matching_attributes`` is the optional
    one, and its absence means the list applies to every attribute type — which
    is why it is modelled as ``None`` here and resolved explicitly at load time
    rather than defaulted to an empty tuple that would read as "applies to
    nothing".

    Extra keys are refused. The official schema sets
    ``additionalProperties: false``, so a file carrying anything else is not a
    richer list, it is a file this code has not been written for.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=200)
    version: int = Field(ge=0)
    description: str = Field(min_length=1, max_length=4000)
    type: str = Field(min_length=1, max_length=32)
    list: tuple[str, ...]
    matching_attributes: tuple[str, ...] | None = None

    @field_validator("type")
    @classmethod
    def _validate_matcher(cls, value: str) -> str:
        if value not in RAW_MATCHER_TYPES:
            msg = f"unknown warninglist matcher type: {value!r}"
            raise ValueError(msg)
        return value

    @field_validator("list")
    @classmethod
    def _validate_entries(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_LIST_ENTRIES:
            msg = "warninglist has more entries than this loader will accept"
            raise ValueError(msg)
        return value

    @property
    def applies_to_all_attributes(self) -> bool:
        """Whether an absent ``matching_attributes`` makes this list universal."""
        return self.matching_attributes is None

    def applies_to(self, attribute_types: frozenset[str]) -> bool:
        """Whether this list may be evaluated for any of ``attribute_types``.

        The authoritative gate. A warninglist declares which MISP attribute
        types it is about, and evaluating it against anything else is not a
        near-miss — it is a different question. A hostname list checked against
        an MD5 would be nonsense even if the strings happened to collide.
        """
        if self.matching_attributes is None:
            return True
        return bool(set(self.matching_attributes) & attribute_types)


class ListOmissionReason(FrozenTiReconModel):
    """Why one upstream list is absent from a snapshot, or from a profile.

    Kept as data with a reason per list so coverage can say what was *not*
    checked. A result must never be able to imply "all MISP warninglists
    checked" when something was left out, and the only way to guarantee that is
    to carry the omissions alongside the answer.
    """

    slug: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=64)
    entry_count: int = Field(ge=0)
    detail: str | None = Field(default=None, max_length=200)


class SnapshotListRecord(FrozenTiReconModel):
    """What a snapshot manifest records about one list it contains.

    Enough to make profile selection a *manifest* decision rather than a parsing
    decision: the entry count and matcher type are here, so a list a profile
    excludes is never read off disk at all. On the pinned snapshot that turns the
    transient cost of a load from hundreds of megabytes of discarded JSON into
    nothing.
    """

    slug: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=200)
    version: int = Field(ge=0)
    matcher: str = Field(min_length=1, max_length=32)
    entry_count: int = Field(ge=0)
    matching_attributes: tuple[str, ...] | None = None
    #: SHA-256 of the stored list file, so a snapshot can be verified without
    #: trusting the filesystem it arrived on.
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class LoadDiagnostics(FrozenTiReconModel):
    """What went wrong, or was left out, while building an index.

    Counts and short reasons only. Upstream data is imperfect — invalid CIDRs,
    string lists holding leading-dot domain fragments, regex written for a
    different engine — and the honest response is to record the loss rather than
    repair the data or hide the repair. Deliberately no raw entries: a diagnostic
    that dumps list contents is a log that leaks a dataset.
    """

    malformed_list_count: int = Field(default=0, ge=0)
    skipped_list_count: int = Field(default=0, ge=0)
    invalid_entry_count: int = Field(default=0, ge=0)
    invalid_cidr_count: int = Field(default=0, ge=0)
    invalid_regex_count: int = Field(default=0, ge=0)
    unsupported_matcher_count: int = Field(default=0, ge=0)
    #: Entries that loaded cleanly but can never match any canonical TI Recon
    #: value — an exact-match list holding ``.example.com``, for instance. Not a
    #: defect to fix here: upstream means them for a matcher we were not asked
    #: to use on them, and silently rewriting them would invent matches.
    unmatchable_entry_count: int = Field(default=0, ge=0)
    notes: tuple[str, ...] = ()

    @property
    def is_clean(self) -> bool:
        return not (
            self.malformed_list_count
            or self.skipped_list_count
            or self.invalid_entry_count
            or self.invalid_cidr_count
            or self.invalid_regex_count
        )

    def merge(self, other: LoadDiagnostics) -> LoadDiagnostics:
        return LoadDiagnostics(
            malformed_list_count=self.malformed_list_count + other.malformed_list_count,
            skipped_list_count=self.skipped_list_count + other.skipped_list_count,
            invalid_entry_count=self.invalid_entry_count + other.invalid_entry_count,
            invalid_cidr_count=self.invalid_cidr_count + other.invalid_cidr_count,
            invalid_regex_count=self.invalid_regex_count + other.invalid_regex_count,
            unsupported_matcher_count=(
                self.unsupported_matcher_count + other.unsupported_matcher_count
            ),
            unmatchable_entry_count=(self.unmatchable_entry_count + other.unmatchable_entry_count),
            notes=self.notes + other.notes,
        )


class SnapshotManifest(FrozenTiReconModel):
    """Where a snapshot came from, what is in it, and what it left behind.

    Provenance is the point. A local dataset with no record of its origin is a
    pile of JSON somebody has to trust; this records the upstream repository, the
    exact commit, when it was built and by what, so a result can name the data it
    was derived from.

    ``dataset_fingerprint`` is computed over the stored lists rather than over
    the source tree, so it changes if and only if the data this package will
    actually read changes. It is what makes a cached answer from an old snapshot
    impossible to serve after a refresh.
    """

    #: Format version of this manifest, so a future layout change is detectable
    #: rather than a parse error.
    snapshot_format: int = Field(default=1, ge=1)

    upstream_repository: str = Field(min_length=1, max_length=200)
    upstream_commit: str = Field(pattern=r"^[0-9a-f]{7,40}$")
    upstream_committed_at: UtcDatetime | None = None

    generated_at: UtcDatetime
    generator: str = Field(min_length=1, max_length=120)

    #: SHA-256 of the upstream ``schema.json`` this build validated against. A
    #: changed schema means the raw model may no longer be faithful.
    schema_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    dataset_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")

    list_count: int = Field(ge=0)
    entry_count: int = Field(ge=0)

    lists: tuple[SnapshotListRecord, ...] = ()
    #: Upstream lists this snapshot does not contain at all, with why. Distinct
    #: from a profile exclusion: this one cannot be turned back on without
    #: rebuilding.
    omitted: tuple[ListOmissionReason, ...] = ()
    diagnostics: LoadDiagnostics = LoadDiagnostics()
    #: License of the upstream dataset. CC0-1.0 for misp-warninglists as a whole;
    #: individual lists may carry their own terms, which is recorded rather than
    #: flattened away.
    license: str = Field(default="CC0-1.0", max_length=120)

    def record(self, slug: str) -> SnapshotListRecord | None:
        return next((item for item in self.lists if item.slug == slug), None)

    @property
    def slugs(self) -> tuple[str, ...]:
        return tuple(item.slug for item in self.lists)
