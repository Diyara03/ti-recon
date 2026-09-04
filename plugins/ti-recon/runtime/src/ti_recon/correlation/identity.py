"""Exact observable identity (Task 14).

Answers one question: are these two records the same object?

Only ever *exactly*. Two addresses in one /24, two samples with the same imphash,
two domains on one certificate, two files a fuzzy hash calls similar — none of
those is identity, and merging on any of them makes every downstream statement
about "this object" untrue in a way nothing later can detect. Similarity
clustering is worth having and belongs in its own layer, on top of exact
relationships that can be trusted.

Node keys come from the Task 3 canonical key, so identity here is the identity
the rest of the system already uses: canonical IP text, canonical IDNA domain,
the conservative canonical URL, and for a file its strongest available digest.

Files need care
---------------

A file is the one observable whose identity arrives in pieces. One provider
answers with a SHA-256, another with an MD5, a third binds all three. The Task 3
key names a file by its *strongest available* hash, so the same sample legitimately
produces ``file:sha256:AAA`` from one provider and ``file:md5:BBB`` from another,
and something has to decide whether those are one sample.

:class:`FileIdentityResolver` decides conservatively:

* a shared SHA-256 is the same sample;
* a shared SHA-1, with nothing stronger disagreeing, is the same sample;
* a shared MD5, with nothing stronger disagreeing, is the same sample — recorded
  as a *legacy* basis, because an attacker can manufacture an MD5 collision on a
  laptop and the whole point of recording the basis is that these are not equally
  strong;
* a stronger hash that disagrees **stops the merge**, whatever the weaker hashes
  say, and produces a correlation issue.

The last rule is the one that matters. Two files sharing an MD5 and differing in
SHA-256 are the textbook collision, and a correlation engine that merged them
would fuse two samples into one node and attribute each one's behaviour to the
other.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ti_recon.correlation.models import CorrelationIssue, CorrelationIssueType, IdentityBasis
from ti_recon.enums import IntelObjectType
from ti_recon.models.intel_object import (
    HASH_ALGORITHM_SLUGS,
    HASH_PREFERENCE_ORDER,
    IntelObject,
    canonical_key_for,
)

__all__ = [
    "HASH_IDENTITY_BASIS",
    "FileIdentityResolution",
    "FileIdentityResolver",
    "file_hashes",
    "node_key_for",
]

#: Which identity basis a shared digest establishes. Strongest first, and
#: deliberately not collapsed into one "hash matched".
HASH_IDENTITY_BASIS: dict[str, IdentityBasis] = {
    "SHA-256": IdentityBasis.SHA256,
    "SHA-1": IdentityBasis.SHA1,
    "MD5": IdentityBasis.LEGACY_MD5,
}


def node_key_for(intel_object: IntelObject) -> str:
    """The correlation key for an object.

    The Task 3 canonical key, unchanged: identity is derived from what the object
    *is*, never from who reported it, which investigation it belongs to, how it was
    displayed, or what anybody labelled it. Those describe an observation.
    """
    return intel_object.canonical_key


def file_hashes(intel_object: IntelObject) -> dict[str, str]:
    """The digests a file object carries, normalized to lowercase hex."""
    raw = intel_object.properties.get("hashes")
    if not isinstance(raw, dict):
        return {}
    found: dict[str, str] = {}
    for algorithm, digest in raw.items():
        if algorithm in HASH_ALGORITHM_SLUGS and isinstance(digest, str) and digest:
            found[algorithm] = digest.lower()
    return found


@dataclass(frozen=True, slots=True)
class FileIdentityResolution:
    """What the resolver decided about one file object."""

    #: The key this object belongs under, which may be an existing node's key.
    node_key: str
    basis: IdentityBasis = IdentityBasis.CANONICAL_VALUE
    #: ``True`` when this merged into a node that already existed.
    merged: bool = False
    #: Set when a stronger hash disagreed and the merge was refused.
    issue: CorrelationIssue | None = None


@dataclass
class FileIdentityResolver:
    """Tracks which digests belong to which file node.

    One instance per investigation graph. It holds only digests and node keys —
    no provider payloads, no evidence, nothing user-identifying beyond the
    observables the investigation is already about.
    """

    #: ``(algorithm, digest) -> node key``.
    _by_digest: dict[tuple[str, str], str] = field(default_factory=dict)
    #: ``node key -> {algorithm: digest}``.
    _hashes: dict[str, dict[str, str]] = field(default_factory=dict)

    def resolve(self, intel_object: IntelObject) -> FileIdentityResolution:
        """Decide which node this file belongs to, and why."""
        if intel_object.object_type is not IntelObjectType.FILE:
            return FileIdentityResolution(node_key=node_key_for(intel_object))

        incoming = file_hashes(intel_object)
        own_key = node_key_for(intel_object)
        candidate = self._candidate_for(incoming)

        if candidate is None:
            self._register(own_key, incoming)
            return FileIdentityResolution(
                node_key=own_key, basis=self._basis_for(incoming, matched=None)
            )

        matched_algorithm, existing_key = candidate
        conflict = self._conflicting_algorithm(existing_key, incoming)
        if conflict is not None:
            # A stronger digest disagrees. Whatever the weaker one says, these are
            # not the same file, and saying so is the whole job.
            self._register(own_key, incoming)
            return FileIdentityResolution(
                node_key=own_key,
                basis=self._basis_for(incoming, matched=None),
                issue=CorrelationIssue(
                    issue_type=CorrelationIssueType.FILE_HASH_CONFLICT,
                    detail=(
                        f"{matched_algorithm} matches but {conflict} differs; "
                        "kept as separate samples"
                    ),
                    node_keys=(existing_key, own_key),
                ),
            )

        self._register(existing_key, incoming)
        return FileIdentityResolution(
            node_key=existing_key,
            basis=self._basis_for(incoming, matched=matched_algorithm),
            merged=True,
        )

    def aliases_for(self, node_key: str) -> tuple[str, ...]:
        """Every confirmed digest for a node, strongest first.

        Accumulated across providers: one answering with SHA-256 and MD5 and
        another with the same SHA-256 and a SHA-1 leaves the node knowing all
        three. Nothing conflicting was ever written, because a conflict refuses the
        merge rather than overwriting a value.
        """
        held = self._hashes.get(node_key, {})
        return tuple(
            f"{HASH_ALGORITHM_SLUGS[algorithm]}:{held[algorithm]}"
            for algorithm in HASH_PREFERENCE_ORDER
            if algorithm in held
        )

    def _candidate_for(self, incoming: dict[str, str]) -> tuple[str, str] | None:
        """The strongest existing match for these digests."""
        for algorithm in HASH_PREFERENCE_ORDER:
            digest = incoming.get(algorithm)
            if digest is None:
                continue
            existing = self._by_digest.get((algorithm, digest))
            if existing is not None:
                return algorithm, existing
        return None

    def _conflicting_algorithm(self, node_key: str, incoming: dict[str, str]) -> str | None:
        """The strongest algorithm on which the candidate and incoming disagree."""
        held = self._hashes.get(node_key, {})
        for algorithm in HASH_PREFERENCE_ORDER:
            mine, theirs = held.get(algorithm), incoming.get(algorithm)
            if mine is not None and theirs is not None and mine != theirs:
                return algorithm
        return None

    def _basis_for(self, incoming: dict[str, str], *, matched: str | None) -> IdentityBasis:
        """Why this object has the identity it has.

        A record binding several digests to one sample is its own basis: the
        provider stated the binding, which is different from TI Recon having
        matched on one digest.
        """
        if matched is not None:
            return HASH_IDENTITY_BASIS[matched]
        if len(incoming) > 1:
            return IdentityBasis.PROVIDER_MULTI_HASH_BINDING
        strongest = next(
            (item for item in HASH_PREFERENCE_ORDER if item in incoming),
            None,
        )
        return HASH_IDENTITY_BASIS[strongest] if strongest else IdentityBasis.CANONICAL_VALUE

    def _register(self, node_key: str, incoming: dict[str, str]) -> None:
        """Record these digests against a node, never overwriting a held value."""
        held = self._hashes.setdefault(node_key, {})
        for algorithm, digest in incoming.items():
            if algorithm not in held:
                held[algorithm] = digest
                self._by_digest[(algorithm, digest)] = node_key


def canonical_key_for_value(object_type: IntelObjectType, canonical_value: str) -> str:
    """A node key for an object type and canonical value, for lookups."""
    return canonical_key_for(object_type, canonical_value)
