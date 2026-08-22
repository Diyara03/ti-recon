"""Bounded, user-isolated artifact storage (Task 8).

In-memory and single-process, like every other store in this codebase so far. A
durable backend (object storage, a database) is a later task; what matters now
is that the *contract* makes the bounds and the isolation structural, so a
backend can be swapped in without relaxing either.

Three rules the contract enforces rather than documents:

**Nobody reads another analyst's page content.** Every operation takes an
:class:`ArtifactScope`, and lookups are filtered by it. Passing an artifact id
from another scope returns nothing — not an error mentioning that it exists
elsewhere, which would itself be a disclosure.

**Storage is bounded twice.** One artifact cannot exceed a per-artifact cap, and
one investigation cannot exceed a total budget or a count. A page under
investigation chooses how big its own DOM is, so an unbounded store is a memory
exhaustion primitive handed to the adversary.

**Identical content is stored once.** Content is addressed by its digest, so the
same phishing kit retrieved from forty scans occupies one entry — which is also
what makes "these forty pages served the same script" cheap to see.
"""

from __future__ import annotations

from typing import Final, Protocol

from ti_recon.artifacts.models import (
    ArtifactKind,
    ArtifactScope,
    StoredArtifact,
    artifact_digest,
    storage_key_for,
)
from ti_recon.models.base import utc_now

__all__ = [
    "DEFAULT_ARTIFACT_LIMITS",
    "ArtifactBudgetExceeded",
    "ArtifactLimits",
    "ArtifactStore",
    "ArtifactStoreError",
    "ArtifactTooLarge",
    "InMemoryArtifactStore",
]


class ArtifactStoreError(Exception):
    """Base class for artifact storage failures."""


class ArtifactTooLarge(ArtifactStoreError):
    """One artifact exceeded the per-artifact ceiling."""

    def __init__(self, kind: ArtifactKind, size_bytes: int, limit: int) -> None:
        self.kind = kind
        self.size_bytes = size_bytes
        self.limit = limit
        super().__init__(f"{kind.value} artifact of {size_bytes} bytes exceeds limit {limit}")


class ArtifactBudgetExceeded(ArtifactStoreError):
    """One investigation's total artifact budget is spent."""

    def __init__(self, investigation_id: str, limit: int) -> None:
        self.investigation_id = investigation_id
        self.limit = limit
        # No sizes and no ids beyond the investigation: an error message about
        # storage should not describe what is in storage.
        super().__init__(f"investigation artifact budget of {limit} exceeded")


class ArtifactLimits:
    """Ceilings applied by the store itself.

    A provider applies its own caps when it fetches; these are the second line,
    so a bug or a new provider cannot fill memory by skipping the first.
    """

    __slots__ = ("max_artifact_bytes", "max_artifacts_per_investigation", "max_total_bytes")

    def __init__(
        self,
        *,
        max_artifact_bytes: int = 8 * 1024 * 1024,
        max_total_bytes: int = 64 * 1024 * 1024,
        max_artifacts_per_investigation: int = 200,
    ) -> None:
        if max_artifact_bytes < 1 or max_total_bytes < 1:
            msg = "artifact limits must be positive"
            raise ValueError(msg)
        if max_artifacts_per_investigation < 1:
            msg = "artifact count limit must be positive"
            raise ValueError(msg)
        self.max_artifact_bytes = max_artifact_bytes
        self.max_total_bytes = max_total_bytes
        self.max_artifacts_per_investigation = max_artifacts_per_investigation


DEFAULT_ARTIFACT_LIMITS: Final[ArtifactLimits] = ArtifactLimits()


class ArtifactStore(Protocol):
    """Where bounded copies of provider-stored content live."""

    def put(
        self,
        scope: ArtifactScope,
        *,
        provider_id: str,
        kind: ArtifactKind,
        content: bytes,
        content_type: str = "application/octet-stream",
        provider_reference: str | None = None,
        truncated: bool = False,
    ) -> StoredArtifact: ...

    def get(self, scope: ArtifactScope, artifact_id: str) -> StoredArtifact | None: ...

    def content(self, scope: ArtifactScope, artifact_id: str) -> bytes | None: ...

    def list(self, scope: ArtifactScope) -> tuple[StoredArtifact, ...]: ...

    def total_bytes(self, scope: ArtifactScope) -> int: ...

    def clear(self, scope: ArtifactScope) -> int: ...


class InMemoryArtifactStore:
    """An :class:`ArtifactStore` held in this process's memory.

    Suitable for a single-process deployment and for tests. Nothing is written
    to disk, which also means no provider-supplied text ever reaches a
    filesystem — the failure mode that makes artifact handling dangerous in the
    first place.
    """

    def __init__(self, limits: ArtifactLimits | None = None) -> None:
        self._limits = DEFAULT_ARTIFACT_LIMITS if limits is None else limits
        self._metadata: dict[str, StoredArtifact] = {}
        self._content: dict[str, bytes] = {}

    @property
    def limits(self) -> ArtifactLimits:
        return self._limits

    def put(
        self,
        scope: ArtifactScope,
        *,
        provider_id: str,
        kind: ArtifactKind,
        content: bytes,
        content_type: str = "application/octet-stream",
        provider_reference: str | None = None,
        truncated: bool = False,
    ) -> StoredArtifact:
        """Store one artifact and return its metadata.

        Re-storing identical content in the same scope returns the existing
        entry rather than a second copy, so a kit served by forty pages is one
        artifact with one digest.
        """
        if len(content) > self._limits.max_artifact_bytes:
            raise ArtifactTooLarge(kind, len(content), self._limits.max_artifact_bytes)

        digest = artifact_digest(content)
        storage_key = storage_key_for(scope, kind=kind, content_sha256=digest)
        existing = self._find_by_key(scope, storage_key)
        if existing is not None:
            return existing

        current = self.list(scope)
        if len(current) >= self._limits.max_artifacts_per_investigation:
            raise ArtifactBudgetExceeded(
                scope.investigation_id, self._limits.max_artifacts_per_investigation
            )
        if sum(item.size_bytes for item in current) + len(content) > self._limits.max_total_bytes:
            raise ArtifactBudgetExceeded(scope.investigation_id, self._limits.max_total_bytes)

        artifact = StoredArtifact(
            user_id=scope.user_id,
            investigation_id=scope.investigation_id,
            provider_id=provider_id,
            kind=kind,
            provider_reference=provider_reference,
            content_type=content_type,
            content_sha256=digest,
            size_bytes=len(content),
            truncated=truncated,
            storage_key=storage_key,
            retrieved_at=utc_now(),
        )
        self._metadata[artifact.id] = artifact
        self._content[storage_key] = content
        return artifact

    def get(self, scope: ArtifactScope, artifact_id: str) -> StoredArtifact | None:
        """Metadata for one artifact, or ``None`` if this scope does not own it."""
        artifact = self._metadata.get(artifact_id)
        if artifact is None or not scope.owns(artifact):
            # Deliberately indistinguishable from "no such artifact": telling a
            # caller that an id exists in someone else's scope is a disclosure.
            return None
        return artifact

    def content(self, scope: ArtifactScope, artifact_id: str) -> bytes | None:
        """The bytes of one artifact, or ``None``.

        The only way to reach stored content, and it needs the owning scope.
        """
        artifact = self.get(scope, artifact_id)
        if artifact is None:
            return None
        return self._content.get(artifact.storage_key)

    def list(self, scope: ArtifactScope) -> tuple[StoredArtifact, ...]:
        return tuple(artifact for artifact in self._metadata.values() if scope.owns(artifact))

    def total_bytes(self, scope: ArtifactScope) -> int:
        return sum(artifact.size_bytes for artifact in self.list(scope))

    def clear(self, scope: ArtifactScope) -> int:
        """Drop everything this scope owns; returns how many entries went.

        An investigation's artifacts are page content that nothing needs once
        the investigation is over, so being able to drop them is part of the
        contract rather than an afterthought.
        """
        doomed = self.list(scope)
        for artifact in doomed:
            # A storage key contains the scope's partition, so no other scope
            # can share it and dropping the bytes here cannot orphan anyone.
            self._metadata.pop(artifact.id, None)
            self._content.pop(artifact.storage_key, None)
        return len(doomed)

    def _find_by_key(self, scope: ArtifactScope, storage_key: str) -> StoredArtifact | None:
        for artifact in self._metadata.values():
            if artifact.storage_key == storage_key and scope.owns(artifact):
                return artifact
        return None

    def __len__(self) -> int:
        return len(self._metadata)

    def __repr__(self) -> str:
        return f"<InMemoryArtifactStore artifacts={len(self._metadata)}>"
