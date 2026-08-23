"""Artifact models (Task 8).

An **artifact** is a bounded copy of something a provider stored: a screenshot,
a DOM snapshot, a response body. TI Recon keeps them so a forensic finding can
be re-examined — "this is the script we extracted that URL from" — and for no
other reason.

Deliberately generic. Nothing here mentions urlscan: any provider that archives
what a browser or a sandbox saw produces the same shape, and a subsystem that
knew about one vendor would have to be rewritten for the second.

The split between :class:`StoredArtifact` and its bytes is the important part.
Metadata is safe to log, serialize and attach to evidence; content is not, and
is only ever handed back deliberately. The bytes are page content chosen by
whoever is being investigated, so they are treated as hostile data throughout:
never rendered, never executed, never used to name a file.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Final

from pydantic import Field, model_validator

from ti_recon.enums import ProviderOperation
from ti_recon.models.base import FrozenTiReconModel, Identifier, UtcDatetime, new_id, utc_now
from ti_recon.models.evidence import RawEvidenceReference

__all__ = [
    "ARTIFACT_STORAGE_KEY_PATTERN",
    "ArtifactKind",
    "ArtifactScope",
    "StoredArtifact",
    "artifact_digest",
    "storage_key_for",
]

#: Storage keys are built from a hashed scope, a kind and a content digest —
#: never from provider text, and never from an id whose characters we do not
#: control. The pattern is asserted on the model, so a key can always be used as
#: a path component without escaping and without a traversal check.
ARTIFACT_STORAGE_KEY_PATTERN: Final[str] = (
    r"^[0-9a-f]{32}/(?:screenshot|dom|response_body|other)/[0-9a-f]{64}$"
)


class ArtifactKind(StrEnum):
    """What a stored artifact is.

    Provider-neutral on purpose: a screenshot is a screenshot whether it came
    from a URL scanner or a sandbox.
    """

    SCREENSHOT = "screenshot"
    DOM = "dom"
    RESPONSE_BODY = "response_body"
    OTHER = "other"


class ArtifactScope(FrozenTiReconModel):
    """Who an artifact belongs to.

    Identity is built from ids only, exactly as :class:`ExecutionScope` is: a
    caller can never reach another analyst's stored page content, because the
    partition it would have to name is derived rather than supplied.
    """

    user_id: Identifier
    investigation_id: Identifier

    @property
    def partition(self) -> str:
        """A path-safe, opaque partition for this scope.

        Hashed rather than spelled out for two reasons. An analyst id may be an
        email or contain any character at all, and interpolating that into a
        path is how traversal bugs happen. And a storage key gets logged, so a
        partition that reads back as somebody's identity is a small privacy leak
        for no benefit.
        """
        material = f"{self.user_id}\x00{self.investigation_id}".encode()
        return hashlib.sha256(material).hexdigest()[:32]

    def owns(self, artifact: StoredArtifact) -> bool:
        return (
            artifact.user_id == self.user_id and artifact.investigation_id == self.investigation_id
        )


class StoredArtifact(FrozenTiReconModel):
    """Metadata for one stored artifact. Never the bytes.

    ``truncated`` matters more than it looks: a screenshot cut off at a byte
    ceiling is not a screenshot, and a script body cut in half may parse into
    findings that are not in the real file. Anything downstream has to be able
    to tell the difference, so it travels with the metadata rather than being
    inferred from the size.
    """

    id: Identifier = Field(default_factory=new_id)
    user_id: Identifier
    investigation_id: Identifier
    provider_id: str = Field(min_length=1, max_length=64)
    kind: ArtifactKind
    #: The provider's own identifier for this artifact — a scan id, a digest.
    #: Recorded for traceability and validated by the provider before it gets
    #: here; never used to build the storage key.
    provider_reference: str | None = Field(default=None, max_length=200)
    content_type: str = Field(default="application/octet-stream", max_length=128)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)
    truncated: bool = False
    storage_key: str = Field(min_length=1, max_length=512, pattern=ARTIFACT_STORAGE_KEY_PATTERN)
    retrieved_at: UtcDatetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _validate_artifact(self) -> StoredArtifact:
        expected = storage_key_for(
            ArtifactScope(user_id=self.user_id, investigation_id=self.investigation_id),
            kind=self.kind,
            content_sha256=self.content_sha256,
        )
        if self.storage_key != expected:
            # The key is derived, so a mismatch means somebody supplied one.
            # Provider-controlled text must never decide where bytes live.
            msg = "storage_key must be derived from the scope, kind and digest"
            raise ValueError(msg)
        return self

    @property
    def is_usable(self) -> bool:
        """Whether the stored bytes represent the whole artifact."""
        return not self.truncated and self.size_bytes > 0

    def to_raw_reference(
        self, *, operation: ProviderOperation = ProviderOperation.LOOKUP
    ) -> RawEvidenceReference:
        """A Task 3 provenance pointer to this artifact.

        Lets a piece of evidence say where it came from without carrying the
        payload, which is the whole point of ``RawEvidenceReference``.
        """
        return RawEvidenceReference(
            investigation_id=self.investigation_id,
            provider=self.provider_id,
            operation=operation,
            storage_key=self.storage_key,
            content_type=self.content_type,
            content_sha256=self.content_sha256,
            size_bytes=self.size_bytes,
            retrieved_at=self.retrieved_at,
            redacted=False,
        )


def artifact_digest(content: bytes) -> str:
    """The SHA-256 of some content, which is also its identity."""
    return hashlib.sha256(content).hexdigest()


def storage_key_for(scope: ArtifactScope, *, kind: ArtifactKind, content_sha256: str) -> str:
    """Where an artifact's bytes live.

    Derived from the scope, the kind and the content digest — never from a
    provider-supplied filename, URL, domain or scan title. Provider text has no
    influence on a path, so a response named ``../../etc/passwd`` is just
    another body with a digest.
    """
    return f"{scope.partition}/{kind.value}/{content_sha256}"
