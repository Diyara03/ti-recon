"""Bounded provider artifact storage (Task 8).

Where TI Recon keeps copies of what a provider already stored — a screenshot, a
DOM snapshot, a response body — so a forensic finding can be re-examined against
the thing it came from.

Provider-neutral by design: nothing here knows about any vendor. Bounded and
user-isolated by construction, because the content is chosen by whoever is being
investigated and belongs to whoever ran the investigation.
"""

from ti_recon.artifacts.models import (
    ARTIFACT_STORAGE_KEY_PATTERN,
    ArtifactKind,
    ArtifactScope,
    StoredArtifact,
    artifact_digest,
    storage_key_for,
)
from ti_recon.artifacts.store import (
    DEFAULT_ARTIFACT_LIMITS,
    ArtifactBudgetExceeded,
    ArtifactLimits,
    ArtifactStore,
    ArtifactStoreError,
    ArtifactTooLarge,
    InMemoryArtifactStore,
)

__all__ = [
    "ARTIFACT_STORAGE_KEY_PATTERN",
    "DEFAULT_ARTIFACT_LIMITS",
    "ArtifactBudgetExceeded",
    "ArtifactKind",
    "ArtifactLimits",
    "ArtifactScope",
    "ArtifactStore",
    "ArtifactStoreError",
    "ArtifactTooLarge",
    "InMemoryArtifactStore",
    "StoredArtifact",
    "artifact_digest",
    "storage_key_for",
]
