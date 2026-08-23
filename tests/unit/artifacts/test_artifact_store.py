"""Bounded, user-isolated artifact storage (Task 8)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ti_recon.artifacts import (
    ArtifactBudgetExceeded,
    ArtifactKind,
    ArtifactLimits,
    ArtifactScope,
    ArtifactStore,
    ArtifactTooLarge,
    InMemoryArtifactStore,
    StoredArtifact,
    artifact_digest,
    storage_key_for,
)
from ti_recon.enums import ProviderOperation

ANALYST = ArtifactScope(user_id="user-a", investigation_id="inv-1")
OTHER_ANALYST = ArtifactScope(user_id="user-b", investigation_id="inv-1")
OTHER_CASE = ArtifactScope(user_id="user-a", investigation_id="inv-2")

DOM = b"<html><body>login</body></html>"


def store(**limits: int) -> InMemoryArtifactStore:
    return InMemoryArtifactStore(ArtifactLimits(**limits) if limits else None)


def put(
    artifact_store: InMemoryArtifactStore,
    scope: ArtifactScope = ANALYST,
    *,
    content: bytes = DOM,
    kind: ArtifactKind = ArtifactKind.DOM,
    **kwargs: object,
) -> StoredArtifact:
    return artifact_store.put(
        scope,
        provider_id="urlscan",
        kind=kind,
        content=content,
        **kwargs,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# Isolation
# --------------------------------------------------------------------------- #


def test_another_analyst_cannot_read_stored_page_content() -> None:
    artifact_store = store()
    artifact = put(artifact_store)
    assert artifact_store.get(OTHER_ANALYST, artifact.id) is None
    assert artifact_store.content(OTHER_ANALYST, artifact.id) is None


def test_a_foreign_id_is_indistinguishable_from_a_missing_one() -> None:
    """Saying "that exists, but not for you" is itself a disclosure."""
    artifact_store = store()
    artifact = put(artifact_store)
    assert artifact_store.get(OTHER_ANALYST, artifact.id) is None
    assert artifact_store.get(OTHER_ANALYST, "no-such-id") is None


def test_the_same_analyst_cannot_reach_another_investigation() -> None:
    artifact_store = store()
    artifact = put(artifact_store)
    assert artifact_store.get(OTHER_CASE, artifact.id) is None
    assert artifact_store.list(OTHER_CASE) == ()


def test_listing_only_returns_what_the_scope_owns() -> None:
    artifact_store = store()
    put(artifact_store, ANALYST)
    put(artifact_store, OTHER_ANALYST, content=b"other")
    assert len(artifact_store.list(ANALYST)) == 1
    assert len(artifact_store.list(OTHER_ANALYST)) == 1
    assert len(artifact_store) == 2


def test_clearing_one_scope_leaves_the_others_alone() -> None:
    artifact_store = store()
    put(artifact_store, ANALYST)
    put(artifact_store, OTHER_ANALYST, content=b"other")
    assert artifact_store.clear(ANALYST) == 1
    assert artifact_store.list(ANALYST) == ()
    assert len(artifact_store.list(OTHER_ANALYST)) == 1


def test_two_scopes_storing_identical_bytes_keep_separate_entries() -> None:
    artifact_store = store()
    mine = put(artifact_store, ANALYST)
    theirs = put(artifact_store, OTHER_ANALYST)
    assert mine.id != theirs.id
    assert mine.storage_key != theirs.storage_key
    artifact_store.clear(ANALYST)
    assert artifact_store.content(OTHER_ANALYST, theirs.id) == DOM


# --------------------------------------------------------------------------- #
# Paths are never provider text
# --------------------------------------------------------------------------- #


def test_a_storage_key_is_derived_from_the_scope_kind_and_digest() -> None:
    artifact = put(store())
    assert artifact.storage_key == storage_key_for(
        ANALYST, kind=ArtifactKind.DOM, content_sha256=artifact_digest(DOM)
    )
    assert artifact.content_sha256 == artifact_digest(DOM)


def test_a_hostile_provider_reference_has_no_influence_on_the_key() -> None:
    artifact = put(store(), provider_reference="../../etc/passwd")
    assert ".." not in artifact.storage_key
    assert "etc" not in artifact.storage_key
    assert artifact.provider_reference == "../../etc/passwd"


def test_a_supplied_storage_key_is_rejected() -> None:
    """The key is derived; accepting one would let provider text pick a path."""
    with pytest.raises(ValidationError, match="derived"):
        StoredArtifact(
            user_id="user-a",
            investigation_id="inv-1",
            provider_id="urlscan",
            kind=ArtifactKind.DOM,
            content_sha256="a" * 64,
            size_bytes=1,
            storage_key="deadbeefdeadbeefdeadbeefdeadbeef/dom/" + "a" * 64,
        )


def test_a_partition_does_not_spell_out_who_it_belongs_to() -> None:
    scope = ArtifactScope(user_id="analyst@example.com", investigation_id="inv-1")
    assert "analyst@example.com" not in scope.partition
    assert "/" not in scope.partition
    assert scope.partition.isalnum()


def test_an_id_with_awkward_characters_still_produces_a_usable_key() -> None:
    scope = ArtifactScope(user_id="../../root", investigation_id="a b/c")
    key = storage_key_for(scope, kind=ArtifactKind.SCREENSHOT, content_sha256="b" * 64)
    assert ".." not in key
    assert key.count("/") == 2


# --------------------------------------------------------------------------- #
# Bounds
# --------------------------------------------------------------------------- #


def test_one_oversized_artifact_is_refused() -> None:
    artifact_store = store(max_artifact_bytes=8)
    with pytest.raises(ArtifactTooLarge) as caught:
        put(artifact_store, content=b"x" * 9)
    assert caught.value.limit == 8
    assert artifact_store.list(ANALYST) == ()


def test_an_investigations_total_budget_is_enforced() -> None:
    artifact_store = store(max_artifact_bytes=100, max_total_bytes=20)
    put(artifact_store, content=b"x" * 15)
    with pytest.raises(ArtifactBudgetExceeded):
        put(artifact_store, content=b"y" * 10)
    assert artifact_store.total_bytes(ANALYST) == 15


def test_an_investigations_artifact_count_is_capped() -> None:
    artifact_store = store(max_artifacts_per_investigation=2)
    put(artifact_store, content=b"one")
    put(artifact_store, content=b"two")
    with pytest.raises(ArtifactBudgetExceeded):
        put(artifact_store, content=b"three")


def test_a_budget_error_does_not_describe_what_is_in_storage() -> None:
    artifact_store = store(max_total_bytes=4)
    with pytest.raises(ArtifactBudgetExceeded) as caught:
        put(artifact_store, content=b"x" * 5)
    text = str(caught.value)
    assert "inv-1" not in text
    assert "user-a" not in text


def test_one_scopes_budget_is_not_spent_by_another() -> None:
    artifact_store = store(max_artifact_bytes=100, max_total_bytes=20)
    put(artifact_store, ANALYST, content=b"x" * 15)
    other = put(artifact_store, OTHER_ANALYST, content=b"y" * 15)
    assert artifact_store.get(OTHER_ANALYST, other.id) is not None


@pytest.mark.parametrize(
    "limits",
    [
        {"max_artifact_bytes": 0},
        {"max_total_bytes": 0},
        {"max_artifacts_per_investigation": 0},
    ],
)
def test_limits_cannot_be_disabled(limits: dict[str, int]) -> None:
    with pytest.raises(ValueError, match="positive"):
        ArtifactLimits(**limits)


# --------------------------------------------------------------------------- #
# Content addressing
# --------------------------------------------------------------------------- #


def test_identical_content_is_stored_once() -> None:
    """Forty pages serving one kit is one artifact — and that is the finding."""
    artifact_store = store()
    first = put(artifact_store)
    second = put(artifact_store)
    assert first.id == second.id
    assert len(artifact_store) == 1


def test_different_kinds_of_identical_bytes_are_separate() -> None:
    artifact_store = store()
    dom = put(artifact_store, kind=ArtifactKind.DOM)
    body = put(artifact_store, kind=ArtifactKind.RESPONSE_BODY)
    assert dom.id != body.id
    assert dom.content_sha256 == body.content_sha256


def test_content_needs_the_owning_scope_to_come_back() -> None:
    artifact_store = store()
    artifact = put(artifact_store)
    assert artifact_store.content(ANALYST, artifact.id) == DOM


def test_metadata_carries_no_content() -> None:
    """Metadata is safe to log and serialize; bytes are not."""
    artifact = put(store())
    dumped = artifact.model_dump(mode="json")
    assert "content" not in dumped
    assert "login" not in repr(dumped)


# --------------------------------------------------------------------------- #
# Truncation and provenance
# --------------------------------------------------------------------------- #


def test_a_truncated_artifact_is_flagged_as_unusable() -> None:
    """Half a screenshot is not a screenshot, and half a script may mislead."""
    artifact = put(store(), truncated=True)
    assert artifact.truncated is True
    assert artifact.is_usable is False


def test_a_complete_artifact_is_usable() -> None:
    assert put(store()).is_usable is True


def test_an_empty_artifact_is_not_usable() -> None:
    assert put(store(), content=b"").is_usable is False


def test_an_artifact_becomes_a_provenance_pointer_without_its_payload() -> None:
    artifact = put(store(), content_type="text/html")
    reference = artifact.to_raw_reference(operation=ProviderOperation.LOOKUP)
    assert reference.storage_key == artifact.storage_key
    assert reference.content_sha256 == artifact.content_sha256
    assert reference.size_bytes == artifact.size_bytes
    assert reference.content_type == "text/html"
    assert "login" not in repr(reference.model_dump(mode="json"))


def test_the_in_memory_store_satisfies_the_protocol() -> None:
    checked: ArtifactStore = InMemoryArtifactStore()
    assert isinstance(repr(checked), str)


def test_clearing_an_empty_scope_is_not_an_error() -> None:
    assert store().clear(ANALYST) == 0


def test_a_store_exposes_the_limits_it_applies() -> None:
    artifact_store = store(max_artifact_bytes=99)
    assert artifact_store.limits.max_artifact_bytes == 99
    assert InMemoryArtifactStore().limits.max_artifact_bytes > 0
