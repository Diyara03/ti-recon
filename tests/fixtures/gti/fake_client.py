"""A scriptable in-memory :class:`GTIClient`.

Adapter and normalizer tests run against this rather than against mocked
``aiohttp`` internals, so they stay independent of vt-py's implementation
details and survive an SDK upgrade. It records every call, which is what makes
the relationship-bounding and descriptor-first assertions possible.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from pydantic import SecretStr

from ti_recon.providers.gti.client import GTIObject, GTIRelationshipDescriptor

__all__ = ["FakeGTIClient", "FakeGTIClientFactory", "RecordedCall"]


@dataclass(frozen=True)
class RecordedCall:
    """One call the adapter made, for assertions about what was requested."""

    operation: str
    collection: str | None = None
    object_id: str | None = None
    relationship: str | None = None
    limit: int | None = None
    exclude_attributes: tuple[str, ...] = ()


@dataclass
class FakeGTIClient:
    """A GTI client backed by dictionaries instead of an API.

    Anything left unset behaves as "GTI has nothing here": relationship lookups
    return empty rather than raising, which is the common real case and keeps
    tests focused on what they are actually asserting.
    """

    primary_objects: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    descriptors: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    relationship_objects: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    quota_payload: dict[str, Any] = field(default_factory=dict)
    behaviour_payload: dict[str, Any] = field(default_factory=dict)

    #: Errors to raise instead of answering, keyed the same way as the data.
    primary_errors: dict[tuple[str, str], BaseException] = field(default_factory=dict)
    relationship_errors: dict[tuple[str, str, str], BaseException] = field(default_factory=dict)
    quota_error: BaseException | None = None
    behaviour_error: BaseException | None = None

    calls: list[RecordedCall] = field(default_factory=list)
    closed: bool = False

    # ------------------------------------------------------------------ #
    # GTIClient
    # ------------------------------------------------------------------ #

    async def get_primary_object(
        self,
        *,
        collection: str,
        object_id: str,
        exclude_attributes: Sequence[str] = (),
    ) -> GTIObject:
        self.calls.append(
            RecordedCall(
                operation="primary",
                collection=collection,
                object_id=object_id,
                exclude_attributes=tuple(exclude_attributes),
            )
        )
        key = (collection, object_id)
        error = self.primary_errors.get(key)
        if error is not None:
            raise error
        payload = self.primary_objects.get(key)
        if payload is None:
            msg = f"no fake primary object registered for {collection}/{object_id}"
            raise AssertionError(msg)
        return _to_object(payload)

    async def get_relationship_descriptors(
        self,
        *,
        collection: str,
        object_id: str,
        relationship: str,
        limit: int,
    ) -> tuple[GTIRelationshipDescriptor, ...]:
        self.calls.append(
            RecordedCall(
                operation="descriptors",
                collection=collection,
                object_id=object_id,
                relationship=relationship,
                limit=limit,
            )
        )
        key = (collection, object_id, relationship)
        error = self.relationship_errors.get(key)
        if error is not None:
            raise error
        payload = self.descriptors.get(key, {})
        items = payload.get("data", []) if isinstance(payload, Mapping) else []
        return tuple(
            GTIRelationshipDescriptor(
                object_type=str(item["type"]),
                object_id=str(item["id"]),
                context_attributes=dict(item.get("context_attributes", {})),
            )
            for item in items[:limit]
            if isinstance(item, Mapping) and "type" in item and "id" in item
        )

    async def get_relationship_objects(
        self,
        *,
        collection: str,
        object_id: str,
        relationship: str,
        limit: int,
    ) -> tuple[GTIObject, ...]:
        self.calls.append(
            RecordedCall(
                operation="objects",
                collection=collection,
                object_id=object_id,
                relationship=relationship,
                limit=limit,
            )
        )
        key = (collection, object_id, relationship)
        error = self.relationship_errors.get(key)
        if error is not None:
            raise error
        payload = self.relationship_objects.get(key, {})
        items = payload.get("data", []) if isinstance(payload, Mapping) else []
        return tuple(_to_object(item) for item in items[:limit] if isinstance(item, Mapping))

    async def get_quota(self) -> Mapping[str, Any]:
        self.calls.append(RecordedCall(operation="quota"))
        if self.quota_error is not None:
            raise self.quota_error
        data = self.quota_payload.get("data", self.quota_payload)
        return dict(data) if isinstance(data, Mapping) else {}

    async def get_file_behavior_summary(self, *, file_id: str) -> Mapping[str, Any]:
        self.calls.append(RecordedCall(operation="behaviour", object_id=file_id))
        if self.behaviour_error is not None:
            raise self.behaviour_error
        data = self.behaviour_payload.get("data", self.behaviour_payload)
        return dict(data) if isinstance(data, Mapping) else {}

    async def close(self) -> None:
        self.closed = True

    # ------------------------------------------------------------------ #
    # Test helpers
    # ------------------------------------------------------------------ #

    def register_primary(self, collection: str, payload: dict[str, Any]) -> None:
        """Register a payload under the id it carries."""
        self.primary_objects[(collection, str(payload["id"]))] = payload

    def register_descriptors(
        self, collection: str, object_id: str, relationship: str, payload: dict[str, Any]
    ) -> None:
        self.descriptors[(collection, object_id, relationship)] = payload

    def register_objects(
        self, collection: str, object_id: str, relationship: str, payload: dict[str, Any]
    ) -> None:
        self.relationship_objects[(collection, object_id, relationship)] = payload

    def fail_relationship(
        self, collection: str, object_id: str, relationship: str, error: BaseException
    ) -> None:
        self.relationship_errors[(collection, object_id, relationship)] = error

    def operations(self, name: str) -> list[RecordedCall]:
        return [call for call in self.calls if call.operation == name]

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def relationships_requested(self) -> list[str]:
        return [call.relationship for call in self.calls if call.relationship is not None]


@dataclass
class FakeGTIClientFactory:
    """Hands out fake clients and remembers which credentials it was asked for.

    The recorded keys are what proves one analyst's credential never builds
    another analyst's client.
    """

    client: FakeGTIClient = field(default_factory=FakeGTIClient)
    per_key: dict[str, FakeGTIClient] = field(default_factory=dict)
    created_for: list[str] = field(default_factory=list)

    def create(self, api_key: SecretStr) -> FakeGTIClient:
        revealed = api_key.get_secret_value()
        self.created_for.append(revealed)
        return self.per_key.get(revealed, self.client)


def _to_object(payload: Mapping[str, Any]) -> GTIObject:
    return GTIObject(
        object_type=str(payload["type"]),
        object_id=str(payload["id"]),
        attributes=dict(payload.get("attributes", {})),
        relationships=dict(payload.get("relationships", {})),
        context_attributes=dict(payload.get("context_attributes", {})),
    )
