"""Capability-based provider registry (Task 5).

The registry is what makes "which vendor do I call?" an unaskable question. The
engine describes what it needs — an object type and an intelligence capability —
and the registry returns whichever registered providers can serve it.

There is deliberately no scoring, prioritization or cost model here. Choosing
*which* of several compatible providers to call, and in what order, is a later
task; conflating selection with matching would bake a policy into a lookup
table.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from ti_recon.enums import ActivityMode, IntelObjectType, ProviderCapability
from ti_recon.providers.adapter import ProviderAdapter
from ti_recon.providers.descriptor import ProviderDescriptor

__all__ = [
    "DuplicateProviderId",
    "ProviderRegistry",
    "ProviderRegistryError",
    "UnknownProvider",
]


class ProviderRegistryError(Exception):
    """Base class for registry failures."""


class DuplicateProviderId(ProviderRegistryError):
    """Another adapter is already registered under this provider id.

    Rejected rather than overwritten: silently replacing an integration would
    make evidence provenance ambiguous, since ``transport_provider`` is just the
    provider id.
    """

    def __init__(self, provider_id: str) -> None:
        self.provider_id = provider_id
        super().__init__(f"provider {provider_id!r} is already registered")


class UnknownProvider(ProviderRegistryError):
    """No adapter is registered under this provider id."""

    def __init__(self, provider_id: str) -> None:
        self.provider_id = provider_id
        super().__init__(f"provider {provider_id!r} is not registered")


class ProviderRegistry:
    """A collection of provider adapters, queryable by capability.

    Holds no credentials and performs no I/O. Every listing method returns
    results ordered by ``provider_id`` so that investigations are reproducible
    and diffable.
    """

    def __init__(self, adapters: Iterable[ProviderAdapter] | None = None) -> None:
        self._adapters: dict[str, ProviderAdapter] = {}
        for adapter in adapters or ():
            self.register(adapter)

    # ------------------------------------------------------------------ #
    # Membership
    # ------------------------------------------------------------------ #

    def register(self, adapter: ProviderAdapter) -> None:
        """Add an adapter. Raises :class:`DuplicateProviderId` on collision."""
        provider_id = adapter.descriptor.provider_id
        if provider_id in self._adapters:
            raise DuplicateProviderId(provider_id)
        self._adapters[provider_id] = adapter

    def unregister(self, provider_id: str) -> None:
        """Remove an adapter. Raises :class:`UnknownProvider` if absent."""
        if provider_id not in self._adapters:
            raise UnknownProvider(provider_id)
        del self._adapters[provider_id]

    def get(self, provider_id: str) -> ProviderAdapter:
        """Return one adapter. Raises :class:`UnknownProvider` if absent."""
        try:
            return self._adapters[provider_id]
        except KeyError:
            raise UnknownProvider(provider_id) from None

    def list_all(self) -> tuple[ProviderAdapter, ...]:
        """All registered adapters, ordered by provider id."""
        return tuple(self._adapters[key] for key in sorted(self._adapters))

    def descriptors(self) -> tuple[ProviderDescriptor, ...]:
        """Descriptors for all registered adapters, ordered by provider id.

        Safe to expose to a caller: a descriptor is a static declaration and
        contains no credential state.
        """
        return tuple(adapter.descriptor for adapter in self.list_all())

    # ------------------------------------------------------------------ #
    # Capability matching
    # ------------------------------------------------------------------ #

    def find_by_object_type(self, object_type: IntelObjectType) -> tuple[ProviderAdapter, ...]:
        """Adapters that can say anything about this object type."""
        return tuple(
            adapter
            for adapter in self.list_all()
            if object_type in adapter.descriptor.supported_object_types
        )

    def find_by_capability(self, capability: ProviderCapability) -> tuple[ProviderAdapter, ...]:
        """Adapters that declare this capability, for any object type."""
        return tuple(
            adapter for adapter in self.list_all() if capability in adapter.descriptor.capabilities
        )

    def find_compatible(
        self,
        object_type: IntelObjectType,
        capability: ProviderCapability,
        *,
        activity_mode: ActivityMode = ActivityMode.PASSIVE,
        requires_credentials: bool | None = None,
    ) -> tuple[ProviderAdapter, ...]:
        """Adapters that can serve ``capability`` for ``object_type``.

        ``activity_mode`` defaults to ``PASSIVE`` and is a filter, not a hint: a
        passive investigation must never be handed an adapter that can only act.

        ``requires_credentials`` optionally narrows to providers that do
        (``True``) or do not (``False``) need one — useful for answering "what
        can we still learn with no keys configured?".
        """
        matches: list[ProviderAdapter] = []
        for adapter in self.list_all():
            descriptor = adapter.descriptor
            if not descriptor.supports(object_type, capability):
                continue
            if activity_mode is ActivityMode.PASSIVE and not descriptor.supports_passive:
                continue
            if activity_mode is ActivityMode.ACTIVE and not descriptor.supports_active:
                continue
            if (
                requires_credentials is not None
                and descriptor.requires_credentials is not requires_credentials
            ):
                continue
            matches.append(adapter)
        return tuple(matches)

    def capabilities_for_object_type(
        self, object_type: IntelObjectType
    ) -> frozenset[ProviderCapability]:
        """Every capability any registered provider offers for this object type.

        Coverage reporting needs this to distinguish "no provider could serve
        that capability" from "providers were tried and found nothing".
        """
        return frozenset(
            capability
            for adapter in self.find_by_object_type(object_type)
            for capability in adapter.descriptor.capabilities
        )

    # ------------------------------------------------------------------ #
    # Container protocol
    # ------------------------------------------------------------------ #

    def __contains__(self, provider_id: object) -> bool:
        return provider_id in self._adapters

    def __len__(self) -> int:
        return len(self._adapters)

    def __iter__(self) -> Iterator[ProviderAdapter]:
        return iter(self.list_all())

    def __repr__(self) -> str:
        return f"<ProviderRegistry providers={sorted(self._adapters)}>"
