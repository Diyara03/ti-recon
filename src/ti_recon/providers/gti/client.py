"""The GTI client boundary (Task 7).

The only module that touches the vt-py *client*: ``vt.Client``, ``vt.Object`` and
``vt.url_id`` appear here and nowhere else. (``errors.py`` also imports
``vt.error.APIError``, purely to recognize it in an ``isinstance`` check.)

Everything above this module works with :class:`GTIObject` and
:class:`GTIRelationshipDescriptor` — plain frozen models — so vt-py's types never
reach the normalizer, the adapter or the core, and the normalizer is testable
from JSON fixtures with vt-py absent.

Why an SDK here at all
----------------------

Task 5 provides a shared, SSRF-bounded ``ProviderHttpClient`` and every other
provider is expected to use it. GTI is an approved exception: the official
``vt-py`` library already encodes v3's object/relationship/pagination model and
URL-identifier scheme, and reimplementing that against a generic transport would
mean maintaining a second, worse copy of Google's API semantics.

The exception is narrow. vt-py is used for *transport and object access only*:

* Task 6's ``ProviderExecutor`` still owns retry, backoff, caching, cooldown,
  concurrency and quota state. This client never sleeps and never retries.
* vt-py's own scan/upload/download methods are never called; see
  :data:`FORBIDDEN_VT_METHODS`.
* TLS verification is not exposed as an option, so it cannot be turned off.
* Request paths are built from a fixed set of collection names plus a validated
  object id, so no caller-supplied string can redirect a request. In particular
  a submitted URL is turned into an opaque identifier by ``vt.url_id`` and never
  becomes part of a URL that TI Recon fetches.

One client instance belongs to one credential. There is deliberately no shared
or cached client keyed by API key: a leaked client is a leaked credential, and
per-user isolation is easier to guarantee when nothing is shared.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from types import TracebackType
from typing import Any, Final, Protocol, Self, runtime_checkable

import vt
from pydantic import Field, SecretStr, field_validator

from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.gti.config import GTIConfig
from ti_recon.providers.gti.errors import translate_gti_error

__all__ = [
    "FORBIDDEN_VT_METHODS",
    "GTI_COLLECTIONS",
    "GTIClient",
    "GTIClientFactory",
    "GTIObject",
    "GTIPathError",
    "GTIRelationshipDescriptor",
    "VtPyGTIClient",
    "VtPyGTIClientFactory",
    "url_identifier",
]

#: The v3 collections this integration reads. A path is only ever built from
#: one of these, never from caller-supplied text.
GTI_COLLECTIONS: Final[frozenset[str]] = frozenset({"files", "domains", "ip_addresses", "urls"})

#: vt-py methods that would make this integration active rather than passive.
#: Listed so a test can assert none of them appears in production GTI code.
FORBIDDEN_VT_METHODS: Final[tuple[str, ...]] = (
    "scan_file",
    "scan_file_async",
    "scan_file_private",
    "scan_file_private_async",
    "scan_url",
    "scan_url_async",
    "scan_url_private",
    "scan_url_private_async",
    "download_file",
    "download_file_async",
    "download_zip_files",
    "download_zip_files_async",
    "post",
    "post_async",
    "post_object",
    "post_object_async",
    "patch",
    "patch_async",
    "patch_object",
    "patch_object_async",
    "delete",
    "delete_async",
)

#: An object id may contain only characters GTI actually uses for identifiers:
#: hex digests, domain names, IP addresses and base64url URL identifiers. This
#: excludes ``/``, ``?``, ``#``, ``:`` and whitespace, so an id can never extend
#: or escape the path it is placed into.
_OBJECT_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"\A[A-Za-z0-9._~=-]{1,512}\Z")

#: Relationship names come from our own verified allowlists, but the guard is
#: cheap and stops a future caller from passing arbitrary text into a path.
_RELATIONSHIP_PATTERN: Final[re.Pattern[str]] = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")


class GTIPathError(ValueError):
    """A path component was not something this client is willing to request."""


class GTIObject(FrozenTiReconModel):
    """One GTI API object, decoupled from vt-py.

    Attributes are kept as a plain mapping rather than a typed model on purpose:
    GTI's schema evolves, and an exhaustive model would fail on the day Google
    adds a field. Normalization reads what it recognizes through :meth:`attribute`
    and leaves the rest alone.
    """

    object_type: str = Field(min_length=1, max_length=64)
    object_id: str = Field(min_length=1, max_length=512)
    attributes: dict[str, Any] = Field(default_factory=dict)
    relationships: dict[str, Any] = Field(default_factory=dict)
    context_attributes: dict[str, Any] = Field(default_factory=dict)

    def attribute(self, name: str, default: Any = None) -> Any:
        """One top-level attribute, or ``default`` if GTI did not send it."""
        return self.attributes.get(name, default)

    def nested(self, *path: str, default: Any = None) -> Any:
        """Walk nested attributes safely.

        Returns ``default`` the moment the path stops being a mapping, so a
        provider changing a nested object into a scalar degrades to "absent"
        rather than raising.
        """
        current: Any = self.attributes
        for step in path:
            if not isinstance(current, Mapping):
                return default
            if step not in current:
                return default
            current = current[step]
        return current

    def mapping(self, name: str) -> dict[str, Any]:
        """One attribute that should be a mapping, or an empty mapping."""
        value = self.attributes.get(name)
        return dict(value) if isinstance(value, Mapping) else {}


class GTIRelationshipDescriptor(FrozenTiReconModel):
    """A lightweight pointer to a related GTI object.

    Descriptors are what the descriptor-first strategy retrieves: enough to know
    *that* a relationship exists and to what, without paying for the full object.
    """

    object_type: str = Field(min_length=1, max_length=64)
    object_id: str = Field(min_length=1, max_length=512)
    context_attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("object_id")
    @classmethod
    def _strip_object_id(cls, value: str) -> str:
        return value.strip()


@runtime_checkable
class GTIClient(Protocol):
    """The GTI operations TI Recon performs. All passive reads.

    Implementations raise normalized
    :class:`~ti_recon.providers.errors.ProviderError` subclasses rather than
    SDK-specific exceptions, and never retry — Task 6 owns that.
    """

    async def get_primary_object(
        self,
        *,
        collection: str,
        object_id: str,
        exclude_attributes: Sequence[str] = (),
    ) -> GTIObject:
        """Fetch one object by collection and id."""
        ...

    async def get_relationship_descriptors(
        self,
        *,
        collection: str,
        object_id: str,
        relationship: str,
        limit: int,
    ) -> tuple[GTIRelationshipDescriptor, ...]:
        """Fetch up to ``limit`` descriptors for one relationship."""
        ...

    async def get_relationship_objects(
        self,
        *,
        collection: str,
        object_id: str,
        relationship: str,
        limit: int,
    ) -> tuple[GTIObject, ...]:
        """Fetch up to ``limit`` full objects for one relationship."""
        ...

    async def get_quota(self) -> Mapping[str, Any]:
        """Fetch this credential's overall quotas.

        Takes no key argument: the client holds the credential and builds the
        path internally, so the API key never crosses this boundary — and the
        path it appears in is never returned, logged or attached to an error.
        """
        ...

    async def get_file_behavior_summary(self, *, file_id: str) -> Mapping[str, Any]:
        """Fetch the aggregated sandbox behaviour summary for a file."""
        ...

    async def close(self) -> None:
        """Release the underlying HTTP session. Safe to call more than once."""
        ...


@runtime_checkable
class GTIClientFactory(Protocol):
    """Builds a client bound to one credential."""

    def create(self, api_key: SecretStr) -> GTIClient:
        """A fresh client for this credential."""
        ...


def url_identifier(url: str) -> str:
    """The GTI object identifier for a URL.

    Delegates to ``vt.url_id`` rather than reimplementing the base64url scheme,
    and is the reason a suspicious URL never becomes part of a request path: the
    identifier is opaque and the URL itself is only ever the object being asked
    about.
    """
    return str(vt.url_id(url))


def _validate_collection(collection: str) -> str:
    if collection not in GTI_COLLECTIONS:
        msg = f"unsupported GTI collection {collection!r}"
        raise GTIPathError(msg)
    return collection


def _validate_object_id(object_id: str) -> str:
    candidate = object_id.strip()
    if not _OBJECT_ID_PATTERN.fullmatch(candidate):
        # The value is not echoed: an id derived from analyst input does not
        # need to travel into an exception message.
        msg = "GTI object id contains characters that are not permitted in a path"
        raise GTIPathError(msg)
    return candidate


def _validate_relationship(relationship: str) -> str:
    if not _RELATIONSHIP_PATTERN.fullmatch(relationship):
        msg = f"unsupported GTI relationship name {relationship!r}"
        raise GTIPathError(msg)
    return relationship


class VtPyGTIClient:
    """A :class:`GTIClient` backed by the official vt-py SDK.

    The underlying ``vt.Client`` is created lazily on first use, because vt-py's
    connector wants a running event loop and constructing one at import time
    creates a loop nobody asked for.
    """

    def __init__(self, api_key: SecretStr, config: GTIConfig | None = None) -> None:
        if not api_key.get_secret_value():
            msg = "GTI requires a non-empty API key"
            raise ValueError(msg)
        self._api_key = api_key
        self._config = config or GTIConfig()
        self._client: vt.Client | None = None
        self._closed = False

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    @property
    def config(self) -> GTIConfig:
        return self._config

    @property
    def is_closed(self) -> bool:
        return self._closed

    def _vt_client(self) -> vt.Client:
        if self._closed:
            msg = "GTI client has been closed"
            raise RuntimeError(msg)
        if self._client is None:
            self._client = vt.Client(
                self._api_key.get_secret_value(),
                agent=self._config.agent,
                host=self._config.host,
                headers=self._config.headers,
                timeout=self._config.timeout_seconds,
                # Explicit: ignore ambient proxy configuration, so provider
                # traffic cannot be silently redirected by the environment.
                trust_env=False,
                # verify_ssl is deliberately not passed and not configurable.
                # vt-py defaults it to True and there is no path to turn it off.
            )
        return self._client

    async def close(self) -> None:
        """Close the aiohttp session vt-py opened. Idempotent."""
        self._closed = True
        client, self._client = self._client, None
        if client is not None:
            await client.close_async()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.close()

    def __repr__(self) -> str:
        """Identify the client without revealing whose credential it holds."""
        return (
            f"<VtPyGTIClient host={self._config.host} "
            f"x_tool={self._config.x_tool} closed={self._closed}>"
        )

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #

    async def get_primary_object(
        self,
        *,
        collection: str,
        object_id: str,
        exclude_attributes: Sequence[str] = (),
    ) -> GTIObject:
        path = f"/{_validate_collection(collection)}/{_validate_object_id(object_id)}"
        params: dict[str, str] = {}
        if exclude_attributes:
            params["exclude_attributes"] = ",".join(exclude_attributes)
        raw = await self._call(
            "primary_lookup",
            self._vt_client().get_object_async(path, params=params or None),
        )
        return _to_gti_object(raw)

    async def get_relationship_descriptors(
        self,
        *,
        collection: str,
        object_id: str,
        relationship: str,
        limit: int,
    ) -> tuple[GTIRelationshipDescriptor, ...]:
        path = (
            f"/{_validate_collection(collection)}/{_validate_object_id(object_id)}"
            f"/relationships/{_validate_relationship(relationship)}"
        )
        payload = await self._call(
            "relationship_descriptors",
            self._vt_client().get_json_async(path, params={"limit": _bounded(limit)}),
            entitlement_sensitive=True,
        )
        return _to_descriptors(payload, limit=_bounded(limit))

    async def get_relationship_objects(
        self,
        *,
        collection: str,
        object_id: str,
        relationship: str,
        limit: int,
    ) -> tuple[GTIObject, ...]:
        path = (
            f"/{_validate_collection(collection)}/{_validate_object_id(object_id)}"
            f"/{_validate_relationship(relationship)}"
        )
        payload = await self._call(
            "relationship_objects",
            self._vt_client().get_json_async(path, params={"limit": _bounded(limit)}),
            entitlement_sensitive=True,
        )
        return _to_objects(payload, limit=_bounded(limit))

    async def get_quota(self) -> Mapping[str, Any]:
        """Fetch overall quotas.

        The API key appears in this path. It is built here, used once, and never
        stored, returned, logged or attached to an error — ``include_detail`` is
        off for exactly that reason.
        """
        path = f"/users/{self._api_key.get_secret_value()}/overall_quotas"
        payload = await self._call(
            "quota_lookup",
            self._vt_client().get_json_async(path),
            include_detail=False,
        )
        data = payload.get("data") if isinstance(payload, Mapping) else None
        return dict(data) if isinstance(data, Mapping) else {}

    async def get_file_behavior_summary(self, *, file_id: str) -> Mapping[str, Any]:
        path = f"/files/{_validate_object_id(file_id)}/behaviour_summary"
        payload = await self._call(
            "file_behavior_summary",
            self._vt_client().get_json_async(path),
            entitlement_sensitive=True,
        )
        data = payload.get("data") if isinstance(payload, Mapping) else None
        return dict(data) if isinstance(data, Mapping) else {}

    # ------------------------------------------------------------------ #
    # Error translation
    # ------------------------------------------------------------------ #

    async def _call(
        self,
        operation: str,
        awaitable: Any,
        *,
        entitlement_sensitive: bool = False,
        include_detail: bool = True,
    ) -> Any:
        """Await one vt-py call, translating any failure.

        No retry and no sleep: Task 6 decides whether a normalized failure is
        worth another attempt.
        """
        try:
            return await awaitable
        except Exception as error:
            raise translate_gti_error(
                error,
                provider_id="gti",
                operation=operation,
                entitlement_sensitive=entitlement_sensitive,
                secret=self._api_key.get_secret_value(),
                include_detail=include_detail,
            ) from None


class VtPyGTIClientFactory:
    """Creates one vt-py-backed client per credential."""

    def __init__(self, config: GTIConfig | None = None) -> None:
        self._config = config or GTIConfig()

    @property
    def config(self) -> GTIConfig:
        return self._config

    def create(self, api_key: SecretStr) -> GTIClient:
        return VtPyGTIClient(api_key, self._config)

    def __repr__(self) -> str:
        return f"<VtPyGTIClientFactory host={self._config.host}>"


# --------------------------------------------------------------------------- #
# vt-py -> TI Recon conversion. Confined to this module by design.
# --------------------------------------------------------------------------- #

#: Upper bound on anything this client will ask GTI for in one call. A caller
#: asking for more is clamped rather than refused, so a policy mistake costs a
#: smaller result rather than an outage.
_MAX_PAGE_SIZE: Final[int] = 40


def _bounded(limit: int) -> int:
    return max(1, min(limit, _MAX_PAGE_SIZE))


def _to_gti_object(raw: Any) -> GTIObject:
    """Convert a ``vt.Object`` into our own frozen model."""
    payload = raw.to_dict() if hasattr(raw, "to_dict") else raw
    return _object_from_payload(payload)


def _object_from_payload(payload: Any) -> GTIObject:
    if not isinstance(payload, Mapping):
        msg = "GTI returned an object that is not a mapping"
        raise ValueError(msg)
    object_type = payload.get("type")
    object_id = payload.get("id")
    if not isinstance(object_type, str) or not isinstance(object_id, str):
        # Identity is the one thing normalization cannot work around.
        msg = "GTI object is missing its type or id"
        raise ValueError(msg)
    attributes = payload.get("attributes")
    relationships = payload.get("relationships")
    context = payload.get("context_attributes")
    return GTIObject(
        object_type=object_type,
        object_id=object_id,
        attributes=dict(attributes) if isinstance(attributes, Mapping) else {},
        relationships=dict(relationships) if isinstance(relationships, Mapping) else {},
        context_attributes=dict(context) if isinstance(context, Mapping) else {},
    )


def _data_items(payload: Any) -> list[Any]:
    if not isinstance(payload, Mapping):
        return []
    data = payload.get("data")
    if isinstance(data, list):
        return list(data)
    return [data] if isinstance(data, Mapping) else []


def _to_descriptors(payload: Any, *, limit: int) -> tuple[GTIRelationshipDescriptor, ...]:
    descriptors: list[GTIRelationshipDescriptor] = []
    for item in _data_items(payload)[:limit]:
        if not isinstance(item, Mapping):
            continue
        object_type = item.get("type")
        object_id = item.get("id")
        if not isinstance(object_type, str) or not isinstance(object_id, str):
            # A descriptor without identity tells us nothing; skipping one bad
            # entry is better than discarding a whole useful relationship.
            continue
        context = item.get("context_attributes")
        descriptors.append(
            GTIRelationshipDescriptor(
                object_type=object_type,
                object_id=object_id,
                context_attributes=dict(context) if isinstance(context, Mapping) else {},
            )
        )
    return tuple(descriptors)


def _to_objects(payload: Any, *, limit: int) -> tuple[GTIObject, ...]:
    objects: list[GTIObject] = []
    for item in _data_items(payload)[:limit]:
        try:
            objects.append(_object_from_payload(item))
        except ValueError:
            continue
    return tuple(objects)
