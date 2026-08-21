"""The GTI provider adapter (Task 7).

Implements the Task 5 :class:`ProviderAdapter` contract over GTI / VirusTotal
API v3. It normalizes and classifies; it does not decide anything about
maliciousness, and it does not retry — Task 6's executor owns retry, backoff,
caching, cooldown, concurrency and quota state.

Client lifetime
---------------

A client is created per call from the supplied credential and closed when the
call ends. That costs a TLS handshake per uncached lookup, and the trade is
deliberate: nothing shared means no session can outlive the credential that
opened it and no credential can be reused for another analyst. Within one
lookup the same client serves the primary object and every relationship, so
pooling still applies where a lookup actually makes several calls, and Task 6's
cache means repeat lookups make none. Per-credential connection reuse is a later
optimization, not a correctness requirement.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from types import TracebackType

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderRunStatus,
)
from ti_recon.execution.clock import Clock, SystemClock
from ti_recon.execution.limits import QuotaStore
from ti_recon.execution.models import ExecutionScope
from ti_recon.models.evidence import RawEvidenceReference
from ti_recon.models.intel_object import IntelObject, strongest_hash
from ti_recon.providers.adapter import (
    CapabilityDiscovery,
    CredentialValidation,
    ProviderAdapter,
    ProviderHealthReport,
)
from ti_recon.providers.capabilities import ProviderHealth
from ti_recon.providers.descriptor import ProviderDescriptor
from ti_recon.providers.errors import (
    ProviderError,
    ProviderInvalidRequestError,
    UnsupportedProviderOperation,
)
from ti_recon.providers.gti.client import (
    GTIClient,
    GTIClientFactory,
    GTIObject,
    VtPyGTIClientFactory,
    url_identifier,
)
from ti_recon.providers.gti.config import GTIConfig
from ti_recon.providers.gti.descriptor import GTI_PROVIDER_ID, build_gti_descriptor
from ti_recon.providers.gti.normalizer import (
    GTINormalization,
    NormalizationContext,
    RelatedItem,
    enrich_primary_object,
    normalize_analysis_stats,
    normalize_assessment,
    normalize_file_behavior,
    normalize_inline_relationships,
    normalize_related_items,
)
from ti_recon.providers.gti.policy import GTILookupPolicy, collection_for_object_type
from ti_recon.providers.gti.quota import GTIQuotaReading, parse_overall_quotas
from ti_recon.providers.gti.relationships import (
    LIMITS_BY_DEPTH,
    RELATIONSHIP_SPECS,
    GTIRelationshipDepth,
    GTIRelationshipLimits,
    GTIRelationshipSpec,
    Retrieval,
    TargetKind,
    depth_for_investigation,
    relationship_plan,
)
from ti_recon.providers.quota import ProviderQuotaSnapshot
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import NormalizedPayload, ProviderResultEnvelope

__all__ = ["GTIAdapter"]

_logger = logging.getLogger(__name__)

#: Categories that prove the credential itself is the problem. Everything else
#: leaves the credential's recorded status alone — see ``validate_credentials``.
_INVALIDATING_CATEGORIES = frozenset({ProviderErrorCategory.AUTHENTICATION_ERROR})


class GTIAdapter(ProviderAdapter):
    """Passive GTI enrichment for IPs, domains, URLs and file hashes."""

    def __init__(
        self,
        *,
        client_factory: GTIClientFactory | None = None,
        config: GTIConfig | None = None,
        lookup_policy: GTILookupPolicy | None = None,
        quota_store: QuotaStore | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._config = GTIConfig() if config is None else config
        self._client_factory = (
            VtPyGTIClientFactory(self._config) if client_factory is None else client_factory
        )
        self._lookup_policy = GTILookupPolicy() if lookup_policy is None else lookup_policy
        # Task 6's own quota store, injected rather than duplicated. Sharing it
        # means the executor's pre-check and this adapter's refresh agree on both
        # the key and the freshness window.
        self._quota_store = quota_store
        self._clock = SystemClock() if clock is None else clock
        self._descriptor = build_gti_descriptor()

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    @property
    def config(self) -> GTIConfig:
        return self._config

    @property
    def lookup_policy(self) -> GTILookupPolicy:
        return self._lookup_policy

    # ------------------------------------------------------------------ #
    # Credential validation
    # ------------------------------------------------------------------ #

    async def validate_credentials(
        self, credential: CredentialMaterial | None
    ) -> CredentialValidation:
        """Check a key by asking GTI for its own quota.

        The cheapest authenticated call available: it touches no IOC, consumes
        no lookup allowance, and proves the key resolves to an active account.

        The mapping is deliberately conservative about what counts as a bad
        credential:

        * an authentication failure is the *only* thing that marks it invalid;
        * ``ForbiddenError`` does not — a 403 usually means this key may not do
          this one thing, and disabling a working Enterprise key over one
          restricted endpoint would be worse than the restriction;
        * quota exhaustion reports the key as valid, because an allowance
          belongs to an account and could not have been spent by an
          unrecognized key;
        * anything transient reports ``UNKNOWN`` rather than guessing, so a
          provider outage never invalidates a good key.
        """
        if credential is None:
            return self._validation(CredentialStatus.INVALID, "no credential supplied")

        try:
            async with self._client_for(credential) as client:
                await client.get_quota()
        except ProviderError as error:
            return self._validation(
                self._status_for_error(error),
                f"quota lookup returned {error.category.value}",
            )
        return self._validation(CredentialStatus.ACTIVE, "quota lookup succeeded")

    @staticmethod
    def _status_for_error(error: ProviderError) -> CredentialStatus:
        if error.category in _INVALIDATING_CATEGORIES:
            return CredentialStatus.INVALID
        if error.category is ProviderErrorCategory.QUOTA_EXCEEDED:
            # An exhausted allowance is proof the account was identified.
            return CredentialStatus.ACTIVE
        return CredentialStatus.UNKNOWN

    def _validation(self, status: CredentialStatus, detail: str) -> CredentialValidation:
        return CredentialValidation(provider_id=GTI_PROVIDER_ID, status=status, detail=detail)

    async def discover_capabilities(
        self, credential: CredentialMaterial | None
    ) -> CapabilityDiscovery:
        """Report what the integration supports, without probing the account.

        Deliberately free of API calls. Probing each capability would cost a
        request per capability and still be a guess, because entitlement can
        differ per object type and per relationship. What a specific key is
        allowed to do is discovered where it matters: at request time, where a
        refusal becomes ``PLAN_LIMITED`` for that operation and leaves the rest
        of the provider usable.
        """
        return CapabilityDiscovery(
            provider_id=GTI_PROVIDER_ID,
            capabilities=self._descriptor.capabilities,
            plan_hint="entitlement is determined per request",
        )

    async def health(self, credential: CredentialMaterial | None = None) -> ProviderHealthReport:
        """Report availability, checking only if a credential is available."""
        if credential is None:
            return ProviderHealthReport(provider_id=GTI_PROVIDER_ID, health=ProviderHealth.UNKNOWN)
        try:
            async with self._client_for(credential) as client:
                await client.get_quota()
        except ProviderError as error:
            health = (
                ProviderHealth.UNAVAILABLE
                if error.category
                in {
                    ProviderErrorCategory.PROVIDER_UNAVAILABLE,
                    ProviderErrorCategory.TRANSIENT_ERROR,
                }
                else ProviderHealth.DEGRADED
            )
            return ProviderHealthReport(
                provider_id=GTI_PROVIDER_ID,
                health=health,
                detail=f"quota lookup returned {error.category.value}",
            )
        return ProviderHealthReport(provider_id=GTI_PROVIDER_ID, health=ProviderHealth.AVAILABLE)

    # ------------------------------------------------------------------ #
    # Quota
    # ------------------------------------------------------------------ #

    async def fetch_quota(self, credential: CredentialMaterial) -> GTIQuotaReading:
        """Read this credential's allowances.

        Raises a normalized :class:`ProviderError` on failure. The failure is
        never described in terms of the endpoint, because that endpoint's path
        contains the API key.
        """
        async with self._client_for(credential) as client:
            payload = await client.get_quota()
        return self._reading_from(payload, credential)

    def _reading_from(
        self, payload: Mapping[str, object], credential: CredentialMaterial
    ) -> GTIQuotaReading:
        return parse_overall_quotas(
            payload,
            user_id=credential.user_id,
            provider_connection_id=credential.connection_id,
            retrieved_at=self._clock.now(),
        )

    async def _refresh_quota_if_stale(
        self, client: GTIClient, credential: CredentialMaterial
    ) -> ProviderQuotaSnapshot | None:
        """Read quota only when Task 6's store has nothing fresh.

        Returning ``None`` means "no refresh needed", which keeps normal
        enrichment at one API call per uncached lookup. A failure here is
        swallowed on purpose: quota is useful context, and losing it must not
        turn a successful IOC lookup into a failed one.
        """
        if not self._lookup_policy.quota_refresh_enabled:
            return None
        if self._quota_store is not None:
            existing = await self._quota_store.get(self._scope_identity(credential))
            if existing is not None:
                return None
        try:
            payload = await client.get_quota()
        except ProviderError as error:
            # Logged without the endpoint: the path contains the API key.
            _logger.info(
                "GTI quota lookup failed",
                extra={
                    "provider": GTI_PROVIDER_ID,
                    "error_category": error.category.value,
                    "provider_error_code": error.provider_error_code,
                },
            )
            return None
        reading = self._reading_from(payload, credential)
        if self._quota_store is not None:
            await self._quota_store.put(self._scope_identity(credential), reading.snapshot)
        return reading.snapshot

    @staticmethod
    def _scope_identity(credential: CredentialMaterial) -> str:
        """The Task 6 scope key for this credential.

        Rebuilt from ids only, and identical to what the executor derives, so
        both sides address the same quota entry.
        """
        return ExecutionScope.for_user(
            provider_id=GTI_PROVIDER_ID,
            user_id=credential.user_id,
            provider_connection_id=credential.connection_id,
        ).identity

    # ------------------------------------------------------------------ #
    # Lookup
    # ------------------------------------------------------------------ #

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        """Passive enrichment of one observable.

        One GTI object fetch, plus a quota refresh only when Task 6's store has
        gone stale. Nothing is submitted, rescanned or downloaded.

        A ``NotFoundError`` is turned into a ``NO_DATA`` envelope rather than
        being allowed to propagate. Both routes report NO_DATA, but an envelope
        can be negatively cached, so an unknown hash costs one API call rather
        than one per investigation that asks about it. NO_DATA means "GTI has
        never seen this" — never that the observable is benign.
        """
        if credential is None:
            raise ProviderInvalidRequestError(
                GTI_PROVIDER_ID,
                message="GTI requires a credential",
                operation="lookup",
            )
        collection, object_id = self._locate(request.intel_object)

        async with self._client_for(credential) as client:
            try:
                gti_object = await client.get_primary_object(
                    collection=collection,
                    object_id=object_id,
                    exclude_attributes=self._lookup_policy.excluded_attributes,
                )
            except ProviderError as error:
                if error.category is ProviderErrorCategory.NOT_FOUND:
                    return self._no_data_envelope(request)
                raise
            enrichment = await self._expand_relationships(
                client, request, collection, object_id, gti_object
            )
            enrichment = enrichment.merge(await self._file_behavior(client, request, object_id))
            quota = await self._refresh_quota_if_stale(client, credential)

        return self._envelope(request, gti_object, quota=quota, extra=enrichment)

    def _locate(self, intel_object: IntelObject) -> tuple[str, str]:
        """The GTI collection and object id for an observable.

        A URL becomes an opaque identifier here, which is what keeps the URL
        under investigation out of every request path TI Recon builds.
        """
        collection = collection_for_object_type(intel_object.object_type)
        if collection is None:
            raise UnsupportedProviderOperation(
                GTI_PROVIDER_ID,
                operation=f"lookup for {intel_object.object_type.value}",
            )
        if intel_object.object_type is IntelObjectType.URL:
            return collection, url_identifier(intel_object.canonical_value)
        if intel_object.object_type is IntelObjectType.FILE:
            return collection, self._file_identifier(intel_object)
        return collection, intel_object.canonical_value

    @staticmethod
    def _file_identifier(intel_object: IntelObject) -> str:
        """The hash GTI should be asked about.

        The strongest available, because a SHA-256 identifies a file
        unambiguously where an MD5 can collide. Falls back to the canonical
        value for a file object whose hashes were recorded elsewhere.
        """
        best = strongest_hash(intel_object.hashes)
        return best[1] if best is not None else intel_object.canonical_value

    def _envelope(
        self,
        request: ProviderRequest,
        gti_object: GTIObject,
        *,
        quota: ProviderQuotaSnapshot | None,
        extra: GTINormalization | None = None,
    ) -> ProviderResultEnvelope:
        raw_reference = self._raw_reference(request, gti_object)
        normalization = self._normalize(request, gti_object, raw_reference=raw_reference)
        if extra is not None:
            normalization = normalization.merge(extra)
        return ProviderResultEnvelope.from_payload(
            provider=GTI_PROVIDER_ID,
            operation=request.operation,
            # A recognized field that would not parse degrades the result to
            # PARTIAL rather than failing it. The evidence that did parse is
            # still worth having, and Task 6 keeps a partial result's evidence
            # while declining to cache it.
            status=(
                ProviderRunStatus.PARTIAL if normalization.degraded else ProviderRunStatus.SUCCESS
            ),
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            payload=_payload_of(normalization),
            raw_reference=raw_reference,
            quota=quota,
        )

    def _no_data_envelope(self, request: ProviderRequest) -> ProviderResultEnvelope:
        return ProviderResultEnvelope.from_payload(
            provider=GTI_PROVIDER_ID,
            operation=request.operation,
            status=ProviderRunStatus.NO_DATA,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            payload=NormalizedPayload(),
        )

    def _raw_reference(
        self, request: ProviderRequest, gti_object: GTIObject
    ) -> RawEvidenceReference:
        """A pointer to the response, carrying no response and no credential.

        The storage key names the collection and object id — never the quota
        path, never a header, never the API key.
        """
        return RawEvidenceReference(
            investigation_id=request.investigation_id,
            provider=GTI_PROVIDER_ID,
            operation=request.operation,
            storage_key=(
                f"gti/{gti_object.object_type}/{gti_object.object_id}/{request.operation.value}"
            ),
            retrieved_at=self._clock.now(),
        )

    def _normalize(
        self,
        request: ProviderRequest,
        gti_object: GTIObject,
        *,
        raw_reference: RawEvidenceReference | None,
    ) -> GTINormalization:
        """Normalize one GTI object into Task 3 models.

        The assessment and the analysis statistics are normalized
        independently, so a missing or unreadable assessment still leaves the
        aggregated reputation, and vice versa. Neither produces a verdict.
        """
        context = NormalizationContext(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            now=self._clock.now(),
            raw_reference_id=raw_reference.id if raw_reference else None,
        )
        enriched = enrich_primary_object(request.intel_object, gti_object)
        result = GTINormalization(objects=(enriched,))
        result = result.merge(normalize_assessment(context, gti_object))
        return result.merge(normalize_analysis_stats(context, gti_object))

    # ------------------------------------------------------------------ #
    # Relationship expansion
    # ------------------------------------------------------------------ #

    async def _expand_relationships(
        self,
        client: GTIClient,
        request: ProviderRequest,
        collection: str,
        object_id: str,
        gti_object: GTIObject,
    ) -> GTINormalization:
        """Fetch and normalize the relationships this depth permits.

        Bounded three ways at once: how many relationship types, how many
        results per type, and how many related objects in total. Pagination is
        never followed — one page per relationship, and the running total stops
        the walk early rather than trimming afterwards, so a cap actually
        prevents calls rather than discarding their results.
        """
        depth = depth_for_investigation(request.depth)
        limits = self._limits_for(request, depth)
        context = self._context(request)
        subject = request.intel_object

        # Free of charge: anything GTI already inlined in the primary response.
        result = normalize_inline_relationships(
            context,
            subject,
            gti_object,
            RELATIONSHIP_SPECS,
            max_per_relationship=limits.max_results_per_relationship,
        )
        if not limits.expands:
            return result

        remaining = limits.max_total_related_objects - len(result.objects)
        plan = relationship_plan(
            subject.object_type,
            depth,
            limits=limits,
            capabilities=request.requested_capabilities,
        )
        for spec in plan:
            if remaining <= 0:
                break
            page = min(self._page_size(spec, limits, depth), remaining)
            items = await self._fetch_related(client, collection, object_id, spec, page, depth)
            if items is None:
                # A plan limitation or a missing relationship: the primary
                # lookup stays useful, so it is recorded and skipped.
                result = result.merge(GTINormalization(warnings=(_degraded_warning(spec),)))
                continue
            normalized = normalize_related_items(context, subject, spec, items)
            result = result.merge(normalized)
            remaining -= len(normalized.objects)
        return result

    def _limits_for(
        self, request: ProviderRequest, depth: GTIRelationshipDepth
    ) -> GTIRelationshipLimits:
        """Depth limits, tightened by the request's own ceilings.

        ``max_results`` only ever narrows: a request asking for more than the
        depth allows does not get to raise the provider's safety cap.
        """
        base = LIMITS_BY_DEPTH[depth]
        if request.max_results is None:
            return base
        return base.model_copy(
            update={
                "max_results_per_relationship": min(
                    base.max_results_per_relationship, request.max_results
                ),
                "max_total_related_objects": min(
                    base.max_total_related_objects, request.max_results
                ),
            }
        )

    @staticmethod
    def _page_size(
        spec: GTIRelationshipSpec,
        limits: GTIRelationshipLimits,
        depth: GTIRelationshipDepth,
    ) -> int:
        """How many results to ask for, tighter for expanded threat objects."""
        if (
            spec.target_kind is TargetKind.THREAT_OBJECT
            and spec.retrieval_at(depth) is Retrieval.OBJECTS
        ):
            return min(
                limits.max_results_per_relationship,
                limits.max_threat_objects_per_relationship,
            )
        return limits.max_results_per_relationship

    async def _fetch_related(
        self,
        client: GTIClient,
        collection: str,
        object_id: str,
        spec: GTIRelationshipSpec,
        limit: int,
        depth: GTIRelationshipDepth,
    ) -> list[RelatedItem] | None:
        """One relationship's page, or ``None`` if GTI would not serve it.

        Descriptor-first: full objects only where the target cannot be
        identified without an attribute, or where a DEEP investigation is paying
        to name a threat collection.
        """
        try:
            if spec.retrieval_at(depth) is Retrieval.DESCRIPTORS:
                descriptors = await client.get_relationship_descriptors(
                    collection=collection,
                    object_id=object_id,
                    relationship=spec.name,
                    limit=limit,
                )
                return [RelatedItem.from_descriptor(item) for item in descriptors]
            objects = await client.get_relationship_objects(
                collection=collection,
                object_id=object_id,
                relationship=spec.name,
                limit=limit,
            )
        except ProviderError as error:
            if error.category in _DEGRADABLE_CATEGORIES:
                _logger.info(
                    "GTI relationship unavailable",
                    extra={
                        "provider": GTI_PROVIDER_ID,
                        "relationship": spec.name,
                        "error_category": error.category.value,
                    },
                )
                return None
            # Anything else is Task 6's decision, not ours to swallow.
            raise
        return [RelatedItem.from_object(item) for item in objects]

    async def _file_behavior(
        self, client: GTIClient, request: ProviderRequest, object_id: str
    ) -> GTINormalization:
        """Sandbox behaviour, for deep file investigations only.

        Three conditions, all required: the observable is a file, the
        investigation is DEEP, and the caller asked for FILE_BEHAVIOR. Detonation
        data is the most expensive and most entitlement-sensitive thing GTI
        offers, so it is never pulled speculatively.

        Only the aggregated summary is read — never the individual sandbox
        reports, of which there can be many per sample.
        """
        if request.intel_object.object_type is not IntelObjectType.FILE:
            return GTINormalization()
        if request.depth is not InvestigationDepth.DEEP:
            return GTINormalization()
        if ProviderCapability.FILE_BEHAVIOR not in request.requested_capabilities:
            return GTINormalization()

        limits = LIMITS_BY_DEPTH[GTIRelationshipDepth.DEEP]
        try:
            summary = await client.get_file_behavior_summary(file_id=object_id)
        except ProviderError as error:
            if error.category in _DEGRADABLE_CATEGORIES:
                _logger.info(
                    "GTI file behaviour unavailable",
                    extra={
                        "provider": GTI_PROVIDER_ID,
                        "error_category": error.category.value,
                    },
                )
                return GTINormalization(warnings=("GTI_FILE_BEHAVIOR_UNAVAILABLE",))
            raise
        return normalize_file_behavior(
            self._context(request),
            request.intel_object,
            summary,
            max_per_source=limits.max_results_per_relationship,
        )

    def _context(self, request: ProviderRequest) -> NormalizationContext:
        return NormalizationContext(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            now=self._clock.now(),
        )

    def normalize(
        self,
        request: ProviderRequest,
        payload: Mapping[str, object],
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizedPayload:
        """Turn a stored GTI payload into Task 3 models.

        The pure, synchronous half of ``lookup``: it accepts the raw response
        body so normalization can be tested against a fixture with no client
        and no network.
        """
        gti_object = GTIObject(
            object_type=str(payload.get("type", request.intel_object.object_type.value)),
            object_id=str(payload.get("id", request.intel_object.canonical_value)),
            attributes=_mapping(payload.get("attributes")),
            relationships=_mapping(payload.get("relationships")),
            context_attributes=_mapping(payload.get("context_attributes")),
        )
        return _payload_of(self._normalize(request, gti_object, raw_reference=raw_reference))

    def classify_error(self, error: Exception) -> ProviderErrorCategory:
        """Normalize an exception the client did not already translate.

        The client raises normalized errors, so this is the safety net for
        anything unexpected escaping it rather than the main mapping path.
        """
        if isinstance(error, ProviderError):
            return error.category
        if isinstance(error, TimeoutError):
            return ProviderErrorCategory.TRANSIENT_ERROR
        if isinstance(error, ValueError):
            # A payload we could not read is a schema problem, and retrying an
            # unreadable response cannot help.
            return ProviderErrorCategory.SCHEMA_ERROR
        return ProviderErrorCategory.UNKNOWN_ERROR

    # ------------------------------------------------------------------ #
    # Client plumbing
    # ------------------------------------------------------------------ #

    def _client_for(self, credential: CredentialMaterial) -> _ClientScope:
        """A client bound to this credential, closed when the block ends."""
        return _ClientScope(self._client_factory.create(credential.secret))

    def __repr__(self) -> str:
        return (
            f"<GTIAdapter host={self._config.host} "
            f"adapter_version={self._descriptor.adapter_version}>"
        )


class _ClientScope:
    """Async context manager that always closes the client it was given.

    A thin wrapper rather than relying on the client's own ``__aenter__``,
    because :class:`GTIClient` is a protocol and an implementation is not
    required to be a context manager.
    """

    def __init__(self, client: GTIClient) -> None:
        self._client = client

    async def __aenter__(self) -> GTIClient:
        return self._client

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self._client.close()


#: Relationship failures that leave the primary lookup usable. An Enterprise
#: relationship this key cannot see, or one GTI does not offer for this object,
#: is a coverage gap rather than a failed enrichment.
_DEGRADABLE_CATEGORIES = frozenset(
    {
        ProviderErrorCategory.PLAN_LIMITED,
        ProviderErrorCategory.PERMISSION_ERROR,
        ProviderErrorCategory.NOT_FOUND,
        ProviderErrorCategory.INVALID_REQUEST,
    }
)


def _degraded_warning(spec: GTIRelationshipSpec) -> str:
    """A safe, greppable marker naming the relationship we could not read."""
    return f"GTI_RELATIONSHIP_UNAVAILABLE:{spec.name}"


def _payload_of(normalization: GTINormalization) -> NormalizedPayload:
    """Project a GTI normalization onto the Task 5 payload shape."""
    return NormalizedPayload(
        evidence=normalization.evidence,
        objects=normalization.objects,
        relationships=normalization.relationships,
        warnings=normalization.warnings,
    )


def _mapping(value: object) -> dict[str, object]:
    """A plain mapping, or an empty one when GTI sent something else."""
    return dict(value) if isinstance(value, Mapping) else {}
