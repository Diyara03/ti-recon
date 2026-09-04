"""The Censys provider adapter (Task 9).

Implements the Task 5 :class:`ProviderAdapter` contract over the Censys Platform
API's host and web-property endpoints. It normalizes and classifies; it decides
nothing about maliciousness, and it does not retry — Task 6's executor owns
retry, backoff, caching, cooldown, concurrency and quota state.

One deterministic request per lookup
------------------------------------

An observable maps onto exactly one Censys asset identity — an address, or a
``hostname:port`` — and that identity is derived by
:mod:`ti_recon.providers.censys.assets` with no search, no ranking and no
candidate selection. One lookup is therefore one asset read, which costs one
credit, and depth changes how much of the returned document is normalized rather
than how many requests are made.

The credit balance is read separately, from an endpoint that costs nothing, and
only when Task 6's quota store has nothing fresh. That is what makes it possible
to notice an empty wallet without spending the last credit to find out.

Censys is not a verdict source
------------------------------

Every piece of evidence this adapter produces is context. An open port is not an
accusation, a reported CVE is not a compromise, and a Censys label is not a
classification. The reasoning lives in
:mod:`ti_recon.providers.censys.normalizer`, where the model itself enforces most
of it.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    ActivityMode,
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    ObjectClass,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution.clock import Clock, SystemClock
from ti_recon.execution.limits import QuotaStore
from ti_recon.execution.models import ExecutionScope
from ti_recon.models.evidence import RawEvidenceReference
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.adapter import (
    CapabilityDiscovery,
    CredentialValidation,
    ProviderAdapter,
    ProviderHealthReport,
)
from ti_recon.providers.capabilities import ProviderHealth
from ti_recon.providers.censys.assets import (
    CensysAsset,
    CensysAssetKind,
    asset_for,
    unsupported_reason_for,
)
from ti_recon.providers.censys.client import (
    CensysClient,
    CensysHttpClient,
    CensysJsonResult,
)
from ti_recon.providers.censys.config import CensysConfig
from ti_recon.providers.censys.credits import (
    CensysCreditReading,
    CensysCreditScope,
    parse_credits,
)
from ti_recon.providers.censys.descriptor import (
    CENSYS_PROVIDER_ID,
    build_censys_descriptor,
)
from ti_recon.providers.censys.errors import credential_validation_for
from ti_recon.providers.censys.normalizer import (
    CensysDocument,
    CensysNormalization,
    NormalizationContext,
    build_evidence,
    enrich_host_object,
    enrich_web_property_object,
    normalize_dns_names,
    normalize_host_observation,
    normalize_labels,
    normalize_network_ownership,
    normalize_not_observed,
    normalize_services,
    normalize_tls_certificates,
    normalize_vulnerabilities,
    normalize_web_property_observation,
)
from ti_recon.providers.censys.organizations import OrganizationDirectory
from ti_recon.providers.censys.policy import (
    CensysDetail,
    CensysLookupPolicy,
    detail_for_depth,
)
from ti_recon.providers.descriptor import ProviderDescriptor
from ti_recon.providers.errors import (
    ProviderError,
    ProviderInvalidRequestError,
    UnsupportedProviderOperation,
)
from ti_recon.providers.quota import ProviderQuotaSnapshot
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import NormalizedPayload, ProviderResultEnvelope
from ti_recon.providers.transport import ProviderTransportError

__all__ = [
    "CENSYS_DOCUMENT_UNREADABLE",
    "CENSYS_NOT_SUPPORTED",
    "UNSUPPORTED_REASONS",
    "CensysAdapter",
    "CensysClientFactory",
]

_logger = logging.getLogger(__name__)

#: Reported when the observable has no deterministic Censys asset — a bare
#: domain, a file hash, an ``ftp`` URL. A coverage gap, never an absence of
#: findings, and :func:`~ti_recon.providers.censys.assets.unsupported_reason_for`
#: says which case it was.
CENSYS_NOT_SUPPORTED: Final[str] = "CENSYS_OBSERVABLE_NOT_SUPPORTED"

#: Reported when a response carried no asset this adapter could read.
CENSYS_DOCUMENT_UNREADABLE: Final[str] = "CENSYS_DOCUMENT_UNREADABLE"

#: Kept for symmetry with the other providers: the warning-to-reason table an
#: envelope quotes. Censys's reasons are per-observable, so the table holds the
#: generic form and the specific sentence comes from the asset module.
UNSUPPORTED_REASONS: Final[dict[str, str]] = {
    CENSYS_NOT_SUPPORTED: "Censys has no deterministic asset identity for this observable"
}


class CensysClientFactory(Protocol):
    """Builds the client one lookup will use."""

    def __call__(self) -> CensysClient: ...


class _DefaultClientFactory:
    """Creates a real HTTP client pinned to the Censys Platform API."""

    def __init__(self, config: CensysConfig) -> None:
        self._config = config

    def __call__(self) -> CensysClient:
        return CensysHttpClient(self._config)


@dataclass(frozen=True, slots=True)
class _Anchor:
    """The object an asset's relationships hang off.

    Usually the submitted observable. For an address-literal URL it is the
    address the URL points at, created here as a derived object — because a URL
    does not belong to an autonomous system and a PTR record does not resolve to
    a page. ``extra`` is that derived object when one was needed.
    """

    object_id: str
    extra: IntelObject | None = None


class CensysAdapter(ProviderAdapter):
    """Passive Censys exposure enrichment for addresses and HTTP(S) URLs."""

    def __init__(
        self,
        *,
        client_factory: CensysClientFactory | None = None,
        config: CensysConfig | None = None,
        lookup_policy: CensysLookupPolicy | None = None,
        organizations: OrganizationDirectory | None = None,
        quota_store: QuotaStore | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._config = CensysConfig() if config is None else config
        self._client_factory: CensysClientFactory = (
            _DefaultClientFactory(self._config) if client_factory is None else client_factory
        )
        self._lookup_policy = CensysLookupPolicy() if lookup_policy is None else lookup_policy
        # Injected rather than constructed: an organization id belongs to a
        # provider connection, and only the credential layer knows those.
        self._organizations = organizations
        # Task 6's own quota store, shared so the executor's pre-check and this
        # adapter's refresh agree on both the key and the freshness window.
        self._quota_store = quota_store
        self._clock = SystemClock() if clock is None else clock
        self._descriptor = build_censys_descriptor()

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    @property
    def config(self) -> CensysConfig:
        return self._config

    @property
    def lookup_policy(self) -> CensysLookupPolicy:
        return self._lookup_policy

    # ------------------------------------------------------------------ #
    # Credentials, capabilities, health
    # ------------------------------------------------------------------ #

    async def validate_credentials(
        self, credential: CredentialMaterial | None
    ) -> CredentialValidation:
        """Check a token by reading its own credit balance.

        The credit endpoints cost zero credits, which makes this the only way to
        validate a Censys token without charging the analyst for the answer.
        Looking up a well-known asset instead would work and would spend a
        credit every time somebody checked whether their key was still good.

        Only a rejected token is reported invalid — an empty wallet or a
        permission refusal means the token is fine and something else is in the
        way. See
        :func:`~ti_recon.providers.censys.errors.credential_status_for`.
        """
        if credential is None:
            return CredentialValidation(
                provider_id=CENSYS_PROVIDER_ID,
                status=CredentialStatus.INVALID,
                detail="no credential supplied",
            )
        try:
            await self.fetch_credits(credential)
        except ProviderError as error:
            return credential_validation_for(CENSYS_PROVIDER_ID, error)
        return credential_validation_for(CENSYS_PROVIDER_ID)

    async def discover_capabilities(
        self, credential: CredentialMaterial | None
    ) -> CapabilityDiscovery:
        """Report what the integration supports, without probing the account.

        Deliberately free of API calls. What a specific token may see is
        discovered at request time, where a refusal becomes a permission fact for
        that asset and leaves the rest usable.
        """
        return CapabilityDiscovery(
            provider_id=CENSYS_PROVIDER_ID,
            capabilities=frozenset(self._descriptor.capabilities),
            plan_hint="direct asset lookups only; search is not enabled",
        )

    async def health(self, credential: CredentialMaterial | None = None) -> ProviderHealthReport:
        """Report availability, checking only if a credential is available."""
        if credential is None:
            return ProviderHealthReport(
                provider_id=CENSYS_PROVIDER_ID, health=ProviderHealth.UNKNOWN
            )
        try:
            await self.fetch_credits(credential)
        except ProviderError as error:
            unavailable = error.category in {
                ProviderErrorCategory.PROVIDER_UNAVAILABLE,
                ProviderErrorCategory.TRANSIENT_ERROR,
            }
            return ProviderHealthReport(
                provider_id=CENSYS_PROVIDER_ID,
                health=ProviderHealth.UNAVAILABLE if unavailable else ProviderHealth.DEGRADED,
                detail=f"credit lookup returned {error.category.value}",
            )
        return ProviderHealthReport(provider_id=CENSYS_PROVIDER_ID, health=ProviderHealth.AVAILABLE)

    # ------------------------------------------------------------------ #
    # Credits
    # ------------------------------------------------------------------ #

    async def fetch_credits(self, credential: CredentialMaterial) -> CensysCreditReading:
        """Read this credential's credit balance. Costs nothing.

        Reads the organization balance when this connection names an
        organization, and the user balance otherwise. The organization id comes
        from the connection's own metadata, resolved per user — see
        :mod:`ti_recon.providers.censys.organizations`.
        """
        client = self._client_factory()
        try:
            return await self._read_credits(client, credential)
        finally:
            await client.aclose()

    async def _read_credits(
        self, client: CensysClient, credential: CredentialMaterial
    ) -> CensysCreditReading:
        organization_id = await self._organization_id(credential)
        if organization_id is not None:
            result = await client.get_organization_credits(
                organization_id=organization_id, credential=credential
            )
            scope = CensysCreditScope.ORGANIZATION
        else:
            result = await client.get_user_credits(credential=credential)
            scope = CensysCreditScope.USER
        return self._reading_from(result, credential, scope)

    def _reading_from(
        self,
        result: CensysJsonResult,
        credential: CredentialMaterial,
        scope: CensysCreditScope,
    ) -> CensysCreditReading:
        return parse_credits(
            result.payload,
            scope=scope,
            user_id=credential.user_id,
            provider_connection_id=credential.connection_id,
            retrieved_at=self._clock.now(),
        )

    async def _refresh_credits_if_stale(
        self, client: CensysClient, credential: CredentialMaterial
    ) -> CensysCreditReading | None:
        """Read the balance only when Task 6's store has nothing fresh.

        ``None`` means "nothing was read" — either the store already had a
        snapshot or the call failed. A failure here is swallowed on purpose: the
        balance is useful context, and losing it must not turn a successful asset
        lookup into a failed one. The endpoint is free, so the only cost of
        reading it is a round trip.
        """
        if not self._lookup_policy.credit_refresh_enabled:
            return None
        if self._quota_store is not None:
            existing = await self._quota_store.get(self._scope_identity(credential))
            if existing is not None:
                return None
        try:
            reading = await self._read_credits(client, credential)
        except ProviderError as error:
            _logger.info(
                "censys credit lookup failed",
                extra={
                    "provider": CENSYS_PROVIDER_ID,
                    "error_category": error.category.value,
                    "provider_error_code": error.provider_error_code,
                },
            )
            return None
        if self._quota_store is not None:
            await self._quota_store.put(self._scope_identity(credential), reading.snapshot)
        return reading

    async def _organization_id(self, credential: CredentialMaterial) -> str | None:
        if self._organizations is None:
            return None
        return await self._organizations.organization_id_for(
            user_id=credential.user_id, connection_id=credential.connection_id
        )

    @staticmethod
    def _scope_identity(credential: CredentialMaterial) -> str:
        """The Task 6 scope key for this credential, rebuilt from ids only."""
        return ExecutionScope.for_user(
            provider_id=CENSYS_PROVIDER_ID,
            user_id=credential.user_id,
            provider_connection_id=credential.connection_id,
        ).identity

    # ------------------------------------------------------------------ #
    # Lookup
    # ------------------------------------------------------------------ #

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        """Passive enrichment of one asset from Censys's last observation.

        One direct read of one deterministic asset identity. Nothing is searched,
        nothing is rescanned, and no live discovery is triggered.
        """
        if credential is None:
            raise ProviderInvalidRequestError(
                CENSYS_PROVIDER_ID, message="censys requires a credential", operation="lookup"
            )
        if (
            request.activity_mode is ActivityMode.ACTIVE
            or request.operation is ProviderOperation.ACTIVE_ACTION
        ):
            # Refusing here as well as in ``active_action`` means a caller
            # bypassing the executor still cannot turn a passive integration
            # into an active one.
            raise UnsupportedProviderOperation(CENSYS_PROVIDER_ID, operation="active_action")

        asset = asset_for(request.intel_object)
        if asset is None:
            # No request is made, so this is not "we looked and found nothing".
            return self._unsupported_envelope(request)

        detail = detail_for_depth(request.depth, self._lookup_policy)
        # Derived once and threaded through: the anchor may *create* an object,
        # so building it twice would mint two ids for one address and leave the
        # relationships pointing at whichever copy came last.
        anchor = self._anchor(request, asset)
        client = self._client_factory()
        try:
            credits = await self._refresh_credits_if_stale(client, credential)
            quota = credits.snapshot if credits is not None else None
            try:
                result = await self._read_asset(client, asset, credential)
            except ProviderError as error:
                if error.category is not ProviderErrorCategory.NOT_FOUND:
                    raise
                return self._not_observed_envelope(request, asset, detail, credits, quota, anchor)
        finally:
            await client.aclose()

        document = CensysDocument(result.payload)
        normalization = self._coverage(request, asset, detail, credits, anchor)
        normalization = normalization.merge(
            self._normalize_document(request, asset, document, detail, anchor)
        )
        status = ProviderRunStatus.PARTIAL if normalization.degraded else ProviderRunStatus.SUCCESS
        return self._envelope(request, normalization, status=status, quota=quota)

    @staticmethod
    async def _read_asset(
        client: CensysClient, asset: CensysAsset, credential: CredentialMaterial
    ) -> CensysJsonResult:
        """The one request this lookup makes."""
        if asset.kind is CensysAssetKind.HOST:
            return await client.get_host(ip=asset.address or "", credential=credential)
        return await client.get_web_property(
            hostname=asset.hostname or "", port=asset.port or 0, credential=credential
        )

    def _not_observed_envelope(
        self,
        request: ProviderRequest,
        asset: CensysAsset,
        detail: CensysDetail,
        credits: CensysCreditReading | None,
        quota: ProviderQuotaSnapshot | None,
        anchor: _Anchor,
    ) -> ProviderResultEnvelope:
        """A lookup that ran and found no such asset.

        ``NO_DATA``, carrying the coverage evidence and an explicit record that
        Censys has no observation — which is a statement about Censys's
        visibility, not about the asset's safety.
        """
        context = self._context(request, asset, anchor)
        normalization = self._coverage(request, asset, detail, credits, anchor).merge(
            normalize_not_observed(
                context, asset_kind=asset.kind.value, asset_identifier=asset.identifier
            )
        )
        if anchor.extra is not None:
            normalization = normalization.merge(CensysNormalization(objects=(anchor.extra,)))
        return self._envelope(request, normalization, status=ProviderRunStatus.NO_DATA, quota=quota)

    # ------------------------------------------------------------------ #
    # Normalization
    # ------------------------------------------------------------------ #

    def _normalize_document(
        self,
        request: ProviderRequest,
        asset: CensysAsset,
        document: CensysDocument,
        detail: CensysDetail,
        anchor: _Anchor,
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> CensysNormalization:
        """Every normalization pass over one asset document.

        Each pass is independent, so one missing or unreadable block still
        leaves the others. None of them produces a verdict — none of them can.
        """
        context = self._context(request, asset, anchor, raw_reference=raw_reference)
        if document.is_empty:
            return CensysNormalization(warnings=(CENSYS_DOCUMENT_UNREADABLE,), degraded=True)

        objects: tuple[IntelObject, ...] = (self._enriched(request, asset, document),)
        if anchor.extra is not None:
            objects = (*objects, anchor.extra)
        result = CensysNormalization(objects=objects)

        if asset.kind is CensysAssetKind.HOST:
            result = result.merge(
                normalize_host_observation(context, document, max_ports=detail.max_ports)
            )
            # Ownership and reverse DNS describe an *address*. They are read for
            # host assets only: a web property is a name on a port, and asking
            # which autonomous system a hostname belongs to would attach a fact
            # about the address behind it to the wrong object.
            result = result.merge(normalize_network_ownership(context, document))
            if detail.include_services:
                result = result.merge(
                    normalize_services(
                        context,
                        document,
                        max_services=detail.max_services,
                        include_software=detail.include_software,
                    )
                )
            if detail.include_dns:
                result = result.merge(
                    normalize_dns_names(context, document, max_names=detail.max_dns_names)
                )
        else:
            result = result.merge(
                normalize_web_property_observation(
                    context,
                    document,
                    max_endpoints=detail.max_endpoints,
                    include_software=detail.include_software,
                )
            )

        if detail.include_tls:
            result = result.merge(
                normalize_tls_certificates(
                    context, document, max_certificates=detail.max_certificates
                )
            )
        if detail.include_labels:
            result = result.merge(normalize_labels(context, document, max_labels=detail.max_labels))
        if detail.include_vulnerabilities:
            result = result.merge(
                normalize_vulnerabilities(
                    context, document, max_vulnerabilities=detail.max_vulnerabilities
                )
            )
        return result

    def _enriched(
        self, request: ProviderRequest, asset: CensysAsset, document: CensysDocument
    ) -> IntelObject:
        if asset.kind is CensysAssetKind.HOST:
            return enrich_host_object(request.intel_object, document)
        return enrich_web_property_object(request.intel_object, document)

    def _coverage(
        self,
        request: ProviderRequest,
        asset: CensysAsset,
        detail: CensysDetail,
        credits: CensysCreditReading | None,
        anchor: _Anchor,
    ) -> CensysNormalization:
        """Record which asset was read, and how much of it was kept.

        "Censys knows nothing about this" means one thing for an address and
        another for a ``hostname:port``, and it means something different again
        when the asset that answered was derived from a URL's address literal.
        Only this says which happened, and the match scope on every other piece
        of evidence agrees with it.
        """
        attributes: dict[str, Any] = {
            "depth": request.depth.value,
            "asset_kind": asset.kind.value,
            "asset": asset.identifier,
            "match_scope": asset.match_scope.value,
            "max_services": detail.max_services,
            "max_dns_names": detail.max_dns_names,
            "max_certificates": detail.max_certificates,
            "max_endpoints": detail.max_endpoints,
        }
        if request.intel_object.object_type is IntelObjectType.URL:
            # The one case where the asset is not the observable's own identity.
            attributes["derived_from"] = "url_authority"
        if credits is not None:
            attributes["credit_scope"] = credits.scope.value
            if credits.remaining is not None:
                attributes["credits_remaining"] = credits.remaining
        evidence = build_evidence(
            self._context(request, asset, anchor),
            evidence_class=EvidenceClass.CONTEXT,
            claim_type="censys_asset_coverage",
            effect=EvidenceEffect.CONTEXT_ONLY,
            attributes=attributes,
        )
        return CensysNormalization(evidence=(evidence,))

    def _anchor(self, request: ProviderRequest, asset: CensysAsset) -> _Anchor:
        """The object this asset's relationships belong to.

        The submitted observable, except when a URL was looked up as a host: then
        the address is a *derived* object and the links hang off it, because a
        URL does not belong to an autonomous system and a reverse-DNS name does
        not resolve to a page.
        """
        subject = request.intel_object
        if asset.kind is not CensysAssetKind.HOST:
            return _Anchor(object_id=subject.id)
        is_the_address = (
            subject.object_type in {IntelObjectType.IPV4_ADDR, IntelObjectType.IPV6_ADDR}
            and subject.canonical_value == asset.address
        )
        if is_the_address:
            return _Anchor(object_id=subject.id)
        derived = IntelObject(
            object_class=ObjectClass.INFRASTRUCTURE,
            object_type=(
                IntelObjectType.IPV6_ADDR
                if ":" in (asset.address or "")
                else IntelObjectType.IPV4_ADDR
            ),
            canonical_value=asset.address or "",
            display_value=asset.address or "",
        )
        return _Anchor(object_id=derived.id, extra=derived)

    def _context(
        self,
        request: ProviderRequest,
        asset: CensysAsset,
        anchor: _Anchor,
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizationContext:
        return NormalizationContext(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            now=self._clock.now(),
            anchor_object_id=anchor.object_id,
            # Decided once, by the asset mapping, so "we asked about the host,
            # not the page" cannot be lost on the way to the evidence.
            match_scope=asset.match_scope,
            raw_reference_id=raw_reference.id if raw_reference else None,
        )

    # ------------------------------------------------------------------ #
    # Contract helpers
    # ------------------------------------------------------------------ #

    def normalize(
        self,
        request: ProviderRequest,
        payload: Mapping[str, object],
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizedPayload:
        """Turn one asset document into Task 3 models. Pure, no I/O.

        An observable with no Censys asset normalizes to nothing rather than
        raising: this is the pure helper, and refusing here would make it
        impossible to test a document against an unrelated request.
        """
        asset = asset_for(request.intel_object)
        if asset is None:
            return NormalizedPayload(warnings=(CENSYS_NOT_SUPPORTED,))
        normalization = self._normalize_document(
            request,
            asset,
            CensysDocument(payload),
            detail_for_depth(request.depth, self._lookup_policy),
            self._anchor(request, asset),
            raw_reference=raw_reference,
        )
        return _payload_of(normalization)

    def classify_error(self, error: Exception) -> ProviderErrorCategory:
        """Map a failure onto a normalized category.

        Transport security failures are reported as invalid requests rather than
        as provider problems: refusing to leave Censys's host is our decision,
        not Censys misbehaving.
        """
        if isinstance(error, ProviderTransportError):
            return ProviderErrorCategory.INVALID_REQUEST
        if isinstance(error, ProviderError):
            return error.category
        if isinstance(error, TimeoutError):
            return ProviderErrorCategory.TRANSIENT_ERROR
        return ProviderErrorCategory.UNKNOWN_ERROR

    def _unsupported_envelope(self, request: ProviderRequest) -> ProviderResultEnvelope:
        """A run that was never attempted, said plainly.

        ``NOT_SUPPORTED`` rather than ``NO_DATA``, and it carries the specific
        reason: a future coverage layer reads this as ``NOT_APPLICABLE`` for the
        capability, not as a covered lookup that found nothing. "Censys cannot be
        asked about a bare domain" and "Censys has never scanned this address"
        are different statements, and collapsing them would let a blind spot read
        as a clean result.
        """
        return ProviderResultEnvelope(
            provider=CENSYS_PROVIDER_ID,
            operation=request.operation,
            status=ProviderRunStatus.NOT_SUPPORTED,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            warnings=(CENSYS_NOT_SUPPORTED,),
            error_message=unsupported_reason_for(request.intel_object)[:500],
        )

    def _envelope(
        self,
        request: ProviderRequest,
        normalization: CensysNormalization,
        *,
        status: ProviderRunStatus,
        quota: ProviderQuotaSnapshot | None = None,
    ) -> ProviderResultEnvelope:
        return ProviderResultEnvelope.from_payload(
            provider=CENSYS_PROVIDER_ID,
            operation=request.operation,
            status=status,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            payload=_payload_of(normalization),
            quota=quota,
        )


def _payload_of(normalization: CensysNormalization) -> NormalizedPayload:
    return NormalizedPayload(
        evidence=normalization.evidence,
        objects=normalization.objects,
        relationships=normalization.relationships,
        warnings=normalization.warnings,
    )
