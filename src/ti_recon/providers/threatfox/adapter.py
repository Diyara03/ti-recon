"""The ThreatFox provider adapter (Task 10).

Implements the Task 5 :class:`ProviderAdapter` contract over ThreatFox's IOC and
hash searches. It normalizes and classifies; it decides nothing about
maliciousness, and it does not retry — Task 6's executor owns retry, backoff,
caching, cooldown, concurrency and quota state.

One request per lookup
----------------------

An observable becomes exactly one query: ``search_ioc`` for an address, a domain
or a URL, and ``search_hash`` for a file. Depth changes how much of that one
response is normalized and nothing else. There is no second call at any depth,
and no tag, family or bulk query exists to make.

The address case, and why it is the interesting one
---------------------------------------------------

ThreatFox stores address intelligence as ``ip:port``, so an exact search for a
bare address finds nothing. That lookup therefore asks for a loose match — and
every record that comes back is re-validated locally before it can become
evidence, because a loose match on a provider we do not control will happily
return ``11.2.3.45:443`` for a search for ``1.2.3.4``. The gate is
:mod:`ti_recon.providers.threatfox.matching`, and what it rejected is published
in the coverage evidence rather than quietly dropped.

Absence
-------

ThreatFox drops IOCs from its API after about six months. A miss is reported as
``NO_DATA`` carrying that horizon explicitly: it means "nothing unexpired
matched", which is not the same statement as "this was never malicious" and is
never reported as benign.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final, Protocol

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    ActivityMode,
    IntelObjectType,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution.clock import Clock, SystemClock
from ti_recon.models.evidence import RawEvidenceReference
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.abusech.client import AbuseChJsonResult
from ti_recon.providers.abusech.errors import (
    credential_validation_for,
    query_status_of,
    translate_query_status,
)
from ti_recon.providers.abusech.evidence import (
    AbuseChNormalization,
    NormalizationContext,
)
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
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import NormalizedPayload, ProviderResultEnvelope
from ti_recon.providers.threatfox.client import (
    THREATFOX_HASH_LENGTHS,
    ThreatFoxClient,
    ThreatFoxConfig,
    ThreatFoxHttpClient,
)
from ti_recon.providers.threatfox.descriptor import (
    THREATFOX_PROVIDER_ID,
    build_threatfox_descriptor,
)
from ti_recon.providers.threatfox.matching import ThreatFoxMatch, match_for
from ti_recon.providers.threatfox.normalizer import (
    ThreatFoxRecord,
    normalize_coverage,
    normalize_hash_association,
    normalize_ioc_match,
    normalize_no_current_record,
    normalize_related_samples,
    records_of,
)
from ti_recon.providers.threatfox.policy import ThreatFoxLookupPolicy
from ti_recon.providers.transport import ProviderTransportError

__all__ = [
    "THREATFOX_NOT_SUPPORTED",
    "UNSUPPORTED_REASONS",
    "ThreatFoxAdapter",
    "ThreatFoxClientFactory",
]

#: Reported when the observable is not something ThreatFox can be asked about —
#: an IPv6 address, or a file identified only by SHA-1. A coverage gap, never an
#: absence of findings.
THREATFOX_NOT_SUPPORTED: Final[str] = "THREATFOX_OBSERVABLE_NOT_SUPPORTED"

#: Reported when a validated ThreatFox response carried no readable record.
THREATFOX_RECORDS_UNREADABLE: Final[str] = "THREATFOX_RECORDS_UNREADABLE"

#: Human-readable reason per warning, carried on the envelope so the execution
#: layer's outcome explains itself without anyone having to look the code up.
UNSUPPORTED_REASONS: Final[dict[str, str]] = {
    THREATFOX_NOT_SUPPORTED: (
        "ThreatFox searches by IPv4, domain, URL or an MD5/SHA-256 file hash; "
        "this observable has no ThreatFox lookup"
    )
}

#: The address lookup is the one that cannot use an exact search: ThreatFox
#: stores addresses as ``ip:port``, so an exact search for a bare address
#: matches nothing. Everything else is stored as itself.
_LOOSE_MATCH_TYPES: Final[frozenset[IntelObjectType]] = frozenset({IntelObjectType.IPV4_ADDR})

#: RFC 5737 TEST-NET-1 — reserved for documentation, never routed, and therefore
#: never anybody's observable. Used only to prove that a key works, so a
#: credential check reveals nothing about any investigation.
_CREDENTIAL_PROBE_ADDRESS: Final[str] = "192.0.2.1"


class ThreatFoxClientFactory(Protocol):
    """Builds the client one lookup will use."""

    def __call__(self) -> ThreatFoxClient: ...


class _DefaultClientFactory:
    """Creates a real HTTP client pinned to ThreatFox."""

    def __init__(self, config: ThreatFoxConfig) -> None:
        self._config = config

    def __call__(self) -> ThreatFoxClient:
        return ThreatFoxHttpClient(self._config)


class ThreatFoxAdapter(ProviderAdapter):
    """Passive ThreatFox IOC enrichment."""

    def __init__(
        self,
        *,
        client_factory: ThreatFoxClientFactory | None = None,
        config: ThreatFoxConfig | None = None,
        lookup_policy: ThreatFoxLookupPolicy | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._config = ThreatFoxConfig() if config is None else config
        self._client_factory: ThreatFoxClientFactory = (
            _DefaultClientFactory(self._config) if client_factory is None else client_factory
        )
        self._lookup_policy = ThreatFoxLookupPolicy() if lookup_policy is None else lookup_policy
        self._clock = SystemClock() if clock is None else clock
        self._descriptor = build_threatfox_descriptor()

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    @property
    def config(self) -> ThreatFoxConfig:
        return self._config

    @property
    def lookup_policy(self) -> ThreatFoxLookupPolicy:
        return self._lookup_policy

    # ------------------------------------------------------------------ #
    # Credentials, capabilities, health
    # ------------------------------------------------------------------ #

    async def validate_credentials(
        self, credential: CredentialMaterial | None
    ) -> CredentialValidation:
        """Check an Auth-Key with one harmless search.

        ThreatFox has no zero-cost status endpoint, so validation has to ask
        *something*. It asks for a reserved documentation address (RFC 5737),
        which is never anybody's observable: the check reveals nothing about an
        investigation and cannot be mistaken for enrichment. A "no result" is
        success — the key was accepted and ThreatFox looked.

        Only a rejected key is reported invalid. That matters more here than
        elsewhere: one Auth-Key serves all three abuse.ch providers, so marking
        it invalid over a ThreatFox refusal would disable URLhaus and
        MalwareBazaar too.
        """
        if credential is None:
            return CredentialValidation(
                provider_id=THREATFOX_PROVIDER_ID,
                status=CredentialStatus.INVALID,
                detail="no credential supplied",
            )
        error = await self._probe(credential)
        return credential_validation_for(THREATFOX_PROVIDER_ID, error)

    async def discover_capabilities(
        self, credential: CredentialMaterial | None
    ) -> CapabilityDiscovery:
        """Report what the integration supports, without probing the account.

        Deliberately free of API calls. abuse.ch meters by behaviour rather than
        by a published budget, so the cheapest capability query is the one that
        makes no request at all.
        """
        return CapabilityDiscovery(
            provider_id=THREATFOX_PROVIDER_ID,
            capabilities=frozenset(self._descriptor.capabilities),
            plan_hint="community API; current IOCs only",
        )

    async def health(self, credential: CredentialMaterial | None = None) -> ProviderHealthReport:
        """Report availability, checking only if a credential is available."""
        if credential is None:
            return ProviderHealthReport(
                provider_id=THREATFOX_PROVIDER_ID, health=ProviderHealth.UNKNOWN
            )
        error = await self._probe(credential)
        if error is None:
            return ProviderHealthReport(
                provider_id=THREATFOX_PROVIDER_ID, health=ProviderHealth.AVAILABLE
            )
        unavailable = error.category in {
            ProviderErrorCategory.PROVIDER_UNAVAILABLE,
            ProviderErrorCategory.TRANSIENT_ERROR,
        }
        return ProviderHealthReport(
            provider_id=THREATFOX_PROVIDER_ID,
            health=ProviderHealth.UNAVAILABLE if unavailable else ProviderHealth.DEGRADED,
            detail=f"probe returned {error.category.value}",
        )

    async def _probe(self, credential: CredentialMaterial) -> ProviderError | None:
        """One search for a reserved address. ``None`` means the key works.

        A "no result" counts as working: the request was authenticated and
        ThreatFox answered honestly about an address nobody has ever reported.
        """
        client = self._client_factory()
        try:
            result = await client.search_ioc(
                search_term=_CREDENTIAL_PROBE_ADDRESS,
                exact_match=True,
                credential=credential,
            )
        except ProviderError as transport_error:
            return transport_error
        finally:
            await client.aclose()

        reported = translate_query_status(
            result.query_status, provider_id=THREATFOX_PROVIDER_ID, operation="threatfox.probe"
        )
        if reported is not None and reported.category is ProviderErrorCategory.NOT_FOUND:
            # ThreatFox looked and had nothing. That is the expected answer for
            # a reserved address, and it proves the key was accepted.
            return None
        return reported

    # ------------------------------------------------------------------ #
    # Lookup
    # ------------------------------------------------------------------ #

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        """Passive enrichment of one observable from ThreatFox's current IOCs.

        One search. Nothing is submitted, no feed is downloaded, and no tag or
        family query is made.
        """
        if credential is None:
            raise ProviderInvalidRequestError(
                THREATFOX_PROVIDER_ID,
                message="threatfox requires a credential",
                operation="lookup",
            )
        if (
            request.activity_mode is ActivityMode.ACTIVE
            or request.operation is ProviderOperation.ACTIVE_ACTION
        ):
            # Refusing here as well as in ``active_action`` means a caller
            # bypassing the executor still cannot turn a passive integration
            # into an active one. ThreatFox accepts IOC submissions; this
            # adapter cannot make one.
            raise UnsupportedProviderOperation(THREATFOX_PROVIDER_ID, operation="active_action")

        plan = self._plan(request.intel_object)
        if plan is None:
            # No search is attempted, so this is not "we looked and found
            # nothing".
            return self._unsupported_envelope(request)

        search_term, is_hash = plan
        exact_match = request.intel_object.object_type not in _LOOSE_MATCH_TYPES
        client = self._client_factory()
        try:
            if is_hash:
                result = await client.search_hash(file_hash=search_term, credential=credential)
            else:
                result = await client.search_ioc(
                    search_term=search_term, exact_match=exact_match, credential=credential
                )
        finally:
            await client.aclose()

        return self._normalize_result(request, result, is_hash=is_hash, exact_match=exact_match)

    def _plan(self, intel_object: IntelObject) -> tuple[str, bool] | None:
        """The one search term for this observable, and whether it is a hash.

        ``None`` means ThreatFox cannot be asked at all.

        For a file this picks the **strongest digest ThreatFox accepts**, once:
        SHA-256 if the object carries one, otherwise MD5. A file identified only
        by SHA-1 yields ``None`` — ThreatFox's hash search does not take SHA-1,
        and asking with a digest the API cannot use would produce a confident
        "not found" that means nothing. Three requests to cover all three
        digests would be worse still: it would triple the cost of one lookup
        against a fair-use-metered account.
        """
        match intel_object.object_type:
            case IntelObjectType.IPV4_ADDR | IntelObjectType.DOMAIN_NAME | IntelObjectType.URL:
                return intel_object.canonical_value, False
            case IntelObjectType.FILE:
                hashes = intel_object.hashes
                for algorithm in ("SHA-256", "MD5"):
                    digest = hashes.get(algorithm)
                    if digest and len(digest) in THREATFOX_HASH_LENGTHS:
                        return digest, True
                return None
            case _:
                return None

    # ------------------------------------------------------------------ #
    # Normalization
    # ------------------------------------------------------------------ #

    def _normalize_result(
        self,
        request: ProviderRequest,
        result: AbuseChJsonResult,
        *,
        is_hash: bool,
        exact_match: bool,
        raw_reference: RawEvidenceReference | None = None,
    ) -> ProviderResultEnvelope:
        """Turn one response into an envelope, honouring the body's own verdict.

        The body status is checked before the payload: on these APIs a rejected
        key, a malformed request and an honest miss all arrive as HTTP 200, and
        reading the empty document instead of the status is how a credential
        failure becomes "this indicator is not known".
        """
        error = translate_query_status(
            result.query_status,
            provider_id=THREATFOX_PROVIDER_ID,
            operation="threatfox.lookup",
        )
        if error is not None and error.category is not ProviderErrorCategory.NOT_FOUND:
            raise error

        bounds = self._lookup_policy.bounds(request.depth)
        context = self._context(request, raw_reference=raw_reference)
        records = records_of(result.payload)

        if error is not None or not records:
            normalization = normalize_coverage(
                context,
                depth=request.depth.value,
                exact_match=exact_match,
                returned=len(records),
                matched=0,
                max_related=bounds.max_related,
            ).merge(normalize_no_current_record(context))
            return self._envelope(request, normalization, status=ProviderRunStatus.NO_DATA)

        if is_hash:
            normalization = normalize_hash_association(
                context, records, max_related=bounds.max_related
            )
            matched = len(records)
        else:
            confirmed = self._confirmed(request.intel_object, records)
            matched = len(confirmed)
            normalization = normalize_ioc_match(context, confirmed, max_related=bounds.max_related)

        coverage = normalize_coverage(
            context,
            depth=request.depth.value,
            exact_match=exact_match,
            returned=len(records),
            matched=matched,
            max_related=bounds.max_related,
        )
        if matched == 0:
            # ThreatFox answered, but nothing it returned survived local
            # validation. That is an absence for this observable, and the
            # coverage evidence says how many records were discarded.
            return self._envelope(
                request,
                coverage.merge(normalize_no_current_record(context)),
                status=ProviderRunStatus.NO_DATA,
            )

        if bounds.include_nested_detail and normalization.evidence:
            normalization = normalization.merge(
                normalize_related_samples(
                    context,
                    records[: bounds.max_related],
                    max_related=bounds.max_nested,
                    evidence_id=normalization.evidence[0].id,
                )
            )

        normalization = coverage.merge(normalization)
        status = ProviderRunStatus.PARTIAL if normalization.degraded else ProviderRunStatus.SUCCESS
        return self._envelope(request, normalization, status=status)

    @staticmethod
    def _confirmed(
        subject: IntelObject, records: Sequence[ThreatFoxRecord]
    ) -> list[tuple[ThreatFoxRecord, ThreatFoxMatch]]:
        """Every record that local validation confirms is about the observable.

        The gate. A record the provider returned but that does not parse back to
        this observable is discarded here and counted in coverage — never
        normalized into evidence about something it is not.
        """
        confirmed: list[tuple[ThreatFoxRecord, ThreatFoxMatch]] = []
        for record in records:
            match = match_for(subject, {"ioc": record.ioc, "ioc_type": record.ioc_type})
            if match is not None:
                confirmed.append((record, match))
        return confirmed

    def _context(
        self,
        request: ProviderRequest,
        *,
        raw_reference: RawEvidenceReference | None = None,
    ) -> NormalizationContext:
        return NormalizationContext(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            now=self._clock.now(),
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
        """Turn one ThreatFox response into Task 3 models. Pure, no I/O."""
        plan = self._plan(request.intel_object)
        if plan is None:
            return NormalizedPayload(warnings=(THREATFOX_NOT_SUPPORTED,))
        envelope = self._normalize_result(
            request,
            AbuseChJsonResult(
                payload=dict(payload),
                query_status=query_status_of(dict(payload)),
            ),
            is_hash=plan[1],
            exact_match=request.intel_object.object_type not in _LOOSE_MATCH_TYPES,
            raw_reference=raw_reference,
        )
        return NormalizedPayload(
            evidence=envelope.evidence,
            objects=envelope.objects,
            relationships=envelope.relationships,
            warnings=envelope.warnings,
        )

    def classify_error(self, error: Exception) -> ProviderErrorCategory:
        """Map a failure onto a normalized category.

        Transport security failures are reported as invalid requests rather than
        as provider problems: refusing to leave ThreatFox's host is our
        decision, not ThreatFox misbehaving.
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

        ``NOT_SUPPORTED`` rather than ``NO_DATA``: "ThreatFox cannot be asked
        about this" and "ThreatFox has no current record" are different
        statements, and collapsing them would let a blind spot read as a clean
        result.
        """
        return ProviderResultEnvelope(
            provider=THREATFOX_PROVIDER_ID,
            operation=request.operation,
            status=ProviderRunStatus.NOT_SUPPORTED,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            warnings=(THREATFOX_NOT_SUPPORTED,),
            error_message=UNSUPPORTED_REASONS[THREATFOX_NOT_SUPPORTED],
        )

    def _envelope(
        self,
        request: ProviderRequest,
        normalization: AbuseChNormalization,
        *,
        status: ProviderRunStatus,
    ) -> ProviderResultEnvelope:
        return ProviderResultEnvelope.from_payload(
            provider=THREATFOX_PROVIDER_ID,
            operation=request.operation,
            status=status,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            payload=NormalizedPayload(
                evidence=normalization.evidence,
                objects=normalization.objects,
                relationships=normalization.relationships,
                warnings=normalization.warnings,
            ),
        )
