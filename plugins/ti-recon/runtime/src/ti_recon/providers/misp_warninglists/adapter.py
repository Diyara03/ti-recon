"""The MISP Warning Lists provider adapter (Task 11).

Implements the Task 5 :class:`ProviderAdapter` contract over a **local** dataset.
It normalizes and classifies; it decides nothing about maliciousness, and every
record it produces is context.

Zero network, by construction rather than by discipline
------------------------------------------------------

There is no client here, no transport, no host and no credential. A lookup reads
an in-memory index built at construction time: no file is opened, no path is
resolved, no name is looked up and no socket is created while an investigation is
running. The dataset is refreshed by an operator running
``tools/update_misp_warninglists.py``, which is the only code in the repository
that touches ``git`` and is unreachable from any adapter method.

Failure semantics
-----------------

* **ERROR** — no usable dataset: the snapshot is missing, unreadable, or fails
  its manifest checks. Reported as a provider failure, never as "nothing matched",
  because a provider that could not read its data has not answered the question.
* **PARTIAL** — the dataset works, but a list that *could have applied to this
  observable* could not be evaluated. Applicability-aware on purpose: a malformed
  phone-number regex list is irrelevant to an IPv4 lookup and must not degrade
  it, while an unusable CIDR list is exactly what that lookup needs to know.
* **NO_DATA** — everything applicable was checked and nothing matched. Which
  means nothing more than that.
* **SUCCESS** — at least one list matched, and every record is ``CONTEXT_ONLY``.

A stale snapshot is none of these. It is a successful lookup whose coverage says
the data is old, because the alternative — failing, or silently refreshing — is
either useless or dishonest.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from ti_recon.credentials.enums import CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    ActivityMode,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.models.evidence import RawEvidenceReference
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
    ProviderSchemaError,
    UnsupportedProviderOperation,
)
from ti_recon.providers.misp_warninglists.candidates import build_candidates
from ti_recon.providers.misp_warninglists.config import MispWarningListsConfig
from ti_recon.providers.misp_warninglists.descriptor import (
    MISP_WARNINGLISTS_PROVIDER_ID,
    build_misp_warninglists_descriptor,
)
from ti_recon.providers.misp_warninglists.loader import WarningListIndex, build_index
from ti_recon.providers.misp_warninglists.normalizer import (
    NormalizationContext,
    normalize_coverage,
    normalize_matches,
    normalize_no_match,
)
from ti_recon.providers.misp_warninglists.policy import MispWarningListsLookupPolicy
from ti_recon.providers.misp_warninglists.profile import WarningListProfile, core_profile
from ti_recon.providers.misp_warninglists.snapshot import (
    SnapshotError,
    WarningListSnapshot,
    load_snapshot,
)
from ti_recon.providers.request import ProviderRequest
from ti_recon.providers.result import NormalizedPayload, ProviderResultEnvelope

__all__ = [
    "MISP_WARNINGLISTS_NOT_SUPPORTED",
    "SNAPSHOT_UNAVAILABLE",
    "UNSUPPORTED_REASONS",
    "MispWarningListsAdapter",
]

#: Reported when the observable is not one this provider can build MISP
#: candidates for. A coverage gap, never an absence of findings.
MISP_WARNINGLISTS_NOT_SUPPORTED: Final[str] = "MISP_WARNINGLISTS_OBSERVABLE_NOT_SUPPORTED"

#: Reported when there is no usable dataset at all.
SNAPSHOT_UNAVAILABLE: Final[str] = "MISP_WARNINGLISTS_SNAPSHOT_UNAVAILABLE"

UNSUPPORTED_REASONS: Final[dict[str, str]] = {
    MISP_WARNINGLISTS_NOT_SUPPORTED: (
        "MISP warninglists are matched against addresses, domains, URLs and file "
        "hashes; this observable type produces no MISP attribute candidates"
    ),
    SNAPSHOT_UNAVAILABLE: (
        "no usable MISP warninglist snapshot; run tools/update_misp_warninglists.py"
    ),
}


class MispWarningListsAdapter(ProviderAdapter):
    """Local false-positive and infrastructure context from MISP warninglists.

    The dataset is loaded once, eagerly, at construction. That is deliberate: a
    lazily-loading adapter would do file I/O inside the first lookup, which is
    precisely the thing this provider promises not to do during enrichment. It
    also means a broken snapshot is discovered when the process starts rather
    than during somebody's investigation.
    """

    def __init__(
        self,
        *,
        config: MispWarningListsConfig | None = None,
        profile: WarningListProfile | None = None,
        lookup_policy: MispWarningListsLookupPolicy | None = None,
    ) -> None:
        self._config = MispWarningListsConfig() if config is None else config
        self._profile = core_profile() if profile is None else profile
        self._lookup_policy = (
            MispWarningListsLookupPolicy() if lookup_policy is None else lookup_policy
        )
        self._snapshot: WarningListSnapshot | None = None
        self._index: WarningListIndex | None = None
        self._load_error: str | None = None
        self._load()
        self._descriptor = build_misp_warninglists_descriptor(
            dataset_version=self._dataset_version()
        )

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #

    def _load(self) -> None:
        """Read the snapshot and compile the selected lists.

        A failure is remembered rather than raised. Constructing a registry must
        not explode because one provider's dataset is missing — the honest
        behaviour is a provider that reports itself unavailable and explains why.
        """
        try:
            snapshot = load_snapshot(self._config.snapshot_root)
        except SnapshotError as error:
            self._load_error = str(error)
            return
        selection = self._profile.select(snapshot.manifest)
        self._snapshot = snapshot
        self._index = build_index(snapshot, selection)

    def _dataset_version(self) -> str | None:
        """The cache discriminator: this dataset, under this profile.

        Fed into the generic ``ProviderDescriptor.dataset_version``, which the
        Task 6 cache key already includes. Refreshing the snapshot or changing
        the profile therefore changes every cache key, with no MISP-specific
        logic anywhere in the execution layer.
        """
        if self._index is None:
            return None
        return self._index.profile_identity

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    @property
    def config(self) -> MispWarningListsConfig:
        return self._config

    @property
    def profile(self) -> WarningListProfile:
        return self._profile

    @property
    def index(self) -> WarningListIndex | None:
        return self._index

    @property
    def snapshot(self) -> WarningListSnapshot | None:
        return self._snapshot

    # ------------------------------------------------------------------ #
    # Credentials, capabilities, health
    # ------------------------------------------------------------------ #

    async def validate_credentials(
        self, credential: CredentialMaterial | None
    ) -> CredentialValidation:
        """Always usable: there is no credential to validate.

        Reported as ``ACTIVE`` rather than refused, because "this provider needs
        no key" and "this provider's key is missing" must not look the same to an
        operator checking their configuration.
        """
        return CredentialValidation(
            provider_id=MISP_WARNINGLISTS_PROVIDER_ID,
            status=CredentialStatus.ACTIVE,
            detail="local dataset; no credential required",
        )

    async def discover_capabilities(
        self, credential: CredentialMaterial | None
    ) -> CapabilityDiscovery:
        return CapabilityDiscovery(
            provider_id=MISP_WARNINGLISTS_PROVIDER_ID,
            capabilities=frozenset(self._descriptor.capabilities),
            plan_hint="local MISP warninglist snapshot; no API, no credential",
        )

    async def health(self, credential: CredentialMaterial | None = None) -> ProviderHealthReport:
        """Health is a question about the dataset, and costs nothing to answer."""
        if self._index is None or self._snapshot is None:
            return ProviderHealthReport(
                provider_id=MISP_WARNINGLISTS_PROVIDER_ID,
                health=ProviderHealth.UNAVAILABLE,
                detail="no usable warninglist snapshot",
            )
        if self._snapshot.is_stale(self._config.stale_after):
            return ProviderHealthReport(
                provider_id=MISP_WARNINGLISTS_PROVIDER_ID,
                health=ProviderHealth.DEGRADED,
                detail="warninglist snapshot is stale",
            )
        return ProviderHealthReport(
            provider_id=MISP_WARNINGLISTS_PROVIDER_ID, health=ProviderHealth.AVAILABLE
        )

    # ------------------------------------------------------------------ #
    # Lookup
    # ------------------------------------------------------------------ #

    async def lookup(
        self, request: ProviderRequest, credential: CredentialMaterial | None
    ) -> ProviderResultEnvelope:
        """Match one observable against the configured warninglists.

        ``credential`` is accepted and ignored — the contract passes it, and this
        provider has nothing to do with it. Notably it is *not* required: a
        lookup with ``None`` works exactly as well, which is the whole point of a
        credential-free provider.
        """
        if (
            request.activity_mode is ActivityMode.ACTIVE
            or request.operation is ProviderOperation.ACTIVE_ACTION
        ):
            # Nothing here could be active — there is no target to contact — but
            # refusing explicitly keeps the passive boundary uniform across every
            # provider rather than implicit in one of them.
            raise UnsupportedProviderOperation(
                MISP_WARNINGLISTS_PROVIDER_ID, operation="active_action"
            )
        if self._index is None or self._snapshot is None:
            return self._unavailable_envelope(request)

        candidates = build_candidates(request.intel_object)
        if not candidates:
            return self._unsupported_envelope(request)

        matches = self._index.match(candidates)
        limit = self._lookup_policy.match_limit(request.depth, self._config.max_match_records)

        attribute_types = frozenset(item.misp_attribute_type for item in candidates)
        unusable = self._index.unusable_for(attribute_types)
        unsupported = self._index.unsupported_applicable(attribute_types)
        partial_reason = _partial_reason(len(unusable), len(unsupported))

        context = NormalizationContext(
            investigation_id=request.investigation_id,
            subject_object_id=request.intel_object.id,
            dataset_fingerprint=self._snapshot.manifest.dataset_fingerprint,
        )
        evidence = []
        if matches:
            evidence.append(normalize_matches(context, matches, self._index, max_records=limit))
        else:
            evidence.append(normalize_no_match(context))
        evidence.append(
            normalize_coverage(
                context,
                snapshot=self._snapshot,
                index=self._index,
                candidates=candidates,
                profile_id=self._profile.profile_id,
                profile_fingerprint=self._profile.fingerprint(),
                depth=request.depth.value,
                total_matches=len(matches),
                normalized_matches=min(len(matches), limit),
                stale_after=self._config.stale_after,
                partial_reason=partial_reason,
            )
        )

        if partial_reason is not None:
            status = ProviderRunStatus.PARTIAL
        elif matches:
            status = ProviderRunStatus.SUCCESS
        else:
            status = ProviderRunStatus.NO_DATA
        return ProviderResultEnvelope.from_payload(
            provider=MISP_WARNINGLISTS_PROVIDER_ID,
            operation=request.operation,
            status=status,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            payload=NormalizedPayload(evidence=tuple(evidence)),
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
        """Not applicable: there is no provider payload to normalize.

        Every other adapter receives a document from an API and turns it into
        models. This one *is* the source, so there is nothing to hand it. Raised
        explicitly rather than returning an empty payload, which would look like
        a document that contained nothing.
        """
        raise UnsupportedProviderOperation(MISP_WARNINGLISTS_PROVIDER_ID, operation="normalize")

    def classify_error(self, error: Exception) -> ProviderErrorCategory:
        """Map a failure onto a normalized category.

        The vocabulary is small because the failure modes are: a snapshot problem
        is a schema/data problem, and there is no network, no throttle and no
        allowance to run out of.
        """
        if isinstance(error, SnapshotError | ProviderSchemaError):
            return ProviderErrorCategory.SCHEMA_ERROR
        if isinstance(error, ProviderError):
            return error.category
        return ProviderErrorCategory.UNKNOWN_ERROR

    def _unsupported_envelope(self, request: ProviderRequest) -> ProviderResultEnvelope:
        return ProviderResultEnvelope(
            provider=MISP_WARNINGLISTS_PROVIDER_ID,
            operation=request.operation,
            status=ProviderRunStatus.NOT_SUPPORTED,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            warnings=(MISP_WARNINGLISTS_NOT_SUPPORTED,),
            error_message=UNSUPPORTED_REASONS[MISP_WARNINGLISTS_NOT_SUPPORTED],
        )

    def _unavailable_envelope(self, request: ProviderRequest) -> ProviderResultEnvelope:
        """No dataset: an error, never an empty answer.

        The distinction an analyst depends on. "No warninglist matched" and "I
        could not read any warninglist" differ completely, and only one of them
        is information.
        """
        return ProviderResultEnvelope(
            provider=MISP_WARNINGLISTS_PROVIDER_ID,
            operation=request.operation,
            status=ProviderRunStatus.ERROR,
            adapter_version=self._descriptor.adapter_version,
            api_version=self._descriptor.api_version,
            error_category=ProviderErrorCategory.SCHEMA_ERROR,
            warnings=(SNAPSHOT_UNAVAILABLE,),
            error_message=UNSUPPORTED_REASONS[SNAPSHOT_UNAVAILABLE],
        )

    def __repr__(self) -> str:
        lists = 0 if self._index is None else len(self._index.lists)
        return (
            f"<MispWarningListsAdapter profile={self._profile.profile_id} "
            f"lists={lists} usable={self._index is not None}>"
        )


def _partial_reason(unusable: int, unsupported: int) -> str | None:
    """Why this lookup is partial, or ``None`` if it is complete.

    Both inputs are already filtered to lists that *apply to this observable*.
    That filtering is what keeps partiality meaningful: without it every lookup
    would inherit every defect in the dataset, and ``PARTIAL`` would stop
    carrying information.
    """
    if unusable and unsupported:
        return f"{unusable} applicable lists unusable, {unsupported} with unsupported matchers"
    if unusable:
        return f"{unusable} applicable lists could not be loaded"
    if unsupported:
        return f"{unsupported} applicable lists use a matcher this build does not evaluate"
    return None
