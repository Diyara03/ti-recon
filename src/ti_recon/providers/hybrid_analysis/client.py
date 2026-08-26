"""The Hybrid Analysis HTTP client (Task 12).

The only module in this package that performs I/O, and it can perform exactly
three reads.

What this client deliberately cannot do
---------------------------------------

Falcon Sandbox's API is large and much of it is dangerous in an automated
pipeline. Absent here, with no code path to reach them:

* ``POST /submit/file``, ``/submit/url``, ``/submit/url-to-file``,
  ``/submit/dropped-file`` — **submitting a customer's file to a community
  platform.** The service's own terms warn that submitted content may be
  retained, used and redistributed, and that screenshots and metadata can expose
  it. That is a decision for a human with a warning in front of them, not a side
  effect of enrichment.
* ``GET /report/{id}/sample``, ``/dropped-file/*`` — **downloading live
  malware** onto the machine running the investigation.
* ``/report/{id}/pcap``, ``/memory-dumps``, ``/screenshots``,
  ``/report/json`` — bulk artifact retrieval this task has no use for.
* ``/quick-scan/*`` — analysis this integration is not authorised to start.
* ``/overview/{sha256}/refresh`` — explicitly refreshes data *from external
  services*, so an enrichment lookup would be triggering third-party queries.
* YARA hunting, advanced search, feeds, file collections.

:data:`ALLOWED_PATHS` is a frozen set of three path *shapes*, checked before a
request is built, and a test asserts the set. The methods on this class are the
only way to reach the transport, so submission and download are unreachable
rather than merely unused — and because every permitted call is a ``GET``, "this
integration never calls ``post``" is available here as a real proof.

The deprecated ``POST /search/hash`` and ``POST /report/summary`` are not
implemented either; the current ``GET`` forms are used.
"""

from __future__ import annotations

import json
import re
from types import TracebackType
from typing import TYPE_CHECKING, Any, Final, Protocol, Self
from urllib.parse import quote

import httpx

from ti_recon.credentials.models import CredentialMaterial
from ti_recon.providers.errors import ProviderInvalidRequestError, ProviderSchemaError
from ti_recon.providers.hybrid_analysis.config import (
    HybridAnalysisConfig,
    build_transport_config,
)
from ti_recon.providers.hybrid_analysis.descriptor import HYBRID_ANALYSIS_PROVIDER_ID
from ti_recon.providers.hybrid_analysis.errors import (
    CONTAINER_REPORT_STATUS,
    translate_status_error,
)
from ti_recon.providers.result import RateLimitSnapshot, RateLimitWindow
from ti_recon.providers.transport import ProviderHttpClient

__all__ = [
    "ALLOWED_PATHS",
    "HASH_LENGTHS",
    "ContainerReport",
    "HybridAnalysisClient",
    "HybridAnalysisHttpClient",
    "HybridAnalysisOperation",
    "HybridAnalysisResponse",
]


class HybridAnalysisOperation:
    """Operation names for logging, metrics and error attribution."""

    SEARCH_HASH: Final[str] = "hybrid_analysis.search_hash"
    REPORT_SUMMARY: Final[str] = "hybrid_analysis.report_summary"
    KEY_CURRENT: Final[str] = "hybrid_analysis.key_current"


#: Every path shape this integration may request. Three reads.
#:
#: ``{id}`` is substituted with a shape-checked report id — see
#: :func:`_validate_report_id`. Nothing here is built from provider-supplied
#: text: a report URL, domain or file path from a response is data and can never
#: become a destination.
ALLOWED_PATHS: Final[frozenset[str]] = frozenset(
    {
        "api/v2/search/hash",
        "api/v2/report/{id}/summary",
        "api/v2/key/current",
    }
)

#: Digest lengths ``GET /search/hash`` accepts. TI Recon ``file`` objects carry
#: MD5, SHA-1 and SHA-256; SHA-512 is accepted by the API but TI Recon never
#: holds one, so it is not offered.
HASH_LENGTHS: Final[frozenset[int]] = frozenset({32, 40, 64})

_HEX: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-f]+\Z")

#: A report id is put into a path, so it is shape-checked first. The API's ids are
#: hex job identifiers, sometimes suffixed with an environment number.
_REPORT_ID: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-zA-Z]{1,64}(?::[0-9]{1,6})?\Z")

#: Bound on the rate-limit header before it is parsed. A header is provider text.
_MAX_LIMITS_HEADER: Final[int] = 2048


class ContainerReport(Exception):
    """A report is an archive rather than a single analysable sample.

    Not an error in any useful sense: the provider answered, and its answer is
    "this identifier names a container". Raised as a distinct type so the adapter
    can record it as report state and continue with whatever else it selected,
    instead of mistaking it for an outage.

    ``related_report_ids`` carries the children the API named, for the record.
    They are **not** fetched — an archive of archives would otherwise become an
    unbounded fan-out of metered requests.
    """

    def __init__(self, report_id: str, related_report_ids: tuple[str, ...] = ()) -> None:
        self.report_id = report_id
        self.related_report_ids = related_report_ids
        super().__init__(f"report {report_id} is a container")


class HybridAnalysisResponse:
    """A decoded JSON body plus whatever the response said about limits."""

    __slots__ = ("payload", "rate_limit")

    def __init__(self, payload: Any, rate_limit: RateLimitSnapshot | None) -> None:
        self.payload = payload
        self.rate_limit = rate_limit


class HybridAnalysisClient(Protocol):
    """The read-only surface the rest of the package may use.

    Three methods. Passivity is not a convention here — there is nothing else to
    call, and adding a submission or download method would mean changing this
    protocol, which is the point of having one.
    """

    async def search_hash(
        self, *, file_hash: str, credential: CredentialMaterial
    ) -> HybridAnalysisResponse: ...

    async def report_summary(
        self, *, report_id: str, credential: CredentialMaterial
    ) -> HybridAnalysisResponse: ...

    async def key_current(self, *, credential: CredentialMaterial) -> HybridAnalysisResponse: ...

    async def aclose(self) -> None: ...


class HybridAnalysisHttpClient:
    """:class:`HybridAnalysisClient` over the shared, host-pinned transport."""

    def __init__(
        self,
        config: HybridAnalysisConfig | None = None,
        *,
        provider_id: str = HYBRID_ANALYSIS_PROVIDER_ID,
        transport: httpx.AsyncBaseTransport | None = None,
        http_client: ProviderHttpClient | None = None,
    ) -> None:
        self._config = HybridAnalysisConfig() if config is None else config
        self._provider_id = provider_id
        self._http = (
            ProviderHttpClient(
                build_transport_config(self._config, provider_id=provider_id),
                transport=transport,
            )
            if http_client is None
            else http_client
        )

    @property
    def config(self) -> HybridAnalysisConfig:
        return self._config

    @property
    def provider_id(self) -> str:
        return self._provider_id

    # ------------------------------------------------------------------ #
    # The three reads
    # ------------------------------------------------------------------ #

    async def search_hash(
        self, *, file_hash: str, credential: CredentialMaterial
    ) -> HybridAnalysisResponse:
        """Find the reports the provider holds for one digest.

        ``GET``, not the deprecated ``POST`` form. The digest is shape-checked
        before it becomes a query value, so a malformed hash never leaves the
        process — a request that could only be rejected is an allowance spent for
        nothing.
        """
        digest = self._validate_digest(file_hash, HybridAnalysisOperation.SEARCH_HASH)
        return await self._get(
            "api/v2/search/hash",
            params={"hash": digest},
            operation=HybridAnalysisOperation.SEARCH_HASH,
            credential=credential,
        )

    async def report_summary(
        self, *, report_id: str, credential: CredentialMaterial
    ) -> HybridAnalysisResponse:
        """Read one report's summary.

        Raises :class:`ContainerReport` on the container status rather than a
        generic error, so the caller can record it and carry on.
        """
        identifier = self._validate_report_id(report_id)
        return await self._get(
            f"api/v2/report/{quote(identifier, safe=':')}/summary",
            params=None,
            operation=HybridAnalysisOperation.REPORT_SUMMARY,
            credential=credential,
            report_id=identifier,
        )

    async def key_current(self, *, credential: CredentialMaterial) -> HybridAnalysisResponse:
        """Read this key's authorization level and limits.

        Used only for explicit credential validation and health, never before a
        lookup: a successful hash search already proves the key can do the work,
        and spending a request to ask permission first would halve an already
        small allowance.

        The response contains the API key itself. The caller must read only the
        safe fields — see the normalizer, which never touches ``api_key``.
        """
        return await self._get(
            "api/v2/key/current",
            params=None,
            operation=HybridAnalysisOperation.KEY_CURRENT,
            credential=credential,
        )

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        return f"<HybridAnalysisHttpClient provider={self._provider_id} host={self._config.host}>"

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    async def _get(
        self,
        path: str,
        *,
        params: dict[str, str] | None,
        operation: str,
        credential: CredentialMaterial,
        report_id: str | None = None,
    ) -> HybridAnalysisResponse:
        """Perform one permitted GET.

        The path is checked against :data:`ALLOWED_PATHS` before the request is
        built, so a path this integration is not allowed to request cannot be
        issued even by a caller inside the package.
        """
        self._assert_allowed(path, operation=operation)
        response = await self._http.get(
            path, params=params, credential=credential, operation=operation
        )
        if 300 <= response.status_code < 400:
            # The transport does not follow redirects, and an authenticated API
            # read has no reason to be redirected. Reported as a shape change
            # rather than chased: chasing it would carry the key onwards.
            raise ProviderSchemaError(
                self._provider_id,
                message="unexpected redirect from the provider API",
                operation=operation,
                provider_error_code=str(response.status_code),
            )
        if response.status_code == CONTAINER_REPORT_STATUS and report_id is not None:
            raise ContainerReport(report_id, self._related_reports(response))
        if response.status_code >= 400:
            raise translate_status_error(
                response, provider_id=self._provider_id, operation=operation
            )
        return HybridAnalysisResponse(
            payload=self._decode_json(response, operation=operation),
            rate_limit=self._rate_limit(response, operation=operation),
        )

    def _assert_allowed(self, path: str, *, operation: str) -> None:
        """Refuse any path outside the frozen allow-list.

        Compared as a *shape*: the report id is replaced by its placeholder so a
        single entry covers every report without the allow-list becoming a
        prefix match, which would let ``/report/{id}/pcap`` through.
        """
        shape = re.sub(r"api/v2/report/[^/]+/", "api/v2/report/{id}/", path)
        if shape not in ALLOWED_PATHS:
            raise ProviderInvalidRequestError(
                self._provider_id,
                message="path is not permitted by this integration",
                operation=operation,
            )

    def _validate_digest(self, value: str, operation: str) -> str:
        candidate = value.strip().lower() if isinstance(value, str) else ""
        if len(candidate) not in HASH_LENGTHS or not _HEX.fullmatch(candidate):
            raise ProviderInvalidRequestError(
                self._provider_id,
                message="value is not an MD5, SHA-1 or SHA-256 digest",
                operation=operation,
            )
        return candidate

    def _validate_report_id(self, value: str) -> str:
        """Shape-check a report id before it is put into a path.

        The id comes from a provider response, which makes it untrusted input on
        the way back out. A value with a slash or a traversal segment would
        change which endpoint is called, so it is refused rather than escaped.
        """
        candidate = value.strip() if isinstance(value, str) else ""
        if not _REPORT_ID.fullmatch(candidate):
            raise ProviderInvalidRequestError(
                self._provider_id,
                message="report identifier has an unexpected shape",
                operation=HybridAnalysisOperation.REPORT_SUMMARY,
            )
        return candidate

    def _decode_json(self, response: httpx.Response, *, operation: str) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            raise ProviderSchemaError(
                self._provider_id, message="response was not valid JSON", operation=operation
            ) from exc

    @staticmethod
    def _related_reports(response: httpx.Response) -> tuple[str, ...]:
        """Child report ids a container response named, bounded.

        Recorded so an analyst knows the archive had children. Never fetched.
        """
        try:
            payload = response.json()
        except ValueError:
            return ()
        if not isinstance(payload, dict):
            return ()
        related = payload.get("related_reports") or payload.get("reports")
        if not isinstance(related, list):
            return ()
        found: list[str] = []
        for item in related[:20]:
            candidate = item if isinstance(item, str) else None
            if candidate is None and isinstance(item, dict):
                raw = item.get("report_id") or item.get("id")
                candidate = raw if isinstance(raw, str) else None
            if candidate and _REPORT_ID.fullmatch(candidate.strip()):
                found.append(candidate.strip())
        return tuple(found)

    def _rate_limit(self, response: httpx.Response, *, operation: str) -> RateLimitSnapshot | None:
        """Parse the ``Api-Limits`` header, or report nothing.

        The header is a JSON object describing the key's allowances and usage.
        Its exact shape is not specified in the API documentation, so it is read
        defensively: any window the provider names becomes a window, and anything
        unparseable produces ``None``.

        ``None`` rather than an empty snapshot with zeroes, and the distinction
        matters. Not knowing an allowance lets the execution layer try; a
        fabricated zero would tell the quota pre-check the provider is exhausted
        and stop it being called at all.
        """
        raw = response.headers.get("Api-Limits")
        if not raw or len(raw) > _MAX_LIMITS_HEADER:
            return None
        try:
            parsed = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(parsed, dict):
            return None

        raw_limits = parsed.get("limits")
        raw_used = parsed.get("used")
        limits: dict[str, Any] = raw_limits if isinstance(raw_limits, dict) else {}
        used: dict[str, Any] = raw_used if isinstance(raw_used, dict) else {}
        windows: list[RateLimitWindow] = []
        for name in sorted({*limits, *used}):
            if not isinstance(name, str) or len(name) > 64:
                continue
            limit = _positive_int(limits.get(name))
            consumed = _positive_int(used.get(name))
            remaining = None
            if limit is not None and consumed is not None:
                remaining = max(0, limit - consumed)
            if limit is None and remaining is None:
                continue
            windows.append(RateLimitWindow(window_name=name[:64], limit=limit, remaining=remaining))
        if not windows:
            return None
        return RateLimitSnapshot(operation=operation, windows=tuple(windows))


def _positive_int(value: Any) -> int | None:
    """A non-negative integer, or ``None``. Never a guess."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str):
        try:
            parsed = int(value.strip())
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    return None


if TYPE_CHECKING:  # pragma: no cover - a compile-time conformance assertion
    # Fails type checking if the concrete client stops satisfying the read-only
    # protocol, which is what keeps "no submission, no download" structural
    # rather than a comment.
    _protocol_conformance: type[HybridAnalysisClient] = HybridAnalysisHttpClient
