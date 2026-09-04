"""The shared abuse.ch HTTP client (Task 10).

One transport for three APIs, because they are the same API three times: a form
POST to a fixed origin, an ``Auth-Key`` header, and a JSON object back whose
``query_status`` carries the real outcome.

POST is not a write
-------------------

These APIs take their parameters in a request body, so every lookup is an HTTP
POST. The other integrations in this repository prove passivity partly by
showing they never call ``post`` — that argument is unavailable here and would
be misleading if it were.

Two body encodings, one gate
----------------------------

The three platforms do not agree on how the body is encoded. URLhaus and
MalwareBazaar take form data — MalwareBazaar's documentation says so explicitly —
while ThreatFox takes a JSON object. :class:`AbuseChBodyEncoding` selects which,
**once per client**, because the encoding is a property of the API rather than of
a call: a per-request choice would be a knob nobody needs and a way to send a
body the tests never exercise.

The encoding changes only how the parameters are serialized. Everything that
makes this client safe — the allow-list check, the field and value validation,
the credential's header-only placement — happens before the encoding is chosen
and applies identically to both. A JSON body is not a way around any of it.

Passivity is instead enforced where it actually lives: in **which query values
may be sent**. Each provider hands this client a frozen allow-list of the
operations it is permitted to perform, and a form naming anything else is
refused before a request is built. ``submit_ioc``, ``get_file``, ``upload``,
``update``, ``add_comment`` and every bulk or hunting query are absent from
those lists, so no code path — not even an unused one — can reach them. A test
asserts the lists directly.

Nothing here downloads a sample, submits an indicator or asks for a rescan.

What is never sent
------------------

The Auth-Key goes in a header and nowhere else. That is worth stating twice for
these providers: because the parameters travel in a form body, a careless
implementation could put the key beside them, where it would end up in any
request log that captures bodies. This client never writes the credential into a
form — the shared transport is the only thing that reads the secret at all, and
it only ever writes it to the configured header.

Body values are validated before they are sent: bounded, free of control
characters, and never credential-shaped. The values are analyst observables, so
they are treated as untrusted input on the way out as well as on the way in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import TracebackType
from typing import Any, Final, Self

import httpx

from ti_recon.credentials.models import CredentialMaterial
from ti_recon.providers.abusech.config import AbuseChConfig, build_transport_config
from ti_recon.providers.abusech.errors import (
    query_status_of,
    translate_status_error,
)
from ti_recon.providers.errors import (
    ProviderError,
    ProviderInvalidRequestError,
    ProviderSchemaError,
)
from ti_recon.providers.transport import ProviderHttpClient
from ti_recon.security import SENSITIVE_KEY_PATTERN

__all__ = ["AbuseChBodyEncoding", "AbuseChHttpClient", "AbuseChJsonResult"]

#: The body field abuse.ch uses to name an operation, where it uses one.
QUERY_FIELD: Final[str] = "query"


class AbuseChBodyEncoding(StrEnum):
    """How one abuse.ch API expects its parameters in the request body.

    Fixed per platform, from each API's own documentation: ThreatFox reads a JSON
    object, URLhaus and MalwareBazaar read form data. Getting this wrong is not a
    validation failure with a useful message — the API simply answers as though
    nothing was asked, which reads exactly like "no record found".
    """

    FORM = "form"
    JSON = "json"


#: Bounds on what may be sent in a body. A search term is an analyst observable
#: — a URL can be long — but it is never unbounded.
_MAX_FORM_VALUE: Final[int] = 4096
_MAX_FORM_FIELDS: Final[int] = 8

#: Metering headers worth carrying upwards. An allow-list, so no ``Set-Cookie``
#: or vendor header ever ends up in a result, a cache entry or a snapshot.
_METERING_HEADER_PREFIXES: Final[tuple[str, ...]] = ("x-ratelimit-", "x-rate-limit-")
_METERING_HEADERS: Final[frozenset[str]] = frozenset({"retry-after"})


@dataclass(frozen=True, slots=True)
class AbuseChJsonResult:
    """A decoded JSON response, its body status, and the metering headers with it.

    ``query_status`` is kept separately because on these APIs it — not the HTTP
    status — is what says whether the lookup worked.
    """

    payload: dict[str, Any]
    query_status: str | None = None
    metering_headers: dict[str, str] = field(default_factory=dict)


class AbuseChHttpClient:
    """A POST-body JSON client pinned to one abuse.ch API and one operation set."""

    def __init__(
        self,
        config: AbuseChConfig,
        *,
        provider_id: str,
        allowed_queries: frozenset[str],
        body_encoding: AbuseChBodyEncoding = AbuseChBodyEncoding.FORM,
        transport: httpx.AsyncBaseTransport | None = None,
        http_client: ProviderHttpClient | None = None,
    ) -> None:
        self._config = config
        self._provider_id = provider_id
        #: The complete set of operations this client may ever perform. Frozen,
        #: and checked on every request rather than trusted to the caller.
        self._allowed_queries = allowed_queries
        #: How this API wants its parameters encoded. Set once, per platform,
        #: from that API's documentation — never chosen per request. Defaults to
        #: form data, which is what two of the three platforms read.
        self._body_encoding = body_encoding
        self._http = (
            ProviderHttpClient(
                build_transport_config(config, provider_id=provider_id),
                transport=transport,
            )
            if http_client is None
            else http_client
        )

    @property
    def config(self) -> AbuseChConfig:
        return self._config

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def allowed_queries(self) -> frozenset[str]:
        return self._allowed_queries

    @property
    def body_encoding(self) -> AbuseChBodyEncoding:
        return self._body_encoding

    # ------------------------------------------------------------------ #
    # The one request shape
    # ------------------------------------------------------------------ #

    async def query(
        self,
        path: str,
        *,
        form: dict[str, Any],
        operation: str,
        credential: CredentialMaterial,
    ) -> AbuseChJsonResult:
        """Perform one lookup against a path relative to the provider's origin.

        The parameters are validated first, the request is sent second, and the
        body's ``query_status`` comes back alongside the payload so the caller can
        act on the outcome the API actually reported.

        Validation runs before the encoding is chosen, so the allow-list and the
        value checks apply identically whether the body goes out as form data or
        as JSON.
        """
        self._validate_form(form, operation=operation)
        response = await self._post_body(
            path, parameters=form, operation=operation, credential=credential
        )
        if 300 <= response.status_code < 400:
            # The transport never follows redirects, and an authenticated API
            # read has no reason to be redirected. Reported as a shape change
            # rather than chased: chasing it would carry the Auth-Key onwards.
            raise ProviderSchemaError(
                self._provider_id,
                message="unexpected redirect from the provider API",
                operation=operation,
                provider_error_code=str(response.status_code),
            )
        if response.status_code >= 400:
            raise translate_status_error(
                response, provider_id=self._provider_id, operation=operation
            )
        payload = self._decode_json(response, operation=operation)
        return AbuseChJsonResult(
            payload=payload,
            query_status=query_status_of(payload),
            metering_headers=self._metering_headers(response.headers),
        )

    async def _post_body(
        self,
        path: str,
        *,
        parameters: dict[str, Any],
        operation: str,
        credential: CredentialMaterial,
    ) -> httpx.Response:
        """Send the already-validated parameters in this API's own encoding.

        The only thing this chooses is serialization. It is reached after
        :meth:`_validate_form` has approved the query name and every value, so
        neither branch can carry something the other could not.

        ``Content-Type`` is left to the HTTP layer, which sets
        ``application/json`` for a JSON body and
        ``application/x-www-form-urlencoded`` for a form. Writing it by hand
        would create a second place for the two to disagree.
        """
        if self._body_encoding is AbuseChBodyEncoding.JSON:
            return await self._http.post(
                path, json=parameters, credential=credential, operation=operation
            )
        return await self._http.post(
            path, data=parameters, credential=credential, operation=operation
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
        return (
            f"<AbuseChHttpClient provider={self._provider_id} "
            f"host={self._config.host} body={self._body_encoding.value}>"
        )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _validate_form(self, form: dict[str, Any], *, operation: str) -> None:
        """Refuse anything that is not a permitted, well-shaped lookup.

        Runs for both body encodings, before either is chosen. The first check is
        the one that keeps this integration passive: a body naming an operation
        outside the allow-list never becomes a request.

        A boolean is accepted **only** in JSON mode, because only there does it
        have a faithful representation. ThreatFox's ``exact_match`` is a JSON
        boolean in its API; putting a Python ``bool`` in a form body would
        serialize as ``True``/``False``, which is not what any of these APIs read.
        Every other value, in both modes, must be a bounded, control-character-free,
        non-credential-shaped string.
        """
        if not form:
            raise self._invalid("empty request body", operation=operation)
        if len(form) > _MAX_FORM_FIELDS:
            raise self._invalid("too many request fields", operation=operation)

        query = form.get(QUERY_FIELD)
        if query is not None and query not in self._allowed_queries:
            raise self._invalid(
                f"operation {query!r} is not permitted by this integration",
                operation=operation,
            )

        for name, value in form.items():
            if SENSITIVE_KEY_PATTERN.search(name):
                raise self._invalid(
                    f"field {name!r} must be supplied as a credential, not a body field",
                    operation=operation,
                )
            if isinstance(value, bool):
                if self._body_encoding is not AbuseChBodyEncoding.JSON:
                    raise self._invalid(
                        f"field {name!r} is a boolean, which only a JSON body can carry",
                        operation=operation,
                    )
                continue
            if not isinstance(value, str) or not value:
                raise self._invalid(f"field {name!r} has no usable value", operation=operation)
            if len(value) > _MAX_FORM_VALUE:
                raise self._invalid(f"field {name!r} is too long", operation=operation)
            if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
                raise self._invalid(
                    f"field {name!r} contains control characters", operation=operation
                )

    def _decode_json(self, response: httpx.Response, *, operation: str) -> dict[str, Any]:
        try:
            payload: Any = response.json()
        except ValueError as exc:
            raise ProviderSchemaError(
                self._provider_id, message="response was not valid JSON", operation=operation
            ) from exc
        if not isinstance(payload, dict):
            raise ProviderSchemaError(
                self._provider_id, message="response was not a JSON object", operation=operation
            )
        return payload

    def _invalid(self, message: str, *, operation: str) -> ProviderError:
        return ProviderInvalidRequestError(self._provider_id, message=message, operation=operation)

    @staticmethod
    def _metering_headers(headers: httpx.Headers) -> dict[str, str]:
        return {
            name.lower(): value
            for name, value in headers.items()
            if name.lower().startswith(_METERING_HEADER_PREFIXES)
            or name.lower() in _METERING_HEADERS
        }
