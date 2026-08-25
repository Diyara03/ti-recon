"""The shared abuse.ch HTTP client (Task 10).

One transport for three APIs, because they are the same API three times: a form
POST to a fixed origin, an ``Auth-Key`` header, and a JSON object back whose
``query_status`` carries the real outcome.

POST is not a write
-------------------

These APIs take their parameters in a form body, so every lookup is an HTTP
POST. The other integrations in this repository prove passivity partly by
showing they never call ``post`` — that argument is unavailable here and would
be misleading if it were.

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

Form values are validated before they are sent: bounded, free of control
characters, and never credential-shaped. The values are analyst observables, so
they are treated as untrusted input on the way out as well as on the way in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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

__all__ = ["AbuseChHttpClient", "AbuseChJsonResult"]

#: The form field abuse.ch uses to name an operation, where it uses one.
QUERY_FIELD: Final[str] = "query"

#: Bounds on what may be sent in a form. A search term is an analyst observable
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
    """A form-POST JSON client pinned to one abuse.ch API and one operation set."""

    def __init__(
        self,
        config: AbuseChConfig,
        *,
        provider_id: str,
        allowed_queries: frozenset[str],
        transport: httpx.AsyncBaseTransport | None = None,
        http_client: ProviderHttpClient | None = None,
    ) -> None:
        self._config = config
        self._provider_id = provider_id
        #: The complete set of operations this client may ever perform. Frozen,
        #: and checked on every request rather than trusted to the caller.
        self._allowed_queries = allowed_queries
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

    # ------------------------------------------------------------------ #
    # The one request shape
    # ------------------------------------------------------------------ #

    async def query(
        self,
        path: str,
        *,
        form: dict[str, str],
        operation: str,
        credential: CredentialMaterial,
    ) -> AbuseChJsonResult:
        """Perform one lookup against a path relative to the provider's origin.

        The form is validated first, the request is sent second, and the body's
        ``query_status`` comes back alongside the payload so the caller can act
        on the outcome the API actually reported.
        """
        self._validate_form(form, operation=operation)
        response = await self._http.post(
            path, data=form, credential=credential, operation=operation
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
        return f"<AbuseChHttpClient provider={self._provider_id} host={self._config.host}>"

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _validate_form(self, form: dict[str, str], *, operation: str) -> None:
        """Refuse anything that is not a permitted, well-shaped lookup.

        Four checks, and the first is the one that keeps this integration
        passive: a form naming an operation outside the allow-list never becomes
        a request.
        """
        if not form:
            raise self._invalid("empty request form", operation=operation)
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
                    f"field {name!r} must be supplied as a credential, not a form field",
                    operation=operation,
                )
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
