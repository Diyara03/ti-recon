"""Which Censys asset answers for which observable (Task 9).

Pure functions. No I/O, no network, no guessing.

Censys addresses two kinds of asset, and each has exactly one deterministic
identity:

* a **host**, identified by an IP address;
* a **web property**, identified by ``hostname:port``.

Every mapping in this module is total and reversible by inspection. There is no
search, no CenQL, no candidate selection and no ranking, because a direct
lookup by a derived identity costs one predictable request and cannot quietly
turn into a broad query that spends an analyst's credits.

The URL mapping
---------------

A URL's path, query and fragment do not participate in a web property's
identity, so they are dropped from the *lookup* and the original URL remains
the investigated object::

    https://example.com/login?x=1   ->  example.com:443
    http://example.com/             ->  example.com:80
    https://example.com:8443/a      ->  example.com:8443

The match scope records the consequence honestly: a web property is the host and
port a URL lives on, not the URL, so evidence from it is ``SAME_HOST`` rather
than ``EXACT_OBSERVABLE``. Reporting it as exact would let "Censys sees an nginx
on this host" read as "Censys sees this page".

Why a bare domain is not mapped
-------------------------------

A domain has no port, and a web property must have one. Quietly looking up
``domain:443`` and ``domain:80`` would produce two requests, two credits spent,
and a result an analyst would reasonably read as "Censys knows nothing about
this domain" when in fact only two of sixty-five thousand ports were asked
about. That is a blind spot dressed as coverage, so a domain is reported as
unsupported instead. Answering it properly needs a search, which is deferred.

Why an address literal in a URL becomes a host lookup
-----------------------------------------------------

``http://198.51.100.7/panel`` has no hostname, so there is no web property to
ask for. Rather than refuse it, the address itself is looked up as a host — a
different question, deliberately answered with a different match scope
(``SAME_IP``) and recorded in the coverage evidence, so nobody can mistake "port
443 is open on this address" for "Censys has seen this page".
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final
from urllib.parse import SplitResult, urlsplit

from pydantic import Field

from ti_recon.enums import IntelObjectType, MatchScope
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization.errors import NormalizationError
from ti_recon.normalization.observables import normalize_domain, normalize_ip

__all__ = [
    "DEFAULT_PORT_FOR_SCHEME",
    "WEB_PROPERTY_SCHEMES",
    "CensysAsset",
    "CensysAssetKind",
    "asset_for",
    "unsupported_reason_for",
]

#: The port a web property takes when a URL does not state one. Observable
#: normalization strips a default port, so this is how it comes back.
DEFAULT_PORT_FOR_SCHEME: Final[dict[str, int]] = {"http": 80, "https": 443}

#: URL schemes that have a Censys web property at all. ``ftp`` is an accepted
#: TI Recon URL scheme and has no web property, so it is unsupported rather than
#: forced onto port 21 and hoped for.
WEB_PROPERTY_SCHEMES: Final[frozenset[str]] = frozenset(DEFAULT_PORT_FOR_SCHEME)


class CensysAssetKind(StrEnum):
    """Which Censys asset endpoint answers for an observable."""

    HOST = "host"
    WEB_PROPERTY = "web_property"


class CensysAsset(FrozenTiReconModel):
    """One deterministic Censys asset identity, and what it means for evidence.

    ``match_scope`` travels with the asset rather than being decided later, so
    the "we asked about the host, not the URL" caveat cannot be lost between
    deriving the identity and attaching evidence to it.
    """

    kind: CensysAssetKind
    #: The address, for a host.
    address: str | None = Field(default=None, max_length=45)
    #: The hostname and port, for a web property.
    hostname: str | None = Field(default=None, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    #: How precisely evidence from this asset applies to the submitted object.
    match_scope: MatchScope = MatchScope.EXACT_OBSERVABLE

    @property
    def identifier(self) -> str:
        """The asset's Censys identity, as it appears in a request path."""
        if self.kind is CensysAssetKind.HOST:
            return self.address or ""
        return f"{self.hostname}:{self.port}"

    def __str__(self) -> str:
        return f"{self.kind.value}:{self.identifier}"


def asset_for(intel_object: IntelObject) -> CensysAsset | None:
    """The Censys asset that answers for ``intel_object``, or ``None``.

    ``None`` means Censys has no deterministic asset for this observable — a
    coverage gap, and the caller must report it as such rather than as a lookup
    that found nothing. :func:`unsupported_reason_for` explains which case it is.
    """
    match intel_object.object_type:
        case IntelObjectType.IPV4_ADDR | IntelObjectType.IPV6_ADDR:
            return _host_asset(intel_object.canonical_value, MatchScope.EXACT_OBSERVABLE)
        case IntelObjectType.URL:
            return _asset_for_url(intel_object.canonical_value)
        case _:
            return None


def unsupported_reason_for(intel_object: IntelObject) -> str:
    """Why Censys cannot answer for this observable, in one readable sentence.

    Kept next to the mapping it explains: a reason that lives far from the rule
    is a reason that goes stale.
    """
    match intel_object.object_type:
        case IntelObjectType.DOMAIN_NAME:
            return (
                "a Censys web property is identified by hostname and port; a bare domain names "
                "no port, and guessing 80 and 443 would report two ports as domain coverage"
            )
        case IntelObjectType.FILE:
            return (
                "Censys indexes certificates by certificate fingerprint, not files by file "
                "hash; a file hash is never reinterpreted as a fingerprint"
            )
        case IntelObjectType.URL:
            return (
                "only http and https URLs map onto a Censys web property, and the URL's host "
                "must be resolvable to a hostname or an address"
            )
        case _:
            return "Censys has no asset identity for this observable type"


def _asset_for_url(canonical_url: str) -> CensysAsset | None:
    """Derive a web property — or a host — from a canonical URL."""
    parts = urlsplit(canonical_url)
    scheme = parts.scheme.lower()
    if scheme not in WEB_PROPERTY_SCHEMES:
        return None
    host = parts.hostname
    if not host:
        return None

    # An address literal authority — v4 or v6 — has no hostname to build a web
    # property from, so the address itself becomes the asset and the scope says
    # that the answer is about the address rather than the page.
    literal = _host_asset(host, MatchScope.SAME_IP)
    if literal is not None:
        return literal

    try:
        hostname = normalize_domain(host).canonical_value
    except NormalizationError:
        return None

    port = _port_for(parts, scheme)
    if port is None:
        return None
    return CensysAsset(
        kind=CensysAssetKind.WEB_PROPERTY,
        hostname=hostname,
        port=port,
        # The web property is where the URL lives, not the URL itself.
        match_scope=MatchScope.SAME_HOST,
    )


def _port_for(parts: SplitResult, scheme: str) -> int | None:
    """The URL's explicit port, or the scheme's default.

    ``SplitResult.port`` raises rather than returning ``None`` for a value that
    is not a port, which is a refusal rather than an error: a URL TI Recon
    cannot read a port out of has no deterministic web property.
    """
    try:
        port = parts.port
    except ValueError:
        return None
    if port is None:
        return DEFAULT_PORT_FOR_SCHEME.get(scheme)
    return port if 1 <= port <= 65535 else None


def _host_asset(value: str, match_scope: MatchScope) -> CensysAsset | None:
    """A host asset, if ``value`` is an address.

    Validated by the same normalizer that validates analyst input, so a value
    that is not an address cannot become one here.
    """
    try:
        normalized = normalize_ip(value)
    except NormalizationError:
        return None
    return CensysAsset(
        kind=CensysAssetKind.HOST,
        address=normalized.canonical_value,
        match_scope=match_scope,
    )
