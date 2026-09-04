"""Turning one observable into the MISP attribute values a warninglist can judge (Task 11).

This module exists because of one rule in the upstream data model:
``matching_attributes`` is **authoritative**. A warninglist declares which MISP
attribute types it is about, and checking it against anything else is not a
generous near-miss — it is a different question. A hostname list evaluated
against an MD5 would be nonsense even in the rare case the strings collided.

So a lookup does not search "the observable" against "the lists". It builds the
explicit set of MISP attribute values this observable legitimately *is*, and each
list is then offered only the candidates whose attribute type it declares.

Several candidates, one observable
----------------------------------

A domain is both a MISP ``domain`` and a MISP ``hostname``; a URL is a ``url``
and, separately, has a host. These are alternate namings and derived components
of a single artifact, never independent observables — so
:class:`WarningListCandidate` carries the observable's identity, and a list that
matches through two candidates is deduplicated into one finding rather than
counted twice.

Nothing is fabricated
---------------------

Only candidates the object actually supports. No ``domain|ip`` for a bare domain,
no ``ip-src|port`` for a portless address, no ``filename|md5`` unless a filename
is genuinely recorded. A composite candidate invented from half its parts would
match upstream entries about something else.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final
from urllib.parse import urlsplit

from pydantic import Field

from ti_recon.enums import IntelObjectType, MatchScope
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.models.intel_object import IntelObject

__all__ = [
    "HASH_ATTRIBUTE_BY_ALGORITHM",
    "MAX_CANDIDATE_LENGTH",
    "SUPPORTED_OBJECT_TYPES",
    "CandidateComponent",
    "WarningListCandidate",
    "build_candidates",
    "candidate_attribute_types",
]

#: TI Recon hash names to MISP attribute types. Every hash the object carries is
#: used: this is a local set lookup, so there is no reason to pick only the
#: strongest digest the way a metered remote API forces — and a warninglist may
#: hold only one of the three.
HASH_ATTRIBUTE_BY_ALGORITHM: Final[dict[str, str]] = {
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA-256": "sha256",
}

#: Observables this provider can build candidates for.
SUPPORTED_OBJECT_TYPES: Final[frozenset[IntelObjectType]] = frozenset(
    {
        IntelObjectType.IPV4_ADDR,
        IntelObjectType.IPV6_ADDR,
        IntelObjectType.DOMAIN_NAME,
        IntelObjectType.URL,
        IntelObjectType.FILE,
    }
)

#: Upper bound on a value offered to a matcher. The pinned snapshot's longest
#: entry is 191 characters; a candidate far longer than any entry cannot match a
#: string, substring or hostname list, and bounding it keeps a pathological URL
#: from being scanned against thousands of substrings.
MAX_CANDIDATE_LENGTH: Final[int] = 4096


class CandidateComponent(StrEnum):
    """Which part of the observable a candidate value came from.

    The distinction this whole provider turns on. ``OBSERVABLE`` is the artifact
    itself; ``URL_HOST`` is a piece of it, and a warninglist matching a piece can
    never say anything about the whole.

    ``https://github.com/attacker/payload.exe`` matching a popular-domain list is
    a fact about ``github.com``. Reporting it as a fact about the URL is how a
    living-off-trusted-sites payload gets waved through.
    """

    OBSERVABLE = "observable"
    URL_HOST = "url_host"


class WarningListCandidate(FrozenTiReconModel):
    """One MISP attribute value derived from one observable."""

    value: str = Field(min_length=1, max_length=MAX_CANDIDATE_LENGTH)
    #: The MISP attribute type this value is, which is what gates every list.
    misp_attribute_type: str = Field(min_length=1, max_length=64)
    component: CandidateComponent = CandidateComponent.OBSERVABLE
    #: How precisely a match on this candidate applies to the observable.
    match_scope: MatchScope = MatchScope.EXACT_OBSERVABLE
    #: The object this candidate was derived from, so several candidates can
    #: never be mistaken for several observables.
    subject_object_id: str = Field(min_length=1, max_length=200)
    #: For a file, which digest algorithm produced this value. Recorded so a
    #: match can say it was found by SHA-1 rather than by SHA-256.
    algorithm: str | None = Field(default=None, max_length=32)

    @property
    def is_component(self) -> bool:
        return self.component is not CandidateComponent.OBSERVABLE


def build_candidates(intel_object: IntelObject) -> tuple[WarningListCandidate, ...]:
    """Every MISP attribute value this observable legitimately produces.

    Empty for an object type this provider does not cover, which the adapter
    reports as ``NOT_SUPPORTED`` — never as a lookup that found nothing.
    """
    match intel_object.object_type:
        case IntelObjectType.IPV4_ADDR | IntelObjectType.IPV6_ADDR:
            return _address_candidates(intel_object)
        case IntelObjectType.DOMAIN_NAME:
            return _domain_candidates(intel_object)
        case IntelObjectType.URL:
            return _url_candidates(intel_object)
        case IntelObjectType.FILE:
            return _file_candidates(intel_object)
        case _:
            return ()


def candidate_attribute_types(
    candidates: tuple[WarningListCandidate, ...],
) -> frozenset[str]:
    """The attribute types present, for gating lists before any value is read."""
    return frozenset(candidate.misp_attribute_type for candidate in candidates)


def _address_candidates(intel_object: IntelObject) -> tuple[WarningListCandidate, ...]:
    """An address, as both MISP directions.

    ``ip-src`` and ``ip-dst`` are the same value asked two ways: a warninglist
    that declares only one direction still applies to an address we hold no
    direction for. Not two observations — the deduplication in
    :mod:`ti_recon.providers.misp_warninglists.matchers` collapses a list matched
    through both.

    No ``ip-src|port`` and no ``domain|ip``: a standalone address names neither a
    port nor a domain, and inventing the missing half would match upstream
    entries about a different thing.
    """
    value = intel_object.canonical_value
    return tuple(
        WarningListCandidate(
            value=value,
            misp_attribute_type=attribute,
            match_scope=MatchScope.EXACT_OBSERVABLE,
            subject_object_id=intel_object.id,
        )
        for attribute in ("ip-src", "ip-dst")
    )


def _domain_candidates(intel_object: IntelObject) -> tuple[WarningListCandidate, ...]:
    """A domain, as both MISP spellings.

    MISP distinguishes ``domain`` from ``hostname`` and warninglists use both,
    sometimes only one. TI Recon has a single canonical domain value, so it is
    offered under both names — again one artifact, deduplicated on the way out.
    """
    value = intel_object.canonical_value
    return tuple(
        WarningListCandidate(
            value=value,
            misp_attribute_type=attribute,
            match_scope=MatchScope.EXACT_OBSERVABLE,
            subject_object_id=intel_object.id,
        )
        for attribute in ("domain", "hostname")
    )


def _url_candidates(intel_object: IntelObject) -> tuple[WarningListCandidate, ...]:
    """A URL, plus its host as a clearly separate component.

    The full URL goes out as ``url`` and ``uri`` — both spellings appear in
    upstream ``matching_attributes`` — at ``EXACT_OBSERVABLE`` scope.

    The host goes out as ``hostname`` at ``SAME_HOST`` scope, tagged
    :attr:`CandidateComponent.URL_HOST`. That is the useful half in practice: a
    malicious path on a popular domain is exactly the case a popular-domain list
    can explain. It is also the dangerous half, so the scope and the component
    keep it visibly narrower than the artifact all the way into the evidence.

    The host is *parsed*, never searched for. Substring-matching a raw URL
    against a hostname list would let a path or a query string masquerade as a
    host: ``http://evil.example/?ref=github.com`` is not hosted on GitHub.
    """
    url = intel_object.canonical_value
    candidates = [
        WarningListCandidate(
            value=url,
            misp_attribute_type=attribute,
            match_scope=MatchScope.EXACT_OBSERVABLE,
            subject_object_id=intel_object.id,
        )
        for attribute in ("url", "uri")
        if len(url) <= MAX_CANDIDATE_LENGTH
    ]
    host = _url_host(url)
    if host is not None:
        candidates.append(
            WarningListCandidate(
                value=host,
                misp_attribute_type="hostname",
                component=CandidateComponent.URL_HOST,
                match_scope=MatchScope.SAME_HOST,
                subject_object_id=intel_object.id,
            )
        )
    return tuple(candidates)


def _file_candidates(intel_object: IntelObject) -> tuple[WarningListCandidate, ...]:
    """Every digest the file object actually carries.

    All of them, unlike the remote providers. There is no request to spend here,
    and the false-positive hash lists genuinely differ in which algorithm they
    hold — ``empty-hashes`` carries MD5, SHA-1 and SHA-256 for the same file, but
    another list may carry only one.

    A ``filename|<hash>`` composite is built only when the object records a real
    filename. Fabricating one from a hash would match entries about a file that
    merely shares a name.
    """
    candidates: list[WarningListCandidate] = []
    hashes = intel_object.hashes
    filename = _filename(intel_object)
    for algorithm, attribute in HASH_ATTRIBUTE_BY_ALGORITHM.items():
        digest = hashes.get(algorithm)
        if not digest:
            continue
        candidates.append(
            WarningListCandidate(
                value=digest,
                misp_attribute_type=attribute,
                match_scope=MatchScope.EXACT_OBSERVABLE,
                subject_object_id=intel_object.id,
                algorithm=algorithm,
            )
        )
        if filename is not None:
            candidates.append(
                WarningListCandidate(
                    value=f"{filename}|{digest}",
                    misp_attribute_type=f"filename|{attribute}",
                    match_scope=MatchScope.EXACT_OBSERVABLE,
                    subject_object_id=intel_object.id,
                    algorithm=algorithm,
                )
            )
    return tuple(candidates)


def _filename(intel_object: IntelObject) -> str | None:
    """A recorded filename, or ``None``.

    Read from the object's own properties only. Bounded and rejected if it
    carries a separator or a control character: a filename becomes half of a
    composite value, and one containing ``|`` would silently change which
    attribute type the composite is.
    """
    raw = intel_object.properties.get("file_name")
    if not isinstance(raw, str):
        return None
    candidate = raw.strip()
    if not candidate or len(candidate) > 255:
        return None
    if "|" in candidate:
        return None
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in candidate):
        return None
    return candidate


def _url_host(url: str) -> str | None:
    """The host of a URL, lowercased, or ``None`` if it has none.

    ``urlsplit`` only; nothing is resolved and nothing is fetched. A URL with no
    host, or one whose host is an address literal in brackets that will not
    parse, yields no host candidate rather than a guess.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = parts.hostname
    if not host:
        return None
    lowered = host.lower().rstrip(".")
    if not lowered or len(lowered) > MAX_CANDIDATE_LENGTH:
        return None
    return lowered
