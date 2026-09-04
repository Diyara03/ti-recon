"""Deciding whether a ThreatFox record is actually about the observable (Task 10).

Pure functions. This module is the gate: nothing ThreatFox returns becomes
evidence without passing through it.

Why a gate is needed at all
---------------------------

ThreatFox stores address intelligence as ``ip:port`` rather than as a bare
address. An exact search for ``1.2.3.4`` would therefore match nothing useful,
so that lookup asks for a loose match — and a loose match on a provider we do not
control is exactly the shape that produces confident nonsense::

    queried:  1.2.3.4
    returned: 11.2.3.45:443     <- contains "1.2.3.4" as a substring

Reporting that as evidence about ``1.2.3.4`` would attribute somebody else's
botnet controller to an unrelated address. So every returned record is re-checked
locally, by parsing it rather than by searching in it: the host component is
split off and compared for **equality**. There is no code path here that uses
``in``, ``startswith`` or a regular expression against an IOC value.

What a match means
------------------

A match also carries how precisely it applies, because the two cases are not the
same claim:

* the record *is* the observable — an exact domain, URL or hash — which is
  ``EXACT_OBSERVABLE``;
* the record is a **port on** the observed address, which is ``SAME_IP``: real
  evidence about that address, but about one service on it rather than about the
  address as a whole.

Keeping those apart is what stops "port 443 on this host was a C2" from being
read later as "this address is a C2 for everything".
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Final

from pydantic import Field

from ti_recon.enums import IntelObjectType, MatchScope
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers.abusech.values import MAX_TEXT, text

__all__ = [
    "MAX_IOC_LENGTH",
    "MatchedComponent",
    "ThreatFoxMatch",
    "match_for",
    "split_host_port",
]

#: Bound on an IOC value read from a response.
MAX_IOC_LENGTH: Final[int] = MAX_TEXT


class MatchedComponent(StrEnum):
    """Which part of a ThreatFox record matched the observable."""

    #: The record's value is the observable.
    EXACT = "exact"
    #: The record is ``host:port`` and its host is the observable.
    HOST = "host"


class ThreatFoxMatch(FrozenTiReconModel):
    """One ThreatFox record confirmed to be about the submitted observable."""

    ioc: str = Field(min_length=1, max_length=MAX_IOC_LENGTH)
    ioc_type: str | None = Field(default=None, max_length=64)
    matched_component: MatchedComponent = MatchedComponent.EXACT
    #: The port, when the record was port-qualified.
    port: int | None = Field(default=None, ge=1, le=65535)
    match_scope: MatchScope = MatchScope.EXACT_OBSERVABLE

    @property
    def is_port_qualified(self) -> bool:
        return self.matched_component is MatchedComponent.HOST


def split_host_port(value: str) -> tuple[str, int] | None:
    """Split ``host:port`` into its parts, or ``None`` if it is not that shape.

    Splits on the *last* colon and requires the remainder to be a plain port
    number, so a value that merely contains a colon is not mistaken for a
    port-qualified one. IPv6 literals are not handled on purpose: ThreatFox's
    representation of them is not established, and this integration does not
    claim IPv6 support.
    """
    host, separator, port = value.rpartition(":")
    if not separator or not host or not port.isdigit():
        return None
    number = int(port)
    if not 1 <= number <= 65535:
        return None
    return host, number


def match_for(subject: IntelObject, entry: Mapping[str, Any]) -> ThreatFoxMatch | None:
    """Whether one ThreatFox record is about ``subject``, and how precisely.

    ``None`` means the record is about something else and must be discarded — a
    loose provider match that did not survive local validation.
    """
    ioc = text(entry.get("ioc"), MAX_IOC_LENGTH)
    if ioc is None:
        return None
    ioc_type = text(entry.get("ioc_type"), 64)

    match subject.object_type:
        case IntelObjectType.IPV4_ADDR:
            return _match_address(subject.canonical_value, ioc, ioc_type)
        case IntelObjectType.DOMAIN_NAME:
            return _match_domain(subject.canonical_value, ioc, ioc_type)
        case IntelObjectType.URL:
            return _match_exact(subject.canonical_value, ioc, ioc_type, case_sensitive=True)
        case IntelObjectType.FILE:
            return _match_hash(subject, ioc, ioc_type)
        case _:
            return None


def _match_address(address: str, ioc: str, ioc_type: str | None) -> ThreatFoxMatch | None:
    """An address matches its own record, or a record for a port on it."""
    if ioc == address:
        return ThreatFoxMatch(
            ioc=ioc,
            ioc_type=ioc_type,
            matched_component=MatchedComponent.EXACT,
            match_scope=MatchScope.EXACT_OBSERVABLE,
        )
    parts = split_host_port(ioc)
    if parts is None:
        return None
    host, port = parts
    # Equality, never containment: "11.2.3.45" must not match "1.2.3.4".
    if host != address:
        return None
    return ThreatFoxMatch(
        ioc=ioc,
        ioc_type=ioc_type,
        matched_component=MatchedComponent.HOST,
        port=port,
        # The claim is about a service on this address, not about the address.
        match_scope=MatchScope.SAME_IP,
    )


def _match_domain(domain: str, ioc: str, ioc_type: str | None) -> ThreatFoxMatch | None:
    """A domain matches its own record, or a record for a port on it.

    Case-insensitive, because a hostname is: the canonical value is already
    lowercase and the provider's copy may not be. Nothing else is relaxed — a
    subdomain is a different observable and does not match.
    """
    if ioc.lower() == domain.lower():
        return ThreatFoxMatch(
            ioc=ioc,
            ioc_type=ioc_type,
            matched_component=MatchedComponent.EXACT,
            match_scope=MatchScope.EXACT_OBSERVABLE,
        )
    parts = split_host_port(ioc)
    if parts is None:
        return None
    host, port = parts
    if host.lower() != domain.lower():
        return None
    return ThreatFoxMatch(
        ioc=ioc,
        ioc_type=ioc_type,
        matched_component=MatchedComponent.HOST,
        port=port,
        match_scope=MatchScope.SAME_HOST,
    )


def _match_exact(
    value: str, ioc: str, ioc_type: str | None, *, case_sensitive: bool
) -> ThreatFoxMatch | None:
    """An exact-value match, with no relaxation whatsoever.

    Used for URLs, where every character carries meaning: a path, a query
    parameter and a fragment are part of the artifact, and a URL that merely
    shares a host is a different observable.
    """
    left = ioc if case_sensitive else ioc.lower()
    right = value if case_sensitive else value.lower()
    if left != right:
        return None
    return ThreatFoxMatch(
        ioc=ioc,
        ioc_type=ioc_type,
        matched_component=MatchedComponent.EXACT,
        match_scope=MatchScope.EXACT_OBSERVABLE,
    )


def _match_hash(subject: IntelObject, ioc: str, ioc_type: str | None) -> ThreatFoxMatch | None:
    """A file matches a record naming any digest the file object carries."""
    lowered = ioc.lower()
    for digest in subject.hashes.values():
        if digest.lower() == lowered:
            return ThreatFoxMatch(
                ioc=ioc,
                ioc_type=ioc_type,
                matched_component=MatchedComponent.EXACT,
                match_scope=MatchScope.EXACT_OBSERVABLE,
            )
    return None
