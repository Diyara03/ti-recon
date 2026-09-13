"""How precisely one stored scan applies to the observable that was submitted.

A Search API hit says only that a historical scan *matched the query*. For an
address the query is ``page.ip:X OR ip:X``, so a hit may be a page hosted on X
-- or a page that merely loaded a font from X. The same holds for a domain
through ``page.domain`` and ``domain``. Everything downstream must therefore
keep three things apart:

* why the search matched (never recorded as a fact about the observable);
* which page the browser actually landed on (``page.url``, ``page.domain``,
  ``page.ip``);
* what a given record is *about*, expressed as its subject and its
  :class:`~ti_recon.enums.MatchScope`.

This module holds the one identity rule both the search selector and the
normalizer read, so a candidate is ranked and a record is scoped by the same
judgement. It imports nothing from either of them.

The rule is deliberately conservative. A page *is* the observable only when
the final page URL, the page's own domain or the page's own address equals it;
a subdomain or another URL on the same host is the neighbourhood, and a page
that merely contacted the observable is incidental to it. A verdict about an
incidental page is a verdict about that page (Task 24, US-01): it is kept, on
the page, and the observable stays linked to the page through the contact
relationship the scan already asserts.
"""

from __future__ import annotations

from typing import Final

from ti_recon.enums import IntelObjectType, MatchScope
from ti_recon.models.intel_object import IntelObject

__all__ = [
    "INCIDENTAL_SCOPES",
    "is_incidental",
    "page_is_observable",
    "page_match_scope",
]

#: Scopes at which the scanned page is not about the observable at all: the
#: observable appears in the scan only because the page contacted it. A
#: verdict on such a page describes the page, never the observable.
INCIDENTAL_SCOPES: Final[frozenset[MatchScope]] = frozenset({MatchScope.CLUSTER})


def page_match_scope(
    subject: IntelObject,
    *,
    page_url: str | None,
    submitted_url: str | None,
    page_domain: str | None,
    page_ip: str | None,
) -> MatchScope:
    """How precisely a scan of this page applies to ``subject``.

    This is the difference between "urlscan saw *this URL* serving a phishing
    kit" and "urlscan saw *something on this IP* serving one". Both are
    evidence; only the first is about the observable itself.
    """
    value = subject.canonical_value
    match subject.object_type:
        case IntelObjectType.URL:
            if page_url == value or submitted_url == value:
                return MatchScope.EXACT_OBSERVABLE
            return MatchScope.SAME_HOST
        case IntelObjectType.DOMAIN_NAME:
            if page_domain == value:
                return MatchScope.SAME_HOST
            if page_domain and page_domain.endswith(f".{value}"):
                return MatchScope.PARENT_DOMAIN
            # The domain was contacted by the page rather than being the page.
            return MatchScope.CLUSTER
        case IntelObjectType.IPV4_ADDR | IntelObjectType.IPV6_ADDR:
            return MatchScope.SAME_IP if page_ip == value else MatchScope.CLUSTER
        case IntelObjectType.FILE:
            # The observable is a response body the page served, not the page.
            return MatchScope.SAME_HOST
        case _:
            return MatchScope.UNKNOWN


def is_incidental(scope: MatchScope) -> bool:
    """Whether a scan at this scope is about something other than the observable."""
    return scope in INCIDENTAL_SCOPES


def page_is_observable(
    subject: IntelObject,
    *,
    page_url: str | None,
    page_domain: str | None,
    page_ip: str | None,
) -> bool:
    """Whether the page the browser landed on *is* the submitted observable.

    Stricter than :func:`page_match_scope`, on purpose: it decides whether the
    page's own hosting facts -- its address, its network, its server, its
    certificate -- may be written onto the observable as properties. A
    redirect's final page has the final page's hosting facts, a subdomain has
    its own, and a page that merely contacted the observable has nothing to
    say about it (Task 24, US-03).
    """
    value = subject.canonical_value
    match subject.object_type:
        case IntelObjectType.URL:
            return page_url == value
        case IntelObjectType.DOMAIN_NAME:
            return page_domain == value
        case IntelObjectType.IPV4_ADDR | IntelObjectType.IPV6_ADDR:
            return page_ip == value
        case _:
            return False
