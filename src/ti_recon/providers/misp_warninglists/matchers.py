"""The four matchers TI Recon runs, and the one it deliberately does not (Task 11).

Upstream defines five matcher types. Four are implemented here — ``string``,
``substring``, ``hostname``, ``cidr`` — and ``regex`` is recognized, recorded and
never executed. That last decision is measured rather than assumed; see
:class:`RegexList`.

Faithful, not helpful
---------------------

The recurring temptation in this file is to improve upstream data. It is
declined everywhere.

``dynamic-dns`` stores all 35,467 of its hostname entries with a leading dot
(``.dynv6.net``). Stripping that dot would look like tidying and would silently
change the claim: with the dot the entry means "subdomains of dynv6.net", and
``dynv6.net`` itself is deliberately not in it. So the dot is honoured, and
``foo.dynv6.net`` matches while ``dynv6.net`` does not.

``google`` and ``microsoft`` are ``string`` lists — exact matching — that also
hold leading-dot entries. Those entries cannot match any canonical TI Recon
domain, ever. Rewriting them into suffix rules would invent matches upstream did
not assert, so they are counted as unmatchable in the load diagnostics and left
exactly as they are.

Structure
---------

Each list compiles once into a form its matcher can answer in constant or
near-constant time, because a lookup runs against every applicable list:

* ``string`` — a ``frozenset`` of entries.
* ``hostname`` — a ``frozenset`` of suffixes, queried with the candidate's own
  label suffixes, so matching is domain-boundary safe by construction rather than
  by a string comparison that could straddle a label.
* ``substring`` — a tuple, scanned. Bounded: the applicable substring lists in
  the pinned snapshot hold 167 entries between them.
* ``cidr`` — single addresses in a set of integers, and real networks bucketed by
  prefix length. A lookup masks the address once per distinct prefix length
  present rather than testing 72,600 networks one at a time.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Final, TypedDict

from pydantic import Field

from ti_recon.models.base import FrozenTiReconModel
from ti_recon.providers.misp_warninglists.candidates import WarningListCandidate
from ti_recon.providers.misp_warninglists.models import (
    MAX_ENTRY_LENGTH,
    LoadDiagnostics,
    RawWarningList,
)

__all__ = [
    "MATCHER_SUPPORT",
    "PCRE_DELIMITED",
    "CidrList",
    "CompiledList",
    "HostnameList",
    "ListMatch",
    "RegexList",
    "StringList",
    "SubstringList",
    "compile_list",
]

#: Which matchers this build evaluates. ``regex`` is ``False`` — see
#: :class:`RegexList` for the measurement behind that.
MATCHER_SUPPORT: Final[dict[str, bool]] = {
    "string": True,
    "substring": True,
    "hostname": True,
    "cidr": True,
    "regex": False,
}

#: Recognizes a PCRE literal — ``/pattern/flags`` — which is what upstream regex
#: entries are. Used only to *identify* them, never to run them.
PCRE_DELIMITED: Final[re.Pattern[str]] = re.compile(r"\A/(?P<pattern>.*)/(?P<flags>[a-zA-Z]*)\Z")


class ListMatch(FrozenTiReconModel):
    """One warninglist matching one candidate."""

    slug: str = Field(min_length=1, max_length=200)
    #: The entry that matched. Bounded, and one entry rather than the list: a
    #: match record is evidence, not a copy of the dataset.
    entry: str = Field(min_length=1, max_length=MAX_ENTRY_LENGTH)
    method: str = Field(min_length=1, max_length=32)
    candidate: WarningListCandidate


class _BaseList(FrozenTiReconModel):
    """What every compiled list shares."""

    slug: str = Field(min_length=1, max_length=200)
    matcher: str = Field(min_length=1, max_length=32)
    attribute_types: frozenset[str] | None = None
    entry_count: int = Field(default=0, ge=0)

    def applies_to(self, attribute_type: str) -> bool:
        """Whether this list may judge a candidate of ``attribute_type``.

        ``None`` is an absent upstream ``matching_attributes``, which the schema
        defines as applying to everything. Worth noting that no list in the
        pinned snapshot omits the field — every one of the 143 declares its
        attributes — so this branch exists for correctness against the schema
        rather than for today's data, and a fixture exercises it.
        """
        if self.attribute_types is None:
            return True
        return attribute_type in self.attribute_types

    def match(self, candidate: WarningListCandidate) -> ListMatch | None:  # pragma: no cover
        raise NotImplementedError


class StringList(_BaseList):
    """Exact matching, and only exact matching.

    No case folding, no trimming, no dot repair. An exact-match list means what
    it says; turning it into a suffix or a prefix rule would manufacture matches
    upstream never asserted.
    """

    entries: frozenset[str]

    def match(self, candidate: WarningListCandidate) -> ListMatch | None:
        if candidate.value in self.entries:
            return ListMatch(
                slug=self.slug, entry=candidate.value, method="string", candidate=candidate
            )
        return None


class SubstringList(_BaseList):
    """The list entry appearing anywhere inside the candidate.

    Empty entries are dropped at compile time rather than here. An empty string
    is contained in every value, so one would turn its list into a universal
    match — the kind of upstream typo that would otherwise flag every observable
    an analyst ever submits.
    """

    entries: tuple[str, ...]

    def match(self, candidate: WarningListCandidate) -> ListMatch | None:
        value = candidate.value
        for entry in self.entries:
            if entry in value:
                return ListMatch(
                    slug=self.slug, entry=entry, method="substring", candidate=candidate
                )
        return None


class HostnameList(_BaseList):
    """Domain-boundary-safe suffix matching.

    ``example.com`` matches ``example.com`` and ``sub.example.com``, and does not
    match ``evil-example.com`` or ``notexample.com``. That is achieved by
    comparing whole label suffixes rather than by string ``endswith``, so a
    boundary can never be straddled.

    Leading dots are preserved and mean what upstream means by them: an entry
    ``.dynv6.net`` matches subdomains and not the bare domain.
    """

    #: Entries with no leading dot: match the domain itself or any subdomain.
    domains: frozenset[str]
    #: Entries written with a leading dot: subdomains only.
    subdomain_only: frozenset[str]

    def match(self, candidate: WarningListCandidate) -> ListMatch | None:
        host = candidate.value.lower().rstrip(".")
        if not host:
            return None
        if host in self.domains:
            return ListMatch(slug=self.slug, entry=host, method="hostname", candidate=candidate)
        labels = host.split(".")
        # Every proper parent, longest first, so the most specific listed suffix
        # is the one reported.
        for index in range(1, len(labels)):
            parent = ".".join(labels[index:])
            if parent in self.domains:
                return ListMatch(
                    slug=self.slug, entry=parent, method="hostname", candidate=candidate
                )
            if parent in self.subdomain_only:
                return ListMatch(
                    slug=self.slug, entry=f".{parent}", method="hostname", candidate=candidate
                )
        return None


class CidrList(_BaseList):
    """Address containment, by the standard library only.

    No DNS. A domain is never resolved to an address to make a CIDR list
    applicable — that would turn a local, deterministic lookup into a network
    call whose answer changes with the resolver.
    """

    #: ``(version, integer address)`` for entries covering exactly one address,
    #: which is 70,274 of the pinned snapshot's 142,874 CIDR entries.
    hosts: frozenset[tuple[int, int]]
    #: ``(version, prefix length) -> masked network addresses``.
    networks: dict[tuple[int, int], frozenset[int]]

    def match(self, candidate: WarningListCandidate) -> ListMatch | None:
        try:
            address = ipaddress.ip_address(candidate.value)
        except ValueError:
            return None
        version = address.version
        numeric = int(address)
        if (version, numeric) in self.hosts:
            return ListMatch(slug=self.slug, entry=str(address), method="cidr", candidate=candidate)
        width = 128 if version == 6 else 32
        for (net_version, prefix), addresses in self.networks.items():
            if net_version != version:
                continue
            shift = width - prefix
            masked = (numeric >> shift) << shift
            if masked in addresses:
                network = ipaddress.ip_network((masked, prefix))
                return ListMatch(
                    slug=self.slug, entry=str(network), method="cidr", candidate=candidate
                )
        return None


class RegexList(_BaseList):
    """Recognized, recorded, and never executed.

    Upstream regex lists are PHP ``preg_match`` patterns, delimited and flagged
    for that engine — ``/((?:\\+|00)1)?([0-9]{3})55501([0-9]{2})/g`` is a real
    entry. Python's ``re`` has no ``g`` flag at all, so translating patterns is a
    compatibility project, and running attacker-adjacent patterns under a
    backtracking engine inside an investigation is a hang waiting to happen.

    The pinned snapshot settles whether that project is needed. It contains
    exactly two regex lists, holding 34 entries:

    * ``common-contact-emails`` — ``email-src``, ``email-dst``, ``target-email``
    * ``phone_numbers`` — ``phone-number``, ``whois-registrant-phone``

    Neither declares a single attribute type TI Recon can produce a candidate
    for. So no applicable regex list exists, no pattern is ever a candidate's
    business, and adding a regex engine would buy exactly nothing while adding a
    timeout, a dependency and a class of hang. Patterns are parsed far enough to
    confirm they are PCRE literals and counted; that is all.

    If a future snapshot adds a regex list targeting an IP, domain, URL or hash
    attribute, :meth:`match` still returns nothing and the load reports it as an
    unsupported *applicable* matcher, which the adapter turns into ``PARTIAL``
    coverage. Silence about a list that could have matched is the one outcome
    this design refuses.
    """

    #: Kept for reporting only.
    pattern_count: int = Field(default=0, ge=0)
    delimited_count: int = Field(default=0, ge=0)

    def match(self, candidate: WarningListCandidate) -> ListMatch | None:
        """Always ``None``. No pattern is executed against any candidate."""
        return None


CompiledList = StringList | SubstringList | HostnameList | CidrList | RegexList


class _ListMeta(TypedDict):
    """The fields every compiled list shares, kept typed rather than as a dict."""

    slug: str
    matcher: str
    attribute_types: frozenset[str] | None
    entry_count: int


def compile_list(slug: str, raw: RawWarningList) -> tuple[CompiledList | None, LoadDiagnostics]:
    """Compile one raw list, reporting what had to be dropped.

    Returns ``(None, diagnostics)`` only when nothing usable survives. A list
    with some invalid entries still loads with the rest: dropping a whole
    infrastructure list because one CIDR is malformed would lose real coverage
    over a typo, and the count of what was dropped travels in the diagnostics.
    """
    attribute_types = (
        None if raw.matching_attributes is None else frozenset(raw.matching_attributes)
    )
    common: _ListMeta = {
        "slug": slug,
        "matcher": raw.type,
        "attribute_types": attribute_types,
        "entry_count": len(raw.list),
    }
    match raw.type:
        case "string":
            return _compile_string(common, raw)
        case "substring":
            return _compile_substring(common, raw)
        case "hostname":
            return _compile_hostname(common, raw)
        case "cidr":
            return _compile_cidr(common, raw)
        case "regex":
            return _compile_regex(common, raw)
        case _:  # pragma: no cover - RawWarningList validates the matcher first
            return None, LoadDiagnostics(
                skipped_list_count=1,
                unsupported_matcher_count=1,
                notes=(f"{slug}: unknown matcher",),
            )


def _usable(entry: object) -> str | None:
    """A non-empty, bounded, control-character-free entry, or ``None``."""
    if not isinstance(entry, str):
        return None
    if not entry or len(entry) > MAX_ENTRY_LENGTH:
        return None
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in entry):
        return None
    return entry


def _compile_string(common: _ListMeta, raw: RawWarningList) -> tuple[CompiledList, LoadDiagnostics]:
    entries: set[str] = set()
    invalid = 0
    unmatchable = 0
    for entry in raw.list:
        usable = _usable(entry)
        if usable is None:
            invalid += 1
            continue
        # A leading dot in an *exact* list can never equal a canonical domain.
        # Counted, not corrected: see the module docstring.
        if usable.startswith("."):
            unmatchable += 1
        entries.add(usable)
    return StringList(**common, entries=frozenset(entries)), LoadDiagnostics(
        invalid_entry_count=invalid, unmatchable_entry_count=unmatchable
    )


def _compile_substring(
    common: _ListMeta, raw: RawWarningList
) -> tuple[CompiledList, LoadDiagnostics]:
    entries: list[str] = []
    invalid = 0
    for entry in raw.list:
        usable = _usable(entry)
        if usable is None:
            invalid += 1
            continue
        entries.append(usable)
    return SubstringList(**common, entries=tuple(sorted(set(entries)))), LoadDiagnostics(
        invalid_entry_count=invalid
    )


def _compile_hostname(
    common: _ListMeta, raw: RawWarningList
) -> tuple[CompiledList, LoadDiagnostics]:
    domains: set[str] = set()
    subdomain_only: set[str] = set()
    invalid = 0
    for entry in raw.list:
        usable = _usable(entry)
        if usable is None:
            invalid += 1
            continue
        lowered = usable.lower().rstrip(".")
        if lowered.startswith("."):
            stripped = lowered.lstrip(".")
            if stripped:
                subdomain_only.add(stripped)
            else:
                invalid += 1
        elif lowered:
            domains.add(lowered)
        else:
            invalid += 1
    return HostnameList(
        **common, domains=frozenset(domains), subdomain_only=frozenset(subdomain_only)
    ), LoadDiagnostics(invalid_entry_count=invalid)


def _compile_cidr(
    common: _ListMeta, raw: RawWarningList
) -> tuple[CompiledList | None, LoadDiagnostics]:
    hosts: set[tuple[int, int]] = set()
    networks: dict[tuple[int, int], set[int]] = {}
    invalid = 0
    for entry in raw.list:
        usable = _usable(entry)
        if usable is None:
            invalid += 1
            continue
        try:
            network = ipaddress.ip_network(usable, strict=False)
        except ValueError:
            # Skipped, never repaired. A malformed prefix is not a hint about
            # which network was meant.
            invalid += 1
            continue
        if network.num_addresses == 1:
            hosts.add((network.version, int(network.network_address)))
        else:
            key = (network.version, network.prefixlen)
            networks.setdefault(key, set()).add(int(network.network_address))
    if not hosts and not networks:
        return None, LoadDiagnostics(
            skipped_list_count=1,
            invalid_cidr_count=invalid,
            notes=(f"{common['slug']}: no usable CIDR entries",),
        )
    return CidrList(
        **common,
        hosts=frozenset(hosts),
        networks={key: frozenset(value) for key, value in networks.items()},
    ), LoadDiagnostics(invalid_cidr_count=invalid)


def _compile_regex(common: _ListMeta, raw: RawWarningList) -> tuple[CompiledList, LoadDiagnostics]:
    """Parse regex entries far enough to count them, and no further.

    Nothing is compiled and nothing will be executed, so an entry that is not a
    PCRE literal is recorded rather than rejected: it is not going to run either
    way, and refusing the list would misreport coverage for lists that cannot
    apply to our candidates in the first place.
    """
    delimited = 0
    malformed = 0
    for entry in raw.list:
        usable = _usable(entry)
        if usable is None:
            malformed += 1
            continue
        if PCRE_DELIMITED.fullmatch(usable):
            delimited += 1
        else:
            malformed += 1
    return RegexList(
        **common, pattern_count=len(raw.list), delimited_count=delimited
    ), LoadDiagnostics(invalid_regex_count=malformed)
