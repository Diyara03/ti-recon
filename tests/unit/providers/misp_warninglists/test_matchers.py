"""Warninglist matcher semantics, against the official rules (Task 11).

The tests that decide whether this provider tells the truth. Every one of them
encodes a rule from the upstream data model rather than a convenience of this
implementation, because the failure mode here is silent: a matcher that is
slightly too generous produces confident context about the wrong thing.
"""

from __future__ import annotations

import pytest

from ti_recon.enums import MatchScope
from ti_recon.providers.misp_warninglists import (
    MATCHER_SUPPORT,
    CandidateComponent,
    CidrList,
    HostnameList,
    RawWarningList,
    RegexList,
    StringList,
    SubstringList,
    WarningListCandidate,
    compile_list,
)


def candidate(
    value: str,
    attribute: str = "domain",
    *,
    component: CandidateComponent = CandidateComponent.OBSERVABLE,
    scope: MatchScope = MatchScope.EXACT_OBSERVABLE,
) -> WarningListCandidate:
    return WarningListCandidate(
        value=value,
        misp_attribute_type=attribute,
        component=component,
        match_scope=scope,
        subject_object_id="object-1",
    )


def compiled(
    matcher: str,
    entries: list[str],
    attributes: list[str] | None = None,
    *,
    slug: str = "fixture",
):
    raw = RawWarningList(
        name=slug,
        version=1,
        description="fixture",
        type=matcher,
        list=tuple(entries),
        matching_attributes=None if attributes is None else tuple(attributes),
    )
    result, diagnostics = compile_list(slug, raw)
    return result, diagnostics


# --------------------------------------------------------------------------- #
# matching_attributes is authoritative
# --------------------------------------------------------------------------- #


def test_a_list_judges_only_the_attribute_types_it_declares() -> None:
    """The gate the whole provider rests on."""
    item, _ = compiled("string", ["example.com"], ["domain", "hostname"])
    assert item is not None
    assert item.applies_to("domain") is True
    assert item.applies_to("hostname") is True
    assert item.applies_to("md5") is False
    assert item.applies_to("url") is False


def test_a_non_applicable_attribute_never_matches_even_on_an_identical_value() -> None:
    """A colliding string is not a match if the list is about something else."""
    item, _ = compiled("string", ["deadbeef"], ["md5"])
    assert item is not None
    assert item.match(candidate("deadbeef", "md5")) is not None
    assert item.applies_to("domain") is False


def test_an_absent_matching_attributes_applies_to_everything() -> None:
    """The schema's own rule for the optional field.

    Worth noting no list in the pinned snapshot omits it — all 143 declare
    theirs — so this path exists for correctness against the schema rather than
    for today's data, which is exactly why it needs a fixture.
    """
    item, _ = compiled("string", ["anything"], None)
    assert item is not None
    assert item.attribute_types is None
    for attribute in ("domain", "md5", "url", "ip-src", "phone-number"):
        assert item.applies_to(attribute) is True


# --------------------------------------------------------------------------- #
# string
# --------------------------------------------------------------------------- #


def test_string_matching_is_exact() -> None:
    item, _ = compiled("string", ["example.com"], ["domain"])
    assert isinstance(item, StringList)
    assert item.match(candidate("example.com")) is not None
    assert item.match(candidate("EXAMPLE.COM")) is None
    assert item.match(candidate("www.example.com")) is None
    assert item.match(candidate("example.co")) is None


def test_string_matching_never_inflates_into_substring() -> None:
    """An exact list containing a fragment must not match values around it."""
    item, _ = compiled("string", ["evil"], ["domain"])
    assert isinstance(item, StringList)
    assert item.match(candidate("evil")) is not None
    assert item.match(candidate("evil.example.com")) is None
    assert item.match(candidate("notevil")) is None


def test_a_leading_dot_in_an_exact_list_is_counted_not_repaired() -> None:
    """`google` and `microsoft` really do this upstream.

    A leading-dot entry in an *exact* list can never equal a canonical domain.
    Rewriting it into a suffix rule would invent matches upstream never
    asserted, so it is recorded as unmatchable and left alone.
    """
    item, diagnostics = compiled("string", [".google.com", "google.com"], ["domain"])
    assert isinstance(item, StringList)
    assert diagnostics.unmatchable_entry_count == 1
    assert item.match(candidate("google.com")) is not None
    assert item.match(candidate("www.google.com")) is None


# --------------------------------------------------------------------------- #
# substring
# --------------------------------------------------------------------------- #


def test_substring_matches_a_contained_entry() -> None:
    item, _ = compiled("substring", ["app.any.run"], ["domain", "url"])
    assert isinstance(item, SubstringList)
    found = item.match(candidate("https://app.any.run/tasks/x", "url"))
    assert found is not None
    assert found.entry == "app.any.run"
    assert found.method == "substring"


def test_substring_does_not_match_an_unrelated_value() -> None:
    item, _ = compiled("substring", ["app.any.run"], ["domain"])
    assert item is not None
    assert item.match(candidate("example.com")) is None


def test_an_empty_substring_entry_cannot_become_a_universal_match() -> None:
    """The upstream typo that would otherwise flag every observable ever."""
    item, diagnostics = compiled("substring", ["", "   ", "any.run"], ["domain"])
    assert isinstance(item, SubstringList)
    assert diagnostics.invalid_entry_count == 2
    assert item.match(candidate("totally-unrelated.example")) is None
    assert item.match(candidate("x.any.run")) is not None


# --------------------------------------------------------------------------- #
# hostname
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("example.com", True),
        ("sub.example.com", True),
        ("deep.sub.example.com", True),
        ("EXAMPLE.COM", True),
        ("example.com.", True),
        ("evil-example.com", False),
        ("notexample.com", False),
        ("example.com.evil.test", False),
        ("example.org", False),
    ],
)
def test_hostname_matching_respects_domain_boundaries(host: str, expected: bool) -> None:
    """Whole-label suffixes, never `endswith`.

    `evil-example.com` ends with the string `example.com` and is a completely
    different domain. Comparing labels makes that structural rather than a bug
    waiting for the wrong test data.
    """
    item, _ = compiled("hostname", ["example.com"], ["hostname"])
    assert isinstance(item, HostnameList)
    assert (item.match(candidate(host, "hostname")) is not None) is expected


def test_a_leading_dot_hostname_entry_means_subdomains_only() -> None:
    """All 35,467 `dynamic-dns` entries are written this way.

    With the dot, upstream means "subdomains of dynv6.net" and deliberately not
    the bare domain. Stripping it would look like tidying and would silently
    widen the claim.
    """
    item, _ = compiled("hostname", [".dynv6.net"], ["hostname"])
    assert isinstance(item, HostnameList)
    assert item.subdomain_only == frozenset({"dynv6.net"})
    found = item.match(candidate("foo.dynv6.net", "hostname"))
    assert found is not None
    assert found.entry == ".dynv6.net"
    assert item.match(candidate("dynv6.net", "hostname")) is None


def test_the_most_specific_listed_suffix_is_reported() -> None:
    item, _ = compiled("hostname", ["com", "example.com"], ["hostname"])
    assert isinstance(item, HostnameList)
    found = item.match(candidate("a.b.example.com", "hostname"))
    assert found is not None
    assert found.entry == "example.com"


def test_a_bare_dot_entry_is_rejected_rather_than_matching_everything() -> None:
    item, diagnostics = compiled("hostname", [".", "example.com"], ["hostname"])
    assert isinstance(item, HostnameList)
    assert diagnostics.invalid_entry_count == 1
    assert item.match(candidate("anything.test", "hostname")) is None


# --------------------------------------------------------------------------- #
# cidr
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("10.0.0.1", True),
        ("10.255.255.254", True),
        ("192.168.1.5", True),
        ("11.0.0.1", False),
        ("172.32.0.1", False),
        ("8.8.8.8", False),
    ],
)
def test_ipv4_containment(address: str, expected: bool) -> None:
    item, _ = compiled(
        "cidr", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], ["ip-src", "ip-dst"]
    )
    assert isinstance(item, CidrList)
    assert (item.match(candidate(address, "ip-src")) is not None) is expected


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("2001:4860:4860::8888", True),
        ("2606:4700:4700::1111", True),
        ("2606:4700:4701::1", False),
        ("2a00::1", False),
    ],
)
def test_ipv6_containment(address: str, expected: bool) -> None:
    item, _ = compiled("cidr", ["2001:4860:4860::8888", "2606:4700:4700::/48"], ["ip-src"])
    assert isinstance(item, CidrList)
    assert (item.match(candidate(address, "ip-src")) is not None) is expected


def test_a_single_address_entry_reports_itself_rather_than_a_prefix() -> None:
    item, _ = compiled("cidr", ["8.8.8.8"], ["ip-src"])
    assert isinstance(item, CidrList)
    found = item.match(candidate("8.8.8.8", "ip-src"))
    assert found is not None
    assert found.entry == "8.8.8.8"


def test_a_network_entry_reports_the_network_that_contained_the_address() -> None:
    item, _ = compiled("cidr", ["162.142.125.0/24"], ["ip-src"])
    assert isinstance(item, CidrList)
    found = item.match(candidate("162.142.125.99", "ip-src"))
    assert found is not None
    assert found.entry == "162.142.125.0/24"


def test_a_malformed_cidr_is_skipped_and_diagnosed_not_repaired() -> None:
    """A broken prefix is not a hint about which network was meant."""
    item, diagnostics = compiled(
        "cidr", ["10.0.0.0/8", "999.999.999.0/24", "10.0.0.0/99", "not-an-ip"], ["ip-src"]
    )
    assert isinstance(item, CidrList)
    assert diagnostics.invalid_cidr_count == 3
    assert item.match(candidate("10.0.0.1", "ip-src")) is not None


def test_a_cidr_list_with_nothing_usable_does_not_load() -> None:
    item, diagnostics = compiled("cidr", ["nonsense", "also-nonsense"], ["ip-src"])
    assert item is None
    assert diagnostics.skipped_list_count == 1
    assert diagnostics.invalid_cidr_count == 2


def test_a_cidr_list_never_matches_a_domain_shaped_value() -> None:
    """No resolution. A domain is not an address and is not made into one."""
    item, _ = compiled("cidr", ["10.0.0.0/8"], ["ip-src", "domain"])
    assert isinstance(item, CidrList)
    assert item.match(candidate("example.com", "domain")) is None


# --------------------------------------------------------------------------- #
# regex: recognized, never executed
# --------------------------------------------------------------------------- #


def test_regex_is_not_a_supported_matcher_in_this_build() -> None:
    """Measured, not assumed — see RegexList's docstring."""
    assert MATCHER_SUPPORT["regex"] is False
    assert all(MATCHER_SUPPORT[name] for name in ("string", "substring", "hostname", "cidr"))


def test_a_regex_list_loads_and_records_its_patterns() -> None:
    item, diagnostics = compiled(
        "regex",
        [r"/((?:\+|00)1)?([0-9]{3})55501([0-9]{2})/g", r"/^(security|abuse)\@.*/i"],
        ["phone-number", "email-src"],
    )
    assert isinstance(item, RegexList)
    assert item.pattern_count == 2
    assert item.delimited_count == 2
    assert diagnostics.invalid_regex_count == 0


def test_a_regex_list_never_matches_anything() -> None:
    """No pattern is executed against any candidate, ever.

    A PHP `preg_match` pattern under a Python backtracking engine is a hang
    waiting to happen, and the pinned snapshot's regex lists target email and
    phone attributes that TI Recon cannot even produce.
    """
    item, _ = compiled("regex", [r"/.*/"], None)
    assert isinstance(item, RegexList)
    for value in ("anything", "security@example.com", "+15555501234", "a" * 500):
        assert item.match(candidate(value, "domain")) is None


def test_a_non_pcre_regex_entry_is_counted_rather_than_run() -> None:
    item, diagnostics = compiled("regex", ["not-a-delimited-pattern"], ["phone-number"])
    assert isinstance(item, RegexList)
    assert diagnostics.invalid_regex_count == 1
    assert item.delimited_count == 0


# --------------------------------------------------------------------------- #
# Entry hygiene, shared by every matcher
# --------------------------------------------------------------------------- #


def test_an_oversized_entry_is_dropped() -> None:
    item, diagnostics = compiled("string", ["x" * 5000, "fine"], ["domain"])
    assert isinstance(item, StringList)
    assert diagnostics.invalid_entry_count == 1
    assert item.match(candidate("fine")) is not None


def test_a_control_character_entry_is_dropped() -> None:
    item, diagnostics = compiled("string", ["bad\x00entry", "fine"], ["domain"])
    assert isinstance(item, StringList)
    assert diagnostics.invalid_entry_count == 1


def test_duplicate_entries_collapse() -> None:
    item, _ = compiled("string", ["example.com", "example.com"], ["domain"])
    assert isinstance(item, StringList)
    assert item.entries == frozenset({"example.com"})
    assert item.entry_count == 2


def test_an_unknown_matcher_type_is_refused_at_the_model() -> None:
    """The schema enumerates five; a sixth is a schema change, not a value."""
    with pytest.raises(ValueError, match="unknown warninglist matcher"):
        RawWarningList(name="x", version=1, description="x", type="bloomfilter", list=("a",))


def test_an_extra_upstream_field_is_refused() -> None:
    """`additionalProperties: false` is honoured rather than tolerated."""
    with pytest.raises(ValueError):
        RawWarningList.model_validate(
            {
                "name": "x",
                "version": 1,
                "description": "x",
                "type": "string",
                "list": ["a"],
                "category": "false_positive",
            }
        )
