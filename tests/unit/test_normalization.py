"""Observable normalization tests (Task 3)."""

from __future__ import annotations

import pytest

from ti_recon.enums import IntelObjectType, ObjectClass
from ti_recon.normalization import (
    NormalizationError,
    normalize_domain,
    normalize_file_hash,
    normalize_ip,
    normalize_observable,
    normalize_url,
)
from ti_recon.normalization.observables import MAX_INPUT_LENGTH

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
MD5 = "d41d8cd98f00b204e9800998ecf8427e"


# --------------------------------------------------------------------------- #
# IPv4
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("8.8.8.8", "8.8.8.8"),
        ("  198.51.100.7  ", "198.51.100.7"),
        ("0.0.0.0", "0.0.0.0"),
        ("255.255.255.255", "255.255.255.255"),
        ("198[.]51[.]100[.]7", "198.51.100.7"),
    ],
)
def test_valid_ipv4(raw: str, canonical: str) -> None:
    result = normalize_observable(raw)
    assert result.intel_object.object_type is IntelObjectType.IPV4_ADDR
    assert result.intel_object.canonical_value == canonical
    assert result.intel_object.canonical_key == f"ipv4-addr:{canonical}"
    assert result.original_input == raw


@pytest.mark.parametrize(
    "raw",
    [
        "256.1.1.1",
        "1.2.3",
        "1.2.3.4.5",
        "010.1.1.1",  # leading zeros are ambiguous (octal) and rejected
        "1.2.3.-4",
        "1.2.3.4/24",
    ],
)
def test_invalid_ipv4_is_not_normalized_as_an_ip(raw: str) -> None:
    with pytest.raises(NormalizationError):
        normalize_ip(raw)


def test_invalid_ipv4_shaped_input_is_rejected_entirely() -> None:
    with pytest.raises(NormalizationError):
        normalize_observable("256.1.1.1")


# --------------------------------------------------------------------------- #
# IPv6
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("2001:DB8::1", "2001:db8::1"),
        ("::1", "::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        # Python canonicalizes IPv4-mapped addresses to hextet form.
        ("::ffff:192.0.2.1", "::ffff:c000:201"),
    ],
)
def test_valid_ipv6(raw: str, canonical: str) -> None:
    result = normalize_observable(raw)
    assert result.intel_object.object_type is IntelObjectType.IPV6_ADDR
    assert result.intel_object.canonical_value == canonical


@pytest.mark.parametrize("raw", ["2001:db8:::1", "gggg::1", "2001:db8::1::2"])
def test_invalid_ipv6(raw: str) -> None:
    with pytest.raises(NormalizationError):
        normalize_ip(raw)


# --------------------------------------------------------------------------- #
# Domains
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("evil.example", "evil.example"),
        ("EVIL.EXAMPLE", "evil.example"),
        ("evil.example.", "evil.example"),
        ("sub.deep.evil.example", "sub.deep.evil.example"),
        ("_dmarc.evil.example", "_dmarc.evil.example"),
        ("xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai"),
        ("host-1.example.co.uk", "host-1.example.co.uk"),
    ],
)
def test_valid_domain(raw: str, canonical: str) -> None:
    result = normalize_observable(raw)
    assert result.intel_object.object_type is IntelObjectType.DOMAIN_NAME
    assert result.intel_object.canonical_value == canonical
    assert result.intel_object.canonical_key == f"domain-name:{canonical}"


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("evil[.]example", "evil.example"),
        ("evil(.)example", "evil.example"),
        ("evil{.}example", "evil.example"),
        ("evil[dot]example", "evil.example"),
        ("EVIL[.]EXAMPLE", "evil.example"),
        ("sub[.]evil[.]example", "sub.evil.example"),
    ],
)
def test_defanged_domain(raw: str, canonical: str) -> None:
    assert normalize_observable(raw).intel_object.canonical_value == canonical


def test_idn_domain_is_punycoded_and_keeps_a_unicode_display_value() -> None:
    result = normalize_observable("пример.рф")
    obj = result.intel_object
    assert obj.canonical_value == "xn--e1afmkfd.xn--p1ai"
    assert obj.display_value == "пример.рф"
    assert obj.canonical_key == "domain-name:xn--e1afmkfd.xn--p1ai"


def test_idn_domain_normalizes_case_via_uts46() -> None:
    assert normalize_domain("BÜCHER.example").canonical_value == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "raw",
    [
        "localhost",
        "example",
        "evil..example",
        "-evil.example",
        "evil-.example",
        "evil.example-",
        "evil.123",
        "evil.exam ple",
        "a" * 64 + ".example",
        ("a" * 60 + ".") * 5 + "example",
        "evil.example/path",
        "evil.example:8080",
        "​evil.example",
    ],
)
def test_invalid_domain(raw: str) -> None:
    with pytest.raises(NormalizationError):
        normalize_domain(raw)


def test_empty_and_oversized_input_is_rejected() -> None:
    with pytest.raises(NormalizationError, match="empty"):
        normalize_observable("   ")
    with pytest.raises(NormalizationError, match="exceeds"):
        normalize_observable("a" * (MAX_INPUT_LENGTH + 1))


def test_input_with_internal_whitespace_is_rejected() -> None:
    with pytest.raises(NormalizationError, match="whitespace"):
        normalize_observable("evil .example")


def test_normalization_does_not_resolve_dns() -> None:
    """A syntactically valid domain that cannot exist still normalizes fine."""
    obj = normalize_domain("this-domain-does-not-resolve.invalid")
    assert obj.canonical_value == "this-domain-does-not-resolve.invalid"


# --------------------------------------------------------------------------- #
# URLs
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("http://evil.example", "http://evil.example/"),
        ("HTTP://EVIL.EXAMPLE/", "http://evil.example/"),
        ("https://evil.example/a", "https://evil.example/a"),
        ("http://evil.example:80/a", "http://evil.example/a"),
        ("https://evil.example:443/a", "https://evil.example/a"),
        ("https://evil.example:8443/a", "https://evil.example:8443/a"),
        ("ftp://evil.example/a", "ftp://evil.example/a"),
        ("http://198.51.100.7/a", "http://198.51.100.7/a"),
        ("http://[2001:0db8::1]:8080/a", "http://[2001:db8::1]:8080/a"),
        ("http://user:pw@evil.example/a", "http://user:pw@evil.example/a"),
    ],
)
def test_valid_url(raw: str, canonical: str) -> None:
    result = normalize_observable(raw)
    assert result.intel_object.object_type is IntelObjectType.URL
    assert result.intel_object.canonical_value == canonical


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("hxxp://evil[.]example/a", "http://evil.example/a"),
        ("hxxps://evil[.]example/a", "https://evil.example/a"),
        ("hXXps://EVIL[.]example/a", "https://evil.example/a"),
        ("http[://]evil[.]example/a", "http://evil.example/a"),
        ("http[:]//evil[.]example/a", "http://evil.example/a"),
    ],
)
def test_defanged_url(raw: str, canonical: str) -> None:
    assert normalize_observable(raw).intel_object.canonical_value == canonical


def test_url_path_case_is_preserved() -> None:
    raw = "https://EVIL.example/Path/To/CaseSensitive.PHP"
    canonical = normalize_observable(raw).intel_object.canonical_value
    assert canonical == "https://evil.example/Path/To/CaseSensitive.PHP"


def test_url_query_is_preserved_verbatim() -> None:
    raw = "https://evil.example/x?z=2&a=1&Empty=&flag&dup=1&dup=2"
    canonical = normalize_observable(raw).intel_object.canonical_value
    assert canonical == "https://evil.example/x?z=2&a=1&Empty=&flag&dup=1&dup=2"


def test_url_percent_encoding_is_not_decoded() -> None:
    raw = "https://evil.example/a%2Fb%20c?q=%3Cscript%3E"
    canonical = normalize_observable(raw).intel_object.canonical_value
    assert canonical == "https://evil.example/a%2Fb%20c?q=%3Cscript%3E"


def test_url_fragment_is_preserved() -> None:
    raw = "https://evil.example/a#Section-2"
    assert normalize_observable(raw).intel_object.canonical_value.endswith("#Section-2")


def test_url_path_defanging_is_not_undone() -> None:
    """Bracketed text in a path is part of the artifact, not defanging."""
    raw = "http://evil[.]example/redirect?to=a[.]b"
    canonical = normalize_observable(raw).intel_object.canonical_value
    assert canonical == "http://evil.example/redirect?to=a[.]b"


def test_url_with_idn_host() -> None:
    result = normalize_observable("http://пример.рф/путь")
    obj = result.intel_object
    assert obj.canonical_value.startswith("http://xn--e1afmkfd.xn--p1ai/")
    assert obj.display_value.startswith("http://пример.рф/")


@pytest.mark.parametrize(
    "raw",
    [
        "file:///etc/passwd",
        "javascript://evil.example/a",
        "data://text/plain",
        "http:///a",
        "http://evil.example:0/a",
        "http://evil.example:99999/a",
        "http://evil.example:port/a",
        "http://not_a_valid_tld./a",
        "http://[2001:db8::1/a",
    ],
)
def test_invalid_url(raw: str) -> None:
    with pytest.raises(NormalizationError):
        normalize_url(raw)


def test_url_without_scheme_is_rejected_by_the_url_normalizer() -> None:
    with pytest.raises(NormalizationError, match="scheme"):
        normalize_url("evil.example/a")


# --------------------------------------------------------------------------- #
# Hashes
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "algorithm", "slug"),
    [
        (MD5, "MD5", "md5"),
        (SHA1, "SHA-1", "sha1"),
        (SHA256, "SHA-256", "sha256"),
    ],
)
def test_valid_hashes(raw: str, algorithm: str, slug: str) -> None:
    result = normalize_observable(raw)
    obj = result.intel_object
    assert obj.object_type is IntelObjectType.FILE
    assert obj.object_class is ObjectClass.OBSERVABLE
    assert obj.canonical_value == raw
    assert obj.properties == {"hashes": {algorithm: raw}}
    assert obj.canonical_key == f"file:{slug}:{raw}"


@pytest.mark.parametrize("raw", [MD5, SHA1, SHA256])
def test_hash_casing_is_normalized_to_lowercase(raw: str) -> None:
    result = normalize_observable(raw.upper())
    assert result.intel_object.canonical_value == raw
    assert result.original_input == raw.upper()


@pytest.mark.parametrize(
    "raw",
    [
        "d41d8cd98f00b204e9800998ecf8427",  # 31 chars
        "d41d8cd98f00b204e9800998ecf8427ee",  # 33 chars
        "z" * 32,
        "0" * 128,  # SHA-512 is out of V1 scope
    ],
)
def test_invalid_hash(raw: str) -> None:
    with pytest.raises(NormalizationError):
        normalize_file_hash(raw)


def test_hash_length_mismatch_is_reported_as_a_hash_problem() -> None:
    with pytest.raises(NormalizationError, match="looks like a hash"):
        normalize_observable("0" * 128)


# --------------------------------------------------------------------------- #
# Ambiguous / unsupported input
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw",
    [
        "not an observable",
        "@@@",
        "1.2.3.4.5.6",
        "http://",
        "://evil.example",
        "user@evil.example",
        "CVE-2026-0001",
    ],
)
def test_unsupported_input_is_rejected(raw: str) -> None:
    with pytest.raises(NormalizationError):
        normalize_observable(raw)


def test_normalization_result_is_immutable() -> None:
    result = normalize_observable("8.8.8.8")
    with pytest.raises(ValueError, match="frozen"):
        result.original_input = "changed"


# --------------------------------------------------------------------------- #
# Edge cases found while measuring coverage
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("raw", [".", "..", "..."])
def test_dot_only_input_is_rejected(raw: str) -> None:
    with pytest.raises(NormalizationError):
        normalize_domain(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "ф" * 70 + ".рф",  # label too long once punycoded
        "\u0640.example",  # Arabic tatweel: disallowed by UTS-46
    ],
)
def test_idna_rejected_domains_are_reported_as_invalid(raw: str) -> None:
    with pytest.raises(NormalizationError, match="internationalized domain name"):
        normalize_domain(raw)


def test_url_with_a_bare_scheme_like_path_component_is_still_a_url() -> None:
    """`a;b` is a path segment, not a scheme, and must survive normalization."""
    canonical = normalize_url("https://evil.example/a;b").canonical_value
    assert canonical == "https://evil.example/a;b"


def test_url_with_userinfo_but_no_host_is_rejected() -> None:
    with pytest.raises(NormalizationError, match="missing a host"):
        normalize_url("http://user@/a")


# --------------------------------------------------------------------------- #
# IPv6 zone identifiers are not part of an address (Task 24 Phase 3)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", ["fe80::1%eth0", "[fe80::1%eth1]", "2001:db8::1%25"])
def test_a_zoned_address_is_refused_not_split_into_several_observables(value: str) -> None:
    from ti_recon.normalization.errors import NormalizationError

    with pytest.raises(NormalizationError, match="zone"):
        normalize_observable(value)


def test_the_bare_ipv6_address_still_normalizes() -> None:
    assert normalize_observable("fe80::1").intel_object.canonical_value == "fe80::1"
