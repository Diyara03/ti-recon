"""Which Censys asset answers for which observable (Task 9).

The mapping is the whole security and cost story for this provider: a
deterministic identity means one predictable request, and the cases that have no
identity must be reported as gaps rather than quietly turned into guesses.
"""

from __future__ import annotations

import pytest

from ti_recon.enums import IntelObjectType, MatchScope, ObjectClass
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers.censys import (
    CensysAssetKind,
    asset_for,
    unsupported_reason_for,
)


def observable(raw: str) -> IntelObject:
    return normalize_observable(raw).intel_object


def file_object(algorithm: str, digest: str) -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=digest,
        display_value=digest,
        properties={"hashes": {algorithm: digest}},
    )


# --------------------------------------------------------------------------- #
# Addresses
# --------------------------------------------------------------------------- #


def test_an_ipv4_address_is_a_host_asset() -> None:
    asset = asset_for(observable("198.51.100.7"))
    assert asset is not None
    assert asset.kind is CensysAssetKind.HOST
    assert asset.identifier == "198.51.100.7"
    assert asset.match_scope is MatchScope.EXACT_OBSERVABLE


def test_an_ipv6_address_is_a_host_asset_too() -> None:
    asset = asset_for(observable("2001:db8::1"))
    assert asset is not None
    assert asset.kind is CensysAssetKind.HOST
    assert asset.identifier == "2001:db8::1"


def test_an_address_answers_for_itself_exactly() -> None:
    asset = asset_for(observable("2001:db8::1"))
    assert asset is not None
    assert asset.match_scope is MatchScope.EXACT_OBSERVABLE


# --------------------------------------------------------------------------- #
# URLs map deterministically onto a web property
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("url", "identifier"),
    [
        ("https://example.com/login", "example.com:443"),
        ("https://example.com/login?next=/admin#top", "example.com:443"),
        ("http://example.com/", "example.com:80"),
        ("http://example.com", "example.com:80"),
        ("https://example.com:8443/a", "example.com:8443"),
        ("http://example.com:8080/a/b/c", "example.com:8080"),
        ("https://EXAMPLE.com/Login", "example.com:443"),
    ],
)
def test_a_url_maps_onto_one_hostname_and_port(url: str, identifier: str) -> None:
    asset = asset_for(observable(url))
    assert asset is not None
    assert asset.kind is CensysAssetKind.WEB_PROPERTY
    assert asset.identifier == identifier


def test_the_path_and_query_never_change_the_identity() -> None:
    """Two URLs on one host and port are one web property."""
    first = asset_for(observable("https://example.com/login"))
    second = asset_for(observable("https://example.com/admin?x=1"))
    assert first is not None
    assert second is not None
    assert first.identifier == second.identifier


def test_a_web_property_is_where_the_url_lives_not_the_url_itself() -> None:
    """Reporting it as exact would let "nginx here" read as "this page"."""
    asset = asset_for(observable("https://example.com/login"))
    assert asset is not None
    assert asset.match_scope is MatchScope.SAME_HOST
    assert asset.match_scope is not MatchScope.EXACT_OBSERVABLE


def test_an_internationalized_host_maps_to_its_ascii_form() -> None:
    asset = asset_for(observable("https://münchen.example/x"))
    assert asset is not None
    assert asset.hostname is not None
    assert asset.hostname.startswith("xn--")


def test_an_ftp_url_has_no_web_property() -> None:
    """An accepted TI Recon scheme with nothing on the other side."""
    assert asset_for(observable("ftp://example.com/pub")) is None


# --------------------------------------------------------------------------- #
# An address literal in a URL
# --------------------------------------------------------------------------- #


def test_an_address_literal_url_becomes_a_host_lookup() -> None:
    asset = asset_for(observable("http://198.51.100.7/panel"))
    assert asset is not None
    assert asset.kind is CensysAssetKind.HOST
    assert asset.identifier == "198.51.100.7"


def test_an_address_literal_url_records_that_it_asked_about_the_address() -> None:
    """Nobody may mistake "port 443 is open" for "Censys has seen this page"."""
    asset = asset_for(observable("http://198.51.100.7/panel"))
    assert asset is not None
    assert asset.match_scope is MatchScope.SAME_IP


def test_an_ipv6_literal_url_becomes_a_host_lookup_too() -> None:
    asset = asset_for(observable("https://[2001:db8::1]:8443/x"))
    assert asset is not None
    assert asset.kind is CensysAssetKind.HOST
    assert asset.identifier == "2001:db8::1"
    assert asset.match_scope is MatchScope.SAME_IP


# --------------------------------------------------------------------------- #
# What has no asset identity
# --------------------------------------------------------------------------- #


def test_a_bare_domain_has_no_asset() -> None:
    """Guessing 80 and 443 would report two ports as domain coverage."""
    assert asset_for(observable("example.com")) is None


def test_a_bare_domain_explains_itself() -> None:
    reason = unsupported_reason_for(observable("example.com"))
    assert "port" in reason
    assert "domain" in reason


@pytest.mark.parametrize(
    ("algorithm", "digest"),
    [("MD5", "c" * 32), ("SHA-1", "d" * 40), ("SHA-256", "a" * 64)],
)
def test_a_file_hash_has_no_asset(algorithm: str, digest: str) -> None:
    """A file hash is never reinterpreted as a certificate fingerprint."""
    assert asset_for(file_object(algorithm, digest)) is None


def test_a_file_hash_explains_the_certificate_confusion_it_avoids() -> None:
    reason = unsupported_reason_for(file_object("SHA-256", "a" * 64))
    assert "certificate" in reason
    assert "fingerprint" in reason


def test_a_sha256_file_hash_and_a_certificate_fingerprint_stay_separate() -> None:
    """Both are 64 hex characters; only one of them identifies a certificate."""
    digest = "a" * 64
    assert asset_for(file_object("SHA-256", digest)) is None


def test_an_unsupported_object_type_still_gets_a_reason() -> None:
    asn = IntelObject(
        object_class=ObjectClass.INFRASTRUCTURE,
        object_type=IntelObjectType.AUTONOMOUS_SYSTEM,
        canonical_value="AS64500",
        display_value="AS64500",
    )
    assert asset_for(asn) is None
    assert unsupported_reason_for(asn)


# --------------------------------------------------------------------------- #
# The identity is safe to interpolate
# --------------------------------------------------------------------------- #


def test_an_asset_identity_carries_no_delimiter_that_could_escape_a_path() -> None:
    for raw in ("198.51.100.7", "https://example.com:8443/a", "2001:db8::1"):
        asset = asset_for(observable(raw))
        assert asset is not None
        assert "/" not in asset.identifier
        assert "?" not in asset.identifier
        assert ".." not in asset.identifier
        assert not any(character.isspace() for character in asset.identifier)


def test_an_asset_renders_readably() -> None:
    asset = asset_for(observable("https://example.com/login"))
    assert str(asset) == "web_property:example.com:443"
