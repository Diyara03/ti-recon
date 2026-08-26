"""Which MISP attribute values an observable legitimately produces (Task 11).

Two failure modes to guard against, in opposite directions. Building too few
candidates silently loses coverage — a warninglist that declares only `ip-dst`
would never be consulted. Building too many invents observables: a `domain|ip`
composite assembled from a domain and nothing else matches upstream entries about
a different thing entirely.
"""

from __future__ import annotations

import pytest

from ti_recon.enums import IntelObjectType, MatchScope, ObjectClass
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers.misp_warninglists import (
    CandidateComponent,
    build_candidates,
    candidate_attribute_types,
)

EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
EMPTY_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def file_object(hashes: dict[str, str], **properties: object) -> IntelObject:
    strongest = hashes.get("SHA-256") or hashes.get("SHA-1") or next(iter(hashes.values()))
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=strongest,
        display_value=strongest,
        properties={"hashes": hashes, **properties},
    )


def types_for(raw: str) -> set[str]:
    return set(candidate_attribute_types(build_candidates(normalize_observable(raw).intel_object)))


# --------------------------------------------------------------------------- #
# Addresses
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("address", ["8.8.8.8", "2001:4860:4860::8888"])
def test_an_address_is_offered_in_both_misp_directions(address: str) -> None:
    """A warninglist declaring only one direction still applies to our address."""
    candidates = build_candidates(normalize_observable(address).intel_object)
    assert {item.misp_attribute_type for item in candidates} == {"ip-src", "ip-dst"}
    assert {item.value for item in candidates} == {
        normalize_observable(address).intel_object.canonical_value
    }
    for item in candidates:
        assert item.match_scope is MatchScope.EXACT_OBSERVABLE
        assert item.component is CandidateComponent.OBSERVABLE


def test_an_address_never_invents_a_port_or_domain_composite() -> None:
    """A standalone address names neither, and half a composite is a wrong key."""
    types = types_for("8.8.8.8")
    for fabricated in ("ip-src|port", "ip-dst|port", "domain|ip"):
        assert fabricated not in types


def test_both_address_candidates_share_one_observable_identity() -> None:
    candidates = build_candidates(normalize_observable("8.8.8.8").intel_object)
    assert len({item.subject_object_id for item in candidates}) == 1


# --------------------------------------------------------------------------- #
# Domains
# --------------------------------------------------------------------------- #


def test_a_domain_is_offered_under_both_misp_spellings() -> None:
    candidates = build_candidates(normalize_observable("example.com").intel_object)
    assert {item.misp_attribute_type for item in candidates} == {"domain", "hostname"}
    assert {item.value for item in candidates} == {"example.com"}


def test_a_domain_never_invents_a_domain_ip_composite() -> None:
    assert "domain|ip" not in types_for("example.com")


# --------------------------------------------------------------------------- #
# URLs: the distinction this provider turns on
# --------------------------------------------------------------------------- #


def test_a_url_offers_the_whole_artifact_and_its_host_separately() -> None:
    candidates = build_candidates(
        normalize_observable("https://github.com/attacker/payload.exe").intel_object
    )
    by_type = {item.misp_attribute_type: item for item in candidates}
    assert set(by_type) == {"url", "uri", "hostname"}

    for attribute in ("url", "uri"):
        assert by_type[attribute].value == "https://github.com/attacker/payload.exe"
        assert by_type[attribute].match_scope is MatchScope.EXACT_OBSERVABLE
        assert by_type[attribute].component is CandidateComponent.OBSERVABLE

    host = by_type["hostname"]
    assert host.value == "github.com"
    assert host.component is CandidateComponent.URL_HOST
    # Narrower, visibly, all the way into the evidence.
    assert host.match_scope is MatchScope.SAME_HOST


def test_the_url_host_is_parsed_and_never_searched_for() -> None:
    """`?ref=github.com` is not GitHub-hosted.

    Substring-matching a raw URL against a hostname list would let a path or a
    query string masquerade as a host, which is a false-positive machine.
    """
    candidates = build_candidates(
        normalize_observable("http://evil.example/?ref=github.com").intel_object
    )
    host = next(item for item in candidates if item.component is CandidateComponent.URL_HOST)
    assert host.value == "evil.example"


def test_a_url_host_is_lowercased_and_root_dot_trimmed() -> None:
    candidates = build_candidates(normalize_observable("http://EXAMPLE.COM./path").intel_object)
    host = next(item for item in candidates if item.component is CandidateComponent.URL_HOST)
    assert host.value == "example.com"


def test_a_url_never_invents_a_domain_ip_composite() -> None:
    assert "domain|ip" not in types_for("https://example.com/a")


# --------------------------------------------------------------------------- #
# Files
# --------------------------------------------------------------------------- #


def test_every_available_hash_is_offered() -> None:
    """Local lookup: no reason to pick only the strongest digest.

    A warninglist may hold only one of the three, so asking with all of them is
    the difference between finding the empty-file context and missing it.
    """
    candidates = build_candidates(
        file_object({"MD5": EMPTY_MD5, "SHA-1": EMPTY_SHA1, "SHA-256": EMPTY_SHA256})
    )
    assert {item.misp_attribute_type for item in candidates} == {"md5", "sha1", "sha256"}
    assert {item.value for item in candidates} == {EMPTY_MD5, EMPTY_SHA1, EMPTY_SHA256}


def test_each_hash_candidate_records_which_algorithm_found_it() -> None:
    candidates = build_candidates(file_object({"MD5": EMPTY_MD5, "SHA-256": EMPTY_SHA256}))
    assert {item.algorithm for item in candidates} == {"MD5", "SHA-256"}


def test_a_single_hash_file_offers_only_that_hash() -> None:
    candidates = build_candidates(file_object({"MD5": EMPTY_MD5}))
    assert [item.misp_attribute_type for item in candidates] == ["md5"]


def test_a_filename_composite_appears_only_when_a_filename_exists() -> None:
    without = build_candidates(file_object({"MD5": EMPTY_MD5}))
    assert all("|" not in item.misp_attribute_type for item in without)

    with_name = build_candidates(file_object({"MD5": EMPTY_MD5}, file_name="invoice.exe"))
    composite = next(item for item in with_name if item.misp_attribute_type == "filename|md5")
    assert composite.value == f"invoice.exe|{EMPTY_MD5}"


def test_a_composite_is_never_fabricated_from_a_hash_alone() -> None:
    candidates = build_candidates(file_object({"SHA-256": EMPTY_SHA256}))
    for fabricated in ("filename|md5", "filename|sha1", "filename|sha256"):
        assert fabricated not in {item.misp_attribute_type for item in candidates}


@pytest.mark.parametrize(
    "filename",
    ["", "   ", "a|b", "bad\x00name", "x" * 300],
)
def test_an_unusable_filename_produces_no_composite(filename: str) -> None:
    """A filename containing `|` would change which attribute type it is."""
    candidates = build_candidates(file_object({"MD5": EMPTY_MD5}, file_name=filename))
    assert all("|" not in item.misp_attribute_type for item in candidates)


def test_a_non_string_filename_is_ignored() -> None:
    candidates = build_candidates(file_object({"MD5": EMPTY_MD5}, file_name=1234))
    assert all("|" not in item.misp_attribute_type for item in candidates)


# --------------------------------------------------------------------------- #
# Unsupported observables
# --------------------------------------------------------------------------- #


def test_an_unsupported_object_type_produces_no_candidates() -> None:
    """Which the adapter reports as NOT_SUPPORTED, never as an empty result."""
    certificate = IntelObject(
        object_class=ObjectClass.INFRASTRUCTURE,
        object_type=IntelObjectType.X509_CERTIFICATE,
        canonical_value="a" * 40,
        display_value="a" * 40,
    )
    assert build_candidates(certificate) == ()
