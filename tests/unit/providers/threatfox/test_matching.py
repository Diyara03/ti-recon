"""The ThreatFox local-validation gate (Task 10).

This is the module that stops somebody else's botnet controller being attributed
to an unrelated address. ThreatFox stores addresses as ``ip:port``, so an address
lookup has to ask for a loose match — and a loose match on a provider we do not
control returns things that merely *contain* the search term.

The substring cases below are the ones that matter. Everything else here exists
to prove the gate is not simply rejecting everything.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Any

import pytest

from fixtures.abusech import payloads
from ti_recon.enums import IntelObjectType, MatchScope, ObjectClass
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers.threatfox import (
    MatchedComponent,
    match_for,
    matching,
    split_host_port,
)

ADDRESS = payloads.SCANNER_IP
DOMAIN = payloads.MALICIOUS_DOMAIN
URL = payloads.MALICIOUS_URL


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


def record(ioc: str, ioc_type: str | None = None) -> dict[str, Any]:
    return {"ioc": ioc, "ioc_type": ioc_type}


# --------------------------------------------------------------------------- #
# The substring problem
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "ioc",
    [
        "11.2.3.45:443",
        "1.2.3.44:443",
        "01.2.3.4:443",
        "1.2.3.4.5:443",
        "192.1.2.3.4:80",
    ],
)
def test_a_record_that_merely_contains_the_address_is_discarded(ioc: str) -> None:
    """A search for 1.2.3.4 must not accept 11.2.3.45."""
    assert match_for(observable("1.2.3.4"), record(ioc, "ip:port")) is None


def test_the_substring_record_from_a_real_shaped_response_is_discarded() -> None:
    entries = payloads.threatfox_ioc_result()["data"]
    subject = observable(ADDRESS)
    matched = [entry for entry in entries if match_for(subject, entry) is not None]
    assert len(matched) == 1
    assert matched[0]["ioc"] == f"{ADDRESS}:443"


def test_the_module_never_uses_containment_against_an_ioc() -> None:
    """Structural, because a single ``in`` would silently reopen the hole."""
    source = Path(inspect.getfile(matching)).read_text(encoding="utf-8")
    tree = ast.parse(source)
    docstrings = {
        ast.get_docstring(node, clean=False)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            assert not any(isinstance(op, ast.In | ast.NotIn) for op in node.ops)
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    for forbidden in ("startswith", "endswith", "find", "search", "match", "index"):
        assert forbidden not in called
    literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value not in docstrings
    ]
    assert all("re." not in literal for literal in literals)


# --------------------------------------------------------------------------- #
# Addresses
# --------------------------------------------------------------------------- #


def test_a_port_qualified_record_matches_its_host() -> None:
    result = match_for(observable(ADDRESS), record(f"{ADDRESS}:443", "ip:port"))
    assert result is not None
    assert result.matched_component is MatchedComponent.HOST
    assert result.port == 443
    assert result.is_port_qualified is True


def test_a_port_qualified_match_is_about_a_service_not_the_address() -> None:
    """ "Port 443 was a C2" must not later read as "this address is a C2"."""
    result = match_for(observable(ADDRESS), record(f"{ADDRESS}:443", "ip:port"))
    assert result is not None
    assert result.match_scope is MatchScope.SAME_IP
    assert result.match_scope is not MatchScope.EXACT_OBSERVABLE


def test_a_bare_address_record_matches_exactly() -> None:
    result = match_for(observable(ADDRESS), record(ADDRESS, "ip"))
    assert result is not None
    assert result.matched_component is MatchedComponent.EXACT
    assert result.match_scope is MatchScope.EXACT_OBSERVABLE
    assert result.port is None


@pytest.mark.parametrize("port", ["0", "65536", "99999", "-1", "http", ""])
def test_a_record_with_an_unusable_port_is_discarded(port: str) -> None:
    assert match_for(observable(ADDRESS), record(f"{ADDRESS}:{port}", "ip:port")) is None


def test_a_record_for_a_different_address_is_discarded() -> None:
    assert match_for(observable(ADDRESS), record("203.0.113.9:443", "ip:port")) is None


# --------------------------------------------------------------------------- #
# Domains
# --------------------------------------------------------------------------- #


def test_a_domain_matches_its_own_record() -> None:
    result = match_for(observable(DOMAIN), record(DOMAIN, "domain"))
    assert result is not None
    assert result.match_scope is MatchScope.EXACT_OBSERVABLE


def test_a_domain_match_is_case_insensitive() -> None:
    result = match_for(observable(DOMAIN), record(DOMAIN.upper(), "domain"))
    assert result is not None


def test_a_subdomain_is_a_different_observable() -> None:
    assert match_for(observable(DOMAIN), record(f"evil.{DOMAIN}", "domain")) is None


def test_a_parent_domain_is_a_different_observable() -> None:
    assert match_for(observable(f"evil.{DOMAIN}"), record(DOMAIN, "domain")) is None


def test_a_port_qualified_domain_matches_the_host() -> None:
    result = match_for(observable(DOMAIN), record(f"{DOMAIN}:8080", "domain"))
    assert result is not None
    assert result.match_scope is MatchScope.SAME_HOST
    assert result.port == 8080


# --------------------------------------------------------------------------- #
# URLs
# --------------------------------------------------------------------------- #


def test_a_url_matches_only_itself() -> None:
    result = match_for(observable(URL), record(URL, "url"))
    assert result is not None
    assert result.match_scope is MatchScope.EXACT_OBSERVABLE


def test_a_url_on_the_same_host_is_a_different_observable() -> None:
    """Path and query are part of the artifact."""
    other = f"http://{DOMAIN}/bin/other.exe"
    assert match_for(observable(URL), record(other, "url")) is None


def test_a_url_match_is_case_sensitive() -> None:
    """A path is case-significant; relaxing that would match the wrong page."""
    assert match_for(observable(URL), record(URL.upper(), "url")) is None


# --------------------------------------------------------------------------- #
# Files
# --------------------------------------------------------------------------- #


def test_a_file_matches_a_record_naming_any_digest_it_carries() -> None:
    subject = IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=payloads.SAMPLE_SHA256,
        display_value=payloads.SAMPLE_SHA256,
        properties={"hashes": {"SHA-256": payloads.SAMPLE_SHA256, "MD5": payloads.SAMPLE_MD5}},
    )
    assert match_for(subject, record(payloads.SAMPLE_MD5, "md5_hash")) is not None
    assert match_for(subject, record(payloads.SAMPLE_SHA256, "sha256_hash")) is not None


def test_a_file_does_not_match_an_unrelated_digest() -> None:
    subject = file_object("SHA-256", payloads.SAMPLE_SHA256)
    assert match_for(subject, record("9" * 64, "sha256_hash")) is None


def test_a_digest_match_is_case_insensitive() -> None:
    subject = file_object("SHA-256", payloads.SAMPLE_SHA256)
    assert match_for(subject, record(payloads.SAMPLE_SHA256.upper(), "sha256_hash")) is not None


# --------------------------------------------------------------------------- #
# Shapes that are not records at all
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("ioc", [None, "", "   ", 12345, [], {}])
def test_an_unreadable_record_is_discarded(ioc: Any) -> None:
    assert match_for(observable(ADDRESS), {"ioc": ioc}) is None


def test_an_unsupported_observable_type_never_matches() -> None:
    asn = IntelObject(
        object_class=ObjectClass.INFRASTRUCTURE,
        object_type=IntelObjectType.AUTONOMOUS_SYSTEM,
        canonical_value="AS64500",
        display_value="AS64500",
    )
    assert match_for(asn, record("AS64500", "asn")) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1.2.3.4:443", ("1.2.3.4", 443)),
        ("example.com:8080", ("example.com", 8080)),
        ("1.2.3.4", None),
        (":443", None),
        ("1.2.3.4:", None),
        ("1.2.3.4:abc", None),
        ("1.2.3.4:0", None),
        ("1.2.3.4:70000", None),
    ],
)
def test_host_port_splitting(value: str, expected: tuple[str, int] | None) -> None:
    assert split_host_port(value) == expected
