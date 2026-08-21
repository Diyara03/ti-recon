"""Cross-cutting credential guards (`ti_recon.security`)."""

from __future__ import annotations

import pytest

from ti_recon.security import (
    REDACTED,
    SENSITIVE_KEY_PATTERN,
    contains_credential_like_key,
    redact_sensitive_text,
    reject_credential_like_keys,
)


@pytest.mark.parametrize(
    "key",
    [
        "api_key",
        "apikey",
        "API-Key",
        "x-apikey",
        "Auth-Key",
        "auth_key",
        "Authorization",
        "access_token",
        "refresh_token",
        "id_token",
        "bearer",
        "secret",
        "client_secret",
        "password",
        "passwd",
        "credential",
        "private_key",
        "session_id",
        "Cookie",
        "Set-Cookie",
    ],
)
def test_credential_like_keys_are_detected(key: str) -> None:
    assert SENSITIVE_KEY_PATTERN.search(key) is not None
    assert contains_credential_like_key({key: "value"}) == key


@pytest.mark.parametrize(
    "key",
    [
        "malware_family",
        "resolved_ip",
        "asn",
        "classification",
        "detection_count",
        "keyword",
        "monkey",
        "first_seen",
    ],
)
def test_ordinary_keys_are_not_flagged(key: str) -> None:
    assert contains_credential_like_key({key: "value"}) is None


def test_nested_detection_reports_the_path() -> None:
    data = {"request": {"headers": {"x-apikey": "v"}}}
    assert contains_credential_like_key(data) == "request.headers.x-apikey"


def test_detection_walks_lists_of_mappings() -> None:
    data = {"items": [{"ok": 1}, {"secret": "v"}]}
    assert contains_credential_like_key(data) == "items.secret"


def test_detection_ignores_lists_of_scalars() -> None:
    assert contains_credential_like_key({"ports": [80, 443], "tags": ["a", "b"]}) is None


def test_detection_ignores_nested_lists_without_mappings() -> None:
    assert contains_credential_like_key({"rows": [[1, 2], [3, 4]]}) is None


def test_empty_mapping_is_clean() -> None:
    assert contains_credential_like_key({}) is None


def test_rejection_names_the_key_but_never_the_value() -> None:
    with pytest.raises(ValueError, match="credential-like key") as excinfo:
        reject_credential_like_keys({"api_key": "super-secret"}, where="Test.field")
    message = str(excinfo.value)
    assert "api_key" in message
    assert "Test.field" in message
    assert "super-secret" not in message


def test_rejection_passes_clean_data() -> None:
    reject_credential_like_keys({"malware_family": "ExampleRAT"}, where="Test.field")


def test_redaction_placeholder_is_not_a_plausible_secret() -> None:
    assert REDACTED == "[REDACTED]"


# --------------------------------------------------------------------------- #
# Free-text redaction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("GET /v3/ip?apikey=SECRETVALUE123 failed", "GET /v3/ip?[REDACTED] failed"),
        ("Authorization: Bearer abc.def.ghi rejected", "[REDACTED] rejected"),
        ('auth-key="topsecret" invalid', "[REDACTED] invalid"),
        ("x-apikey: aaaabbbbcccc", "[REDACTED]"),
        ("password=hunter2&user=bob", "[REDACTED]&user=bob"),
        ("client_secret: 'abc123' expired", "[REDACTED] expired"),
        ("connection reset by peer", "connection reset by peer"),
        ("quota exhausted for this account", "quota exhausted for this account"),
    ],
)
def test_redaction_removes_credential_assignments(text: str, expected: str) -> None:
    assert redact_sensitive_text(text) == expected


def test_redaction_replaces_the_key_as_well_as_the_value() -> None:
    """Leaving `api_key=` behind would still look like a credential downstream."""
    result = redact_sensitive_text("api_key=abcdef123456")
    assert "abcdef123456" not in result
    assert "api_key" not in result


def test_redaction_handles_a_scheme_before_its_header_name() -> None:
    """The scheme rule must run first, or the token survives the header collapse."""
    assert "abc.def.ghi" not in redact_sensitive_text("Authorization: Bearer abc.def.ghi")


def test_redaction_is_idempotent() -> None:
    once = redact_sensitive_text("apikey=abc123456789")
    assert redact_sensitive_text(once) == once


def test_redaction_bounds_the_length() -> None:
    long_text = "connection reset " * 100
    result = redact_sensitive_text(long_text, max_length=80)
    assert len(result) <= 80
    assert result.endswith("…")


def test_short_text_is_not_truncated() -> None:
    assert redact_sensitive_text("timeout", max_length=80) == "timeout"


def test_redaction_is_best_effort_and_has_a_known_gap() -> None:
    """A header name with no separator is not matched.

    Documented rather than papered over: the executor's `_safe_message`
    withholds any message that still trips the key guard, which is the actual
    guarantee behind this function.
    """
    leaky = redact_sensitive_text("X-Api-Key aaaabbbbcccc rejected")
    assert SENSITIVE_KEY_PATTERN.search(leaky) is not None
