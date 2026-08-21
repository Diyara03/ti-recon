"""Cross-cutting credential guards (`ti_recon.security`)."""

from __future__ import annotations

import pytest

from ti_recon.security import (
    REDACTED,
    SENSITIVE_KEY_PATTERN,
    contains_credential_like_key,
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
