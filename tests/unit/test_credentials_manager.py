"""Credential lifecycle and user-scoped resolution (Task 4)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import SecretStr

from ti_recon.credentials import (
    ABUSE_CH_GROUP,
    AuthType,
    ConnectionNotFound,
    CredentialManager,
    CredentialNotConfigured,
    CredentialResolver,
    CredentialStatus,
    CredentialUnusable,
    InMemoryConnectionRepository,
    InMemorySecretStore,
    PolicyDenied,
    PolicyStatus,
    SecretNotFound,
    SecretRef,
    credential_group_for,
    providers_in_group,
)
from ti_recon.models.base import utc_now

USER_A = "user-a"
USER_B = "user-b"
KEY_A = "vt-key-AAAA1111"
KEY_B = "vt-key-BBBB2222"


class Harness:
    """A credential stack wired to in-memory backends."""

    def __init__(self) -> None:
        self.store = InMemorySecretStore()
        self.repository = InMemoryConnectionRepository()
        self.manager = CredentialManager(self.store, self.repository)
        self.resolver = CredentialResolver(self.store, self.repository)


@pytest.fixture
def harness() -> Harness:
    return Harness()


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #


async def test_create_connection_returns_metadata_without_the_secret(harness: Harness) -> None:
    connection = await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    assert connection.user_id == USER_A
    assert connection.secret_reference.owner_user_id == USER_A
    assert KEY_A not in connection.model_dump_json()


async def test_new_credential_starts_unvalidated(harness: Harness) -> None:
    connection = await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    assert connection.status is CredentialStatus.UNKNOWN
    assert connection.last_validated_at is None


async def test_empty_secret_is_rejected(harness: Harness) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        await harness.manager.create_connection(
            user_id=USER_A,
            provider_id="fake_aggregator",
            secret="",
            auth_type=AuthType.API_KEY,
        )
    assert len(harness.store) == 0


async def test_second_connection_for_the_same_group_is_rejected(harness: Harness) -> None:
    await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    with pytest.raises(ValueError, match="already has a connection"):
        await harness.manager.create_connection(
            user_id=USER_A,
            provider_id="fake_aggregator",
            secret=KEY_B,
            auth_type=AuthType.API_KEY,
        )


async def test_failed_save_leaves_no_orphaned_secret(harness: Harness) -> None:
    await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    before = len(harness.store)
    with pytest.raises(ValueError, match="already has a connection"):
        await harness.manager.create_connection(
            user_id=USER_A,
            provider_id="fake_aggregator",
            secret=KEY_B,
            auth_type=AuthType.API_KEY,
        )
    assert len(harness.store) == before


async def test_replace_credential_rotates_the_secret_and_the_reference(
    harness: Harness,
) -> None:
    connection = await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    old_reference = connection.secret_reference

    updated = await harness.manager.replace_credential(
        user_id=USER_A, connection_id=connection.id, secret=KEY_B
    )

    assert updated.secret_reference != old_reference
    resolved = await harness.resolver.resolve(
        authenticated_user_id=USER_A, provider_id="fake_aggregator"
    )
    assert resolved.reveal() == KEY_B
    # Old secret removed, and exactly one secret remains for this user.
    with pytest.raises(SecretNotFound):
        await harness.store.get_secret(old_reference)
    assert len(harness.store) == 1


async def test_replace_credential_resets_validation_state(harness: Harness) -> None:
    connection = await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    await harness.manager.set_status(
        user_id=USER_A, connection_id=connection.id, status=CredentialStatus.ACTIVE
    )
    updated = await harness.manager.replace_credential(
        user_id=USER_A, connection_id=connection.id, secret=KEY_B
    )
    assert updated.status is CredentialStatus.UNKNOWN
    assert updated.last_validated_at is None


async def test_disable_connection_keeps_the_secret_but_blocks_resolution(
    harness: Harness,
) -> None:
    connection = await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    disabled = await harness.manager.disable_connection(user_id=USER_A, connection_id=connection.id)
    assert disabled.status is CredentialStatus.DISABLED
    assert await harness.store.exists(disabled.secret_reference) is True
    with pytest.raises(CredentialUnusable):
        await harness.resolver.resolve(authenticated_user_id=USER_A, provider_id="fake_aggregator")


async def test_set_status_active_records_validation_time(harness: Harness) -> None:
    connection = await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    updated = await harness.manager.set_status(
        user_id=USER_A, connection_id=connection.id, status=CredentialStatus.ACTIVE
    )
    assert updated.last_validated_at is not None


async def test_record_usage_stamps_last_used(harness: Harness) -> None:
    connection = await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    assert connection.last_used_at is None
    updated = await harness.manager.record_usage(user_id=USER_A, connection_id=connection.id)
    assert updated.last_used_at is not None


async def test_disconnect_removes_connection_and_secret(harness: Harness) -> None:
    connection = await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    assert await harness.manager.disconnect(user_id=USER_A, connection_id=connection.id) is True
    assert await harness.manager.get_connection(user_id=USER_A, connection_id=connection.id) is None
    assert await harness.store.exists(connection.secret_reference) is False


async def test_disconnect_of_unknown_connection_is_false(harness: Harness) -> None:
    assert await harness.manager.disconnect(user_id=USER_A, connection_id="nope") is False


async def test_expired_credential_is_not_usable(harness: Harness) -> None:
    connection = await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    expired = connection.model_copy(update={"expires_at": utc_now() - timedelta(seconds=1)})
    await harness.repository.save(expired)
    assert expired.is_usable is False


async def test_policy_blocked_connection_is_refused(harness: Harness) -> None:
    await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
        policy_status=PolicyStatus.BLOCKED,
    )
    with pytest.raises(PolicyDenied):
        await harness.resolver.resolve(authenticated_user_id=USER_A, provider_id="fake_aggregator")


async def test_restricted_policy_still_allows_use(harness: Harness) -> None:
    await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
        policy_status=PolicyStatus.RESTRICTED,
    )
    resolved = await harness.resolver.resolve(
        authenticated_user_id=USER_A, provider_id="fake_aggregator"
    )
    assert resolved.reveal() == KEY_A


async def test_unconfigured_provider_raises_not_configured(harness: Harness) -> None:
    with pytest.raises(CredentialNotConfigured):
        await harness.resolver.resolve(authenticated_user_id=USER_A, provider_id="fake_aggregator")


async def test_has_credential_does_not_touch_the_secret(harness: Harness) -> None:
    assert (
        await harness.resolver.has_credential(
            authenticated_user_id=USER_A, provider_id="fake_aggregator"
        )
        is False
    )
    await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    assert (
        await harness.resolver.has_credential(
            authenticated_user_id=USER_A, provider_id="fake_aggregator"
        )
        is True
    )


async def test_secret_accepts_secretstr_input(harness: Harness) -> None:
    await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=SecretStr(KEY_A),
        auth_type=AuthType.API_KEY,
    )
    resolved = await harness.resolver.resolve(
        authenticated_user_id=USER_A, provider_id="fake_aggregator"
    )
    assert resolved.reveal() == KEY_A


# --------------------------------------------------------------------------- #
# abuse.ch credential group
# --------------------------------------------------------------------------- #


def test_abuse_ch_group_membership() -> None:
    assert credential_group_for("threatfox") == ABUSE_CH_GROUP
    assert credential_group_for("urlhaus") == ABUSE_CH_GROUP
    assert credential_group_for("malwarebazaar") == ABUSE_CH_GROUP
    assert providers_in_group(ABUSE_CH_GROUP) == frozenset(
        {"threatfox", "urlhaus", "malwarebazaar"}
    )


def test_ungrouped_provider_forms_a_group_of_one() -> None:
    assert credential_group_for("fake_aggregator") == "fake_aggregator"
    assert providers_in_group("fake_aggregator") == frozenset({"fake_aggregator"})


async def test_one_abuse_ch_key_serves_all_three_services(harness: Harness) -> None:
    await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="threatfox",
        secret="abuse-key-AAAA",
        auth_type=AuthType.AUTH_KEY,
    )
    for provider_id in ("threatfox", "urlhaus", "malwarebazaar"):
        resolved = await harness.resolver.resolve(
            authenticated_user_id=USER_A, provider_id=provider_id
        )
        assert resolved.reveal() == "abuse-key-AAAA"
        assert resolved.provider_id == provider_id
        assert resolved.credential_group == ABUSE_CH_GROUP
        assert resolved.auth_type is AuthType.AUTH_KEY


async def test_abuse_ch_grouping_remains_user_scoped(harness: Harness) -> None:
    await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="threatfox",
        secret="abuse-key-AAAA",
        auth_type=AuthType.AUTH_KEY,
    )
    await harness.manager.create_connection(
        user_id=USER_B,
        provider_id="urlhaus",
        secret="abuse-key-BBBB",
        auth_type=AuthType.AUTH_KEY,
    )
    a = await harness.resolver.resolve(authenticated_user_id=USER_A, provider_id="malwarebazaar")
    b = await harness.resolver.resolve(authenticated_user_id=USER_B, provider_id="malwarebazaar")
    assert a.reveal() == "abuse-key-AAAA"
    assert b.reveal() == "abuse-key-BBBB"


async def test_deleting_one_users_abuse_ch_key_leaves_the_other(harness: Harness) -> None:
    a_connection = await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="threatfox",
        secret="abuse-key-AAAA",
        auth_type=AuthType.AUTH_KEY,
    )
    await harness.manager.create_connection(
        user_id=USER_B,
        provider_id="threatfox",
        secret="abuse-key-BBBB",
        auth_type=AuthType.AUTH_KEY,
    )
    await harness.manager.disconnect(user_id=USER_A, connection_id=a_connection.id)
    with pytest.raises(CredentialNotConfigured):
        await harness.resolver.resolve(authenticated_user_id=USER_A, provider_id="urlhaus")
    b = await harness.resolver.resolve(authenticated_user_id=USER_B, provider_id="urlhaus")
    assert b.reveal() == "abuse-key-BBBB"


# --------------------------------------------------------------------------- #
# Metadata reads are scoped
# --------------------------------------------------------------------------- #


async def test_list_connections_only_returns_the_callers_own(harness: Harness) -> None:
    await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    await harness.manager.create_connection(
        user_id=USER_B,
        provider_id="fake_aggregator",
        secret=KEY_B,
        auth_type=AuthType.API_KEY,
    )
    listed = await harness.manager.list_connections(user_id=USER_A)
    assert [connection.user_id for connection in listed] == [USER_A]


async def test_lifecycle_operations_on_another_users_connection_fail(
    harness: Harness,
) -> None:
    a_connection = await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    for operation in (
        harness.manager.replace_credential(
            user_id=USER_B, connection_id=a_connection.id, secret=KEY_B
        ),
        harness.manager.disable_connection(user_id=USER_B, connection_id=a_connection.id),
        harness.manager.record_usage(user_id=USER_B, connection_id=a_connection.id),
    ):
        with pytest.raises(ConnectionNotFound):
            await operation


async def test_another_users_disconnect_attempt_is_a_no_op(harness: Harness) -> None:
    a_connection = await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    assert await harness.manager.disconnect(user_id=USER_B, connection_id=a_connection.id) is False
    resolved = await harness.resolver.resolve(
        authenticated_user_id=USER_A, provider_id="fake_aggregator"
    )
    assert resolved.reveal() == KEY_A


async def test_find_connection_for_provider_resolves_via_the_group(
    harness: Harness,
) -> None:
    created = await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="threatfox",
        secret="abuse-key-AAAA",
        auth_type=AuthType.AUTH_KEY,
    )
    found = await harness.manager.find_connection_for_provider(
        user_id=USER_A, provider_id="malwarebazaar"
    )
    assert found is not None
    assert found.id == created.id
    assert (
        await harness.manager.find_connection_for_provider(
            user_id=USER_B, provider_id="malwarebazaar"
        )
        is None
    )


async def test_failed_rotation_rolls_back_the_new_secret(harness: Harness) -> None:
    """A rotation that cannot be recorded must not leave a stray secret behind."""
    connection = await harness.manager.create_connection(
        user_id=USER_A,
        provider_id="fake_aggregator",
        secret=KEY_A,
        auth_type=AuthType.API_KEY,
    )
    original_save = harness.repository.save
    calls = {"n": 0}

    async def failing_save(updated: object) -> None:
        calls["n"] += 1
        msg = "storage unavailable"
        raise RuntimeError(msg)

    harness.repository.save = failing_save  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="storage unavailable"):
        await harness.manager.replace_credential(
            user_id=USER_A, connection_id=connection.id, secret=KEY_B
        )
    harness.repository.save = original_save  # type: ignore[method-assign]

    assert calls["n"] == 1
    # The old secret is still there, the new one is gone, and nothing leaked.
    assert len(harness.store) == 1
    resolved = await harness.resolver.resolve(
        authenticated_user_id=USER_A, provider_id="fake_aggregator"
    )
    assert resolved.reveal() == KEY_A


def test_secret_reference_str_shows_no_secret() -> None:
    reference = SecretRef(owner_user_id=USER_A, key="opaque-key")
    text = str(reference)
    assert USER_A in text
    assert "opaque-key" in text
    assert KEY_A not in text
