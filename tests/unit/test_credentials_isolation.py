"""Cross-user credential isolation (Task 4).

The requirement is blunt: user A must never be able to obtain user B's
credential, by any route the credential layer exposes. These tests enumerate the
routes.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from ti_recon.credentials import (
    AuthType,
    ConnectionNotFound,
    CredentialManager,
    CredentialNotConfigured,
    CredentialResolver,
    InMemoryConnectionRepository,
    InMemorySecretStore,
    ProviderConnection,
    SecretNotFound,
    SecretRef,
)

USER_A = "user-a"
USER_B = "user-b"
VT_KEY_A = "vt-key-AAAA1111"
VT_KEY_B = "vt-key-BBBB2222"
PROVIDER = "fake_aggregator"


class Harness:
    def __init__(self) -> None:
        self.store = InMemorySecretStore()
        self.repository = InMemoryConnectionRepository()
        self.manager = CredentialManager(self.store, self.repository)
        self.resolver = CredentialResolver(self.store, self.repository)


@pytest.fixture
async def two_users() -> tuple[Harness, ProviderConnection, ProviderConnection]:
    harness = Harness()
    a = await harness.manager.create_connection(
        user_id=USER_A,
        provider_id=PROVIDER,
        secret=VT_KEY_A,
        auth_type=AuthType.API_KEY,
    )
    b = await harness.manager.create_connection(
        user_id=USER_B,
        provider_id=PROVIDER,
        secret=VT_KEY_B,
        auth_type=AuthType.API_KEY,
    )
    return harness, a, b


async def test_each_user_resolves_their_own_key(
    two_users: tuple[Harness, ProviderConnection, ProviderConnection],
) -> None:
    harness, _, _ = two_users
    a = await harness.resolver.resolve(authenticated_user_id=USER_A, provider_id=PROVIDER)
    b = await harness.resolver.resolve(authenticated_user_id=USER_B, provider_id=PROVIDER)
    assert a.reveal() == VT_KEY_A
    assert b.reveal() == VT_KEY_B
    assert a.user_id == USER_A
    assert b.user_id == USER_B


async def test_resolution_never_returns_the_other_users_key(
    two_users: tuple[Harness, ProviderConnection, ProviderConnection],
) -> None:
    harness, _, _ = two_users
    a = await harness.resolver.resolve(authenticated_user_id=USER_A, provider_id=PROVIDER)
    b = await harness.resolver.resolve(authenticated_user_id=USER_B, provider_id=PROVIDER)
    assert a.reveal() != VT_KEY_B
    assert b.reveal() != VT_KEY_A


async def test_user_a_cannot_read_user_b_secret_with_a_stolen_reference(
    two_users: tuple[Harness, ProviderConnection, ProviderConnection],
) -> None:
    """Even holding B's reference key, A's owner scope makes it unreadable."""
    harness, _, b_connection = two_users
    forged = SecretRef(owner_user_id=USER_A, key=b_connection.secret_reference.key)
    with pytest.raises(SecretNotFound):
        await harness.store.get_secret(forged)


async def test_user_a_cannot_read_user_b_connection_metadata(
    two_users: tuple[Harness, ProviderConnection, ProviderConnection],
) -> None:
    harness, _, b_connection = two_users
    assert (
        await harness.manager.get_connection(user_id=USER_A, connection_id=b_connection.id) is None
    )


async def test_user_a_cannot_list_user_b_connections(
    two_users: tuple[Harness, ProviderConnection, ProviderConnection],
) -> None:
    harness, a_connection, _ = two_users
    listed = await harness.manager.list_connections(user_id=USER_A)
    assert [connection.id for connection in listed] == [a_connection.id]


async def test_user_a_cannot_rotate_user_b_credential(
    two_users: tuple[Harness, ProviderConnection, ProviderConnection],
) -> None:
    harness, _, b_connection = two_users
    with pytest.raises(ConnectionNotFound):
        await harness.manager.replace_credential(
            user_id=USER_A, connection_id=b_connection.id, secret="attacker-key"
        )
    b = await harness.resolver.resolve(authenticated_user_id=USER_B, provider_id=PROVIDER)
    assert b.reveal() == VT_KEY_B


async def test_user_a_cannot_disable_user_b_credential(
    two_users: tuple[Harness, ProviderConnection, ProviderConnection],
) -> None:
    harness, _, b_connection = two_users
    with pytest.raises(ConnectionNotFound):
        await harness.manager.disable_connection(user_id=USER_A, connection_id=b_connection.id)
    b = await harness.resolver.resolve(authenticated_user_id=USER_B, provider_id=PROVIDER)
    assert b.reveal() == VT_KEY_B


async def test_user_a_cannot_delete_user_b_credential(
    two_users: tuple[Harness, ProviderConnection, ProviderConnection],
) -> None:
    harness, _, b_connection = two_users
    assert await harness.manager.disconnect(user_id=USER_A, connection_id=b_connection.id) is False
    b = await harness.resolver.resolve(authenticated_user_id=USER_B, provider_id=PROVIDER)
    assert b.reveal() == VT_KEY_B


async def test_deleting_user_a_credential_does_not_affect_user_b(
    two_users: tuple[Harness, ProviderConnection, ProviderConnection],
) -> None:
    harness, a_connection, _ = two_users
    await harness.manager.disconnect(user_id=USER_A, connection_id=a_connection.id)

    with pytest.raises(CredentialNotConfigured):
        await harness.resolver.resolve(authenticated_user_id=USER_A, provider_id=PROVIDER)
    b = await harness.resolver.resolve(authenticated_user_id=USER_B, provider_id=PROVIDER)
    assert b.reveal() == VT_KEY_B


async def test_rotating_user_a_credential_does_not_affect_user_b(
    two_users: tuple[Harness, ProviderConnection, ProviderConnection],
) -> None:
    harness, a_connection, _ = two_users
    await harness.manager.replace_credential(
        user_id=USER_A, connection_id=a_connection.id, secret="vt-key-AAAA-ROTATED"
    )
    a = await harness.resolver.resolve(authenticated_user_id=USER_A, provider_id=PROVIDER)
    b = await harness.resolver.resolve(authenticated_user_id=USER_B, provider_id=PROVIDER)
    assert a.reveal() == "vt-key-AAAA-ROTATED"
    assert b.reveal() == VT_KEY_B


async def test_unconfigured_user_gets_the_same_error_as_a_foreign_lookup() -> None:
    """A missing credential and someone else's credential are indistinguishable."""
    harness = Harness()
    await harness.manager.create_connection(
        user_id=USER_B,
        provider_id=PROVIDER,
        secret=VT_KEY_B,
        auth_type=AuthType.API_KEY,
    )
    with pytest.raises(CredentialNotConfigured) as configured_only_for_b:
        await harness.resolver.resolve(authenticated_user_id=USER_A, provider_id=PROVIDER)

    empty = Harness()
    with pytest.raises(CredentialNotConfigured) as nobody_configured:
        await empty.resolver.resolve(authenticated_user_id=USER_A, provider_id=PROVIDER)

    assert str(configured_only_for_b.value) == str(nobody_configured.value)


async def test_error_text_never_contains_another_users_secret() -> None:
    harness = Harness()
    await harness.manager.create_connection(
        user_id=USER_B,
        provider_id=PROVIDER,
        secret=VT_KEY_B,
        auth_type=AuthType.API_KEY,
    )
    with pytest.raises(CredentialNotConfigured) as excinfo:
        await harness.resolver.resolve(authenticated_user_id=USER_A, provider_id=PROVIDER)
    assert VT_KEY_B not in str(excinfo.value)
    assert USER_B not in str(excinfo.value)


async def test_a_connection_cannot_be_built_pointing_at_a_foreign_secret() -> None:
    """The model itself refuses to reference another user's secret."""
    with pytest.raises(ValidationError, match="owned by the connection's user"):
        ProviderConnection(
            user_id=USER_A,
            provider_id=PROVIDER,
            credential_group=PROVIDER,
            auth_type=AuthType.API_KEY,
            secret_reference=SecretRef(owner_user_id=USER_B, key="b-key"),
        )


async def test_store_isolation_holds_for_identical_key_strings() -> None:
    store = InMemorySecretStore()
    await store.put_secret(SecretRef(owner_user_id=USER_A, key="k"), SecretStr(VT_KEY_A))
    await store.put_secret(SecretRef(owner_user_id=USER_B, key="k"), SecretStr(VT_KEY_B))
    await store.delete_secret(SecretRef(owner_user_id=USER_A, key="k"))
    assert await store.exists(SecretRef(owner_user_id=USER_A, key="k")) is False
    remaining = await store.get_secret(SecretRef(owner_user_id=USER_B, key="k"))
    assert remaining.get_secret_value() == VT_KEY_B


async def test_resolver_has_no_unscoped_lookup_api() -> None:
    """There must be no way to ask for a credential without naming the user."""
    import inspect

    for name in ("resolve", "has_credential"):
        signature = inspect.signature(getattr(CredentialResolver, name))
        assert "authenticated_user_id" in signature.parameters
        parameter = signature.parameters["authenticated_user_id"]
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
        assert parameter.default is inspect.Parameter.empty
