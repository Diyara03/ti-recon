"""Secret handling and non-leakage (Task 4)."""

from __future__ import annotations

import json
import logging
import pickle

import pytest
from pydantic import SecretStr, ValidationError

from ti_recon.credentials import (
    AuthType,
    CredentialMaterial,
    CredentialStatus,
    InMemoryConnectionRepository,
    InMemorySecretStore,
    ProviderConnection,
    SecretNotFound,
    SecretRef,
)

SECRET = "vt-key-AAAA1111BBBB2222"


def make_connection(user_id: str = "user-a", **overrides: object) -> ProviderConnection:
    kwargs: dict[str, object] = {
        "user_id": user_id,
        "provider_id": "fake_aggregator",
        "credential_group": "fake_aggregator",
        "auth_type": AuthType.API_KEY,
        "secret_reference": SecretRef(owner_user_id=user_id, key="key-1"),
    }
    kwargs.update(overrides)
    return ProviderConnection(**kwargs)  # type: ignore[arg-type]


def make_material(secret: str = SECRET) -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id="user-a",
        provider_id="fake_aggregator",
        credential_group="fake_aggregator",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(secret),
    )


# --------------------------------------------------------------------------- #
# ProviderConnection never holds a secret
# --------------------------------------------------------------------------- #


def test_connection_holds_a_reference_not_a_secret() -> None:
    connection = make_connection()
    assert "secret" not in set(ProviderConnection.model_fields) - {"secret_reference"}
    assert isinstance(connection.secret_reference, SecretRef)


def test_connection_serialization_contains_no_secret_value() -> None:
    connection = make_connection()
    payload = json.dumps(connection.model_dump(mode="json"))
    assert SECRET not in payload


def test_connection_reference_must_belong_to_its_user() -> None:
    with pytest.raises(ValidationError, match="owned by the connection's user"):
        ProviderConnection(
            user_id="user-a",
            provider_id="fake_aggregator",
            credential_group="fake_aggregator",
            auth_type=AuthType.API_KEY,
            secret_reference=SecretRef(owner_user_id="user-b", key="key-1"),
        )


def test_connection_metadata_rejects_credential_like_keys() -> None:
    with pytest.raises(ValidationError, match="credential-like key"):
        make_connection(metadata={"api_key": SECRET})


# --------------------------------------------------------------------------- #
# CredentialMaterial does not leak
# --------------------------------------------------------------------------- #


def test_secret_absent_from_repr() -> None:
    assert SECRET not in repr(make_material())


def test_secret_absent_from_str() -> None:
    assert SECRET not in str(make_material())


def test_secret_absent_from_model_dump() -> None:
    assert SECRET not in str(make_material().model_dump())


def test_secret_absent_from_json_dump() -> None:
    assert SECRET not in make_material().model_dump_json()


def test_secret_absent_from_formatted_string() -> None:
    material = make_material()
    assert SECRET not in f"{material}"
    assert SECRET not in f"{material.secret}"


def test_secret_absent_from_exception_text() -> None:
    material = make_material()
    try:
        raise RuntimeError(f"provider call failed for {material}")
    except RuntimeError as exc:
        assert SECRET not in str(exc)


def test_secret_absent_from_validation_error_text() -> None:
    """Pydantic must not echo rejected input back into the error message."""
    with pytest.raises(ValidationError) as excinfo:
        CredentialMaterial(
            connection_id="conn-1",
            user_id="user-a",
            provider_id="",
            credential_group="fake_aggregator",
            auth_type=AuthType.API_KEY,
            secret=SecretStr(SECRET),
        )
    assert SECRET not in str(excinfo.value)


def test_secret_absent_from_logging_output(caplog: pytest.LogCaptureFixture) -> None:
    material = make_material()
    with caplog.at_level(logging.DEBUG):
        logging.getLogger("test").info("using credential %s", material)
    assert SECRET not in caplog.text


def test_secret_is_reachable_only_through_reveal() -> None:
    assert make_material().reveal() == SECRET


def test_material_is_immutable() -> None:
    with pytest.raises(ValidationError, match="frozen"):
        make_material().provider_id = "other"


def test_secret_absent_from_pickle_free_text_representations() -> None:
    """A pickled model still holds the secret; text representations must not."""
    material = make_material()
    assert SECRET.encode() in pickle.dumps(material)  # documents the boundary
    assert SECRET not in repr(material)


# --------------------------------------------------------------------------- #
# InMemorySecretStore
# --------------------------------------------------------------------------- #


async def test_store_round_trip() -> None:
    store = InMemorySecretStore()
    ref = SecretRef(owner_user_id="user-a", key="key-1")
    await store.put_secret(ref, SecretStr(SECRET))
    assert (await store.get_secret(ref)).get_secret_value() == SECRET
    assert await store.exists(ref) is True


async def test_store_missing_secret_raises() -> None:
    store = InMemorySecretStore()
    with pytest.raises(SecretNotFound):
        await store.get_secret(SecretRef(owner_user_id="user-a", key="missing"))


async def test_store_delete_is_idempotent() -> None:
    store = InMemorySecretStore()
    ref = SecretRef(owner_user_id="user-a", key="key-1")
    await store.put_secret(ref, SecretStr(SECRET))
    await store.delete_secret(ref)
    await store.delete_secret(ref)
    assert await store.exists(ref) is False


async def test_store_keys_are_owner_scoped() -> None:
    """The same key string under two owners is two different secrets."""
    store = InMemorySecretStore()
    await store.put_secret(SecretRef(owner_user_id="user-a", key="shared"), SecretStr("a"))
    await store.put_secret(SecretRef(owner_user_id="user-b", key="shared"), SecretStr("b"))
    a = await store.get_secret(SecretRef(owner_user_id="user-a", key="shared"))
    b = await store.get_secret(SecretRef(owner_user_id="user-b", key="shared"))
    assert a.get_secret_value() == "a"
    assert b.get_secret_value() == "b"


async def test_store_rejects_foreign_owner_for_a_known_key() -> None:
    store = InMemorySecretStore()
    await store.put_secret(SecretRef(owner_user_id="user-a", key="key-1"), SecretStr(SECRET))
    with pytest.raises(SecretNotFound):
        await store.get_secret(SecretRef(owner_user_id="user-b", key="key-1"))


def test_store_is_labelled_not_production_ready() -> None:
    assert InMemorySecretStore.is_production_ready is False
    assert "NOT FOR PRODUCTION" in (InMemorySecretStore.__doc__ or "")


def test_repository_is_labelled_not_production_ready() -> None:
    assert InMemoryConnectionRepository.is_production_ready is False
    assert "NOT FOR PRODUCTION" in (InMemoryConnectionRepository.__doc__ or "")


async def test_store_repr_reveals_nothing() -> None:
    store = InMemorySecretStore()
    await store.put_secret(SecretRef(owner_user_id="user-a", key="key-1"), SecretStr(SECRET))
    text = repr(store)
    assert SECRET not in text
    assert "user-a" not in text
    assert "key-1" not in text


def test_credential_status_is_separate_from_provider_status() -> None:
    """Credential validity and provider runtime status are different axes."""
    from ti_recon.enums import ProviderRunStatus

    credential_values = {member.value for member in CredentialStatus}
    run_values = {member.value for member in ProviderRunStatus}
    assert credential_values & run_values == set()
