"""Resolving a Censys organization id, per connection (Task 9).

The organization id decides whose credit balance is read. A lookup that could
resolve another analyst's organization would report the wrong balance and send a
request against an account the caller has nothing to do with, so the isolation
tests here matter more than the parsing ones.
"""

from __future__ import annotations

import logging

import pytest

from ti_recon.credentials import (
    AuthType,
    CredentialManager,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.providers.censys import (
    ORGANIZATION_METADATA_KEY,
    ConnectionOrganizationDirectory,
    StaticOrganizationDirectory,
    normalize_organization_id,
)


async def connection_for(
    *, user_id: str, organization_id: str | None
) -> tuple[InMemoryConnectionRepository, str]:
    repository = InMemoryConnectionRepository()
    manager = CredentialManager(InMemorySecretStore(), repository)
    metadata = {ORGANIZATION_METADATA_KEY: organization_id} if organization_id is not None else {}
    connection = await manager.create_connection(
        user_id=user_id,
        provider_id="censys",
        secret="censys-pat-SHOULD-NOT-LEAK-1234567890",
        auth_type=AuthType.BEARER_TOKEN,
        metadata=metadata,
    )
    return repository, connection.id


# --------------------------------------------------------------------------- #
# Shape
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "value",
    ["org-1", "ORG_2", "a", "0123456789abcdef", "A" * 64],
)
def test_a_usable_organization_id_is_accepted(value: str) -> None:
    assert normalize_organization_id(value) == value


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "   ",
        "../../accounts/users",
        "org/1",
        "org 1",
        "org.1",
        "org%2f1",
        "-leading-dash",
        "_leading-underscore",
        "A" * 65,
        123,
        True,
    ],
)
def test_anything_that_could_escape_a_path_segment_is_refused(value: object) -> None:
    assert normalize_organization_id(value) is None


def test_surrounding_whitespace_is_stripped() -> None:
    assert normalize_organization_id("  org-1  ") == "org-1"


# --------------------------------------------------------------------------- #
# Reading it out of the analyst's own connection
# --------------------------------------------------------------------------- #


async def test_the_organization_is_read_from_the_connection_metadata() -> None:
    repository, connection_id = await connection_for(user_id="analyst-a", organization_id="org-1")
    directory = ConnectionOrganizationDirectory(repository)
    resolved = await directory.organization_id_for(user_id="analyst-a", connection_id=connection_id)
    assert resolved == "org-1"


async def test_a_connection_with_no_organization_resolves_to_nothing() -> None:
    repository, connection_id = await connection_for(user_id="analyst-a", organization_id=None)
    directory = ConnectionOrganizationDirectory(repository)
    assert (
        await directory.organization_id_for(user_id="analyst-a", connection_id=connection_id)
        is None
    )


async def test_one_analysts_connection_id_resolves_nothing_for_another() -> None:
    """The isolation is the repository's, not a rule this class remembers."""
    repository, connection_id = await connection_for(user_id="analyst-a", organization_id="org-1")
    directory = ConnectionOrganizationDirectory(repository)
    assert (
        await directory.organization_id_for(user_id="analyst-b", connection_id=connection_id)
        is None
    )


async def test_an_unknown_connection_resolves_to_nothing() -> None:
    repository, _ = await connection_for(user_id="analyst-a", organization_id="org-1")
    directory = ConnectionOrganizationDirectory(repository)
    assert (
        await directory.organization_id_for(user_id="analyst-a", connection_id="conn-nope") is None
    )


async def test_an_unusable_organization_id_is_dropped_rather_than_used(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A malformed value must not fail a lookup the user endpoint can answer."""
    repository, connection_id = await connection_for(
        user_id="analyst-a", organization_id="../../users"
    )
    directory = ConnectionOrganizationDirectory(repository)
    with caplog.at_level(logging.INFO):
        resolved = await directory.organization_id_for(
            user_id="analyst-a", connection_id=connection_id
        )
    assert resolved is None
    assert any("organization id ignored" in record.getMessage() for record in caplog.records)


async def test_a_dropped_organization_id_never_appears_in_a_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    repository, connection_id = await connection_for(
        user_id="analyst-a", organization_id="../../secret-account"
    )
    directory = ConnectionOrganizationDirectory(repository)
    with caplog.at_level(logging.INFO):
        await directory.organization_id_for(user_id="analyst-a", connection_id=connection_id)
    for record in caplog.records:
        assert "secret-account" not in str(record.__dict__)


# --------------------------------------------------------------------------- #
# The static directory
# --------------------------------------------------------------------------- #


async def test_the_static_directory_is_keyed_by_user_and_connection() -> None:
    directory = StaticOrganizationDirectory()
    directory.set(user_id="analyst-a", connection_id="conn-1", organization_id="org-1")

    assert await directory.organization_id_for(user_id="analyst-a", connection_id="conn-1") == (
        "org-1"
    )
    assert await directory.organization_id_for(user_id="analyst-b", connection_id="conn-1") is None


async def test_the_static_directory_refuses_an_unusable_id() -> None:
    directory = StaticOrganizationDirectory()
    with pytest.raises(ValueError, match="unusable shape"):
        directory.set(user_id="analyst-a", connection_id="conn-1", organization_id="../x")


async def test_the_static_directory_can_be_seeded_and_counted() -> None:
    directory = StaticOrganizationDirectory({("analyst-a", "conn-1"): "org-1"})
    assert len(directory) == 1
    assert "entries=1" in repr(directory)
