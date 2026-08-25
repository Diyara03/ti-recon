"""A blacklisted abuse.ch Auth-Key stops being spent (Task 10).

``query_status = user_blacklisted`` is abuse.ch saying it has cut this account
off. It stays a ``PERMISSION_ERROR`` — the key is intact, nothing has been spent,
and marking it invalid would make an analyst replace a working key — but a
permission error alone earns no cooldown, so without the mechanism tested here
the next investigation asks again, and the one after that.

That repetition is not merely wasteful. abuse.ch meters by *behaviour* rather
than against a published budget, so a client that keeps calling after being
blocked is producing the exact behaviour that earned the block.

The two halves of the fix are tested separately. The generic half — an adapter
may attach a credential cooldown hint, and nothing gets one without asking — is
in ``tests/unit/execution/test_retry.py`` and ``test_limits.py``. This file is
the abuse.ch half: that these statuses ask for it, that nothing else does, and
what the suppression actually does to three providers sharing one key.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from fixtures.abusech import payloads
from ti_recon.credentials.enums import CredentialStatus
from ti_recon.credentials.groups import ABUSE_CH_GROUP
from ti_recon.enums import ProviderErrorCategory, ProviderRunStatus
from ti_recon.execution import CooldownReason
from ti_recon.execution.models import ExecutionScope
from ti_recon.providers.abusech.errors import (
    BLACKLIST_QUERY_STATUSES,
    QUERY_STATUS_CATEGORIES,
    category_for_query_status,
    credential_validation_for,
    translate_query_status,
)
from ti_recon.providers.abusech.policy import ABUSE_CH_BLACKLIST_COOLDOWN_SECONDS
from ti_recon.providers.errors import ProviderPermissionError
from unit.providers.abusech.test_execution import (
    KEY_A,
    KEY_B,
    USER_A,
    USER_B,
    Stack,
    file_object,
    request_for,
)

BLACKLISTED: dict[str, Any] = {"query_status": "user_blacklisted"}


def blacklist_error(provider_id: str = "threatfox") -> Any:
    return translate_query_status(
        "user_blacklisted", provider_id=provider_id, operation=f"{provider_id}.lookup"
    )


# --------------------------------------------------------------------------- #
# The category is unchanged
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("status", sorted(BLACKLIST_QUERY_STATUSES))
def test_a_blacklist_status_remains_a_permission_error(status: str) -> None:
    """Not an authentication failure, and not a spent quota."""
    assert category_for_query_status(status) is ProviderErrorCategory.PERMISSION_ERROR
    assert QUERY_STATUS_CATEGORIES[status] is ProviderErrorCategory.PERMISSION_ERROR


def test_a_blacklisted_key_is_still_a_valid_key() -> None:
    """One Auth-Key serves three providers; this must not disable the others."""
    validation = credential_validation_for("threatfox", blacklist_error())
    assert validation.status is CredentialStatus.ACTIVE
    assert validation.status is not CredentialStatus.INVALID


def test_a_blacklist_error_is_typed_as_a_permission_error() -> None:
    error = blacklist_error()
    assert isinstance(error, ProviderPermissionError)
    assert error.provider_error_code == "user_blacklisted"


# --------------------------------------------------------------------------- #
# The abuse.ch decision to ask for a pause
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("status", sorted(BLACKLIST_QUERY_STATUSES))
def test_a_blacklist_status_asks_for_a_credential_cooldown(status: str) -> None:
    error = translate_query_status(status, provider_id="urlhaus", operation="urlhaus.url")
    assert error is not None
    assert error.credential_cooldown_hint_seconds == ABUSE_CH_BLACKLIST_COOLDOWN_SECONDS


def test_the_cooldown_duration_is_configurable() -> None:
    """It is TI Recon's request-suppression figure, not a documented ban length."""
    error = translate_query_status(
        "user_blacklisted",
        provider_id="threatfox",
        operation="op",
        blacklist_cooldown_seconds=60.0,
    )
    assert error is not None
    assert error.credential_cooldown_hint_seconds == 60.0


def test_the_default_duration_is_six_hours() -> None:
    assert ABUSE_CH_BLACKLIST_COOLDOWN_SECONDS == 6 * 60 * 60


def test_the_default_duration_is_not_silently_capped_away() -> None:
    """Asking for more than Task 6's ceiling would mean the value is a fiction."""
    from ti_recon.execution.limits import MAX_COOLDOWN_SECONDS

    assert ABUSE_CH_BLACKLIST_COOLDOWN_SECONDS <= MAX_COOLDOWN_SECONDS


@pytest.mark.parametrize(
    "status",
    [
        "no_api_key",
        "invalid_api_key",
        "unauthorized",
        "illegal_hash",
        "invalid_url",
        "rate_limited",
        "no_result",
        "hash_not_found",
        "something_unknown",
    ],
)
def test_no_other_status_asks_for_a_credential_cooldown(status: str) -> None:
    """Deliberately narrow: only a refused *account* earns silence."""
    error = translate_query_status(status, provider_id="threatfox", operation="op")
    if error is not None:
        assert error.credential_cooldown_hint_seconds is None


# --------------------------------------------------------------------------- #
# What it does to a run
# --------------------------------------------------------------------------- #


@pytest.fixture
async def blocked() -> Stack:
    """A stack whose ThreatFox key has just been blacklisted."""
    stack = Stack()
    await stack.add_credential(USER_A, KEY_A)
    stack.threatfox_client.ioc_payload = dict(BLACKLISTED)
    await stack.executor.execute(stack.threatfox, request_for(), stack.context())
    return stack


async def test_a_blacklisted_key_is_reported_and_not_retried() -> None:
    stack = Stack()
    await stack.add_credential(USER_A, KEY_A)
    stack.threatfox_client.ioc_payload = dict(BLACKLISTED)

    outcome = await stack.executor.execute(stack.threatfox, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.ERROR
    assert outcome.error_category is ProviderErrorCategory.PERMISSION_ERROR
    assert outcome.attempts == 1
    assert stack.threatfox_client.call_count("search_ioc") == 1


async def test_a_blacklisted_key_puts_the_credential_on_cooldown() -> None:
    stack = Stack()
    await stack.add_credential(USER_A, KEY_A)
    stack.threatfox_client.ioc_payload = dict(BLACKLISTED)

    outcome = await stack.executor.execute(stack.threatfox, request_for(), stack.context())
    assert outcome.cooldown_applied is True
    assert outcome.cooldown_reason is CooldownReason.PROVIDER_DIRECTED
    assert outcome.cooldown_until is not None
    assert (
        outcome.cooldown_until - stack.clock.now()
    ).total_seconds() == ABUSE_CH_BLACKLIST_COOLDOWN_SECONDS


async def test_the_next_identical_request_makes_no_provider_call(blocked: Stack) -> None:
    before = len(blocked.threatfox_client.calls)
    outcome = await blocked.executor.execute(blocked.threatfox, request_for(), blocked.context())
    assert outcome.called_provider is False
    assert outcome.attempts == 0
    assert len(blocked.threatfox_client.calls) == before


async def test_a_different_observable_is_suppressed_too(blocked: Stack) -> None:
    """The credential is refused for everything, not for one search term."""
    before = len(blocked.threatfox_client.calls)
    outcome = await blocked.executor.execute(
        blocked.threatfox, request_for(payloads.MALICIOUS_DOMAIN), blocked.context()
    )
    assert outcome.status is ProviderRunStatus.TEMPORARILY_UNAVAILABLE
    assert outcome.called_provider is False
    assert len(blocked.threatfox_client.calls) == before


async def test_the_suppressed_run_is_not_reported_as_a_spent_quota(blocked: Stack) -> None:
    """Nothing was spent. Reporting an exhausted allowance would misdescribe it."""
    outcome = await blocked.executor.execute(blocked.threatfox, request_for(), blocked.context())
    assert outcome.status is not ProviderRunStatus.QUOTA_EXCEEDED
    assert outcome.error_category is ProviderErrorCategory.PERMISSION_ERROR


async def test_a_suppressed_run_yields_no_evidence_and_no_absence(blocked: Stack) -> None:
    """Coverage was lost. It must not look like a lookup that found nothing."""
    outcome = await blocked.executor.execute(blocked.threatfox, request_for(), blocked.context())
    assert outcome.status is not ProviderRunStatus.NO_DATA
    assert outcome.result is None


# --------------------------------------------------------------------------- #
# The shared key: one blacklist, three providers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("sibling", ["urlhaus", "malwarebazaar"])
async def test_a_threatfox_blacklist_suppresses_its_siblings(blocked: Stack, sibling: str) -> None:
    """The same Auth-Key is blocked, so hammering the other two proves nothing."""
    adapter, request, client = (
        (blocked.urlhaus, request_for(payloads.MALICIOUS_URL), blocked.urlhaus_client)
        if sibling == "urlhaus"
        else (blocked.malwarebazaar, request_for(file_object()), blocked.malwarebazaar_client)
    )
    outcome = await blocked.executor.execute(adapter, request, blocked.context())
    assert outcome.status is ProviderRunStatus.TEMPORARILY_UNAVAILABLE
    assert outcome.called_provider is False
    assert outcome.attempts == 0
    assert client.calls == []


async def test_the_cooldown_is_keyed_to_the_credential_not_to_one_provider(
    blocked: Stack,
) -> None:
    connection = await blocked.connections.find_by_group(USER_A, ABUSE_CH_GROUP)
    assert connection is not None
    identity = ExecutionScope.for_user(
        provider_id="threatfox",
        user_id=USER_A,
        provider_connection_id=connection.id,
        credential_group=ABUSE_CH_GROUP,
    ).credential_identity
    entry = await blocked.cooldowns.active(scope_identity=identity or "", operation="lookup")
    assert entry is not None
    assert entry.reason is CooldownReason.PROVIDER_DIRECTED
    # Provider-wide: a refused credential is refused for every operation.
    assert entry.operation is None


async def test_the_blacklist_does_not_invalidate_the_stored_connection(blocked: Stack) -> None:
    connection = await blocked.connections.find_by_group(USER_A, ABUSE_CH_GROUP)
    assert connection is not None
    assert connection.status is CredentialStatus.ACTIVE


async def test_another_analysts_key_is_untouched(blocked: Stack) -> None:
    """Isolation: one analyst's block never silences another's key."""
    await blocked.add_credential(USER_B, KEY_B)
    blocked.threatfox_client.ioc_payload = payloads.threatfox_ioc_result()

    outcome = await blocked.executor.execute(
        blocked.threatfox, request_for(), blocked.context(USER_B)
    )
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert outcome.called_provider is True


async def test_the_cooldown_lifts_on_its_own(blocked: Stack) -> None:
    blocked.threatfox_client.ioc_payload = payloads.threatfox_ioc_result()
    blocked.clock.advance(ABUSE_CH_BLACKLIST_COOLDOWN_SECONDS + 1)

    outcome = await blocked.executor.execute(blocked.threatfox, request_for(), blocked.context())
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert outcome.called_provider is True


# --------------------------------------------------------------------------- #
# Neighbouring behaviours that must not change
# --------------------------------------------------------------------------- #


async def test_a_rejected_key_still_behaves_as_before() -> None:
    """An authentication failure earns no cooldown; the analyst fixes the key."""
    stack = Stack()
    await stack.add_credential(USER_A, KEY_A)
    stack.threatfox_client.ioc_payload = {"query_status": "no_api_key"}

    outcome = await stack.executor.execute(stack.threatfox, request_for(), stack.context())
    assert outcome.error_category is ProviderErrorCategory.AUTHENTICATION_ERROR
    assert outcome.cooldown_applied is False
    assert outcome.attempts == 1

    again = await stack.executor.execute(
        stack.threatfox, request_for(payloads.MALICIOUS_DOMAIN), stack.context()
    )
    assert again.called_provider is True


async def test_an_absence_still_triggers_no_cooldown() -> None:
    stack = Stack()
    await stack.add_credential(USER_A, KEY_A)
    stack.threatfox_client.ioc_payload = payloads.threatfox_no_result()

    outcome = await stack.executor.execute(stack.threatfox, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.NO_DATA
    assert outcome.cooldown_applied is False
    assert outcome.cooldown_reason is None


async def test_an_invalid_request_still_triggers_no_cooldown() -> None:
    stack = Stack()
    await stack.add_credential(USER_A, KEY_A)
    stack.threatfox_client.ioc_payload = {"query_status": "illegal_search_term"}

    outcome = await stack.executor.execute(stack.threatfox, request_for(), stack.context())
    assert outcome.error_category is ProviderErrorCategory.INVALID_REQUEST
    assert outcome.cooldown_applied is False


# --------------------------------------------------------------------------- #
# Secrets
# --------------------------------------------------------------------------- #


async def test_no_secret_reaches_the_cooldown_metadata(blocked: Stack) -> None:
    connection = await blocked.connections.find_by_group(USER_A, ABUSE_CH_GROUP)
    assert connection is not None
    identity = ExecutionScope.for_user(
        provider_id="threatfox",
        user_id=USER_A,
        provider_connection_id=connection.id,
        credential_group=ABUSE_CH_GROUP,
    ).credential_identity
    entry = await blocked.cooldowns.active(scope_identity=identity or "", operation="lookup")
    assert entry is not None

    serialized = json.dumps(entry.model_dump(mode="json"))
    assert KEY_A not in serialized
    assert "SHOULD-NOT-LEAK" not in serialized
    # Identifiers only: a user id, a group name, a connection id.
    assert connection.id in serialized
    assert str(connection.secret_reference) not in serialized


async def test_no_secret_reaches_a_suppressed_outcome(blocked: Stack) -> None:
    outcome = await blocked.executor.execute(
        blocked.urlhaus, request_for(payloads.MALICIOUS_URL), blocked.context()
    )
    serialized = outcome.model_dump_json()
    assert KEY_A not in serialized
    assert "SHOULD-NOT-LEAK" not in serialized
