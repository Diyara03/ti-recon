"""Which door a credential may use, as observed live with a Business-Free key (Task 24).

The live account behaved like this: ``/ping`` 200 with a named plan, and the
Community endpoint usable. Through TI Recon the full context endpoint answered
200 for the same address, so the fallback was never exercised live -- these
regressions exercise it deterministically, and pin the four outcomes the
brief asked to be confirmed:

* **G** -- a full-tier answer is ``SUCCESS`` at access level ``full``;
* **H** -- a refused full context (``403`` / plan limit) earns exactly one
  Community attempt, whose answer is ``SUCCESS`` at level ``community`` with
  the gap recorded and the credential left usable;
* **I** -- a rejected key (``401``) is an authentication failure, never probed
  and never reinterpreted as a free tier, and the credential is marked invalid;
* **F** -- a Community ``404`` is ``NO_DATA`` at level ``community``, never a
  benign finding and never an authentication failure.

And in every case the access path that produced the answer is preserved on
the coverage record, which is what the report's highlight is read from.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from fixtures.greynoise import payloads
from fixtures.greynoise.fake_client import FakeGreyNoiseClient, FakeGreyNoiseClientFactory
from ti_recon.credentials.enums import AuthType, CredentialStatus
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution.clock import ManualClock
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.errors import ProviderAuthenticationError, provider_error_for
from ti_recon.providers.greynoise import (
    GREYNOISE_COMMUNITY_ACCESS_ONLY,
    GreyNoiseAccessLevel,
    GreyNoiseAdapter,
    GreyNoiseLookupPolicy,
)
from ti_recon.providers.greynoise.errors import (
    GREYNOISE_STATUS_CATEGORIES,
    credential_status_for,
)

FAKE_KEY = "greynoise-key-SHOULD-NOT-LEAK-tiers-0001"
FULL = FakeGreyNoiseClient.FULL
COMMUNITY = FakeGreyNoiseClient.COMMUNITY


def _credential(user_id: str = "analyst-a") -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="conn-1",
        user_id=user_id,
        provider_id="greynoise",
        credential_group="greynoise",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(FAKE_KEY),
    )


def _request() -> ProviderRequest:
    return ProviderRequest(
        investigation_id="inv-1",
        intel_object=normalize_observable(payloads.SCANNER_IP).intel_object,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({ProviderCapability.SCANNER_CONTEXT}),
    )


def _adapter(
    client: FakeGreyNoiseClient, policy: GreyNoiseLookupPolicy | None = None
) -> GreyNoiseAdapter:
    return GreyNoiseAdapter(
        client_factory=FakeGreyNoiseClientFactory(client),  # type: ignore[arg-type]
        lookup_policy=policy,
        clock=ManualClock(),
    )


def _coverage(envelope: Any) -> dict[str, Any]:
    return next(
        item.attributes for item in envelope.evidence if item.claim_type == "greynoise_coverage"
    )


def _refusal(category: ProviderErrorCategory) -> Any:
    return provider_error_for(category, "greynoise")


# --------------------------------------------------------------------------- #
# The status table itself
# --------------------------------------------------------------------------- #


def test_the_three_statuses_that_matter_map_to_three_different_categories() -> None:
    assert GREYNOISE_STATUS_CATEGORIES[401] is ProviderErrorCategory.AUTHENTICATION_ERROR
    assert GREYNOISE_STATUS_CATEGORIES[403] is ProviderErrorCategory.PERMISSION_ERROR
    assert GREYNOISE_STATUS_CATEGORIES[404] is ProviderErrorCategory.NOT_FOUND


def test_only_a_rejected_key_invalidates_the_credential() -> None:
    """A refused endpoint leaves the key ACTIVE; only a rejected key does not."""
    assert credential_status_for(ProviderErrorCategory.AUTHENTICATION_ERROR) is (
        CredentialStatus.INVALID
    )
    assert credential_status_for(ProviderErrorCategory.PERMISSION_ERROR) is CredentialStatus.ACTIVE
    assert credential_status_for(ProviderErrorCategory.PLAN_LIMITED) is CredentialStatus.ACTIVE
    assert credential_status_for(ProviderErrorCategory.NOT_FOUND) is not CredentialStatus.INVALID


# --------------------------------------------------------------------------- #
# G -- full tier
# --------------------------------------------------------------------------- #


async def test_g_a_full_tier_answer_is_a_success_at_level_full() -> None:
    client = FakeGreyNoiseClient()
    envelope = await _adapter(client).lookup(_request(), _credential())
    assert envelope.status is ProviderRunStatus.SUCCESS
    assert client.call_count(FULL) == 1
    assert not client.called(COMMUNITY)
    coverage = _coverage(envelope)
    assert coverage["access_level"] == GreyNoiseAccessLevel.FULL.value
    assert "full_context_unavailable" not in coverage
    assert GREYNOISE_COMMUNITY_ACCESS_ONLY not in envelope.warnings


async def test_g_a_full_tier_404_is_no_data_at_level_full() -> None:
    """The paid endpoint answered; absence is the finding and full access is confirmed."""
    client = FakeGreyNoiseClient()
    client.fail(FULL, _refusal(ProviderErrorCategory.NOT_FOUND))
    envelope = await _adapter(client).lookup(_request(), _credential())
    assert envelope.status is ProviderRunStatus.NO_DATA
    assert not client.called(COMMUNITY)
    assert _coverage(envelope)["access_level"] == "full"


# --------------------------------------------------------------------------- #
# H -- full tier unavailable, Community fallback
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "category", [ProviderErrorCategory.PERMISSION_ERROR, ProviderErrorCategory.PLAN_LIMITED]
)
async def test_h_a_refused_full_context_falls_back_to_community_once(
    category: ProviderErrorCategory,
) -> None:
    client = FakeGreyNoiseClient()
    client.fail(FULL, _refusal(category))
    adapter = _adapter(client)
    envelope = await adapter.lookup(_request(), _credential())

    assert envelope.status is ProviderRunStatus.SUCCESS
    assert client.call_count(FULL) == 1
    assert client.call_count(COMMUNITY) == 1
    coverage = _coverage(envelope)
    assert coverage["access_level"] == GreyNoiseAccessLevel.COMMUNITY.value
    assert coverage["full_context_unavailable"] is True
    assert GREYNOISE_COMMUNITY_ACCESS_ONLY in envelope.warnings
    # The Community answer is a real answer: the classification is on record.
    assert any(item.claim_type == "greynoise_classification" for item in envelope.evidence)

    # And the credential is not labelled invalid for it: the next lookup goes
    # straight to the door that worked, with no second probe of the paid one.
    await adapter.lookup(_request(), _credential())
    assert client.call_count(FULL) == 1
    assert client.call_count(COMMUNITY) == 2


async def test_h_a_community_404_after_a_refusal_still_proves_community_access() -> None:
    client = FakeGreyNoiseClient()
    client.fail(FULL, _refusal(ProviderErrorCategory.PERMISSION_ERROR))
    client.fail(COMMUNITY, _refusal(ProviderErrorCategory.NOT_FOUND))
    adapter = _adapter(client)
    envelope = await adapter.lookup(_request(), _credential())
    assert envelope.status is ProviderRunStatus.NO_DATA
    assert _coverage(envelope)["access_level"] == "community"
    await adapter.lookup(_request(), _credential())
    assert client.call_count(FULL) == 1, "a legitimate 404 remembered the Community level"


# --------------------------------------------------------------------------- #
# I -- a real authentication failure, where no fallback applies
# --------------------------------------------------------------------------- #


async def test_i_a_rejected_key_is_raised_never_probed_and_never_a_free_tier() -> None:
    client = FakeGreyNoiseClient()
    client.fail(FULL, _refusal(ProviderErrorCategory.AUTHENTICATION_ERROR))
    with pytest.raises(ProviderAuthenticationError) as raised:
        await _adapter(client).lookup(_request(), _credential())
    assert raised.value.category is ProviderErrorCategory.AUTHENTICATION_ERROR
    assert not client.called(COMMUNITY)
    assert credential_status_for(raised.value.category) is CredentialStatus.INVALID


async def test_i_a_key_rejected_by_community_during_the_probe_is_reported_as_rejected() -> None:
    """The 403 earned a probe; the probe's 401 is the more important fact."""
    client = FakeGreyNoiseClient()
    client.fail(FULL, _refusal(ProviderErrorCategory.PERMISSION_ERROR))
    client.fail(COMMUNITY, _refusal(ProviderErrorCategory.AUTHENTICATION_ERROR))
    with pytest.raises(ProviderAuthenticationError):
        await _adapter(client).lookup(_request(), _credential())


async def test_i_a_rejected_key_under_a_pinned_community_mode_is_still_rejected() -> None:
    from ti_recon.providers.greynoise import GreyNoiseAccessMode

    client = FakeGreyNoiseClient()
    client.fail(COMMUNITY, _refusal(ProviderErrorCategory.AUTHENTICATION_ERROR))
    adapter = _adapter(client, GreyNoiseLookupPolicy(access_mode=GreyNoiseAccessMode.COMMUNITY))
    with pytest.raises(ProviderAuthenticationError):
        await adapter.lookup(_request(), _credential())
    assert not client.called(FULL)


# --------------------------------------------------------------------------- #
# F -- Community 404
# --------------------------------------------------------------------------- #


async def test_f_a_community_404_is_no_data_and_not_an_authentication_failure() -> None:
    from ti_recon.providers.greynoise import GreyNoiseAccessMode

    client = FakeGreyNoiseClient()
    client.fail(COMMUNITY, _refusal(ProviderErrorCategory.NOT_FOUND))
    adapter = _adapter(client, GreyNoiseLookupPolicy(access_mode=GreyNoiseAccessMode.COMMUNITY))
    envelope = await adapter.lookup(_request(), _credential())
    assert envelope.status is ProviderRunStatus.NO_DATA
    assert envelope.error_message is None
    assert _coverage(envelope)["access_level"] == "community"
    assert not any(item.effect.value != "context_only" for item in envelope.evidence)


# --------------------------------------------------------------------------- #
# The access path is preserved, whichever door answered
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "scripted, expected",
    [
        ({}, "full"),
        ({FULL: ProviderErrorCategory.PERMISSION_ERROR}, "community"),
        ({FULL: ProviderErrorCategory.NOT_FOUND}, "full"),
    ],
    ids=["full-200", "full-403-community-200", "full-404"],
)
async def test_which_door_answered_is_always_on_the_coverage_record(
    scripted: dict[str, ProviderErrorCategory], expected: str
) -> None:
    client = FakeGreyNoiseClient()
    for operation, category in scripted.items():
        client.fail(operation, _refusal(category))
    envelope = await _adapter(client).lookup(_request(), _credential())
    assert _coverage(envelope)["access_level"] == expected
    assert FAKE_KEY not in envelope.model_dump_json()
