"""Optional GTI live smoke tests (Task 7).

**Disabled by default.** These are the only tests in the repository that touch a
real API, and they stay off unless explicitly enabled:

.. code-block:: bash

    RUN_GTI_LIVE_TESTS=1 VT_APIKEY=<your key> uv run pytest tests/live -q
    # optional: GTI_X_TOOL=yourorg.yourtool.0.1

Without both variables every test here skips, so a default ``pytest`` run, CI
and pre-commit never contact Google.

What these check, and what they deliberately do not
---------------------------------------------------

They check that a request succeeds, that the response normalizes into TI Recon
models, and that an assessment is present when the account is entitled to one.

They do **not** assert today's verdict for any object. Provider data changes,
and a test that fails because Google reclassified something is a test that
teaches you to ignore failures.

Rules these obey
----------------

Passive GET requests only. No submissions, no scans, no downloads. QUICK depth,
so relationship expansion is off and each test costs one API call. Nothing is
written to disk. The API key is never printed, and neither is raw provider data
beyond the small assertions below.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
from pydantic import SecretStr

from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    EvidenceClass,
    InvestigationDepth,
    ProviderCapability,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.gti import GTIAdapter, GTIConfig, gti_config_from_env

RUN_LIVE_ENV_VAR = "RUN_GTI_LIVE_TESTS"
API_KEY_ENV_VAR = "VT_APIKEY"

#: A well-known public address that will not disappear and is not malicious
#: infrastructure. Deliberately boring: a live test should not depend on
#: somebody's C2 still being up.
SMOKE_IP = "8.8.8.8"

_enabled = os.environ.get(RUN_LIVE_ENV_VAR) == "1"
_api_key = os.environ.get(API_KEY_ENV_VAR, "")

pytestmark = pytest.mark.skipif(
    not (_enabled and _api_key),
    reason=(
        f"GTI live tests are off. Enable with {RUN_LIVE_ENV_VAR}=1 and {API_KEY_ENV_VAR}=<key>."
    ),
)


def live_credential() -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="live-connection",
        user_id="live-analyst",
        provider_id="gti",
        credential_group="virustotal",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(_api_key),
    )


@pytest.fixture
async def adapter() -> AsyncIterator[GTIAdapter]:
    """A real adapter pointed at the real API.

    ``x-tool`` comes from the environment when set, so a live run identifies
    itself to Google as whoever is running it.
    """
    config: GTIConfig = gti_config_from_env()
    yield GTIAdapter(config=config)


def quick_request(raw: str, capability: ProviderCapability) -> ProviderRequest:
    """One passive, shallow lookup: no relationships, one API call."""
    return ProviderRequest(
        investigation_id="live-smoke",
        intel_object=normalize_observable(raw).intel_object,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset({capability}),
        depth=InvestigationDepth.QUICK,
    )


async def test_the_credential_is_accepted(adapter: GTIAdapter) -> None:
    """One quota call: cheapest possible proof the key works."""
    result = await adapter.validate_credentials(live_credential())
    assert result.is_usable, f"credential validation returned {result.status.value}"


async def test_a_public_address_normalizes(adapter: GTIAdapter) -> None:
    """The request succeeds and the response becomes TI Recon models."""
    outcome = await adapter.lookup(
        quick_request(SMOKE_IP, ProviderCapability.REPUTATION), live_credential()
    )

    assert outcome.status in {ProviderRunStatus.SUCCESS, ProviderRunStatus.PARTIAL}
    assert outcome.provider == "gti"
    assert outcome.api_version == "v3"
    assert outcome.objects, "expected the primary object to be normalized"

    # Structure only. No assertion about what Google currently thinks of it:
    # provider data changes, and pinning today's verdict would make this test
    # fail for a reason nobody should act on.
    for evidence in outcome.evidence:
        assert evidence.transport_provider == "gti"
        assert evidence.source_family == "google_ti"
        assert evidence.lineage_group_id


async def test_an_assessment_appears_when_the_account_is_entitled(
    adapter: GTIAdapter,
) -> None:
    """GTI assessments require entitlement, so absence is reported, not failed."""
    outcome = await adapter.lookup(
        quick_request(SMOKE_IP, ProviderCapability.REPUTATION), live_credential()
    )

    assessments = [
        evidence for evidence in outcome.evidence if evidence.claim_type == "gti_assessment"
    ]
    if not assessments:
        pytest.skip("no gti_assessment returned; this account may not be GTI-entitled")

    assessment = assessments[0]
    assert assessment.evidence_class is EvidenceClass.CURATED_THREAT_ASSERTION
    assert "verdict" in assessment.attributes


async def test_quota_is_readable(adapter: GTIAdapter) -> None:
    """Reads allowances only. The endpoint's path is never printed or logged."""
    reading = await adapter.fetch_quota(live_credential())
    assert reading.bucket_names, "expected at least one quota bucket"
    # Counts, not the key: nothing here renders the credential.
    assert _api_key not in reading.snapshot.model_dump_json()


async def test_nothing_active_is_reachable(adapter: GTIAdapter) -> None:
    """A last guard that a live run cannot submit or detonate anything."""
    from ti_recon.providers import UnsupportedProviderOperation

    with pytest.raises(UnsupportedProviderOperation):
        await adapter.active_action(
            quick_request(SMOKE_IP, ProviderCapability.REPUTATION), live_credential()
        )
    assert adapter.descriptor.supports_active is False
