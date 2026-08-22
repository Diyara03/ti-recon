"""Optional urlscan live smoke tests (Task 8).

**Disabled by default.** Together with the GTI ones these are the only tests in
the repository that touch a real API, and they stay off unless explicitly
enabled:

.. code-block:: bash

    RUN_URLSCAN_LIVE_TESTS=1 URLSCAN_API_KEY=<your key> uv run pytest tests/live -q

Without both variables every test here skips, so a default ``pytest`` run, CI
and pre-commit never contact urlscan.

What these check, and what they deliberately do not
---------------------------------------------------

They check that a search and a stored-result read succeed, and that what comes
back normalizes into TI Recon models with the right provenance.

They do **not** assert today's verdict for anything, and they do not scan.
Provider data changes, and a test that fails because a page was reclassified is
a test that teaches you to ignore failures.

Rules these obey
----------------

Passive GET requests only against endpoints urlscan already has data for. Every
search is date bounded — STANDARD to 180 days, DEEP to whatever historical range
the account reports — so a live run never asks urlscan for an open-ended index
scan. No submission, no rescan, no live scan, no downloads — the integration has no code
path for any of those, and these tests do not add one. STANDARD depth, so a run
costs one search plus a small number of stored-result reads. The forensic tests
run at DEEP with WEB_FORENSICS and read stored artifacts only; nothing is
written to disk. The API key is never printed, and neither is retrieved page
content.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
from pydantic import SecretStr

from ti_recon.artifacts import ArtifactScope, InMemoryArtifactStore
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    InvestigationDepth,
    ProviderCapability,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.urlscan import UrlscanAdapter, UrlscanConfig

RUN_LIVE_ENV_VAR = "RUN_URLSCAN_LIVE_TESTS"
API_KEY_ENV_VAR = "URLSCAN_API_KEY"

#: A domain that is scanned constantly and is not anybody's malicious
#: infrastructure. Deliberately boring: a live test should not depend on a
#: particular phishing site still being up.
SMOKE_DOMAIN = "example.com"

_enabled = os.environ.get(RUN_LIVE_ENV_VAR) == "1"
_api_key = os.environ.get(API_KEY_ENV_VAR, "")

pytestmark = pytest.mark.skipif(
    not (_enabled and _api_key),
    reason=(
        f"urlscan live tests are off. Enable with {RUN_LIVE_ENV_VAR}=1 and {API_KEY_ENV_VAR}=<key>."
    ),
)


def live_credential() -> CredentialMaterial:
    return CredentialMaterial(
        connection_id="live-connection",
        user_id="live-analyst",
        provider_id="urlscan",
        credential_group="urlscan",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(_api_key),
    )


@pytest.fixture
async def artifacts() -> InMemoryArtifactStore:
    return InMemoryArtifactStore()


@pytest.fixture
async def adapter(artifacts: InMemoryArtifactStore) -> AsyncIterator[UrlscanAdapter]:
    yield UrlscanAdapter(config=UrlscanConfig(), artifact_store=artifacts)


def request_for(
    raw: str,
    *,
    depth: InvestigationDepth = InvestigationDepth.STANDARD,
    capabilities: frozenset[ProviderCapability] | None = None,
) -> ProviderRequest:
    return ProviderRequest(
        investigation_id="live-smoke",
        intel_object=normalize_observable(raw).intel_object,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=capabilities or frozenset({ProviderCapability.REPUTATION}),
        depth=depth,
    )


async def test_the_credential_is_accepted(adapter: UrlscanAdapter) -> None:
    """One quota call: the cheapest possible proof the key works."""
    result = await adapter.validate_credentials(live_credential())
    assert result.is_usable, f"credential validation returned {result.status.value}"


async def test_quota_reports_the_read_allowances(adapter: UrlscanAdapter) -> None:
    reading = await adapter.fetch_quota(live_credential())
    assert not reading.snapshot.is_empty, "expected at least one gating allowance"
    for bucket in reading.snapshot.buckets:
        assert bucket.name.startswith(("search_", "retrieve_"))


async def test_a_well_known_domain_normalizes(adapter: UrlscanAdapter) -> None:
    """The search and the stored-result reads succeed and become TI Recon models."""
    outcome = await adapter.lookup(request_for(SMOKE_DOMAIN), live_credential())

    assert outcome.status in {
        ProviderRunStatus.SUCCESS,
        ProviderRunStatus.PARTIAL,
        ProviderRunStatus.NO_DATA,
    }
    assert outcome.provider == "urlscan"
    assert outcome.api_version == "v1"

    # Structure and provenance only. Nothing about what urlscan currently
    # thinks of the domain: that changes, and pinning it would make this test
    # fail for a reason nobody should act on.
    for evidence in outcome.evidence:
        assert evidence.transport_provider == "urlscan"
        assert evidence.lineage_group_id
        assert evidence.source_reliability is None
        assert evidence.information_credibility is None


async def test_an_ordinary_lookup_retrieves_no_page_content(
    adapter: UrlscanAdapter, artifacts: InMemoryArtifactStore
) -> None:
    """The two-mode promise, against the real API."""
    await adapter.lookup(request_for(SMOKE_DOMAIN), live_credential())
    scope = ArtifactScope(user_id="live-analyst", investigation_id="live-smoke")
    assert artifacts.list(scope) == ()


async def test_an_explicit_forensic_run_captures_stored_artifacts(
    adapter: UrlscanAdapter, artifacts: InMemoryArtifactStore
) -> None:
    """Passive throughout: everything read here is content urlscan already holds."""
    outcome = await adapter.lookup(
        request_for(
            SMOKE_DOMAIN,
            depth=InvestigationDepth.DEEP,
            capabilities=frozenset(
                {ProviderCapability.REPUTATION, ProviderCapability.WEB_FORENSICS}
            ),
        ),
        live_credential(),
    )
    assert outcome.provider == "urlscan"

    scope = ArtifactScope(user_id="live-analyst", investigation_id="live-smoke")
    stored = artifacts.list(scope)
    if not stored:
        pytest.skip("urlscan returned no stored artifacts for this domain")

    # Metadata only. Retrieved page content is never printed, asserted against
    # or written anywhere.
    for artifact in stored:
        assert artifact.provider_id == "urlscan"
        assert len(artifact.content_sha256) == 64
        assert artifact.size_bytes > 0


async def test_the_provider_reports_itself_available(adapter: UrlscanAdapter) -> None:
    report = await adapter.health(live_credential())
    assert report.provider_id == "urlscan"
    assert report.health.value in {"available", "degraded", "unavailable", "unknown"}
