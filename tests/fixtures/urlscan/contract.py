"""A urlscan adapter wired to fake data, for the Task 5 contract suite.

The suite drives an adapter from its own descriptor, so this factory has to
answer for whichever object type the suite picks. The fake client returns the
same scan for every search, which is enough for the contract's questions —
those are about shape, provenance and refusal, not about content.
"""

from __future__ import annotations

from fixtures.urlscan import payloads
from fixtures.urlscan.fake_client import FakeUrlscanClient, FakeUrlscanClientFactory
from ti_recon.artifacts import InMemoryArtifactStore
from ti_recon.execution.clock import ManualClock
from ti_recon.providers.urlscan.adapter import UrlscanAdapter

__all__ = ["contract_client", "contract_urlscan_adapter"]


def contract_client() -> FakeUrlscanClient:
    return FakeUrlscanClient(
        search_payload=payloads.search_payload(),
        result_payloads={payloads.SCAN_ID: payloads.result_payload()},
    )


def contract_urlscan_adapter() -> UrlscanAdapter:
    return UrlscanAdapter(
        client_factory=FakeUrlscanClientFactory(contract_client()),  # type: ignore[arg-type]
        artifact_store=InMemoryArtifactStore(),
        clock=ManualClock(),
    )
