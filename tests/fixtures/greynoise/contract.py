"""A GreyNoise adapter wired to fake data, for the Task 5 contract suite.

The suite drives an adapter from its own descriptor, so this factory has to
answer for whichever object type the suite picks — which for GreyNoise is always
IPv4, the only type it declares. The fake client returns the same document for
every address, which is enough for the contract's questions: those are about
shape, provenance and refusal, not about content.
"""

from __future__ import annotations

from fixtures.greynoise.fake_client import FakeGreyNoiseClient, FakeGreyNoiseClientFactory
from ti_recon.execution.clock import ManualClock
from ti_recon.providers.greynoise.adapter import GreyNoiseAdapter

__all__ = ["contract_client", "contract_greynoise_adapter"]


def contract_client() -> FakeGreyNoiseClient:
    return FakeGreyNoiseClient()


def contract_greynoise_adapter() -> GreyNoiseAdapter:
    return GreyNoiseAdapter(
        client_factory=FakeGreyNoiseClientFactory(contract_client()),  # type: ignore[arg-type]
        clock=ManualClock(),
    )
