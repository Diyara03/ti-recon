"""A Censys adapter wired to fake data, for the Task 5 contract suite.

The suite drives an adapter from its own descriptor and picks the alphabetically
first supported object type, which for Censys is IPv4. The fake client answers
for the contract suite's own sample address as well as this package's, because
the contract asks about shape, provenance and refusal rather than content.
"""

from __future__ import annotations

from fixtures.censys import payloads
from fixtures.censys.fake_client import FakeCensysClient, FakeCensysClientFactory
from ti_recon.execution.clock import ManualClock
from ti_recon.providers.censys.adapter import CensysAdapter

__all__ = ["contract_censys_adapter", "contract_client"]


def contract_client() -> FakeCensysClient:
    return FakeCensysClient(
        hosts={
            payloads.HOST_IP: payloads.host_payload(),
            # The contract suite's own sample IPv6 address, so a descriptor
            # change that adds it does not turn into a mystery failure.
            "2001:db8::1": payloads.host_payload(ip="2001:db8::1"),
        }
    )


def contract_censys_adapter() -> CensysAdapter:
    return CensysAdapter(
        client_factory=FakeCensysClientFactory(contract_client()),  # type: ignore[arg-type]
        clock=ManualClock(),
    )
