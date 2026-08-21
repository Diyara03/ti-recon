"""A GTI adapter wired to fake data, for the Task 5 contract suite.

The reusable contract suite drives an adapter entirely from its own descriptor,
so this factory has to answer for whichever object type and capability the suite
picks. It registers a primary object for every collection GTI serves rather than
guessing which one will be chosen.
"""

from __future__ import annotations

from fixtures.gti import payloads
from fixtures.gti.fake_client import FakeGTIClient, FakeGTIClientFactory
from ti_recon.execution import ManualClock
from ti_recon.providers.gti import GTIAdapter, url_identifier

__all__ = ["CONTRACT_URL", "contract_client", "contract_gti_adapter"]

#: The URL the contract suite submits for a ``url`` observable.
CONTRACT_URL = "https://contract.example/a"


def contract_client() -> FakeGTIClient:
    """A client that answers for every observable type the suite may pick."""
    fake = FakeGTIClient(
        quota_payload=payloads.overall_quotas_payload(),
        behaviour_payload=payloads.behaviour_summary_payload(),
    )
    fake.register_primary("domains", payloads.domain_object(object_id="contract.example"))
    fake.register_primary("ip_addresses", payloads.ip_object(object_id="198.51.100.7"))
    fake.register_primary("ip_addresses", payloads.ip_object(object_id="2001:db8::1"))
    fake.register_primary("files", payloads.file_object())
    fake.register_primary(
        "urls",
        payloads.url_object(object_id=url_identifier(CONTRACT_URL), url=CONTRACT_URL),
    )
    return fake


def contract_gti_adapter() -> GTIAdapter:
    """A GTI adapter that performs no I/O."""
    return GTIAdapter(
        client_factory=FakeGTIClientFactory(client=contract_client()),
        clock=ManualClock(),
    )
