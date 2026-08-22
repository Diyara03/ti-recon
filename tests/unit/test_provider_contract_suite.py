"""Apply the reusable adapter contract suite to every adapter.

The fakes cover the shapes of the contract; the real integrations are held to
exactly the same one, each wired to a fake client so the suite still performs no
I/O.
"""

from __future__ import annotations

from fixtures.adapter_contract import ProviderAdapterContractTests
from fixtures.fake_providers import (
    FakeAggregatorProvider,
    FakeMinimalProvider,
    FakeScannerProvider,
    FakeWarningListProvider,
)
from fixtures.gti.contract import contract_gti_adapter
from fixtures.urlscan.contract import contract_urlscan_adapter
from ti_recon.providers import ProviderAdapter


class TestFakeScannerContract(ProviderAdapterContractTests):
    def make_adapter(self) -> ProviderAdapter:
        return FakeScannerProvider()


class TestFakeAggregatorContract(ProviderAdapterContractTests):
    def make_adapter(self) -> ProviderAdapter:
        return FakeAggregatorProvider()


class TestFakeWarningListContract(ProviderAdapterContractTests):
    """Also covers the credential-free path: this provider needs no key."""

    def make_adapter(self) -> ProviderAdapter:
        return FakeWarningListProvider()


class TestFakeMinimalContract(ProviderAdapterContractTests):
    """The smallest legal adapter: proves the optional parts are optional."""

    def make_adapter(self) -> ProviderAdapter:
        return FakeMinimalProvider()


class TestGTIContract(ProviderAdapterContractTests):
    """The first real provider, held to exactly the same contract as the fakes."""

    def make_adapter(self) -> ProviderAdapter:
        return contract_gti_adapter()


class TestUrlscanContract(ProviderAdapterContractTests):
    """Held to the same contract, including that active operations are refused."""

    def make_adapter(self) -> ProviderAdapter:
        return contract_urlscan_adapter()
