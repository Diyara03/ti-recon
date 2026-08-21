"""Apply the reusable adapter contract suite to every fake adapter.

Adding a real provider later means adding one class here.
"""

from __future__ import annotations

from fixtures.adapter_contract import ProviderAdapterContractTests
from fixtures.fake_providers import (
    FakeAggregatorProvider,
    FakeMinimalProvider,
    FakeScannerProvider,
    FakeWarningListProvider,
)
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
