"""The shipped provider adapters, as one list (Task 20).

The counterpart to :mod:`ti_recon.planning.catalog`, which holds the same
providers' *planning profiles*. Two catalogues rather than one because they
answer different questions — what exists, and what the planner may choose
automatically — but they must name the same providers, and a test compares them
so neither can drift.

Why a catalogue at all
----------------------

Before this, an application had to assemble nine imports to get a working
registry, which meant every interface that wanted the real provider stack
maintained its own copy of the list. The first one to forget a provider would
silently investigate with less than the repository ships, and nothing would say
so.

Constructing an adapter contacts nothing
----------------------------------------

Every adapter here builds with no arguments and creates its client lazily, so
building the whole catalogue performs no HTTP, no DNS and no authentication. A
provider is contacted only when Task 13 selects it and Task 6 executes it — which
is what keeps ``ti-recon providers`` and ``ti-recon schema`` offline commands.

Credentials are not consulted here either. An adapter with no configured key is
still registered, because "the analyst has not configured this source" and "this
source does not exist" are different facts and Task 18 needs to tell them apart.
Registration makes the first reachable as ``NOT_CONFIGURED``; omission would
report it as a catalogue blind spot.
"""

from __future__ import annotations

from collections.abc import Callable

from ti_recon.providers.adapter import ProviderAdapter
from ti_recon.providers.censys import CensysAdapter
from ti_recon.providers.greynoise import GreyNoiseAdapter
from ti_recon.providers.gti import GTIAdapter
from ti_recon.providers.hybrid_analysis import HybridAnalysisAdapter
from ti_recon.providers.malwarebazaar import MalwareBazaarAdapter
from ti_recon.providers.misp_warninglists import MispWarningListsAdapter
from ti_recon.providers.threatfox import ThreatFoxAdapter
from ti_recon.providers.urlhaus import UrlhausAdapter
from ti_recon.providers.urlscan import UrlscanAdapter

__all__ = ["SHIPPED_ADAPTER_BUILDERS", "build_default_adapters"]

#: Every provider integration this repository ships.
#:
#: Builders rather than instances: an adapter holds per-run state, so a shared
#: instance would be shared between investigations.
SHIPPED_ADAPTER_BUILDERS: tuple[Callable[[], ProviderAdapter], ...] = (
    CensysAdapter,
    GreyNoiseAdapter,
    GTIAdapter,
    HybridAnalysisAdapter,
    MalwareBazaarAdapter,
    MispWarningListsAdapter,
    ThreatFoxAdapter,
    UrlhausAdapter,
    UrlscanAdapter,
)


def build_default_adapters() -> list[ProviderAdapter]:
    """One fresh instance of every shipped adapter.

    Configured entirely from each provider's own defaults. Nothing here reads a
    credential, opens a connection or overrides a base URL — the config models
    own their endpoints, and letting an application pass one in would be a new
    place to point this engine at a host nobody vetted.
    """
    return [builder() for builder in SHIPPED_ADAPTER_BUILDERS]
