"""The shipped provider catalogue, for planning (Task 13).

The one module in this package that names providers, and the only one that may.
It exists so a caller can get a working planner without assembling nine imports,
and so "which providers are plannable today" has a single answer a test can check
against the adapter registry.

Everything else under :mod:`ti_recon.planning` is provider-neutral, which a test
enforces on the AST — this file is excluded from that check by name, because a
catalogue of providers that could not name providers would be an empty list.
"""

from __future__ import annotations

from ti_recon.planning.policy import ProviderPlanningRegistry
from ti_recon.providers.censys import build_censys_planning_profile
from ti_recon.providers.greynoise import build_greynoise_planning_profile
from ti_recon.providers.gti import build_gti_planning_profile
from ti_recon.providers.hybrid_analysis import build_hybrid_analysis_planning_profile
from ti_recon.providers.malwarebazaar import build_malwarebazaar_planning_profile
from ti_recon.providers.misp_warninglists import build_misp_warninglists_planning_profile
from ti_recon.providers.threatfox import build_threatfox_planning_profile
from ti_recon.providers.urlhaus import build_urlhaus_planning_profile
from ti_recon.providers.urlscan import build_urlscan_planning_profile

__all__ = ["PLANNING_PROFILE_BUILDERS", "build_default_planning_registry"]

#: Every provider the planner may choose automatically today.
#:
#: A provider absent from this list is still usable directly; it is simply not
#: chosen on an analyst's behalf. That separation is deliberate — an integration
#: can land before anybody decides it should be part of default enrichment.
PLANNING_PROFILE_BUILDERS = (
    build_censys_planning_profile,
    build_greynoise_planning_profile,
    build_gti_planning_profile,
    build_hybrid_analysis_planning_profile,
    build_malwarebazaar_planning_profile,
    build_misp_warninglists_planning_profile,
    build_threatfox_planning_profile,
    build_urlhaus_planning_profile,
    build_urlscan_planning_profile,
)


def build_default_planning_registry() -> ProviderPlanningRegistry:
    """A planning registry holding every shipped provider's profile."""
    return ProviderPlanningRegistry(tuple(builder() for builder in PLANNING_PROFILE_BUILDERS))
