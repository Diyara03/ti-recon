"""The composition root: which provider owns which extractor (Task 15).

**The only module under ``reasoning/`` allowed to name a provider**, and a test
reads the AST of every other one to keep it that way. The rule is the same one
Task 13 applies to ``planning/catalog.py``, for the same reason: the moment a
generic evaluator learns that URLhaus has a ``url_status``, adding a provider
means editing the reasoning core, and provider semantics start drifting away from
the code that produced them.

Imports are deliberately function-local. Each provider's ``qualification`` module
imports the shared Task 15 vocabulary, so a module-level import here would close a
cycle — ``ti_recon.reasoning`` -> catalog -> a provider -> ``ti_recon.reasoning``
— that resolves or fails depending on which module a process happens to import
first. Deferring the import to registry construction removes the question
entirely, and costs one dictionary build per engine.
"""

from __future__ import annotations

from ti_recon.reasoning.extraction import ProviderQualifier

__all__ = ["default_qualifiers", "qualified_provider_ids"]


def default_qualifiers() -> dict[str, ProviderQualifier]:
    """Every shipped provider's pure translation into the Task 15 vocabulary.

    A provider absent from this map is not an error. Its evidence still counts
    towards coverage, and the result names it as unqualified rather than implying
    everything returned was examined.
    """
    from ti_recon.providers.censys import qualification as censys
    from ti_recon.providers.censys.descriptor import CENSYS_PROVIDER_ID
    from ti_recon.providers.greynoise import qualification as greynoise
    from ti_recon.providers.greynoise.descriptor import GREYNOISE_PROVIDER_ID
    from ti_recon.providers.gti import qualification as gti
    from ti_recon.providers.gti.descriptor import GTI_PROVIDER_ID
    from ti_recon.providers.hybrid_analysis import qualification as hybrid_analysis
    from ti_recon.providers.hybrid_analysis.descriptor import HYBRID_ANALYSIS_PROVIDER_ID
    from ti_recon.providers.malwarebazaar import qualification as malwarebazaar
    from ti_recon.providers.malwarebazaar.descriptor import MALWAREBAZAAR_PROVIDER_ID
    from ti_recon.providers.misp_warninglists import qualification as misp_warninglists
    from ti_recon.providers.misp_warninglists.descriptor import MISP_WARNINGLISTS_PROVIDER_ID
    from ti_recon.providers.threatfox import qualification as threatfox
    from ti_recon.providers.threatfox.descriptor import THREATFOX_PROVIDER_ID
    from ti_recon.providers.urlhaus import qualification as urlhaus
    from ti_recon.providers.urlhaus.descriptor import URLHAUS_PROVIDER_ID
    from ti_recon.providers.urlscan import qualification as urlscan
    from ti_recon.providers.urlscan.descriptor import URLSCAN_PROVIDER_ID

    return {
        CENSYS_PROVIDER_ID: censys.qualify,
        GREYNOISE_PROVIDER_ID: greynoise.qualify,
        GTI_PROVIDER_ID: gti.qualify,
        HYBRID_ANALYSIS_PROVIDER_ID: hybrid_analysis.qualify,
        MALWAREBAZAAR_PROVIDER_ID: malwarebazaar.qualify,
        MISP_WARNINGLISTS_PROVIDER_ID: misp_warninglists.qualify,
        THREATFOX_PROVIDER_ID: threatfox.qualify,
        URLHAUS_PROVIDER_ID: urlhaus.qualify,
        URLSCAN_PROVIDER_ID: urlscan.qualify,
    }


def qualified_provider_ids() -> tuple[str, ...]:
    """Provider ids with an extractor, sorted."""
    return tuple(sorted(default_qualifiers()))
