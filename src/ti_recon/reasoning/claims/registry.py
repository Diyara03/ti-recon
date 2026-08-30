"""The composition root: which provider translates its own claims (Task 17A).

**The only module under ``reasoning/claims/`` and ``reasoning/fusion/`` allowed
to name a provider**, following the pattern Task 13's ``planning/catalog.py`` and
Task 15's ``reasoning/catalog.py`` already set. A test reads the AST of every
other module in both packages to keep it that way.

Imports are function-local for the same reason Task 15's catalog defers its own:
each provider's ``claim_semantics`` module imports the shared claim vocabulary,
so a module-level import here would close a cycle that resolves or fails
depending on which module a process happens to import first.

A provider with no translator is not an error
---------------------------------------------

Censys and MISP Warning Lists emit no directional evidence at all -- exposure is
not an accusation and a warninglist hit is context -- so they have nothing to
translate and appear here not at all. Any *other* provider without a translator
falls through to a conservative default that marks its directional claims
``UNCLASSIFIED_DIRECTIONAL``: retained, visible, and never decisive. A coverage
test then fails, so adding a provider forces an intentional decision rather than
silently downgrading its findings.
"""

from __future__ import annotations

from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.claims.models import (
    ClaimSemantic,
    NormalizedClaim,
    claim_from,
)
from ti_recon.reasoning.claims.translation import (
    ClaimTranslationContext,
    ClaimTranslator,
    directional_evidence,
)

__all__ = ["default_translators", "translate_envelope", "translated_provider_ids"]


def default_translators() -> dict[str, ClaimTranslator]:
    """Every shipped provider that makes a directional claim.

    Censys and MISP Warning Lists are absent because neither produces
    directional evidence: Task 9 makes every Censys record context, and Task 11
    makes every warninglist hit context. A translator for either would be a
    module that could never fire.
    """
    from ti_recon.providers.greynoise import claim_semantics as greynoise
    from ti_recon.providers.greynoise.descriptor import GREYNOISE_PROVIDER_ID
    from ti_recon.providers.gti import claim_semantics as gti
    from ti_recon.providers.gti.descriptor import GTI_PROVIDER_ID
    from ti_recon.providers.hybrid_analysis import claim_semantics as hybrid_analysis
    from ti_recon.providers.hybrid_analysis.descriptor import HYBRID_ANALYSIS_PROVIDER_ID
    from ti_recon.providers.malwarebazaar import claim_semantics as malwarebazaar
    from ti_recon.providers.malwarebazaar.descriptor import MALWAREBAZAAR_PROVIDER_ID
    from ti_recon.providers.threatfox import claim_semantics as threatfox
    from ti_recon.providers.threatfox.descriptor import THREATFOX_PROVIDER_ID
    from ti_recon.providers.urlhaus import claim_semantics as urlhaus
    from ti_recon.providers.urlhaus.descriptor import URLHAUS_PROVIDER_ID
    from ti_recon.providers.urlscan import claim_semantics as urlscan
    from ti_recon.providers.urlscan.descriptor import URLSCAN_PROVIDER_ID

    return {
        GREYNOISE_PROVIDER_ID: greynoise.translate,
        GTI_PROVIDER_ID: gti.translate,
        HYBRID_ANALYSIS_PROVIDER_ID: hybrid_analysis.translate,
        MALWAREBAZAAR_PROVIDER_ID: malwarebazaar.translate,
        THREATFOX_PROVIDER_ID: threatfox.translate,
        URLHAUS_PROVIDER_ID: urlhaus.translate,
        URLSCAN_PROVIDER_ID: urlscan.translate,
    }


def translated_provider_ids() -> tuple[str, ...]:
    return tuple(sorted(default_translators()))


def unclassified_translation(
    envelope: ProviderResultEnvelope, context: ClaimTranslationContext
) -> tuple[NormalizedClaim, ...]:
    """The conservative default for a provider with no translator.

    Every directional finding survives and is visible; none of them can be
    decisive, because nothing knows what they assert. Dropping them instead would
    hide a real claim, and guessing a semantic would be worse than either.
    """
    return tuple(
        claim_from(
            evidence,
            policy_version=context.policy_version,
            semantic=ClaimSemantic.UNCLASSIFIED_DIRECTIONAL,
            subject_key=context.subject_key_for(evidence.subject_object_id),
            source_partial=context.source_partial,
        )
        for evidence in directional_evidence(envelope)
    )


def translate_envelope(
    envelope: ProviderResultEnvelope,
    context: ClaimTranslationContext,
    translators: dict[str, ClaimTranslator] | None = None,
) -> tuple[NormalizedClaim, ...]:
    """Turn one provider result into claims, falling back conservatively."""
    registry = default_translators() if translators is None else translators
    translator = registry.get(envelope.provider)
    if translator is None:
        return unclassified_translation(envelope, context)
    return translator(envelope, context)
