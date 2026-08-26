"""Enrichment policy: budgets, goal templates and the profile registry (Task 13).

Every number here is a **TI Recon policy default**, configurable, and makes no
claim about any provider's real limits. Provider limits are the providers'
business and are enforced inside them.

Why budgets at all
------------------

Without one, "enrich this" means "call everything configured", which gets more
expensive every time a provider is added and produces its worst results exactly
when it matters: during an incident, on a shared allowance, with an analyst
waiting. The budget makes the cost of an investigation a property of its depth
rather than of the catalogue's size.

Goal templates
--------------

Goals are declared per observable family, in terms of capabilities that exist in
the Task 3 vocabulary. No template names a provider, and the planner discards any
goal the registry cannot serve — a goal nobody can satisfy is a permanent
coverage gap reported as though somebody had failed.
"""

from __future__ import annotations

from typing import Final

from pydantic import Field

from ti_recon.enums import (
    CoverageRelevance,
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
)
from ti_recon.models.base import FrozenTiReconModel
from ti_recon.planning.goals import CapabilityGoal, GoalActivation
from ti_recon.planning.models import EnrichmentBudget, ProviderPlanningProfile

__all__ = [
    "DEFAULT_BUDGETS",
    "DEFAULT_GOAL_TEMPLATES",
    "EnrichmentPolicy",
    "ProviderPlanningRegistry",
    "UnknownProviderError",
]

#: Remote-run and high-cost allowances per depth.
#:
#: QUICK buys one good answer plus free context. STANDARD buys SOC-grade
#: enrichment — a couple of independent sources and one specialization. DEEP
#: broadens semantic coverage without becoming "call everything": six runs is
#: enough for two independent families on the primary capability plus several
#: distinct capabilities, and stops well short of the catalogue.
DEFAULT_BUDGETS: Final[dict[InvestigationDepth, tuple[int, int]]] = {
    InvestigationDepth.QUICK: (2, 0),
    InvestigationDepth.STANDARD: (4, 1),
    InvestigationDepth.DEEP: (6, 2),
}


def _reputation(minimum_families: int = 2) -> CapabilityGoal:
    """The primary directional goal for every observable family.

    ``REQUIRED`` because an enrichment that learned nothing about whether anyone
    has seen this observable has not enriched anything, however much context it
    collected.
    """
    return CapabilityGoal(
        capability=ProviderCapability.REPUTATION,
        relevance=CoverageRelevance.REQUIRED,
        minimum_source_families=minimum_families,
        activation=GoalActivation.IMMEDIATE,
    )


def _false_positive_context() -> CapabilityGoal:
    """Cheap, complementary, and never a substitute.

    ``OPTIONAL`` and one family. It runs early because it costs nothing, and
    satisfying it can never satisfy a threat-intelligence goal — a warninglist
    match explains evidence, it does not replace it.
    """
    return CapabilityGoal(
        capability=ProviderCapability.FALSE_POSITIVE_CONTEXT,
        relevance=CoverageRelevance.OPTIONAL,
        minimum_source_families=1,
        activation=GoalActivation.IMMEDIATE,
    )


#: Goal templates per observable family, per depth.
#:
#: Read as: at this depth, for this kind of observable, these are the things
#: worth knowing. Capabilities only — the planner resolves them to providers.
DEFAULT_GOAL_TEMPLATES: Final[
    dict[IntelObjectType, dict[InvestigationDepth, tuple[CapabilityGoal, ...]]]
] = {
    IntelObjectType.FILE: {
        InvestigationDepth.QUICK: (_false_positive_context(), _reputation(1)),
        InvestigationDepth.STANDARD: (
            _false_positive_context(),
            _reputation(2),
            CapabilityGoal(
                capability=ProviderCapability.MALWARE_INTELLIGENCE,
                relevance=CoverageRelevance.RELEVANT,
            ),
            # Conditional at STANDARD: worth the cost when there is directional
            # evidence to explain or a baseline that found nothing, and not
            # otherwise.
            CapabilityGoal(
                capability=ProviderCapability.FILE_BEHAVIOR,
                relevance=CoverageRelevance.OPTIONAL,
                activation=GoalActivation.AFTER_BASELINE,
                minimum_depth=InvestigationDepth.STANDARD,
                requires_trigger=True,
            ),
        ),
        InvestigationDepth.DEEP: (
            _false_positive_context(),
            _reputation(2),
            CapabilityGoal(
                capability=ProviderCapability.MALWARE_INTELLIGENCE,
                relevance=CoverageRelevance.RELEVANT,
            ),
            # Expected at DEEP rather than conditional: what a sample did when
            # run is exactly what a deep file investigation is for.
            CapabilityGoal(
                capability=ProviderCapability.FILE_BEHAVIOR,
                relevance=CoverageRelevance.RELEVANT,
                activation=GoalActivation.AFTER_BASELINE,
                minimum_depth=InvestigationDepth.STANDARD,
            ),
            CapabilityGoal(
                capability=ProviderCapability.THREAT_ASSOCIATIONS,
                relevance=CoverageRelevance.OPTIONAL,
                activation=GoalActivation.AFTER_BASELINE,
            ),
        ),
    },
    IntelObjectType.URL: {
        InvestigationDepth.QUICK: (_false_positive_context(), _reputation(1)),
        InvestigationDepth.STANDARD: (
            _false_positive_context(),
            _reputation(2),
            CapabilityGoal(
                capability=ProviderCapability.WEB_BEHAVIOR,
                relevance=CoverageRelevance.RELEVANT,
                activation=GoalActivation.AFTER_BASELINE,
            ),
            # Retrieving and analysing stored page content is expensive and
            # entitlement-sensitive; nobody should pay for it unasked.
            CapabilityGoal(
                capability=ProviderCapability.WEB_FORENSICS,
                relevance=CoverageRelevance.OPTIONAL,
                activation=GoalActivation.EXPLICIT_ONLY,
                minimum_depth=InvestigationDepth.STANDARD,
            ),
        ),
        InvestigationDepth.DEEP: (
            _false_positive_context(),
            _reputation(2),
            CapabilityGoal(
                capability=ProviderCapability.WEB_BEHAVIOR,
                relevance=CoverageRelevance.RELEVANT,
                activation=GoalActivation.AFTER_BASELINE,
            ),
            CapabilityGoal(
                capability=ProviderCapability.WEB_FORENSICS,
                relevance=CoverageRelevance.OPTIONAL,
                activation=GoalActivation.AFTER_BASELINE,
                minimum_depth=InvestigationDepth.DEEP,
                requires_trigger=True,
            ),
        ),
    },
    IntelObjectType.DOMAIN_NAME: {
        InvestigationDepth.QUICK: (_false_positive_context(), _reputation(1)),
        InvestigationDepth.STANDARD: (
            _false_positive_context(),
            _reputation(2),
            CapabilityGoal(
                capability=ProviderCapability.CURRENT_INFRASTRUCTURE,
                relevance=CoverageRelevance.RELEVANT,
                activation=GoalActivation.AFTER_BASELINE,
            ),
        ),
        InvestigationDepth.DEEP: (
            _false_positive_context(),
            _reputation(2),
            CapabilityGoal(
                capability=ProviderCapability.CURRENT_INFRASTRUCTURE,
                relevance=CoverageRelevance.RELEVANT,
                activation=GoalActivation.AFTER_BASELINE,
            ),
            CapabilityGoal(
                capability=ProviderCapability.HISTORICAL_INFRASTRUCTURE,
                relevance=CoverageRelevance.OPTIONAL,
                activation=GoalActivation.AFTER_BASELINE,
                minimum_depth=InvestigationDepth.DEEP,
            ),
        ),
    },
    IntelObjectType.IPV4_ADDR: {
        InvestigationDepth.QUICK: (
            _false_positive_context(),
            _reputation(1),
            # Cheap, and the single most common explanation for a noisy address.
            CapabilityGoal(
                capability=ProviderCapability.SCANNER_CONTEXT,
                relevance=CoverageRelevance.OPTIONAL,
            ),
        ),
        InvestigationDepth.STANDARD: (
            _false_positive_context(),
            _reputation(2),
            CapabilityGoal(
                capability=ProviderCapability.SCANNER_CONTEXT,
                relevance=CoverageRelevance.RELEVANT,
            ),
            CapabilityGoal(
                capability=ProviderCapability.NETWORK_OWNERSHIP,
                relevance=CoverageRelevance.RELEVANT,
                activation=GoalActivation.AFTER_BASELINE,
            ),
        ),
        InvestigationDepth.DEEP: (
            _false_positive_context(),
            _reputation(2),
            CapabilityGoal(
                capability=ProviderCapability.SCANNER_CONTEXT,
                relevance=CoverageRelevance.RELEVANT,
            ),
            CapabilityGoal(
                capability=ProviderCapability.NETWORK_OWNERSHIP,
                relevance=CoverageRelevance.RELEVANT,
                activation=GoalActivation.AFTER_BASELINE,
            ),
            CapabilityGoal(
                capability=ProviderCapability.CURRENT_INFRASTRUCTURE,
                relevance=CoverageRelevance.OPTIONAL,
                activation=GoalActivation.AFTER_BASELINE,
                minimum_depth=InvestigationDepth.DEEP,
            ),
        ),
    },
    # IPv6 is not a copy of IPv4: several providers do not support it, and the
    # goals reflect what is actually reachable rather than pretending otherwise.
    # No provider-specific condition is needed — an unsatisfiable goal is
    # dropped because no registered provider serves it.
    IntelObjectType.IPV6_ADDR: {
        InvestigationDepth.QUICK: (_false_positive_context(), _reputation(1)),
        InvestigationDepth.STANDARD: (
            _false_positive_context(),
            _reputation(2),
            CapabilityGoal(
                capability=ProviderCapability.NETWORK_OWNERSHIP,
                relevance=CoverageRelevance.RELEVANT,
                activation=GoalActivation.AFTER_BASELINE,
            ),
        ),
        InvestigationDepth.DEEP: (
            _false_positive_context(),
            _reputation(2),
            CapabilityGoal(
                capability=ProviderCapability.NETWORK_OWNERSHIP,
                relevance=CoverageRelevance.RELEVANT,
                activation=GoalActivation.AFTER_BASELINE,
            ),
            CapabilityGoal(
                capability=ProviderCapability.CURRENT_INFRASTRUCTURE,
                relevance=CoverageRelevance.OPTIONAL,
                activation=GoalActivation.AFTER_BASELINE,
                minimum_depth=InvestigationDepth.DEEP,
            ),
        ),
    },
}


class UnknownProviderError(ValueError):
    """A policy named a provider the registry does not have.

    Raised rather than ignored. A misspelled allowlist entry that silently did
    nothing would look like a working restriction and quietly permit everything
    the caller meant to exclude.
    """


class EnrichmentPolicy(FrozenTiReconModel):
    """Configurable planning defaults."""

    budgets: dict[InvestigationDepth, tuple[int, int]] = Field(
        default_factory=lambda: dict(DEFAULT_BUDGETS)
    )
    goal_templates: dict[IntelObjectType, dict[InvestigationDepth, tuple[CapabilityGoal, ...]]] = (
        Field(default_factory=lambda: dict(DEFAULT_GOAL_TEMPLATES))
    )

    def budget_for(
        self, depth: InvestigationDepth, *, override_remote: int | None = None
    ) -> EnrichmentBudget:
        """The budget for ``depth``, optionally reduced by the caller.

        An override may only *lower* the allowance. A caller asking for more than
        policy permits is asking policy to be different, which is a
        configuration change rather than a request parameter.
        """
        remote, high_cost = self.budgets.get(depth, DEFAULT_BUDGETS[InvestigationDepth.STANDARD])
        if override_remote is not None:
            remote = min(remote, override_remote)
            high_cost = min(high_cost, remote)
        return EnrichmentBudget(max_remote_provider_runs=remote, max_high_cost_runs=high_cost)

    def goals_for(
        self,
        object_type: IntelObjectType,
        depth: InvestigationDepth,
        *,
        requested: frozenset[ProviderCapability] = frozenset(),
    ) -> tuple[CapabilityGoal, ...]:
        """Goals for this observable at this depth, plus anything asked for.

        An explicitly requested capability becomes a ``REQUIRED`` goal even if no
        template mentions it, and replaces a template goal for the same
        capability: a caller naming it has said it matters more than the default
        judgement did.
        """
        template = self.goal_templates.get(object_type, {}).get(depth, ())
        goals = {goal.capability: goal for goal in template if goal.exists_at(depth)}
        for capability in sorted(requested, key=lambda item: item.value):
            goals[capability] = CapabilityGoal(
                capability=capability,
                relevance=CoverageRelevance.REQUIRED,
                minimum_source_families=1,
                activation=GoalActivation.IMMEDIATE,
            )
        return tuple(goals[key] for key in sorted(goals, key=lambda item: item.value))


class ProviderPlanningRegistry:
    """Planning profiles, addressed by provider id.

    Separate from :class:`~ti_recon.providers.registry.ProviderRegistry` because
    they answer different questions: that one knows which adapters exist and what
    they support, this one knows what asking them costs and whether asking
    discloses anything. A provider can be registered as an adapter without being
    plannable, which is how a provider gets integrated before anybody decides it
    should be chosen automatically.
    """

    def __init__(self, profiles: tuple[ProviderPlanningProfile, ...] = ()) -> None:
        self._profiles: dict[str, ProviderPlanningProfile] = {}
        for profile in profiles:
            self.register(profile)

    def register(self, profile: ProviderPlanningProfile) -> None:
        if profile.provider_id in self._profiles:
            msg = f"duplicate planning profile for {profile.provider_id!r}"
            raise ValueError(msg)
        self._profiles[profile.provider_id] = profile

    def get(self, provider_id: str) -> ProviderPlanningProfile | None:
        return self._profiles.get(provider_id)

    def require(self, provider_id: str) -> ProviderPlanningProfile:
        profile = self._profiles.get(provider_id)
        if profile is None:
            raise UnknownProviderError(f"no planning profile for {provider_id!r}")
        return profile

    def all(self) -> tuple[ProviderPlanningProfile, ...]:
        return tuple(self._profiles[key] for key in sorted(self._profiles))

    @property
    def provider_ids(self) -> frozenset[str]:
        return frozenset(self._profiles)

    def validate_names(self, names: frozenset[str]) -> None:
        """Refuse a policy that names a provider nobody registered."""
        unknown = sorted(names - self.provider_ids)
        if unknown:
            raise UnknownProviderError(f"unknown provider ids in planning policy: {unknown}")

    def __len__(self) -> int:
        return len(self._profiles)

    def __repr__(self) -> str:
        return f"<ProviderPlanningRegistry profiles={len(self._profiles)}>"
