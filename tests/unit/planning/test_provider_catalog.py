"""The shipped catalogue, as the planner sees it (Task 13).

The other planning suites use fake providers on purpose. This one is the opposite
check: that the nine real integrations describe themselves coherently enough for
a provider-neutral planner to schedule them, and that adding a tenth cannot leave
it silently unplannable.

No network. The registry is built from real adapters, the one credential-free
provider reads its shipped snapshot from disk, and Hybrid Analysis runs behind a
fake client — the repository's non-loopback guard is active throughout.
"""

from __future__ import annotations

import ast
import importlib
import pkgutil
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

from fixtures.hybrid_analysis import payloads
from fixtures.hybrid_analysis.fake_client import ClientFactory, FakeHybridAnalysisClient
from fixtures.planning import fake_outcome
from ti_recon.credentials import (
    AuthType,
    CredentialManager,
    CredentialResolver,
    CredentialStatus,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.enums import (
    ActivityMode,
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
    ProviderCapability,
    ProviderOperation,
)
from ti_recon.execution import (
    ConcurrencyLimiter,
    ExecutionContext,
    FixedJitter,
    InMemoryCooldownStore,
    InMemoryExecutionMetricsSink,
    InMemoryProviderCache,
    InMemoryQuotaStore,
    ManualClock,
    ProviderExecutor,
    ProviderPolicyRegistry,
    RecordingSleeper,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.planning import (
    AdaptiveEnrichmentOrchestrator,
    AdaptiveEnrichmentPlanner,
    CallCostClass,
    EnrichmentPlanningRequest,
    PlanningConstraints,
    ProviderLocality,
    ProviderPlanningProfile,
    StopReason,
)
from ti_recon.planning.catalog import PLANNING_PROFILE_BUILDERS, build_default_planning_registry
from ti_recon.providers.abusech import ABUSE_CH_SOURCE_FAMILY
from ti_recon.providers.censys import CensysAdapter
from ti_recon.providers.descriptor import ProviderDescriptor
from ti_recon.providers.greynoise import GreyNoiseAdapter
from ti_recon.providers.gti import GTIAdapter
from ti_recon.providers.hybrid_analysis import (
    HYBRID_ANALYSIS_PROVIDER_ID,
    HybridAnalysisAdapter,
    build_hybrid_analysis_execution_policy,
)
from ti_recon.providers.malwarebazaar import MalwareBazaarAdapter
from ti_recon.providers.misp_warninglists import (
    MISP_WARNINGLISTS_PROVIDER_ID,
    MispWarningListsAdapter,
    build_misp_warninglists_execution_policy,
)
from ti_recon.providers.registry import ProviderRegistry
from ti_recon.providers.threatfox import ThreatFoxAdapter
from ti_recon.providers.urlhaus import UrlhausAdapter
from ti_recon.providers.urlscan import UrlscanAdapter

PLANNING_PACKAGE = Path("src/ti_recon/planning")

#: The one module allowed to name a provider.
CATALOGUE_MODULE = "catalog.py"


@lru_cache(maxsize=1)
def real_descriptors() -> tuple[ProviderDescriptor, ...]:
    """Descriptors of every shipped provider, discovered rather than listed.

    Discovery matters: a tenth provider added with no planning profile has to
    fail this suite rather than quietly never being chosen.
    """
    import ti_recon.providers as providers_package

    found: list[ProviderDescriptor] = []
    for module in pkgutil.iter_modules(providers_package.__path__):
        if not module.ispkg:
            continue
        try:
            descriptor_module = importlib.import_module(
                f"ti_recon.providers.{module.name}.descriptor"
            )
        except ModuleNotFoundError:
            # A shared support package (abusech) has no descriptor of its own.
            continue
        for name in dir(descriptor_module):
            if name.startswith("build_") and name.endswith("_descriptor"):
                found.append(getattr(descriptor_module, name)())
    return tuple(found)


@lru_cache(maxsize=1)
def profiles_by_id() -> dict[str, ProviderPlanningProfile]:
    return {profile.provider_id: profile for profile in build_default_planning_registry().all()}


@lru_cache(maxsize=1)
def real_registry() -> ProviderRegistry:
    """Every shipped adapter, constructed without credentials."""
    return ProviderRegistry(
        [
            CensysAdapter(),
            GTIAdapter(),
            GreyNoiseAdapter(),
            HybridAnalysisAdapter(),
            MalwareBazaarAdapter(),
            MispWarningListsAdapter(),
            ThreatFoxAdapter(),
            UrlhausAdapter(),
            UrlscanAdapter(),
        ]
    )


def real_planner() -> AdaptiveEnrichmentPlanner:
    return AdaptiveEnrichmentPlanner(
        registry=real_registry(), profiles=build_default_planning_registry()
    )


def file_object(digest: str = payloads.SAMPLE_SHA256) -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=digest,
        display_value=digest,
        properties={"hashes": {"SHA-256": digest}},
    )


def plan_names(
    request: EnrichmentPlanningRequest, *, limit: int = 20
) -> tuple[list[str], StopReason]:
    """Provider/capability pairs a plan would choose, with every call succeeding."""
    plan = real_planner()
    state = plan.initial_state(request)
    chosen: list[str] = []
    stop = StopReason.NO_ELIGIBLE_PROVIDER
    for _ in range(limit):
        decision = plan.next(request, state)
        if decision.stop is not None:
            stop = decision.stop
            break
        call = decision.call
        assert call is not None
        chosen.append(f"{call.provider_id}:{call.capability.value}")
        state.observe(call, fake_outcome(call.provider_id, source_family=call.source_family))
    return chosen, stop


# --------------------------------------------------------------------------- #
# The catalogue agrees with the descriptors
# --------------------------------------------------------------------------- #


def test_every_shipped_provider_has_a_planning_profile() -> None:
    """A provider with no profile is usable directly but never chosen.

    That is a legitimate state, so this asserts the *current* set rather than
    forbidding the gap — but it fails when a provider is added, which is the
    moment somebody has to decide whether default enrichment should use it.
    """
    described = {descriptor.provider_id for descriptor in real_descriptors()}
    planned = set(profiles_by_id())
    assert described == planned, f"providers without a planning profile: {described - planned}"


def test_the_catalogue_has_one_builder_per_provider() -> None:
    assert len(PLANNING_PROFILE_BUILDERS) == len(profiles_by_id())


@pytest.mark.parametrize("descriptor", real_descriptors(), ids=lambda d: d.provider_id)
def test_a_profile_agrees_with_its_descriptor(descriptor: ProviderDescriptor) -> None:
    """The profile adds planning facts; it never restates or contradicts the
    descriptor's own declarations."""
    profile = profiles_by_id()[descriptor.provider_id]
    assert profile.source_family == descriptor.source_family
    assert profile.planning_capabilities <= descriptor.capabilities
    assert profile.elevated_cost_capabilities <= profile.planning_capabilities
    assert descriptor.supports_passive
    assert not descriptor.supports_active


@pytest.mark.parametrize("descriptor", real_descriptors(), ids=lambda d: d.provider_id)
def test_locality_matches_whether_a_provider_leaves_the_machine(
    descriptor: ProviderDescriptor,
) -> None:
    """A LOCAL provider must genuinely be local.

    The converse is deliberately not asserted: a credential-free provider may
    still be remote, and reading "no API key" as "discloses nothing" is the
    mistake this field exists to prevent.
    """
    profile = profiles_by_id()[descriptor.provider_id]
    if profile.locality is ProviderLocality.LOCAL:
        assert not descriptor.requires_credentials
        assert profile.cost_class is CallCostClass.ZERO


def test_the_only_local_provider_is_the_local_dataset() -> None:
    local = {
        profile.provider_id
        for profile in profiles_by_id().values()
        if profile.locality is ProviderLocality.LOCAL
    }
    assert local == {MISP_WARNINGLISTS_PROVIDER_ID}


def test_the_abusech_platforms_are_one_source_family() -> None:
    """Three datasets, one organization. Two of them agreeing is one source."""
    trio = {"threatfox", "urlhaus", "malwarebazaar"}
    families = {profiles_by_id()[name].source_family for name in trio}
    assert families == {ABUSE_CH_SOURCE_FAMILY}


def test_the_sandbox_is_high_cost_and_not_a_shallow_default() -> None:
    profile = profiles_by_id()[HYBRID_ANALYSIS_PROVIDER_ID]
    assert profile.cost_class is CallCostClass.HIGH
    assert profile.minimum_depth is InvestigationDepth.STANDARD


@pytest.mark.parametrize("descriptor", real_descriptors(), ids=lambda d: d.provider_id)
def test_every_profile_declares_how_its_response_is_shaped(
    descriptor: ProviderDescriptor,
) -> None:
    """Capability invariance decides whether asking again is incremental work or a
    duplicate request, so it must be a deliberate declaration per provider.

    A provider whose response is shaped by the request is exactly a provider whose
    adapter reads ``requested_capabilities``; today that is GTI (its relationship
    plan is filtered by the set, and the behaviour summary is fetched only when
    FILE_BEHAVIOR is in it) and urlscan (page artifacts only on WEB_FORENSICS).
    Everything else performs one read and normalizes whatever came back.
    """
    profile = profiles_by_id()[descriptor.provider_id]
    request_shaped = {"gti", "urlscan"}
    assert profile.capability_invariant_response is (descriptor.provider_id not in request_shaped)


def test_an_elevated_capability_is_never_bundleable() -> None:
    """The two rules are linked on purpose: an expensive capability must win a
    decision of its own, or a bundle becomes a way to spend the high-cost budget
    nobody decided to spend."""
    for profile in profiles_by_id().values():
        for capability in profile.elevated_cost_capabilities:
            assert not profile.bundleable(capability), profile.provider_id


def test_a_capability_invariant_provider_credits_only_what_it_supports() -> None:
    """MalwareBazaar answers files; being asked about one must not credit coverage
    for capabilities it only offers elsewhere."""
    profile = profiles_by_id()["malwarebazaar"]
    answered = profile.answered_by_one_response(
        frozenset({ProviderCapability.REPUTATION}),
        supported=frozenset({ProviderCapability.REPUTATION}),
    )
    assert answered == frozenset({ProviderCapability.REPUTATION})


def test_a_request_shaped_provider_credits_only_what_was_asked() -> None:
    profile = profiles_by_id()["gti"]
    answered = profile.answered_by_one_response(
        frozenset({ProviderCapability.REPUTATION}),
        supported=frozenset(ProviderCapability),
    )
    assert answered == frozenset({ProviderCapability.REPUTATION})


def test_a_provider_cheap_for_summaries_and_expensive_for_content_says_so() -> None:
    """One cost class per provider cannot describe urlscan or GTI honestly."""
    assert (
        profiles_by_id()["urlscan"].cost_for(ProviderCapability.WEB_FORENSICS) is CallCostClass.HIGH
    )
    assert profiles_by_id()["urlscan"].cost_for(ProviderCapability.REPUTATION) is (
        CallCostClass.MEDIUM
    )
    assert profiles_by_id()["gti"].cost_for(ProviderCapability.FILE_BEHAVIOR) is CallCostClass.HIGH


# --------------------------------------------------------------------------- #
# Planning over the real catalogue
# --------------------------------------------------------------------------- #


def test_the_local_dataset_is_consulted_first_at_every_depth() -> None:
    """Free, discloses nothing, and can explain everything after it."""
    for depth in InvestigationDepth:
        chosen, _ = plan_names(EnrichmentPlanningRequest(intel_object=file_object(), depth=depth))
        assert chosen[0].startswith(MISP_WARNINGLISTS_PROVIDER_ID), (depth, chosen)


def test_a_quick_file_lookup_never_reaches_the_sandbox() -> None:
    chosen, _ = plan_names(
        EnrichmentPlanningRequest(intel_object=file_object(), depth=InvestigationDepth.QUICK)
    )
    assert not any(name.startswith(HYBRID_ANALYSIS_PROVIDER_ID) for name in chosen)


def test_a_deep_file_lookup_reaches_a_behaviour_source() -> None:
    """At DEEP, what the sample did is part of the question.

    Which source answers is not fixed: GTI also declares file behaviour and
    outranks the dedicated sandbox on priority, so the assertion is about the
    *capability* being planned — exactly the substitution a capability-driven
    planner exists to allow.
    """
    chosen, _ = plan_names(
        EnrichmentPlanningRequest(intel_object=file_object(), depth=InvestigationDepth.DEEP)
    )
    assert any(name.endswith(":file_behavior") for name in chosen), chosen


def test_the_sandbox_is_planned_at_deep_when_the_other_behaviour_source_is_unavailable() -> None:
    """A provider being denied moves the plan to another source rather than
    dropping the capability."""
    chosen, _ = plan_names(
        EnrichmentPlanningRequest(
            intel_object=file_object(),
            depth=InvestigationDepth.DEEP,
            constraints=PlanningConstraints(provider_denylist=frozenset({"gti"})),
        )
    )
    assert f"{HYBRID_ANALYSIS_PROVIDER_ID}:file_behavior" in chosen, chosen


def test_the_sandbox_stays_out_of_a_quick_lookup_even_with_no_alternative() -> None:
    chosen, _ = plan_names(
        EnrichmentPlanningRequest(
            intel_object=file_object(),
            depth=InvestigationDepth.QUICK,
            constraints=PlanningConstraints(provider_denylist=frozenset({"gti"})),
        )
    )
    assert not any(name.startswith(HYBRID_ANALYSIS_PROVIDER_ID) for name in chosen)


def test_an_explicit_behaviour_request_reaches_the_sandbox_first() -> None:
    plan = real_planner()
    request = EnrichmentPlanningRequest(
        intel_object=file_object(),
        depth=InvestigationDepth.STANDARD,
        requested_capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
    )
    decision = plan.next(request, plan.initial_state(request))
    assert decision.call is not None
    assert decision.call.capability is ProviderCapability.FILE_BEHAVIOR
    assert decision.call.provider_id in {HYBRID_ANALYSIS_PROVIDER_ID, "gti"}


def test_two_abusech_platforms_do_not_satisfy_a_two_family_reputation_target() -> None:
    """The invariant the shared source family exists to protect."""
    plan = real_planner()
    request = EnrichmentPlanningRequest(
        intel_object=file_object(),
        depth=InvestigationDepth.STANDARD,
        constraints=PlanningConstraints(
            provider_allowlist=frozenset({"threatfox", "urlhaus", "malwarebazaar"})
        ),
    )
    state = plan.initial_state(request)
    for _ in range(6):
        decision = plan.next(request, state)
        if decision.stop is not None:
            break
        call = decision.call
        assert call is not None
        state.observe(call, fake_outcome(call.provider_id, source_family=call.source_family))
    assert state.covered_families[ProviderCapability.REPUTATION] == {ABUSE_CH_SOURCE_FAMILY}
    goal = next(goal for goal in state.goals if goal.capability is ProviderCapability.REPUTATION)
    assert not state.satisfied(goal, 2)


def test_an_ipv4_only_provider_is_not_planned_for_ipv6() -> None:
    chosen, _ = plan_names(
        EnrichmentPlanningRequest(
            intel_object=normalize_observable("2001:db8::1").intel_object,
            depth=InvestigationDepth.DEEP,
        )
    )
    assert not any(name.startswith("greynoise") for name in chosen)


def test_a_bare_domain_is_not_planned_for_the_web_property_provider() -> None:
    """Censys names a web property by hostname *and port*; a bare domain names no
    port, so its descriptor does not claim the observable."""
    chosen, _ = plan_names(
        EnrichmentPlanningRequest(
            intel_object=normalize_observable("example.com").intel_object,
            depth=InvestigationDepth.DEEP,
        )
    )
    assert not any(name.startswith("censys") for name in chosen)


def test_web_forensics_is_never_bought_unasked_at_standard_depth() -> None:
    chosen, _ = plan_names(
        EnrichmentPlanningRequest(
            intel_object=normalize_observable("https://example.com/a").intel_object,
            depth=InvestigationDepth.STANDARD,
        )
    )
    assert not any(name.endswith("web_forensics") for name in chosen)


def test_web_forensics_is_reachable_when_requested() -> None:
    chosen, _ = plan_names(
        EnrichmentPlanningRequest(
            intel_object=normalize_observable("https://example.com/a").intel_object,
            depth=InvestigationDepth.STANDARD,
            requested_capabilities=frozenset({ProviderCapability.WEB_FORENSICS}),
        )
    )
    assert "urlscan:web_forensics" in chosen


# --------------------------------------------------------------------------- #
# End to end, through the execution layer
# --------------------------------------------------------------------------- #


class Stack:
    """Planner, executor and real adapters, with a fake sandbox client."""

    def __init__(self) -> None:
        self.clock = ManualClock()
        self.secrets = InMemorySecretStore()
        self.connections = InMemoryConnectionRepository()
        self.manager = CredentialManager(self.secrets, self.connections)
        self.sandbox_client = FakeHybridAnalysisClient()
        self.registry = ProviderRegistry(
            [
                MispWarningListsAdapter(),
                HybridAnalysisAdapter(client_factory=ClientFactory(self.sandbox_client)),  # type: ignore[arg-type]
            ]
        )
        self.metrics = InMemoryExecutionMetricsSink()
        self.executor = ProviderExecutor(
            credential_resolver=CredentialResolver(self.secrets, self.connections),
            cache=InMemoryProviderCache(clock=self.clock),
            quota_store=InMemoryQuotaStore(clock=self.clock),
            cooldown_store=InMemoryCooldownStore(clock=self.clock),
            limiter=ConcurrencyLimiter(max_concurrency=4),
            policies=ProviderPolicyRegistry(
                policies=[
                    build_misp_warninglists_execution_policy(),
                    build_hybrid_analysis_execution_policy(),
                ]
            ),
            metrics=self.metrics,
            clock=self.clock,
            sleeper=RecordingSleeper(self.clock),
            jitter=FixedJitter(0.0),
        )
        self.orchestrator = AdaptiveEnrichmentOrchestrator(
            planner=AdaptiveEnrichmentPlanner(
                registry=self.registry, profiles=build_default_planning_registry()
            ),
            executor=self.executor,
            registry=self.registry,
        )

    async def add_sandbox_credential(self, user_id: str) -> None:
        await self.manager.create_connection(
            user_id=user_id,
            provider_id=HYBRID_ANALYSIS_PROVIDER_ID,
            secret="ha-key-SHOULD-NOT-LEAK",
            auth_type=AuthType.API_KEY,
            status=CredentialStatus.ACTIVE,
        )

    def context(self, user_id: str = "analyst-a") -> ExecutionContext:
        return ExecutionContext(authenticated_user_id=user_id, request_id="req-1")


async def test_the_local_dataset_runs_with_no_credential_and_no_remote_budget() -> None:
    """The shipped snapshot, read from disk, through the real executor."""
    stack = Stack()
    result = await stack.orchestrator.run(
        EnrichmentPlanningRequest(
            intel_object=normalize_observable("8.8.8.8").intel_object,
            depth=InvestigationDepth.STANDARD,
        ),
        stack.context(),
        investigation_id="inv-1",
    )
    local = [
        attempt
        for attempt in result.attempts
        if attempt.provider_id == MISP_WARNINGLISTS_PROVIDER_ID
    ]
    assert len(local) == 1
    assert local[0].called_provider is True
    assert local[0].coverage_gained is True
    assert result.budget.remote_runs_used == 0
    assert result.budget.high_cost_runs_used == 0


async def test_the_sandbox_runs_through_the_executor_when_requested() -> None:
    stack = Stack()
    await stack.add_sandbox_credential("analyst-a")
    result = await stack.orchestrator.run(
        EnrichmentPlanningRequest(
            intel_object=file_object(),
            depth=InvestigationDepth.STANDARD,
            requested_capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
        ),
        stack.context(),
        investigation_id="inv-1",
    )
    sandbox = [
        attempt for attempt in result.attempts if attempt.provider_id == HYBRID_ANALYSIS_PROVIDER_ID
    ]
    assert len(sandbox) == 1
    assert sandbox[0].called_provider is True
    assert result.budget.remote_runs_used == 1
    assert result.budget.high_cost_runs_used == 1
    assert stack.sandbox_client.call_count("search_hash") == 1
    # Every provider call went through Task 6, which is what recorded them.
    assert len(stack.metrics.executions) == len(result.attempts)


async def test_a_missing_credential_costs_that_provider_and_nothing_else() -> None:
    """No credential is configured for the sandbox here."""
    stack = Stack()
    result = await stack.orchestrator.run(
        EnrichmentPlanningRequest(
            intel_object=file_object(),
            depth=InvestigationDepth.DEEP,
        ),
        stack.context(),
        investigation_id="inv-1",
    )
    sandbox = [
        attempt for attempt in result.attempts if attempt.provider_id == HYBRID_ANALYSIS_PROVIDER_ID
    ]
    assert sandbox and all(attempt.called_provider is False for attempt in sandbox)
    assert stack.sandbox_client.request_count == 0
    assert result.budget.remote_runs_used == 0
    assert any(attempt.provider_id == MISP_WARNINGLISTS_PROVIDER_ID for attempt in result.attempts)


async def test_a_run_produces_no_verdict_and_no_score() -> None:
    """Task 13 schedules and reports coverage. Fusion is a later task."""
    stack = Stack()
    result = await stack.orchestrator.run(
        EnrichmentPlanningRequest(intel_object=file_object()),
        stack.context(),
        investigation_id="inv-1",
    )

    def keys(value: Any) -> set[str]:
        if isinstance(value, dict):
            found = set(value)
            for item in value.values():
                found |= keys(item)
            return found
        if isinstance(value, (list, tuple)):
            return {name for item in value for name in keys(item)}
        return set()

    every_key = keys(result.model_dump())
    assert every_key
    for forbidden in ("verdict", "risk", "score", "confidence", "reliability", "severity"):
        assert not [name for name in every_key if forbidden in name], forbidden
    # What it does carry: what was asked, what happened, and what is still
    # uncovered.
    assert result.has_uncovered_required_capability in {True, False}
    assert result.coverage


# --------------------------------------------------------------------------- #
# Structural guards
# --------------------------------------------------------------------------- #


@lru_cache(maxsize=1)
def provider_packages() -> frozenset[str]:
    """Directory names of the concrete provider packages."""
    import ti_recon.providers as providers_package

    return frozenset(
        module.name for module in pkgutil.iter_modules(providers_package.__path__) if module.ispkg
    )


def planning_modules() -> list[Path]:
    return sorted(path for path in PLANNING_PACKAGE.glob("*.py"))


def string_constants(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


def test_no_planning_module_but_the_catalogue_names_a_provider() -> None:
    """The provider-neutrality invariant, checked on the AST.

    Docstrings are excluded by construction — only string *constants* used as
    values are compared, and every name is compared whole, so a module may
    discuss providers in prose while never encoding one in behaviour.
    """
    names = {descriptor.provider_id for descriptor in real_descriptors()}
    names |= {descriptor.source_family for descriptor in real_descriptors()}
    offenders: list[str] = []
    for path in planning_modules():
        if path.name == CATALOGUE_MODULE:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = {
            node.value.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        }
        for value in string_constants(path):
            if value in docstrings:
                continue
            if value in names:
                offenders.append(f"{path.name}: {value}")
    assert offenders == []


def test_no_planning_module_imports_a_provider_package_except_the_catalogue() -> None:
    """The framework modules — adapter, registry, request — are fair game; a
    concrete integration is not."""
    offenders: list[str] = []
    for path in planning_modules():
        if path.name == CATALOGUE_MODULE:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module = ""
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
            elif isinstance(node, ast.Import):
                module = node.names[0].name
            if module.startswith("ti_recon.providers."):
                second = module.split(".")[2]
                if second in provider_packages():
                    offenders.append(f"{path.name}: {module}")
    assert offenders == []


def test_the_planner_imports_no_secret_material_and_no_http_client() -> None:
    """Planning decides *what to ask*. Credentials and transport belong to the
    layers below it, and a planning trace can only leak a secret it can reach."""
    forbidden_modules = ("httpx", "ti_recon.credentials", "ti_recon.providers.http")
    forbidden_names = ("SecretStr", "InMemorySecretStore", "CredentialResolver")
    offenders: list[str] = []
    for path in planning_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if any(
                    module == item or module.startswith(f"{item}.") for item in forbidden_modules
                ):
                    offenders.append(f"{path.name}: {module}")
                offenders.extend(
                    f"{path.name}: {alias.name}"
                    for alias in node.names
                    if alias.name in forbidden_names
                )
            elif isinstance(node, ast.Import):
                offenders.extend(
                    f"{path.name}: {alias.name}"
                    for alias in node.names
                    if alias.name in forbidden_modules
                )
    assert offenders == []


def test_no_planning_module_can_name_an_active_operation() -> None:
    """The structural half of "an automatic plan cannot submit anything".

    Every ``ProviderOperation`` and ``ActivityMode`` attribute mentioned anywhere
    under ``planning/`` must be the passive one. A future edit that reached for a
    submission would have to write the name, and the name is what this reads.
    """
    allowed = {
        "ProviderOperation": {ProviderOperation.LOOKUP.name},
        "ActivityMode": {ActivityMode.PASSIVE.name},
    }
    offenders: list[str] = []
    for path in planning_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id in allowed
                and node.attr not in allowed[node.value.id]
            ):
                offenders.append(f"{path.name}: {node.value.id}.{node.attr}")
    assert offenders == []


def test_no_planning_module_calls_an_adapter_client_or_sleeps() -> None:
    """Task 6 owns transport, retry and waiting. A planner that slept would be
    retrying without saying so."""
    # Deliberately narrow: ``get`` is a mapping read here, and forbidding it
    # would make the guard about Python rather than about layering.
    forbidden_calls = {
        "sleep",
        "post",
        "put",
        "delete",
        "patch",
        "lookup",
        "validate_credentials",
        "resolve",
    }
    offenders: list[str] = []
    for path in planning_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                target: Any = node.func
                name = target.attr if isinstance(target, ast.Attribute) else None
                if name in forbidden_calls:
                    offenders.append(f"{path.name}: {name}")
    assert offenders == []
