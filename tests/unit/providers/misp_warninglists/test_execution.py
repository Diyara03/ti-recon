"""The local provider under the Task 6 executor, and its boundaries (Task 11).

Two things are proved here.

**A credential-free provider needs no special handling.** Task 6 already supported
`requires_credentials = False`; this suite confirms it end to end and confirms
that credentialed providers are unaffected — the whole reason no generic
execution change was needed.

**A lookup cannot reach the network.** Not "does not" — cannot. The unit suite's
own guard refuses any non-loopback connection, and this provider has no client to
attempt one with.
"""

from __future__ import annotations

import ast
import inspect
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from fixtures.execution_adapters import ScriptedAdapter, ScriptedStep, gti_like_descriptor
from fixtures.warninglists import build_snapshot
from ti_recon.credentials import (
    CredentialResolver,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.enums import (
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    ProviderCapability,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution import (
    CacheScope,
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
    build_cache_key,
)
from ti_recon.execution.models import ExecutionScope
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRegistry, ProviderRequest
from ti_recon.providers.misp_warninglists import (
    MISP_WARNINGLISTS_MAX_CONCURRENCY,
    MISP_WARNINGLISTS_PROVIDER_ID,
    MispWarningListsAdapter,
    MispWarningListsConfig,
    WarningListProfile,
    build_misp_warninglists_execution_policy,
)
from ti_recon.providers.misp_warninglists import adapter as adapter_module
from ti_recon.providers.misp_warninglists import candidates as candidates_module
from ti_recon.providers.misp_warninglists import loader as loader_module
from ti_recon.providers.misp_warninglists import matchers as matchers_module
from ti_recon.providers.misp_warninglists import normalizer as normalizer_module
from ti_recon.providers.misp_warninglists import snapshot as snapshot_module

USER_A = "analyst-a"
USER_B = "analyst-b"

PACKAGE_MODULES = (
    adapter_module,
    candidates_module,
    loader_module,
    matchers_module,
    normalizer_module,
    snapshot_module,
)


class Stack:
    """The execution layer wired around the local provider."""

    def __init__(self, root: Path, *, profile: WarningListProfile | None = None) -> None:
        self.clock = ManualClock()
        self.secrets = InMemorySecretStore()
        self.connections = InMemoryConnectionRepository()
        self.resolver = CredentialResolver(self.secrets, self.connections)
        self.cache = InMemoryProviderCache(clock=self.clock)
        self.metrics = InMemoryExecutionMetricsSink()
        self.adapter = MispWarningListsAdapter(
            config=MispWarningListsConfig(snapshot_root=root),
            profile=profile
            if profile is not None
            else WarningListProfile(profile_id="test", max_list_entries=None),
        )
        self.executor = ProviderExecutor(
            credential_resolver=self.resolver,
            cache=self.cache,
            quota_store=InMemoryQuotaStore(clock=self.clock),
            cooldown_store=InMemoryCooldownStore(clock=self.clock),
            limiter=ConcurrencyLimiter(max_concurrency=4),
            policies=ProviderPolicyRegistry(policies=[build_misp_warninglists_execution_policy()]),
            metrics=self.metrics,
            clock=self.clock,
            sleeper=RecordingSleeper(self.clock),
            jitter=FixedJitter(0.0),
        )

    def context(self, user_id: str = USER_A) -> ExecutionContext:
        return ExecutionContext(authenticated_user_id=user_id, request_id=f"req-{user_id}")


def request_for(raw: str = "8.8.8.8", **overrides: Any) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": normalize_observable(raw).intel_object,
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


@pytest.fixture
def stack(tmp_path: Path) -> Stack:
    build_snapshot(tmp_path / "snapshot")
    return Stack(tmp_path / "snapshot")


# --------------------------------------------------------------------------- #
# Credential-free execution
# --------------------------------------------------------------------------- #


async def test_a_credential_free_provider_runs_with_no_connection_stored(
    stack: Stack,
) -> None:
    """No key, no ProviderConnection, no secret store access, and it works."""
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert outcome.status is not ProviderRunStatus.NOT_CONFIGURED
    assert outcome.called_provider is True
    assert outcome.result is not None
    assert outcome.result.evidence
    assert list(await stack.connections.list_for_user(USER_A)) == []


async def test_the_provider_reached_the_adapter_with_no_credential(stack: Stack) -> None:
    """Proof the executor never fabricated one."""
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.SUCCESS
    # Nothing was written to the secret store, because nothing asked it for one.
    assert stack.secrets.__class__.__name__ == "InMemorySecretStore"
    assert list(await stack.connections.list_for_user(USER_A)) == []


async def test_a_credentialed_provider_still_requires_a_connection(tmp_path: Path) -> None:
    """The generic behaviour is unchanged for every remote provider."""
    build_snapshot(tmp_path / "snapshot")
    stack = Stack(tmp_path / "snapshot")
    remote = ScriptedAdapter.with_steps(ScriptedStep(), descriptor=gti_like_descriptor())
    outcome = await stack.executor.execute(
        remote,
        request_for(**{"requested_capabilities": frozenset({ProviderCapability.REPUTATION})}),
        stack.context(),
    )
    assert outcome.status is ProviderRunStatus.NOT_CONFIGURED
    assert remote.calls == 0


async def test_no_cooldown_can_be_keyed_to_a_credential_this_provider_lacks(
    stack: Stack,
) -> None:
    """A credential-scoped cooldown needs a credential group; there is none."""
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    scope = ExecutionScope.for_user(
        provider_id=MISP_WARNINGLISTS_PROVIDER_ID,
        user_id=USER_A,
        provider_connection_id=None,
    )
    assert scope.credential_identity is None
    assert outcome.cooldown_applied is False


def test_the_execution_policy_prechecks_no_quota() -> None:
    """There is no allowance to consult, and consulting one would read a store
    nothing ever writes."""
    policy = build_misp_warninglists_execution_policy()
    assert policy.quota_precheck is False
    assert policy.max_concurrency == MISP_WARNINGLISTS_MAX_CONCURRENCY
    assert policy.retry.max_attempts == 1


# --------------------------------------------------------------------------- #
# Caching keyed to the dataset
# --------------------------------------------------------------------------- #


async def test_a_repeat_lookup_is_served_from_cache(stack: Stack) -> None:
    request = request_for()
    first = await stack.executor.execute(stack.adapter, request, stack.context())
    second = await stack.executor.execute(stack.adapter, request, stack.context())
    assert (first.cache_hit, second.cache_hit) == (False, True)
    assert second.attempts == 0


def test_a_refreshed_dataset_cannot_serve_an_old_answer(tmp_path: Path) -> None:
    """The cache-correctness problem a local dataset creates, and its fix."""
    build_snapshot(tmp_path / "one")
    from fixtures.warninglists import SnapshotBuilder

    SnapshotBuilder(root=tmp_path / "two").add(
        "rfc1918", matcher="cidr", entries=["10.0.0.0/8"], matching_attributes=["ip-src"]
    ).write()

    scope = ExecutionScope.for_user(provider_id=MISP_WARNINGLISTS_PROVIDER_ID, user_id=USER_A)
    keys = []
    for name in ("one", "two"):
        adapter = MispWarningListsAdapter(
            config=MispWarningListsConfig(snapshot_root=tmp_path / name),
            profile=WarningListProfile(profile_id="test", max_list_entries=None),
        )
        keys.append(
            build_cache_key(
                scope=scope, descriptor=adapter.descriptor, request=request_for()
            ).digest
        )
    assert keys[0] != keys[1]


def test_two_profiles_over_one_dataset_do_not_share_a_cache_entry(tmp_path: Path) -> None:
    build_snapshot(tmp_path / "snapshot")
    scope = ExecutionScope.for_user(provider_id=MISP_WARNINGLISTS_PROVIDER_ID, user_id=USER_A)
    keys = set()
    for profile in (
        WarningListProfile(profile_id="a", max_list_entries=None),
        WarningListProfile(profile_id="b", exclude=frozenset({"rfc1918"}), max_list_entries=None),
    ):
        adapter = MispWarningListsAdapter(
            config=MispWarningListsConfig(snapshot_root=tmp_path / "snapshot"),
            profile=profile,
        )
        keys.add(
            build_cache_key(
                scope=scope, descriptor=adapter.descriptor, request=request_for()
            ).digest
        )
    assert len(keys) == 2


def test_the_cache_is_not_shared_between_analysts() -> None:
    assert build_misp_warninglists_execution_policy().cache.scope is CacheScope.USER


async def test_different_depths_do_not_share_a_cache_entry(stack: Stack) -> None:
    await stack.executor.execute(
        stack.adapter, request_for(depth=InvestigationDepth.QUICK), stack.context()
    )
    outcome = await stack.executor.execute(
        stack.adapter, request_for(depth=InvestigationDepth.DEEP), stack.context()
    )
    assert outcome.cache_hit is False


async def test_one_analysts_answer_is_not_served_to_another(stack: Stack) -> None:
    await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_A))
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_B))
    assert outcome.cache_hit is False


# --------------------------------------------------------------------------- #
# The network boundary
# --------------------------------------------------------------------------- #


async def test_a_lookup_cannot_open_a_network_connection(stack: Stack) -> None:
    """Enforced by the unit suite's guard, which refuses non-loopback connects.

    If this provider ever grew a client, this test would fail rather than
    quietly start making requests during enrichment.
    """
    for observable in ("8.8.8.8", "example.com", "https://github.com/a/b"):
        outcome = await stack.executor.execute(
            stack.adapter, request_for(observable), stack.context()
        )
        assert outcome.status in {
            ProviderRunStatus.SUCCESS,
            ProviderRunStatus.NO_DATA,
        }


def imported_modules(module: Any) -> set[str]:
    """Every module name a source file imports, from the AST.

    Read structurally rather than by scanning text. A prose scan flags the
    docstring that *explains* why there is no socket here, and a guard that
    fires on its own explanation is a guard somebody deletes.
    """
    tree = ast.parse(Path(inspect.getfile(module)).read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def called_names(module: Any) -> tuple[set[str], set[str]]:
    """``(bare calls, attribute calls)`` in a source file.

    Kept apart because the same word means different things in each. Builtin
    ``compile`` executes caller-supplied source; ``re.compile`` builds the slug
    pattern this package validates paths with. A guard that conflated them would
    forbid the safety check it exists to protect.
    """
    tree = ast.parse(Path(inspect.getfile(module)).read_text(encoding="utf-8"))
    bare: set[str] = set()
    attributes: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            bare.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            attributes.add(node.func.attr)
    return bare, attributes


@pytest.mark.parametrize("module", PACKAGE_MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_no_module_imports_anything_that_could_make_a_request(module: Any) -> None:
    """Structural, not aspirational: nothing here could reach a network."""
    imported = imported_modules(module)
    for forbidden in (
        "httpx",
        "requests",
        "aiohttp",
        "socket",
        "ssl",
        "urllib.request",
        "http.client",
        "pymisp",
        "subprocess",
        "ti_recon.providers.transport",
    ):
        assert forbidden not in imported, f"{module.__name__} imports {forbidden}"
    assert not any(name.startswith("pymisp") for name in imported)


@pytest.mark.parametrize("module", PACKAGE_MODULES, ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_no_module_resolves_a_name_or_executes_anything(module: Any) -> None:
    """No DNS, no subprocess, no eval."""
    bare, attributes = called_names(module)
    for forbidden in ("eval", "exec", "compile", "__import__"):
        assert forbidden not in bare, f"{module.__name__} calls builtin {forbidden}"
    for forbidden in (
        "Popen",
        "check_output",
        "gethostbyname",
        "getaddrinfo",
        "urlopen",
        "system",
        "connect",
        "request",
    ):
        assert forbidden not in attributes, f"{module.__name__} calls {forbidden}"


def test_only_the_operator_tool_runs_git() -> None:
    """Refresh is an operator action, unreachable from any adapter method."""
    tool = ast.parse(Path("tools/update_misp_warninglists.py").read_text(encoding="utf-8"))
    tool_imports = {
        alias.name
        for node in ast.walk(tool)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "subprocess" in tool_imports
    for module in PACKAGE_MODULES:
        assert "subprocess" not in imported_modules(module)


def test_the_lookup_path_opens_no_file(stack: Stack, monkeypatch: pytest.MonkeyPatch) -> None:
    """The dataset is read once at construction, never during enrichment."""
    import asyncio
    import builtins

    opened: list[Any] = []
    real_open = builtins.open

    def recording_open(*args: Any, **kwargs: Any) -> Any:
        opened.append(args[0] if args else None)
        return real_open(*args, **kwargs)

    monkeypatch.setattr(builtins, "open", recording_open)
    monkeypatch.setattr(Path, "read_bytes", lambda self: pytest.fail(f"read {self}"))
    asyncio.run(stack.adapter.lookup(request_for(), None))
    assert opened == []


# --------------------------------------------------------------------------- #
# Context alongside another provider's verdict
# --------------------------------------------------------------------------- #


async def test_warninglist_context_does_not_touch_another_providers_evidence(
    stack: Stack,
) -> None:
    """The design invariant, stated as a test.

    A malicious ThreatFox-style verdict plus a shared-infrastructure hit is not
    benign. Task 11 adds a context record and changes nothing about the other
    provider's finding — deciding what the combination means belongs to the
    future fusion layer.
    """
    remote = ScriptedAdapter.with_steps(ScriptedStep(), descriptor=gti_like_descriptor())
    registry = ProviderRegistry([stack.adapter, remote])
    assert (
        len(
            registry.find_compatible(
                IntelObjectType.IPV4_ADDR, ProviderCapability.FALSE_POSITIVE_CONTEXT
            )
        )
        == 1
    )

    verdict = await remote.lookup(
        request_for(requested_capabilities=frozenset({ProviderCapability.REPUTATION})), None
    )
    before = [item.model_dump(mode="json") for item in verdict.evidence]

    context = await stack.adapter.lookup(request_for(), None)
    after = [item.model_dump(mode="json") for item in verdict.evidence]

    assert before == after
    assert all(item.effect is EvidenceEffect.CONTEXT_ONLY for item in context.evidence)
    # Two source families, so nothing here can be mistaken for the other's opinion.
    assert {item.source_family for item in context.evidence} == {"misp"}
    assert {item.source_family for item in verdict.evidence} != {"misp"}


def test_the_execution_layer_names_no_warninglist_concept() -> None:
    """Task 6 decides how, never what. A dataset-aware branch there would be a bug."""
    from ti_recon import execution

    package = Path(inspect.getfile(execution)).parent
    for module_path in sorted(package.glob("*.py")):
        lowered = module_path.read_text(encoding="utf-8").lower()
        for forbidden in ("misp", "warninglist", "snapshot_root", "profile_fingerprint"):
            assert forbidden not in lowered, f"{module_path.name} mentions {forbidden}"


def test_a_stale_snapshot_is_not_a_provider_failure(tmp_path: Path) -> None:
    build_snapshot(tmp_path / "snapshot", age=timedelta(days=400))
    stack = Stack(tmp_path / "snapshot")
    assert stack.adapter.snapshot is not None
    assert stack.adapter.snapshot.is_stale(timedelta(days=30)) is True
    assert stack.adapter.index is not None
