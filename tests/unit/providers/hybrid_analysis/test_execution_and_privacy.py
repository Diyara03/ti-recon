"""Hybrid Analysis under Task 6, and what it refuses to keep (Task 12).

Two halves. The first proves the provider is not special: it runs behind the same
cache, cooldown, quota and concurrency machinery as everything else, with no
sandbox-shaped branch in the execution layer. The second proves that provider and
submitter text — a document password, someone's case comment, a command line that
reads like an instruction — stays out of evidence or stays inert.
"""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from pydantic import SecretStr

from fixtures.hybrid_analysis import payloads
from fixtures.hybrid_analysis.fake_client import ClientFactory, FakeHybridAnalysisClient
from ti_recon.credentials import (
    AuthType,
    CredentialManager,
    CredentialResolver,
    CredentialStatus,
    InMemoryConnectionRepository,
    InMemorySecretStore,
)
from ti_recon.enums import (
    CoverageStatus,
    EvidenceEffect,
    IntelObjectType,
    InvestigationDepth,
    ObjectClass,
    ProviderCapability,
    ProviderErrorCategory,
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
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.errors import provider_error_for
from ti_recon.providers.hybrid_analysis import (
    ASSESSMENT_CLAIM_TYPE,
    BEHAVIOUR_CLAIM_TYPE,
    EXCLUDED_DETONATION_FIELDS,
    HYBRID_ANALYSIS_MAX_CONCURRENCY,
    HYBRID_ANALYSIS_NO_DATA_TTL_SECONDS,
    HYBRID_ANALYSIS_PROVIDER_ID,
    HYBRID_ANALYSIS_SUCCESS_TTL_SECONDS,
    SAFE_DETONATION_FIELDS,
    HybridAnalysisAdapter,
    build_hybrid_analysis_execution_policy,
)

KEY_A = "ha-key-analyst-a-SHOULD-NOT-LEAK"
KEY_B = "ha-key-analyst-b-SHOULD-NOT-LEAK"
USER_A = "analyst-a"
USER_B = "analyst-b"


def file_object() -> IntelObject:
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=payloads.SAMPLE_SHA256,
        display_value=payloads.SAMPLE_SHA256,
        properties={"hashes": {"SHA-256": payloads.SAMPLE_SHA256}},
    )


def request_for(subject: Any = None, **overrides: Any) -> ProviderRequest:
    kwargs: dict[str, Any] = {
        "investigation_id": "inv-1",
        "intel_object": subject if subject is not None else file_object(),
        "operation": ProviderOperation.LOOKUP,
        "requested_capabilities": frozenset({ProviderCapability.FILE_BEHAVIOR}),
    }
    kwargs.update(overrides)
    return ProviderRequest(**kwargs)


class Stack:
    """The execution layer wired around a fake client."""

    def __init__(self, client: FakeHybridAnalysisClient | None = None) -> None:
        self.clock = ManualClock()
        self.secrets = InMemorySecretStore()
        self.connections = InMemoryConnectionRepository()
        self.manager = CredentialManager(self.secrets, self.connections)
        self.resolver = CredentialResolver(self.secrets, self.connections)
        self.cache = InMemoryProviderCache(clock=self.clock)
        self.metrics = InMemoryExecutionMetricsSink()
        self.client = client if client is not None else FakeHybridAnalysisClient()
        self.adapter = HybridAnalysisAdapter(client_factory=ClientFactory(self.client))  # type: ignore[arg-type]
        self.executor = ProviderExecutor(
            credential_resolver=self.resolver,
            cache=self.cache,
            quota_store=InMemoryQuotaStore(clock=self.clock),
            cooldown_store=InMemoryCooldownStore(clock=self.clock),
            limiter=ConcurrencyLimiter(max_concurrency=4),
            policies=ProviderPolicyRegistry(policies=[build_hybrid_analysis_execution_policy()]),
            metrics=self.metrics,
            clock=self.clock,
            sleeper=RecordingSleeper(self.clock),
            jitter=FixedJitter(0.0),
        )

    async def add_credential(self, user_id: str, secret: str) -> str:
        connection = await self.manager.create_connection(
            user_id=user_id,
            provider_id=HYBRID_ANALYSIS_PROVIDER_ID,
            secret=secret,
            auth_type=AuthType.API_KEY,
            status=CredentialStatus.ACTIVE,
        )
        return connection.id

    def context(self, user_id: str = USER_A) -> ExecutionContext:
        return ExecutionContext(authenticated_user_id=user_id, request_id=f"req-{user_id}")


@pytest.fixture
async def stack() -> Stack:
    built = Stack()
    await built.add_credential(USER_A, KEY_A)
    return built


# --------------------------------------------------------------------------- #
# Ordinary execution
# --------------------------------------------------------------------------- #


async def test_a_standard_lookup_makes_two_requests_through_the_executor(
    stack: Stack,
) -> None:
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.SUCCESS
    assert outcome.attempts == 1
    assert outcome.cache_hit is False
    assert outcome.called_provider is True
    assert stack.client.call_count("search_hash") == 1
    assert stack.client.call_count("report_summary") == 1


async def test_a_repeat_lookup_makes_no_provider_call(stack: Stack) -> None:
    request = request_for()
    first = await stack.executor.execute(stack.adapter, request, stack.context())
    second = await stack.executor.execute(stack.adapter, request, stack.context())
    assert (first.cache_hit, second.cache_hit) == (False, True)
    assert second.attempts == 0
    assert second.called_provider is False
    assert stack.client.request_count == 2


async def test_a_deeper_lookup_is_not_served_from_a_shallower_answer(stack: Stack) -> None:
    """QUICK never fetched a summary; serving it for DEEP would lie."""
    await stack.executor.execute(
        stack.adapter, request_for(depth=InvestigationDepth.QUICK), stack.context()
    )
    outcome = await stack.executor.execute(
        stack.adapter, request_for(depth=InvestigationDepth.DEEP), stack.context()
    )
    assert outcome.cache_hit is False


async def test_an_absence_is_cached_briefly_and_a_hit_for_longer() -> None:
    """A new detonation can appear; a completed report cannot un-happen."""
    policy = build_hybrid_analysis_execution_policy()
    assert policy.cache.success_ttl_seconds == HYBRID_ANALYSIS_SUCCESS_TTL_SECONDS
    assert policy.cache.no_data_ttl_seconds == HYBRID_ANALYSIS_NO_DATA_TTL_SECONDS
    assert HYBRID_ANALYSIS_NO_DATA_TTL_SECONDS < HYBRID_ANALYSIS_SUCCESS_TTL_SECONDS


async def test_an_absent_report_is_cached_as_an_absence(stack: Stack) -> None:
    stack.client.search_payload = payloads.search_hash_no_reports()
    request = request_for()
    first = await stack.executor.execute(stack.adapter, request, stack.context())
    second = await stack.executor.execute(stack.adapter, request, stack.context())
    assert first.status is ProviderRunStatus.NO_DATA
    assert second.cache_hit is True
    assert second.status is ProviderRunStatus.NO_DATA


async def test_an_analyst_without_a_key_gets_not_configured() -> None:
    stack = Stack()
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.NOT_CONFIGURED
    assert outcome.attempts == 0
    assert stack.client.calls == []


async def test_an_unsupported_observable_costs_no_request(stack: Stack) -> None:
    outcome = await stack.executor.execute(
        stack.adapter,
        request_for(normalize_observable("example.com").intel_object),
        stack.context(),
    )
    assert outcome.status is ProviderRunStatus.NOT_SUPPORTED
    assert outcome.status is not ProviderRunStatus.NO_DATA
    assert stack.client.calls == []


async def test_a_malformed_hash_costs_no_request() -> None:
    """The model refuses a non-hex digest, so nothing reaches the transport."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        IntelObject(
            object_class=ObjectClass.OBSERVABLE,
            object_type=IntelObjectType.FILE,
            canonical_value="zz" + "a" * 62,
            display_value="zz" + "a" * 62,
            properties={"hashes": {"SHA-256": "zz" + "a" * 62}},
        )


# --------------------------------------------------------------------------- #
# Isolation and limits
# --------------------------------------------------------------------------- #


async def test_one_analysts_answer_is_never_served_to_another(stack: Stack) -> None:
    """Even a public report is read against a specific account's quota."""
    await stack.add_credential(USER_B, KEY_B)
    request = request_for()
    await stack.executor.execute(stack.adapter, request, stack.context(USER_A))
    outcome = await stack.executor.execute(stack.adapter, request, stack.context(USER_B))
    assert outcome.cache_hit is False


async def test_the_cache_is_never_global() -> None:
    assert build_hybrid_analysis_execution_policy().cache.scope is CacheScope.USER


async def test_a_rate_limit_puts_this_analyst_on_cooldown(stack: Stack) -> None:
    stack.client.fail(
        "search_hash",
        provider_error_for(ProviderErrorCategory.QUOTA_EXCEEDED, HYBRID_ANALYSIS_PROVIDER_ID),
    )
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status is ProviderRunStatus.QUOTA_EXCEEDED
    assert outcome.cooldown_applied is True


async def test_one_analysts_cooldown_does_not_affect_another(stack: Stack) -> None:
    await stack.add_credential(USER_B, KEY_B)
    stack.client.fail(
        "search_hash",
        provider_error_for(ProviderErrorCategory.QUOTA_EXCEEDED, HYBRID_ANALYSIS_PROVIDER_ID),
    )
    blocked = await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_A))
    assert blocked.cooldown_applied is True

    stack.client.errors.clear()
    allowed = await stack.executor.execute(stack.adapter, request_for(), stack.context(USER_B))
    assert allowed.status is ProviderRunStatus.SUCCESS


async def test_an_authentication_failure_is_not_retried(stack: Stack) -> None:
    stack.client.fail(
        "search_hash",
        provider_error_for(ProviderErrorCategory.AUTHENTICATION_ERROR, HYBRID_ANALYSIS_PROVIDER_ID),
    )
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.attempts == 1
    assert stack.client.call_count("search_hash") == 1


async def test_concurrency_stays_at_one() -> None:
    """A restricted key's allowance is small, and the provider also limits an API
    key to two source addresses per hour — parallelism buys latency at the cost of
    reliability."""
    assert HYBRID_ANALYSIS_MAX_CONCURRENCY == 1
    assert build_hybrid_analysis_execution_policy().max_concurrency == 1


async def test_identical_concurrent_lookups_are_coalesced() -> None:
    assert build_hybrid_analysis_execution_policy().coalesce_requests is True


async def test_quota_headers_reach_the_execution_layer() -> None:
    """The provider's own numbers, not the documentation's."""
    from ti_recon.providers.result import RateLimitSnapshot, RateLimitWindow

    snapshot = RateLimitSnapshot(
        operation="hybrid_analysis.search_hash",
        windows=(RateLimitWindow(window_name="minute", limit=5, remaining=4),),
    )
    stack = Stack(FakeHybridAnalysisClient(rate_limit=snapshot))
    await stack.add_credential(USER_A, KEY_A)
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.rate_limit_snapshot is not None
    assert outcome.rate_limit_snapshot.windows[0].remaining == 4


def test_the_execution_layer_depends_on_no_sandbox_concept() -> None:
    """Task 6 decides how, never what.

    Checked as imports plus provider names rather than as prose: `retry.py`
    legitimately says "submit, rescan or detonate" while explaining why active
    operations are never retried, and a scan that flagged generic vocabulary
    would fire on a correct comment.
    """
    from ti_recon import execution

    package = Path(inspect.getfile(execution)).parent
    for module_path in sorted(package.glob("*.py")):
        source = module_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        for forbidden in ("ti_recon.sandbox", "ti_recon.providers.hybrid_analysis"):
            assert not any(name.startswith(forbidden) for name in imported), (
                f"{module_path.name} imports {forbidden}"
            )
        for name in ("hybrid_analysis", "falcon"):
            assert name not in source.lower(), f"{module_path.name} mentions {name}"


async def test_a_sandbox_finding_never_becomes_a_coverage_verdict(stack: Stack) -> None:
    """The executor reports what happened, not what it means."""
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status in set(ProviderRunStatus)
    assert not hasattr(outcome, "verdict")
    assert CoverageStatus.COVERED not in {getattr(outcome, "coverage", None)}


# --------------------------------------------------------------------------- #
# Privacy: submitter metadata never becomes evidence
# --------------------------------------------------------------------------- #


async def test_submission_metadata_never_reaches_evidence(stack: Stack) -> None:
    """The fixture deliberately carries all four excluded fields.

    They belong to whoever submitted the sample — possibly years ago, possibly
    someone else's incident — and a document password in an evidence record is
    indefensible.
    """
    outcome = await stack.executor.execute(
        stack.adapter, request_for(depth=InvestigationDepth.DEEP), stack.context()
    )
    assert outcome.result is not None
    serialized = json.dumps(outcome.result.model_dump(mode="json"))
    for leaked in (
        "infected",
        "ACME-4471",
        "soc@acme.example",
        "PROXY",
        "10.0.0.9",
        "configured-by-submitter",
        "2026-01-01 00:00:00",
    ):
        assert leaked not in serialized, leaked


def test_the_exclusion_list_is_data_a_test_can_assert() -> None:
    assert set(EXCLUDED_DETONATION_FIELDS) == {
        "document_password",
        "comment",
        "environment_variable",
        "custom_commandline",
        "custom_system_date_time",
    }
    for reason in EXCLUDED_DETONATION_FIELDS.values():
        assert reason
    # And no field is on both lists.
    assert not set(SAFE_DETONATION_FIELDS) & set(EXCLUDED_DETONATION_FIELDS)


async def test_the_safe_execution_context_is_kept(stack: Stack) -> None:
    """Excluding submitter metadata must not cost the quality signal."""
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.result is not None
    behaviour = next(
        item for item in outcome.result.evidence if item.claim_type == BEHAVIOUR_CLAIM_TYPE
    )
    assert behaviour.attributes["runtime_seconds"] == 120
    assert behaviour.attributes["network_mode"] == "default"
    assert behaviour.attributes["action_script"] == "default"
    assert behaviour.attributes["anti_evasion"] is True


async def test_a_base64_icon_never_reaches_evidence(stack: Stack) -> None:
    """No analytical value, and it would dominate the record's size."""
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.result is not None
    serialized = json.dumps(outcome.result.model_dump(mode="json"))
    assert "iVBORw0KGgo" not in serialized
    assert len(serialized) < 60_000


async def test_relayed_av_and_ml_data_do_not_become_votes(stack: Stack) -> None:
    """GTI already provides direct reputation; this must not double-count it."""
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.result is not None
    directional = [
        item for item in outcome.result.evidence if item.effect is not EvidenceEffect.CONTEXT_ONLY
    ]
    assert len(directional) == 1
    assert directional[0].claim_type == ASSESSMENT_CLAIM_TYPE
    serialized = json.dumps(outcome.result.model_dump(mode="json"))
    # The nested vendor material is not adopted at all.
    assert "machine_learning_models" not in serialized
    assert "av_detect" not in serialized


async def test_no_key_reaches_the_result_or_the_metrics(stack: Stack) -> None:
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    serialized = json.dumps(outcome.model_dump(mode="json"))
    assert KEY_A not in serialized
    assert "SHOULD-NOT-LEAK" not in serialized
    assert KEY_A not in json.dumps([str(item) for item in stack.metrics.executions])


# --------------------------------------------------------------------------- #
# Untrusted text
# --------------------------------------------------------------------------- #


async def test_provider_text_that_reads_like_an_instruction_stays_data() -> None:
    """Every attacker- or submitter-controlled field carries an injection attempt.

    It must survive as bounded, inert provider data: nothing here may choose an
    endpoint, a command, a file or a destination.
    """
    stack = Stack(FakeHybridAnalysisClient(default_summary=payloads.summary_hostile_text()))
    await stack.add_credential(USER_A, KEY_A)
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.status in {ProviderRunStatus.SUCCESS, ProviderRunStatus.PARTIAL}
    assert outcome.result is not None
    behaviour = next(
        item for item in outcome.result.evidence if item.claim_type == BEHAVIOUR_CLAIM_TYPE
    )
    # Retained as a string, bounded, and attached to a context record.
    command = behaviour.attributes["processes"][0]["command_line"]
    assert "Ignore all previous instructions" in command
    assert len(command) <= 2048
    assert behaviour.effect is EvidenceEffect.CONTEXT_ONLY
    # It named a URL, and nothing fetched it: the only calls made were the two
    # permitted reads.
    assert {name for name, _ in stack.client.calls} <= {"search_hash", "report_summary"}


async def test_hostile_text_is_stripped_of_control_characters(stack: Stack) -> None:
    stack.client.default_summary = payloads.summary_malicious(
        processes=[
            {
                "uid": "1",
                "name": "evil.exe",
                "command_line": "cmd\x00.exe /c\r\nSet-Cookie: x=y",
            }
        ]
    )
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.result is not None
    behaviour = next(
        item for item in outcome.result.evidence if item.claim_type == BEHAVIOUR_CLAIM_TYPE
    )
    command = behaviour.attributes["processes"][0]["command_line"]
    assert "\x00" not in command
    assert "\n" not in command
    assert "\r" not in command


async def test_an_enormous_command_line_is_bounded(stack: Stack) -> None:
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.result is not None
    behaviour = next(
        item for item in outcome.result.evidence if item.claim_type == BEHAVIOUR_CLAIM_TYPE
    )
    for process in behaviour.attributes["processes"]:
        assert len(process.get("command_line", "")) <= 2048


async def test_an_enormous_signature_description_is_bounded(stack: Stack) -> None:
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.result is not None
    behaviour = next(
        item for item in outcome.result.evidence if item.claim_type == BEHAVIOUR_CLAIM_TYPE
    )
    for signature in behaviour.attributes["signatures"]:
        assert len(signature.get("description", "")) <= 1024


async def test_a_malformed_attack_id_is_dropped_rather_than_stored(stack: Stack) -> None:
    """An ATT&CK id is a lookup key elsewhere; a malformed one is worse than none."""
    outcome = await stack.executor.execute(stack.adapter, request_for(), stack.context())
    assert outcome.result is not None
    behaviour = next(
        item for item in outcome.result.evidence if item.claim_type == BEHAVIOUR_CLAIM_TYPE
    )
    ids = {item.get("attack_id") for item in behaviour.attributes["mitre_techniques"]}
    assert "T1055" in ids
    assert "T1059.003" in ids
    assert "not-an-id" not in ids


def test_no_provider_string_can_choose_a_destination() -> None:
    """Structural: request paths come from constants, never from response data."""
    from ti_recon.providers.hybrid_analysis import client as client_module

    tree = ast.parse(Path(inspect.getfile(client_module)).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        rendered = "".join(part.value for part in node.values if isinstance(part, ast.Constant))
        if "api/v2" not in rendered:
            continue
        # The only interpolated route is the report path, and its variable part
        # is a validated identifier rather than raw provider text.
        assert rendered.startswith("api/v2/report/")


# --------------------------------------------------------------------------- #
# Nothing is submitted or downloaded, proved through the transport
# --------------------------------------------------------------------------- #


@respx.mock
async def test_a_full_deep_lookup_issues_only_permitted_gets() -> None:
    respx.get("https://hybrid-analysis.com/api/v2/search/hash").mock(
        return_value=httpx.Response(200, json=payloads.search_hash_divergent())
    )
    respx.route(url__startswith="https://hybrid-analysis.com/api/v2/report/").mock(
        return_value=httpx.Response(200, json=payloads.summary_malicious())
    )
    forbidden = respx.route(
        url__regex=r"https://hybrid-analysis\.com/api/v2/(submit|quick-scan|overview|feed).*"
    ).mock(return_value=httpx.Response(200, json={}))

    from ti_recon.credentials.models import CredentialMaterial

    credential = CredentialMaterial(
        connection_id="c",
        user_id=USER_A,
        provider_id=HYBRID_ANALYSIS_PROVIDER_ID,
        credential_group=HYBRID_ANALYSIS_PROVIDER_ID,
        auth_type=AuthType.API_KEY,
        secret=SecretStr(KEY_A),
    )
    await HybridAnalysisAdapter().lookup(request_for(depth=InvestigationDepth.DEEP), credential)
    assert not forbidden.called
    assert len(respx.calls) == 3
    for call in respx.calls:
        assert call.request.method == "GET"
        path = call.request.url.path
        assert path.startswith("/api/v2/search/hash") or path.endswith("/summary")
