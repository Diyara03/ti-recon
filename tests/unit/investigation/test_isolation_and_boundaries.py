"""What the workflow must never do (Task 19).

Four families of guarantee, each of which fails quietly rather than loudly if it
breaks: pivot policy stays where the caller set it, run state does not survive
into the next investigation, cancellation stays cancellation, and the generic
workflow never learns a provider's name.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest

from fixtures.investigation import (
    InvestigationStack,
    claim_evidence,
    file_root,
    observable_root,
    spec,
)
from fixtures.investigation.stack import ScriptedProvider
from ti_recon.correlation import MAX_AUTOMATIC_PIVOT_HOP, PivotMode
from ti_recon.correlation.policy import PivotPolicy
from ti_recon.enums import (
    IntelObjectType,
    ProviderCapability,
    RelationshipType,
    Verdict,
)
from ti_recon.investigation import (
    InvestigationError,
    InvestigationOrchestrator,
    InvestigationRequest,
    WorkflowStopReason,
)
from ti_recon.reasoning.claims.models import ClaimSemantic

WORKFLOW_PACKAGE = Path("src/ti_recon/investigation")
REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE

DIGEST = "a" * 64
CONTACTED = "evil.example"


def _pivot_stack() -> tuple[InvestigationStack, object]:
    """A sample that contacted a domain, and a provider that can answer both."""
    root = file_root(DIGEST)
    provider = ScriptedProvider(
        spec(
            "repo",
            family="fam_repo",
            capabilities=frozenset({INTELLIGENCE, REPUTATION}),
            object_types=frozenset({IntelObjectType.FILE, IntelObjectType.DOMAIN_NAME}),
        ),
        {
            DIGEST: claim_evidence(
                ClaimSemantic.MALWARE_SAMPLE_IDENTITY,
                relations=((RelationshipType.CONTACTS, CONTACTED, "contacted"),),
            ),
            CONTACTED: claim_evidence(ClaimSemantic.MALICIOUS_REPUTATION),
        },
    )
    return InvestigationStack(providers=[provider]), root


# --------------------------------------------------------------------------- #
# Pivot policy is the caller's, and stays theirs
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_pivot_mode_none_enriches_nothing() -> None:
    """Relationships are learned and never followed.

    The graph still records what the provider said — declining to chase a lead is
    not declining to remember it.
    """
    stack, root = _pivot_stack()
    await stack.add_credentials()

    result = await stack.investigate(
        InvestigationRequest(root=root), pivot_policy=PivotPolicy(mode=PivotMode.NONE)
    )

    assert result.pivot_mode == PivotMode.NONE.value
    assert result.correlation.pivot_runs == ()
    assert CONTACTED not in {value for value, _ in stack.requests_for("repo")}


@pytest.mark.asyncio
async def test_pivot_mode_recommend_keeps_candidates_without_querying_them() -> None:
    """Recommending is not enriching, and readiness cannot upgrade it.

    A caller who chose RECOMMEND declined the disclosure that a pivot lookup
    makes. Readiness wanting more data about the root is not their consent to
    tell a third party about something the root merely touched.
    """
    stack, root = _pivot_stack()
    await stack.add_credentials()

    result = await stack.investigate(
        InvestigationRequest(root=root), pivot_policy=PivotPolicy(mode=PivotMode.RECOMMEND)
    )

    assert result.pivot_mode == PivotMode.RECOMMEND.value
    assert result.correlation.pivot_runs == ()
    assert CONTACTED not in {value for value, _ in stack.requests_for("repo")}


@pytest.mark.asyncio
async def test_a_pivot_target_is_enriched_at_most_once() -> None:
    """Once per investigation, however many rounds happen.

    The correlation session's graph carries the enriched set, so a target reached
    in one round is not reached again in the next — which is also how a *second
    hop* would appear without anyone deciding to allow one.
    """
    stack, root = _pivot_stack()
    await stack.add_credentials()

    result = await stack.investigate(
        InvestigationRequest(root=root),
        pivot_policy=PivotPolicy(mode=PivotMode.ENRICH, allow_remote_pivot_lookup=True),
    )

    asked = [value for value, _ in stack.requests_for("repo")]
    assert asked.count(CONTACTED) <= 1
    assert result.correlation.pivot_budget is not None


def test_the_one_hop_limit_is_a_module_constant_the_workflow_cannot_reach() -> None:
    """Task 14 owns the hop bound, and no round resets it.

    A workflow that tracked hops itself would eventually disagree with the layer
    that enforces them, and the disagreement would show up as a second hop
    nobody authorised.
    """
    assert MAX_AUTOMATIC_PIVOT_HOP == 1

    for path in sorted(WORKFLOW_PACKAGE.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        assert "MAX_AUTOMATIC_PIVOT_HOP" not in source
        assert "hop" not in source.lower().replace("workflow", "")


# --------------------------------------------------------------------------- #
# Run state does not survive
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_two_investigations_through_one_orchestrator_share_nothing() -> None:
    """The second run must not inherit the first's graph, budget or attempts.

    The orchestrator is reusable on purpose, so every piece of run memory lives
    in a per-run object. If any of it were held on the instance, a long-lived
    service would slowly accumulate one enormous investigation.
    """
    stack, first_root = _pivot_stack()
    await stack.add_credentials()
    second_root = observable_root("198.51.100.9")

    first = await stack.investigate(InvestigationRequest(root=first_root))
    second = await stack.investigate(InvestigationRequest(root=second_root))

    assert first.investigation_id != second.investigation_id
    assert second.root.canonical_key == second_root.canonical_key
    assert second.correlation.root_node_key == second_root.canonical_key
    # No node from the first investigation appears in the second's graph.
    first_keys = {node.node_key for node in first.correlation.graph_nodes}
    second_keys = {node.node_key for node in second.correlation.graph_nodes}
    assert first_root.canonical_key not in second_keys
    assert second_root.canonical_key not in first_keys
    # And the second run started with its own allowance.
    assert second.enrichment.budget.remote_runs_used <= len(second.enrichment.attempts)


@pytest.mark.asyncio
async def test_each_analyst_gets_their_own_execution_scope() -> None:
    """The scope reaches every provider call unchanged.

    Substituting a shared or default scope would cross the user isolation every
    cache, cooldown and entitlement store below depends on — and the second
    analyst would silently read the first one's answers.
    """
    stack, root = _pivot_stack()
    await stack.add_credentials(user_id="analyst-a")

    first = await stack.investigate(InvestigationRequest(root=root), user_id="analyst-a")
    # A second analyst with no credentials of their own cannot borrow the first's.
    second = await stack.investigate(InvestigationRequest(root=root), user_id="analyst-b")

    assert first.assessment.assessment.verdict is Verdict.MALICIOUS
    unconfigured = {attempt.status.value for attempt in second.enrichment.attempts}
    assert "not_configured" in unconfigured


# --------------------------------------------------------------------------- #
# Failures
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_cancellation_propagates_untouched() -> None:
    """A caller going away is not a provider becoming unavailable.

    Converting one into the other would put an operational event into an
    analytical record, where a reader would later mistake it for something a
    source did.
    """
    gate = asyncio.Event()
    root = file_root(DIGEST)
    blocking = ScriptedProvider(
        spec("slow", family="fam_slow", capabilities=frozenset({INTELLIGENCE, REPUTATION})),
        {DIGEST: claim_evidence(ClaimSemantic.MALWARE_SAMPLE_IDENTITY)},
        gate=gate,
    )
    stack = InvestigationStack(providers=[blocking])
    await stack.add_credentials()

    task = asyncio.ensure_future(stack.investigate(InvestigationRequest(root=root)))
    # Wait until the provider is genuinely mid-call before cancelling, so this
    # tests cancellation of work in flight rather than of a finished coroutine.
    for _ in range(100):
        await asyncio.sleep(0)
        if blocking.requests:
            break
    assert blocking.requests, "the provider was never reached"

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_a_stage_describing_another_observable_is_a_workflow_error() -> None:
    """Structural, and raised rather than reported.

    An assessment of one object presented as an assessment of another is not a
    coverage limitation. Returning INCONCLUSIVE would make a software fault look
    like a conclusion somebody could act on.
    """
    stack, root = _pivot_stack()
    await stack.add_credentials()

    other = observable_root("203.0.113.5")
    orchestrator: InvestigationOrchestrator = stack.orchestrator
    original = orchestrator._check_consistency

    def wrong_root(request, analysis):  # type: ignore[no-untyped-def]
        return original(request.model_copy(update={"root": other}), analysis)

    orchestrator._check_consistency = wrong_root  # type: ignore[method-assign]
    try:
        with pytest.raises(InvestigationError):
            await stack.investigate(InvestigationRequest(root=root))
    finally:
        orchestrator._check_consistency = original  # type: ignore[method-assign]


# --------------------------------------------------------------------------- #
# Static boundaries
# --------------------------------------------------------------------------- #

_PROVIDER_TOKENS = (
    "gti",
    "virustotal",
    "greynoise",
    "censys",
    "threatfox",
    "urlhaus",
    "malwarebazaar",
    "hybrid_analysis",
    "misp",
    "urlscan",
    "abuse_ch",
)


def test_the_workflow_names_no_provider() -> None:
    """Composition happens through registries, never through a name.

    Reads string literals as well as imports: a provider id smuggled in as a
    comparison string would be exactly as much of a leak as an import, and would
    make the workflow a second, worse planner.
    """
    offenders: list[str] = []
    for path in sorted(WORKFLOW_PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                lowered = node.value.lower()
                offenders += [
                    f"{path.name}: {token}"
                    for token in _PROVIDER_TOKENS
                    if token in lowered.split() or lowered == token
                ]
            if isinstance(node, ast.ImportFrom) and node.module:
                offenders += [
                    f"{path.name}: imports {node.module}"
                    for token in _PROVIDER_TOKENS
                    if f"providers.{token}" in node.module
                ]

    assert offenders == []


def test_the_workflow_opens_no_network_of_its_own() -> None:
    """Every external call goes through Task 13 to Task 6 to an adapter.

    That path is where the cache, the cooldown, the quota, the retry policy, the
    execution scope and the budget accounting live. A direct call would bypass
    all six at once.
    """
    banned_modules = {"httpx", "socket", "requests", "urllib"}
    offenders: list[str] = []
    for path in sorted(WORKFLOW_PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                offenders += [
                    f"{path.name}: {alias.name}"
                    for alias in node.names
                    if alias.name.split(".")[0] in banned_modules
                ]
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.split(".")[0] in banned_modules
            ):
                offenders.append(f"{path.name}: {node.module}")

    assert offenders == []


def test_the_workflow_never_calls_an_adapter_directly() -> None:
    """Provider execution belongs to Task 13 and Task 6.

    A ``lookup`` call from here would skip the cache, the cooldown, the quota
    check, the retry policy and the budget charge — every one of which exists
    because somebody once needed it.
    """
    offenders: list[str] = []
    for path in sorted(WORKFLOW_PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {
                "lookup",
                "batch_lookup",
                "active_action",
            }:
                offenders.append(f"{path.name}: .{node.attr}()")
    assert offenders == []


def test_the_workflow_produces_no_action_or_severity() -> None:
    """No field a reader could mistake for a recommendation.

    Whether to block, quarantine or close depends on asset criticality, business
    impact and incident policy — none of which this engine has ever seen.
    """
    from ti_recon.investigation import InvestigationResult, InvestigationRound

    banned = {
        "risk",
        "score",
        "severity",
        "priority",
        "block",
        "quarantine",
        "isolate",
        "suppress",
        "allowlist",
        "incident",
        "remediation",
        "action",
    }
    for model in (InvestigationResult, InvestigationRound):
        offenders = [name for name in model.model_fields if set(name.lower().split("_")) & banned]
        assert offenders == [], model.__name__

    for reason in WorkflowStopReason:
        assert not (set(reason.value.split("_")) & banned), reason


# --------------------------------------------------------------------------- #
# The default composition uses the catalogues everything else uses
# --------------------------------------------------------------------------- #


def test_the_default_composition_reuses_the_shipped_catalogues() -> None:
    """One source of truth per catalogue, not a hand-written second list.

    A parallel list is the kind of mistake that never fails: a provider added to
    the real catalogue keeps working everywhere except inside a full
    investigation, and the run is quietly narrower than every suite believes.
    """
    from ti_recon.investigation.composition import build_default_reasoning_engines
    from ti_recon.planning.catalog import build_default_planning_registry
    from ti_recon.reasoning.catalog import default_qualifiers
    from ti_recon.reasoning.claims.registry import default_translators

    engines = build_default_reasoning_engines()

    assert engines.fusion.translators == default_translators()
    assert engines.temporal.qualifiers == default_qualifiers()
    # Every planning profile the catalogue offers, none invented here.
    assert len(build_default_planning_registry().all()) >= 9


def test_the_composition_module_is_the_only_place_naming_a_provider() -> None:
    """Provider imports are isolated to the composition root.

    The generic workflow reaches the catalogues through that one module and
    otherwise operates entirely on registries and interfaces.
    """
    import ast

    generic = [
        path for path in sorted(WORKFLOW_PACKAGE.rglob("*.py")) if path.name != "composition.py"
    ]
    for path in generic:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert "catalog" not in node.module, f"{path.name} reaches a catalogue"
                assert "claims.registry" not in node.module, path.name


@pytest.mark.asyncio
async def test_the_same_investigation_answers_identically() -> None:
    """Deterministic given the same scripted answers and the same clock.

    Evidence ids are minted per collection, so the two runs' record identities
    differ by design — what must not differ is anything the workflow decided.
    """
    first_stack, root = _pivot_stack()
    await first_stack.add_credentials()
    second_stack, _ = _pivot_stack()
    await second_stack.add_credentials()

    first = await first_stack.investigate(InvestigationRequest(root=root))
    second = await second_stack.investigate(InvestigationRequest(root=root))

    assert first.assessment.assessment.verdict is second.assessment.assessment.verdict
    assert first.assessment.assessment.confidence is second.assessment.assessment.confidence
    assert first.readiness.readiness_status is second.readiness.readiness_status
    assert first.readiness.continuation_state is second.readiness.continuation_state
    assert first.stop_reason is second.stop_reason
    assert len(first.rounds) == len(second.rounds)
    assert [item.node_key for item in first.correlation.graph_nodes] == [
        item.node_key for item in second.correlation.graph_nodes
    ]


@pytest.mark.asyncio
async def test_the_workflow_reads_no_clock_of_its_own() -> None:
    """The injected clock supplies every analysis instant.

    A wall-clock read inside the workflow would make an investigation
    unreproducible for a reason nothing in the result could explain.
    """
    stack, root = _pivot_stack()
    await stack.add_credentials()

    result = await stack.investigate(InvestigationRequest(root=root))

    assert result.evaluated_at == stack.clock.now()
    for item in result.rounds:
        assert item.evaluated_at == stack.clock.now()
