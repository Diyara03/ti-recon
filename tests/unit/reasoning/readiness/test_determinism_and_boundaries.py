"""What readiness must never do (Task 18).

The structural guarantees. Readiness reads a finished investigation and adds a
view of it; if it could reach back and change the assessment, or reach out to a
provider, or quietly grow an opinion about severity, the separation the previous
five tasks were built around would be gone.

Four things are pinned here: the assessment is untouched, the answer is
deterministic and clock-free, the vocabulary contains nothing actionable, and the
generic modules name no provider.
"""

from __future__ import annotations

import ast
import random
from pathlib import Path

import pytest

from fixtures.readiness import (
    assess,
    attempt,
    coverage_item,
    file_object,
    observable,
    scenario,
    skipped,
)
from ti_recon.enums import (
    CoverageRelevance,
    InvestigationDepth,
    ProviderCapability,
    ProviderRunStatus,
    Verdict,
)
from ti_recon.planning.models import SkipReason
from ti_recon.reasoning.fusion.policy import FUSION_POLICY_VERSION, VERDICT_RULES
from ti_recon.reasoning.readiness import (
    AssessmentReadinessEngine,
    AssessmentReadinessResult,
    ContinuationState,
    CoverageAdequacy,
    CoverageRequirement,
    GapType,
    InformationNeed,
    InMemoryReadinessMetricsSink,
    ReadinessCoverageSummary,
    ReadinessGap,
    ReadinessInputMismatch,
    ReadinessMetric,
    ReadinessPurpose,
    ReadinessStatus,
    RequirementEvaluation,
    SourceCheck,
    adequacy_for,
    continuation_for,
    is_material,
    status_for,
)

READINESS_PACKAGE = Path("src/ti_recon/reasoning/readiness")
REPUTATION = ProviderCapability.REPUTATION
INTELLIGENCE = ProviderCapability.MALWARE_INTELLIGENCE


def _rich_scenario(root=None):
    """A scenario with something of every kind in it."""
    root = file_object(sha256="a" * 64) if root is None else root
    return (
        scenario(root, depth=InvestigationDepth.DEEP)
        .with_claim("malware_sample_identity", provider="alpha", source_family="fam_a")
        .with_claim("c2_association", provider="beta", source_family="fam_b")
        .with_attempt(attempt(REPUTATION, provider="rep", source_family="fam_rep"))
        .with_attempt(attempt(INTELLIGENCE, provider="alpha", source_family="fam_a"))
        .with_attempt(
            attempt(
                ProviderCapability.FILE_BEHAVIOR,
                provider="sandbox",
                status=ProviderRunStatus.NOT_CONFIGURED,
            )
        )
        .with_coverage(coverage_item(REPUTATION))
        .with_coverage(coverage_item(INTELLIGENCE))
        .with_skip(skipped(ProviderCapability.THREAT_ASSOCIATIONS, SkipReason.BUDGET_EXHAUSTED))
    )


# --------------------------------------------------------------------------- #
# The assessment is not touched
# --------------------------------------------------------------------------- #


def test_readiness_leaves_the_fusion_result_byte_identical() -> None:
    """Serialized before, serialized after, compared exactly.

    The strongest form of the invariant: not "the verdict looks the same" but
    "no field of the Task 17 result moved at all".
    """
    scene = _rich_scenario()
    fusion = scene.fusion()
    before = fusion.model_dump_json()

    AssessmentReadinessEngine().evaluate(
        fusion=fusion,
        planning=scene.planning(),
        qualification=scene.qualification(),
        reasoning=scene.reasoning(),
    )

    assert fusion.model_dump_json() == before


COVERAGE_PERTURBATIONS = {
    "missing_provider": lambda scene: scene.with_attempt(
        attempt(REPUTATION, provider="gone", status=ProviderRunStatus.NOT_CONFIGURED)
    ),
    "partial_provider": lambda scene: scene.with_attempt(
        attempt(REPUTATION, provider="half", status=ProviderRunStatus.PARTIAL)
    ),
    "no_data": lambda scene: scene.with_attempt(
        attempt(REPUTATION, provider="empty", status=ProviderRunStatus.NO_DATA)
    ),
    "sandbox_unavailable": lambda scene: scene.with_attempt(
        attempt(
            ProviderCapability.FILE_BEHAVIOR,
            provider="sbx2",
            status=ProviderRunStatus.TEMPORARILY_UNAVAILABLE,
        )
    ),
    "budget_exhausted": lambda scene: scene.with_skip(
        skipped(ProviderCapability.CURRENT_INFRASTRUCTURE, SkipReason.BUDGET_EXHAUSTED)
    ),
    "quota_exceeded": lambda scene: scene.with_attempt(
        attempt(INTELLIGENCE, provider="spent", status=ProviderRunStatus.QUOTA_EXCEEDED)
    ),
}


@pytest.mark.parametrize("case", sorted(COVERAGE_PERTURBATIONS))
def test_no_coverage_change_moves_the_verdict_or_confidence(case: str) -> None:
    """Readiness may change; correctness may not.

    This is the boundary Task 17 had to defend twice from inside its own layer.
    Defending it from outside matters just as much: an incomplete investigation
    does not make a correct assessment less correct.

    One scenario is built and then perturbed in place, so the evidence -- and
    therefore the run-scoped assessment id -- is literally the same. Building
    two scenarios would mint fresh evidence UUIDs and make the ids differ for a
    reason that has nothing to do with coverage.
    """
    scene = _rich_scenario()
    baseline = assess(scene)
    perturbed = assess(COVERAGE_PERTURBATIONS[case](scene))

    assert perturbed.verdict is baseline.verdict
    assert perturbed.confidence is baseline.confidence
    assert perturbed.verdict_rule_id == baseline.verdict_rule_id
    assert perturbed.assessment_id == baseline.assessment_id


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #


def test_the_same_investigation_answers_identically() -> None:
    """No clock, no randomness, no ordering luck."""
    scene = _rich_scenario()
    first = assess(scene)
    second = assess(scene)

    assert first.model_dump_json() == second.model_dump_json()
    assert first.result_id == second.result_id


def test_the_answer_does_not_depend_on_input_order() -> None:
    """Shuffle everything shuffleable; get the same result id back.

    Discovery order is an accident of execution scheduling. If it reached the
    output, two runs over one investigation could disagree for no reason anybody
    could explain.
    """
    scene = _rich_scenario()
    forward = assess(scene)

    # The same investigation, re-ordered in place: same evidence, same claims,
    # different discovery sequence.
    rng = random.Random(20260830)
    rng.shuffle(scene.attempts)
    rng.shuffle(scene.coverage)
    rng.shuffle(scene.skips)
    backward = assess(scene)

    assert backward.result_id == forward.result_id
    assert backward.readiness_status is forward.readiness_status
    assert [item.requirement.capability for item in backward.requirement_evaluations] == [
        item.requirement.capability for item in forward.requirement_evaluations
    ]
    assert [gap.gap_id for gap in backward.gaps] == [gap.gap_id for gap in forward.gaps]


def test_the_evaluated_instant_comes_from_task_15() -> None:
    """Carried through, never read from a clock.

    A stored investigation re-evaluated years later must answer as it did the
    first time, which is impossible if anything here asks what time it is.
    """
    scene = _rich_scenario()
    result = assess(scene)

    assert result.evaluated_at == scene.qualification().evaluated_at


def test_nothing_in_the_package_reads_a_clock() -> None:
    """Structural, so a future edit cannot quietly introduce one.

    The metrics module is exempt: a metric's own recording timestamp is not an
    input to any decision, and no rule reads it back.
    """
    offenders: list[str] = []
    for path in sorted(READINESS_PACKAGE.rglob("*.py")):
        if path.name == "metrics.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {"now", "utcnow", "today"}:
                offenders.append(f"{path.name}: {node.attr}")
            if isinstance(node, ast.Name) and node.id == "utc_now":
                offenders.append(f"{path.name}: utc_now")

    assert offenders == []


# --------------------------------------------------------------------------- #
# Input integrity
# --------------------------------------------------------------------------- #


def test_artifacts_from_different_investigations_are_refused() -> None:
    """Two observables, one answer -- refused rather than averaged.

    Evaluating a planning run for one observable against an assessment of
    another would produce a confident statement about nothing in particular,
    which is worse than an error because it looks like a result.
    """
    scene = _rich_scenario()
    other = scenario(observable("203.0.113.10")).with_claim(
        "c2_association", provider="alpha", source_family="fam_a"
    )

    with pytest.raises(ReadinessInputMismatch):
        AssessmentReadinessEngine().evaluate(
            fusion=other.fusion(),
            planning=scene.planning(),
            qualification=scene.qualification(),
            reasoning=scene.reasoning(),
        )


def test_only_the_supported_purpose_is_accepted() -> None:
    """v1 answers one question, and says so rather than guessing.

    Readiness for containment or alert closure depends on organisational context
    TI Recon has no access to; offering a purpose it cannot evaluate would make
    the answer look authoritative when it is not.
    """
    assert list(ReadinessPurpose) == [ReadinessPurpose.ANALYST_TRIAGE]

    scene = _rich_scenario()
    result = assess(scene, purpose=ReadinessPurpose.ANALYST_TRIAGE)
    assert result.purpose is ReadinessPurpose.ANALYST_TRIAGE


# --------------------------------------------------------------------------- #
# The vocabulary contains nothing actionable
# --------------------------------------------------------------------------- #

#: Matched against whole underscore-separated segments, not as substrings.
#: ``checks_blocked`` is a coverage state and ``rationale`` merely contains
#: "ratio" -- a substring test flags both and teaches the next reader to loosen
#: the guard, which is how a real one would get through later.
_BANNED_FIELD_SEGMENTS = frozenset(
    {
        "risk",
        "score",
        "scores",
        "severity",
        "priority",
        "percent",
        "percentage",
        "ratio",
        "weight",
        "weighted",
        "block",
        "quarantine",
        "isolate",
        "suppress",
        "allowlist",
        "incident",
        "vote",
        "votes",
    }
)

_READINESS_MODELS = (
    AssessmentReadinessResult,
    ReadinessCoverageSummary,
    ReadinessGap,
    CoverageRequirement,
    RequirementEvaluation,
    SourceCheck,
    InformationNeed,
    ReadinessMetric,
)


@pytest.mark.parametrize("model", _READINESS_MODELS, ids=lambda item: item.__name__)
def test_no_readiness_model_carries_a_score_or_an_action(model) -> None:
    """Structural, at field-name level.

    Readiness is external-TI coverage. It does not know asset criticality,
    business impact or incident policy, so a field named for any of them would
    be a promise the engine cannot keep.
    """
    offenders = [
        name for name in model.model_fields if set(name.lower().split("_")) & _BANNED_FIELD_SEGMENTS
    ]

    assert offenders == []


def test_the_status_vocabulary_recommends_nothing() -> None:
    """Every member describes the investigation, not what to do about it."""
    banned = {"safe", "clear", "block", "close", "actionable", "malicious", "benign"}
    for status in ReadinessStatus:
        assert not (set(status.value.split("_")) & banned), status


def test_no_coverage_percentage_is_exposed() -> None:
    """Counts only.

    A ratio invites reading 78% as readiness, which is meaningless when the
    missing requirements are the only ones that could resolve the question.
    """
    summary = assess(_rich_scenario()).coverage_summary
    assert all(
        isinstance(getattr(summary, name), int) for name in ReadinessCoverageSummary.model_fields
    )


# --------------------------------------------------------------------------- #
# Provider neutrality and isolation
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


def test_generic_readiness_names_no_provider() -> None:
    """Policy reasons about capabilities; providers appear only in traces.

    Reads string literals as well as imports, because a provider id smuggled in
    as a comparison string would be exactly as much of a leak as an import.
    """
    offenders: list[str] = []
    for path in sorted(READINESS_PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                lowered = node.value.lower()
                for token in _PROVIDER_TOKENS:
                    # Whole-word only: prose in a docstring may legitimately use
                    # a word like "missing" that contains no provider at all.
                    if token in lowered.split() or lowered == token:
                        offenders.append(f"{path.name}: {token}")
            if isinstance(node, ast.ImportFrom) and node.module:
                for token in _PROVIDER_TOKENS:
                    if f"providers.{token}" in node.module:
                        offenders.append(f"{path.name}: imports {node.module}")

    assert offenders == []


def test_readiness_performs_no_network_or_provider_execution() -> None:
    """No transport, no planner run, no adapter.

    Readiness consumes finished artifacts. Importing an HTTP client or the
    planner's orchestrator would mean it could start an investigation of its
    own, which is Task 19's job and not this layer's.
    """
    banned_modules = {"httpx", "socket", "asyncio"}
    banned_imports = {
        "ti_recon.planning.orchestrator",
        "ti_recon.execution",
        "ti_recon.credentials",
    }
    offenders: list[str] = []
    for path in sorted(READINESS_PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                offenders += [
                    f"{path.name}: {alias.name}"
                    for alias in node.names
                    if alias.name.split(".")[0] in banned_modules
                ]
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in banned_modules:
                    offenders.append(f"{path.name}: {node.module}")
                offenders += [
                    f"{path.name}: {node.module}"
                    for banned in banned_imports
                    if node.module.startswith(banned)
                ]

    assert offenders == []


def test_metrics_carry_no_observable_or_investigation_label() -> None:
    """Low cardinality by construction.

    This layer sees the whole investigation, so a label holding the observable
    would turn a metrics pipeline into a record of everything anybody has looked
    up.
    """
    sink = InMemoryReadinessMetricsSink()
    assess(_rich_scenario(), engine=AssessmentReadinessEngine(metrics=sink))

    assert len(sink.metrics) == 1
    banned = ("target", "observable", "hash", "url", "user", "investigation", "provider")
    offenders = [name for name in ReadinessMetric.model_fields if any(t in name for t in banned)]
    assert offenders == []


# --------------------------------------------------------------------------- #
# Materiality is bound to Task 17's vocabulary by identity, not by shape
# --------------------------------------------------------------------------- #


def test_strong_basis_rules_are_imported_identities_not_parsed_strings() -> None:
    """A rename must be a build error, not a silent behaviour change.

    Every member of ``STRONG_BASIS_RULES`` comes from Task 17's own
    ``VERDICT_RULES``, so the two cannot drift. Matching on "decisive" appearing
    in a rule id, or on a prefix, would keep working after a rename while
    quietly meaning something else.
    """
    from ti_recon.reasoning.fusion.policy import VERDICT_RULES
    from ti_recon.reasoning.readiness.policy import (
        STRONG_BASIS_RULES,
        SUPPORTED_FUSION_POLICY_VERSION,
    )

    assert STRONG_BASIS_RULES <= set(VERDICT_RULES.values())
    assert STRONG_BASIS_RULES == {
        VERDICT_RULES["malicious_decisive"],
        VERDICT_RULES["malicious_corroborated"],
        VERDICT_RULES["likely_benign_explained"],
    }
    assert SUPPORTED_FUSION_POLICY_VERSION == FUSION_POLICY_VERSION

    # No substring or prefix matching anywhere in the policy module.
    source = Path("src/ti_recon/reasoning/readiness/policy.py").read_text(encoding="utf-8")
    for pattern in ("startswith", "endswith", "re.match", "re.search", "in verdict_rule_id"):
        assert pattern not in source


MATERIALITY_CASES = {
    "decisive_malicious": (VERDICT_RULES["malicious_decisive"], False),
    "corroborated_malicious": (VERDICT_RULES["malicious_corroborated"], False),
    "explained_benign": (VERDICT_RULES["likely_benign_explained"], False),
    "residual_suspicious": (VERDICT_RULES["suspicious_residual"], True),
    "single_source_benign": (VERDICT_RULES["likely_benign_directional"], True),
    "unknown_future_rule": ("malicious.some_future_rule.v9", True),
    "decisive_looking_unknown": ("decisive.but.not.a.real.rule", True),
}


@pytest.mark.parametrize("case", sorted(MATERIALITY_CASES))
def test_relevant_requirements_stay_material_unless_the_basis_is_known_strong(
    case: str,
) -> None:
    """Unknown rules fail conservatively.

    The last two rows matter most. A rule id this table has never seen — because
    Task 17 gained one, or because something malformed arrived — must not
    suppress relevant requirements. Assuming an unknown rule is strong would
    quietly declare an investigation adequately covered on the authority of a
    rule nobody here has reviewed, and the second row shows a substring test
    would have done exactly that.
    """
    rule_id, expected = MATERIALITY_CASES[case]

    assert (
        is_material(
            criticality=CoverageRelevance.RELEVANT,
            verdict=Verdict.SUSPICIOUS,
            verdict_rule_id=rule_id,
        )
        is expected
    )


@pytest.mark.parametrize(
    "criticality,expected",
    [(CoverageRelevance.REQUIRED, True), (CoverageRelevance.OPTIONAL, False)],
)
def test_required_always_matters_and_optional_never_does(
    criticality: CoverageRelevance, expected: bool
) -> None:
    """Neither depends on the basis, so neither consults the rule id."""
    for rule_id in (VERDICT_RULES["malicious_decisive"], VERDICT_RULES["suspicious_residual"]):
        assert (
            is_material(
                criticality=criticality, verdict=Verdict.SUSPICIOUS, verdict_rule_id=rule_id
            )
            is expected
        )


# --------------------------------------------------------------------------- #
# The two-axis algebra
# --------------------------------------------------------------------------- #


def test_only_certain_axis_pairings_are_reachable() -> None:
    """The impossible combinations, enumerated rather than left to a fallback.

    ``ADEQUATE`` and ``LIMITED`` both require zero material gaps, and every
    continuation other than ``COMPLETE`` requires at least one. So the two
    functions can never jointly produce a non-complete continuation alongside
    either of those adequacies, and the headline such a pairing would take is
    unreachable too.

    Derived by driving both policy functions over every input shape rather than
    asserted from reading them, so a change that makes one of the pairings
    reachable fails here instead of quietly picking a branch.
    """
    reachable: set[tuple[CoverageAdequacy, ContinuationState]] = set()
    gap_shapes = [
        frozenset(),
        frozenset({GapType.NOT_ATTEMPTED}),
        frozenset({GapType.NOT_CONFIGURED}),
        frozenset({GapType.CAPABILITY_UNAVAILABLE}),
    ]
    for verdict in Verdict:
        for gaps in gap_shapes:
            for limitations in (0, 1):
                for unresolved in (0, 1):
                    adequacy = adequacy_for(
                        verdict=verdict,
                        material_gaps=len(gaps),
                        limitations=limitations,
                        unresolved_inputs=unresolved,
                    )
                    reachable.add((adequacy, continuation_for(material_gap_types=gaps)))

    impossible = {
        (adequacy, continuation)
        for adequacy in (CoverageAdequacy.ADEQUATE, CoverageAdequacy.LIMITED)
        for continuation in ContinuationState
        if continuation is not ContinuationState.COMPLETE
    }
    assert reachable & impossible == set()
    # And the pairings that do occur are the ones the status table describes.
    assert (CoverageAdequacy.ADEQUATE, ContinuationState.COMPLETE) in reachable
    assert (CoverageAdequacy.INADEQUATE, ContinuationState.COMPLETE) in reachable
    assert (CoverageAdequacy.INADEQUATE, ContinuationState.MORE_DATA_AVAILABLE) in reachable
    assert (CoverageAdequacy.INADEQUATE, ContinuationState.BLOCKED) in reachable
    assert (CoverageAdequacy.INADEQUATE, ContinuationState.EXHAUSTED) in reachable


def test_inadequate_with_a_complete_continuation_is_unresolved() -> None:
    """Reachable, and deliberately not READY.

    An INCONCLUSIVE verdict with every applicable source already asked has no
    material gap left — nothing more to do — and still has not resolved the
    observable. That is the one place the two axes genuinely disagree, and
    ``EXHAUSTED`` must not read as ``ADEQUATE``.
    """
    adequacy = adequacy_for(
        verdict=Verdict.INCONCLUSIVE, material_gaps=0, limitations=0, unresolved_inputs=0
    )
    continuation = continuation_for(material_gap_types=frozenset())

    assert adequacy is CoverageAdequacy.INADEQUATE
    assert continuation is ContinuationState.COMPLETE
    assert (
        status_for(adequacy=adequacy, continuation=continuation, limitations=0)
        is ReadinessStatus.UNRESOLVED
    )


def test_ready_means_no_material_gap_not_nothing_left_to_query() -> None:
    """READY is about materiality, not exhaustion.

    A decisive identification with an optional capability never obtained is
    READY. The unobtained capability is an execution fact in the trace, not a
    headline limitation — otherwise every investigation would be limited by
    whatever the catalogue happens to contain but did not run.
    """
    root = file_object(sha256="a" * 64)
    result = assess(
        scenario(root)
        .with_claim("malware_sample_identity", provider="alpha", source_family="fam_a")
        .with_attempt(attempt(REPUTATION, provider="rep", source_family="fam_rep"))
        .with_attempt(attempt(INTELLIGENCE, provider="alpha", source_family="fam_a"))
        .with_attempt(
            attempt(
                ProviderCapability.FILE_BEHAVIOR,
                provider="sandbox",
                status=ProviderRunStatus.NOT_CONFIGURED,
            )
        )
    )

    assert result.readiness_status is ReadinessStatus.READY
    assert result.limitations == ()
    # The failure is not hidden: it is in the requirement's own check trace.
    behaviour = next(
        item
        for item in result.requirement_evaluations
        if item.requirement.capability is ProviderCapability.FILE_BEHAVIOR
    )
    assert "not_configured" in {check.raw_status for check in behaviour.checks}
