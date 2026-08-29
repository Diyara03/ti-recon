"""What Task 15 may not do, and what it must reproduce exactly.

Structural guards on the AST rather than on prose, following Tasks 12-14: a
module may discuss the network in a docstring while importing no socket, and a
check that read comments would fire on its own explanation.

The determinism tests matter more here than anywhere else in the repository.
A qualification is meant to be stored, re-read and compared: if the same inputs
at the same ``as_of`` produced different bytes, a diff between two runs would
mean nothing, and nobody could tell a policy change from a dict reordering.
"""

from __future__ import annotations

import ast
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from fixtures.reasoning import (
    AS_OF,
    file_object,
    gti_file_envelope,
    malwarebazaar_envelope,
    observable,
    sandbox_envelope,
    threatfox_compromised_envelope,
    threatfox_ip_envelope,
    urlhaus_url_envelope,
    urlscan_scan_envelope,
)
from ti_recon.correlation import (
    CorrelationEngine,
    GraphNode,
    InvestigationGraph,
    RelationBasis,
    RelationshipAssertion,
)
from ti_recon.enums import RelationshipType
from ti_recon.reasoning import (
    CLOCK_SKEW_TOLERANCE,
    SIGNAL_CUES,
    ContextSignal,
    ContextSignalType,
    InMemoryQualificationMetricsSink,
    InterpretationCue,
    InterpretationCueType,
    SourceLifecycleState,
    SubjectKind,
    TemporalContextEngine,
    TemporalFact,
    TemporalFactKind,
    TemporalIssue,
    TemporalIssueType,
    TemporalQualification,
    observable_subject,
    qualify_facts,
    report_subject,
)
from ti_recon.reasoning.models import CONCLUSION_FIELD_PATTERN
from ti_recon.reasoning.results import QualificationCoverage, TemporalContextResult

REASONING_PACKAGE = Path("src/ti_recon/reasoning")

#: Modules that must stay vendor-neutral. ``catalog.py`` is the deliberate
#: composition root and is the only place a provider may be named.
NEUTRAL_MODULES = tuple(
    path
    for path in sorted(REASONING_PACKAGE.glob("*.py"))
    if path.name not in {"catalog.py", "__init__.py"}
)

#: Every shipped provider id, as it would appear if one leaked into the engine.
PROVIDER_IDS = (
    "gti",
    "urlscan",
    "greynoise",
    "censys",
    "threatfox",
    "urlhaus",
    "malwarebazaar",
    "misp_warninglists",
    "hybrid_analysis",
    "virustotal",
)


def imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            found.add(node.module or "")
        elif isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
    return found


def string_constants(path: Path) -> set[str]:
    """Every string literal in a module, which is where a vendor id would hide."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }


# --------------------------------------------------------------------------- #
# Network and credentials
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("path", NEUTRAL_MODULES, ids=lambda item: item.name)
def test_no_reasoning_module_can_reach_the_network(path: Path) -> None:
    """Task 15 reasons over data already in hand. It resolves nothing, fetches
    nothing and opens nothing — a qualification must be runnable on a stored
    result years later with the network unplugged."""
    forbidden = {"socket", "httpx", "requests", "urllib.request", "dns", "asyncio"}
    assert not (imports(path) & forbidden), path.name


@pytest.mark.parametrize(
    "path",
    (*NEUTRAL_MODULES, REASONING_PACKAGE / "catalog.py"),
    ids=lambda item: item.name,
)
def test_no_reasoning_module_touches_a_credential(path: Path) -> None:
    found = imports(path)
    assert not [item for item in found if item.startswith("ti_recon.credentials")], path.name
    assert "SecretStr" not in path.read_text(encoding="utf-8"), path.name


def test_no_reasoning_module_calls_anything_that_reaches_out() -> None:
    forbidden = {"getaddrinfo", "gethostbyname", "post", "fetch", "connect", "urlopen", "lookup"}
    offenders = [
        f"{path.name}: {node.func.attr}"
        for path in (*NEUTRAL_MODULES, REASONING_PACKAGE / "catalog.py")
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in forbidden
    ]
    assert offenders == []


# --------------------------------------------------------------------------- #
# Vendor neutrality
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("path", NEUTRAL_MODULES, ids=lambda item: item.name)
def test_no_generic_module_names_a_provider(path: Path) -> None:
    """The rule Task 13 applies to its planner, for the same reason.

    A generic evaluator that learned URLhaus has a ``url_status`` would have to
    be edited every time a provider was added, and provider semantics would start
    drifting away from the code that produced them.
    """
    # Exact literals only, which is precisely the check that matters: a
    # comparison like ``provider == "urlhaus"`` produces the literal, while a
    # docstring *discussing* that anti-pattern is one long constant that is not
    # equal to it. A guard that read prose would fire on its own explanation.
    literals = string_constants(path)
    assert not [item for item in PROVIDER_IDS if item in literals], path.name
    assert not [
        item
        for item in imports(path)
        if item.startswith("ti_recon.providers.")
        and "." in item.removeprefix("ti_recon.providers.")
    ], path.name


def test_only_the_catalog_imports_a_concrete_provider() -> None:
    """And it does so inside a function, so the shared vocabulary a provider
    imports cannot close an import cycle back through this package."""
    catalog = REASONING_PACKAGE / "catalog.py"
    tree = ast.parse(catalog.read_text(encoding="utf-8"))
    module_level = {node.module or "" for node in tree.body if isinstance(node, ast.ImportFrom)}
    assert not [item for item in module_level if item.startswith("ti_recon.providers.")]

    from ti_recon.reasoning import qualified_provider_ids

    assert set(qualified_provider_ids()) == set(PROVIDER_IDS) - {"virustotal"}


def test_a_provider_without_an_extractor_is_named_rather_than_ignored() -> None:
    """A blind spot in the qualification layer is coverage, not an error."""
    engine = TemporalContextEngine(qualifiers={})
    result = engine.evaluate(as_of=AS_OF, results=[urlhaus_url_envelope()])
    assert result.coverage.providers_without_qualifier == ("urlhaus",)
    assert result.coverage.qualifiers_used == ()
    assert result.coverage.evidence_items_examined > 0


# --------------------------------------------------------------------------- #
# No verdict, anywhere
# --------------------------------------------------------------------------- #


def test_no_task_15_model_carries_a_conclusion_field() -> None:
    """Field-name level, so a future addition trips it.

    Task 15 hands the fusion layer facts to weigh. A field called
    ``risk_score`` would be read instead of the weighing being done, and the
    layering would be gone without anybody deciding to remove it.
    """
    models = (
        TemporalFact,
        TemporalQualification,
        TemporalIssue,
        ContextSignal,
        InterpretationCue,
        QualificationCoverage,
        TemporalContextResult,
    )
    offenders = [
        f"{model.__name__}.{name}"
        for model in models
        for name in model.model_fields
        if CONCLUSION_FIELD_PATTERN.search(name)
    ]
    assert offenders == []


def test_the_reasoning_package_never_imports_the_assessment_layer() -> None:
    """Producing a verdict is the future fusion layer's job, and a package that
    could construct an ``Assessment`` would eventually be asked to."""
    for path in (*NEUTRAL_MODULES, REASONING_PACKAGE / "catalog.py"):
        found = imports(path)
        assert "ti_recon.models.assessment" not in found, path.name
    text = "\n".join(path.read_text(encoding="utf-8") for path in REASONING_PACKAGE.glob("*.py"))
    for name in ("Assessment", "AssessmentContribution", "Verdict"):
        assert name not in text


def test_a_cue_refuses_a_conclusion_in_its_structured_detail() -> None:
    with pytest.raises(ValueError, match="conclusion field"):
        InterpretationCue(
            cue_type=InterpretationCueType.TEST_ARTIFACT_CONTEXT,
            purpose=SIGNAL_CUES[ContextSignalType.TEST_ARTIFACT][1],
            subject=observable_subject("domain-name:evil.example"),
            detail={"risk_score": 90},
        )


def test_a_signal_refuses_provider_prose_in_its_structured_detail() -> None:
    """Detail is vocabulary and small identifiers, never a provider payload."""
    with pytest.raises(ValueError, match="exceeds"):
        ContextSignal(
            signal_type=ContextSignalType.WARNINGLIST_MATCH,
            subject=observable_subject("domain-name:evil.example"),
            origin=SIGNAL_CUES[ContextSignalType.TEST_ARTIFACT][0].__class__
            and __import__(
                "ti_recon.reasoning", fromlist=["SignalOrigin"]
            ).SignalOrigin.ENGINE_POLICY,
            detail={"note": "x" * 500},
        )


def test_every_cue_type_the_package_can_emit_has_a_rule_behind_it() -> None:
    """No aspirational vocabulary: an enum member nothing produces is a promise
    the layer does not keep."""
    from ti_recon.reasoning.cues import LIFECYCLE_CUES

    produced = (
        {item[0] for item in SIGNAL_CUES.values()}
        | {item[0] for item in LIFECYCLE_CUES.values()}
        | {
            InterpretationCueType.HISTORICAL_MALICIOUS_CURRENTLY_INACTIVE,
            InterpretationCueType.PUBLIC_SERVICE_MAY_EXPLAIN_CONTACT,
        }
    )
    assert produced == set(InterpretationCueType)


# --------------------------------------------------------------------------- #
# Time: no hidden clock, no repair
# --------------------------------------------------------------------------- #


def test_a_future_timestamp_is_preserved_and_left_unaged() -> None:
    """Not clamped: an "age" of zero would read as "observed just now", which is
    precisely the wrong reading for a timestamp that cannot be right."""
    ahead = AS_OF + timedelta(days=3)
    fact = _fact(TemporalFactKind.LAST_OBSERVED, ahead)

    evaluated = qualify_facts([fact], as_of=AS_OF)
    qualification = evaluated.qualifications[0]

    assert qualification.fact.instant == ahead  # unchanged
    assert qualification.age_seconds is None
    assert qualification.age_days is None
    assert TemporalIssueType.FUTURE_TIMESTAMP in qualification.issue_types
    assert [item.issue_type for item in evaluated.issues] == [TemporalIssueType.FUTURE_TIMESTAMP]


def test_ordinary_clock_skew_is_absorbed_without_an_issue() -> None:
    """We and a provider do not share a clock; a couple of minutes is not a
    data problem worth putting in front of an analyst."""
    slightly_ahead = AS_OF + (CLOCK_SKEW_TOLERANCE / 2)
    evaluated = qualify_facts([_fact(TemporalFactKind.LAST_OBSERVED, slightly_ahead)], as_of=AS_OF)
    assert evaluated.qualifications[0].age_seconds == 0.0
    assert evaluated.issues == ()


def test_an_inverted_interval_is_reported_and_never_swapped() -> None:
    """Swapping the endpoints would invent an observation window the source
    never described, and the correction would be invisible."""
    start = _fact(TemporalFactKind.VALID_FROM, datetime(2026, 5, 1, tzinfo=UTC))
    end = _fact(TemporalFactKind.VALID_UNTIL, datetime(2026, 3, 1, tzinfo=UTC))

    evaluated = qualify_facts([start, end], as_of=AS_OF)

    issues = [
        item for item in evaluated.issues if item.issue_type is TemporalIssueType.INVALID_INTERVAL
    ]
    assert len(issues) == 1
    assert issues[0].kind is TemporalFactKind.VALID_FROM
    # Both endpoints survive with their original values.
    instants = {item.fact.kind: item.fact.instant for item in evaluated.qualifications}
    assert instants[TemporalFactKind.VALID_FROM] == datetime(2026, 5, 1, tzinfo=UTC)
    assert instants[TemporalFactKind.VALID_UNTIL] == datetime(2026, 3, 1, tzinfo=UTC)


def test_two_providers_reporting_one_bound_each_are_not_an_inverted_interval() -> None:
    """A first-seen from one source and a last-seen from another are two
    observations. Pairing them would manufacture a disagreement out of two
    perfectly consistent records."""
    late_start = _fact(
        TemporalFactKind.FIRST_OBSERVED, datetime(2026, 5, 1, tzinfo=UTC), origin="alpha"
    )
    early_end = _fact(
        TemporalFactKind.LAST_OBSERVED, datetime(2026, 3, 1, tzinfo=UTC), origin="beta"
    )
    assert qualify_facts([late_start, early_end], as_of=AS_OF).issues == ()


def test_nothing_in_the_package_reads_a_wall_clock() -> None:
    """``as_of`` is an argument, so a rule can never quietly become
    time-dependent in a place that is never handed a time."""
    offenders = [
        f"{path.name}: {node.func.attr}"
        for path in REASONING_PACKAGE.glob("*.py")
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"now", "utcnow", "today", "time"}
    ]
    # ``metrics.py`` stamps a metric with ``utc_now`` via a default factory,
    # which is a call site nothing reasons from; anything else is a hidden clock.
    assert offenders == []


def test_an_extractor_is_never_handed_a_clock() -> None:
    """Structural: the context a provider extractor receives has no time field."""
    from ti_recon.reasoning.extraction import QualificationContext

    assert not [
        name
        for name in QualificationContext.__dataclass_fields__
        if any(word in name for word in ("time", "now", "clock", "as_of"))
    ]


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #


def _full_inputs() -> tuple[object, ...]:
    return (
        urlhaus_url_envelope(),
        threatfox_ip_envelope(),
        threatfox_compromised_envelope(),
        malwarebazaar_envelope(),
        gti_file_envelope(),
        urlscan_scan_envelope(),
        sandbox_envelope(),
    )


def test_the_same_inputs_at_the_same_as_of_serialize_identically() -> None:
    """A stored qualification has to be re-derivable, or a diff between two runs
    means nothing."""
    envelopes = _full_inputs()
    engine = TemporalContextEngine()
    first = engine.evaluate(as_of=AS_OF, results=envelopes)
    second = engine.evaluate(as_of=AS_OF, results=envelopes)
    assert first.model_dump_json() == second.model_dump_json()


def test_shuffling_provider_results_changes_nothing() -> None:
    """Providers answer in whatever order Task 13 chose and Task 6 returned.
    Interpretation must not depend on it."""
    envelopes = list(_full_inputs())
    engine = TemporalContextEngine()
    baseline = engine.evaluate(as_of=AS_OF, results=envelopes).model_dump_json()

    shuffler = random.Random(20260829)
    for _ in range(5):
        shuffled = envelopes[:]
        shuffler.shuffle(shuffled)
        assert engine.evaluate(as_of=AS_OF, results=shuffled).model_dump_json() == baseline


def test_shuffling_graph_assertions_changes_nothing() -> None:
    """Two assertions on one edge, added in either order, qualify identically."""
    keys = []
    for order in (0, 1):
        graph = _graph_with_two_assertions(reverse=bool(order))
        result = TemporalContextEngine().evaluate(as_of=AS_OF, graph=graph)
        keys.append(result.model_dump_json())
    assert keys[0] == keys[1]


def test_two_assertions_on_one_edge_stay_two_observations() -> None:
    """A 2025 sighting and a 2026 sighting are two observations, never a
    continuous association across the years between them."""
    graph = _graph_with_two_assertions()
    result = TemporalContextEngine().evaluate(as_of=AS_OF, graph=graph)

    relationship_facts = [
        item.fact
        for item in result.temporal_qualifications
        if item.fact.subject.kind is SubjectKind.RELATIONSHIP
    ]
    # Two assertions, each contributing its own first- and last-observed bound.
    assert len(relationship_facts) == 4
    assert sorted({item.instant.year for item in relationship_facts}) == [2025, 2026]

    # Each keeps its own asserter, so neither can be read as covering the other,
    # and no fact spans the years between them.
    by_family: dict[str, set[int]] = {}
    for item in relationship_facts:
        by_family.setdefault(item.source_family or "", set()).add(item.instant.year)
    assert by_family == {"alpha": {2025}, "beta": {2026}}

    # The observation basis rides along as provenance and changes nothing else.
    assert {item.relation_basis for item in relationship_facts} == {
        RelationBasis.PROVIDER_REPORTED,
        RelationBasis.PROVIDER_OBSERVED,
    }
    assert result.coverage.relationship_assertions_examined == 2


def test_only_as_of_dependent_output_moves_when_as_of_moves() -> None:
    envelopes = _full_inputs()
    engine = TemporalContextEngine()
    early = engine.evaluate(as_of=AS_OF, results=envelopes)
    later = engine.evaluate(as_of=AS_OF + timedelta(days=1), results=envelopes)

    assert early.context_signals == later.context_signals
    assert early.interpretation_cues == later.interpretation_cues
    assert [item.fact for item in early.temporal_qualifications] == [
        item.fact for item in later.temporal_qualifications
    ]
    assert later.evaluated_at == AS_OF + timedelta(days=1)


def test_nothing_serialized_carries_a_python_object_identity() -> None:
    result = TemporalContextEngine().evaluate(as_of=AS_OF, results=_full_inputs())
    dumped = result.model_dump_json()
    assert "0x" not in dumped
    assert " object at " not in dumped


# --------------------------------------------------------------------------- #
# Metrics and coverage
# --------------------------------------------------------------------------- #


def test_metrics_are_counts_and_a_closed_cue_vocabulary() -> None:
    """A metric labelled with the IOC would turn a metrics pipeline into a record
    of every value every analyst has looked at."""
    sink = InMemoryQualificationMetricsSink(max_records=4)
    engine = TemporalContextEngine(metrics=sink)
    engine.evaluate(as_of=AS_OF, results=_full_inputs())

    metric = sink.records[-1]
    assert metric.temporal_facts > 0
    assert set(metric.cues_by_type) <= {item.value for item in InterpretationCueType}
    dumped = metric.model_dump_json()
    for leak in ("evil.example", "malware.example", "198.51.100", "analyst-a", "inv-1"):
        assert leak not in dumped


def test_the_metrics_sink_is_bounded_and_unfit_for_production() -> None:
    sink = InMemoryQualificationMetricsSink(max_records=1)
    assert sink.is_production_ready is False
    with pytest.raises(ValueError, match="max_records"):
        InMemoryQualificationMetricsSink(max_records=0)


def test_coverage_reports_what_was_examined_without_calling_absence_an_error() -> None:
    """Most providers time some claims and not others. Turning every missing
    timestamp into an issue would bury the two cases that mean the data is
    actually wrong."""
    result = TemporalContextEngine().evaluate(as_of=AS_OF, results=_full_inputs())
    coverage = result.coverage

    assert coverage.provider_results_examined == 7
    assert coverage.evidence_items_examined > coverage.evidence_with_temporal_facts
    assert coverage.temporal_issues == 0
    assert coverage.providers_without_qualifier == ()
    assert len(coverage.qualifiers_available) == 9


def test_a_partial_provider_result_is_marked_on_every_fact_it_produced() -> None:
    """ "From what was returned" rather than "from the record"."""
    from ti_recon.enums import ProviderRunStatus

    envelope = malwarebazaar_envelope()
    partial = envelope.model_copy(
        update={"status": ProviderRunStatus.PARTIAL, "error_category": None}
    )
    result = TemporalContextEngine().evaluate(as_of=AS_OF, results=[partial])

    assert result.coverage.partial_provider_results == 1
    assert result.temporal_qualifications
    assert all(item.fact.source_partial for item in result.temporal_qualifications)


def _fact(kind: TemporalFactKind, instant: datetime, *, origin: str = "alpha") -> TemporalFact:
    return TemporalFact(
        subject=report_subject("sandbox_x", "job-1"),
        kind=kind,
        instant=instant,
        transport_provider=origin,
        origin_provider=origin,
        source_family=origin,
    )


def _graph_with_two_assertions(*, reverse: bool = False) -> InvestigationGraph:
    """One edge, two providers, two separate years."""
    sample = file_object(sha256="f" * 64)
    domain = observable("evil.example")
    graph = InvestigationGraph(investigation_id="inv-1", authenticated_user_id="analyst-a")
    engine = CorrelationEngine(graph=graph)
    engine.add_root(sample)
    graph.upsert_node(
        GraphNode(node_key=domain.canonical_key, intel_object=domain, discovered_at_hop=1)
    )
    assertions = [
        RelationshipAssertion(
            basis=RelationBasis.PROVIDER_REPORTED,
            transport_provider="alpha",
            origin_provider="alpha",
            source_family="alpha",
            lineage_group_id="alpha:alpha",
            first_seen=datetime(2025, 1, 2, tzinfo=UTC),
            last_seen=datetime(2025, 1, 2, tzinfo=UTC),
        ),
        RelationshipAssertion(
            basis=RelationBasis.PROVIDER_OBSERVED,
            transport_provider="beta",
            origin_provider="beta",
            source_family="beta",
            lineage_group_id="beta:beta",
            first_seen=datetime(2026, 1, 2, tzinfo=UTC),
            last_seen=datetime(2026, 1, 2, tzinfo=UTC),
        ),
    ]
    for assertion in reversed(assertions) if reverse else assertions:
        graph.add_assertion(
            source_key=sample.canonical_key,
            relationship_type=RelationshipType.CONTACTS,
            target_key=domain.canonical_key,
            assertion=assertion,
        )
    return graph


# --------------------------------------------------------------------------- #
# Relayed sources
# --------------------------------------------------------------------------- #


def test_a_relayed_finding_is_never_independent_corroboration() -> None:
    """URLhaus relays a VirusTotal ratio; GTI answers directly from the same
    upstream. That is one source appearing twice, and Task 15's job is to make
    the dependence visible rather than to decide what it costs."""
    relayed = urlhaus_url_envelope()
    direct = gti_file_envelope()
    result = TemporalContextEngine().evaluate(as_of=AS_OF, results=[relayed, direct])

    signals = result.signals_of(ContextSignalType.RELAYED_SOURCE)
    assert signals
    virustotal = [item for item in signals if item.origin_provider == "virustotal"]
    assert virustotal
    assert virustotal[0].transport_provider == "urlhaus"
    # The relayed VirusTotal finding carries the same family a direct GTI result
    # carries, which is exactly what stops them counting as two.
    assert virustotal[0].detail["direct_family_present"] is True

    cues = result.cues_of(InterpretationCueType.RELAYED_SOURCE_NOT_INDEPENDENT)
    assert cues
    assert not [item for item in cues if "score" in item.detail or "weight" in item.detail]


def test_a_relayed_finding_alone_still_records_its_dependence() -> None:
    """Relayed is relayed whether or not the upstream also answered directly."""
    result = TemporalContextEngine().evaluate(as_of=AS_OF, results=[urlhaus_url_envelope()])
    virustotal = [
        item
        for item in result.signals_of(ContextSignalType.RELAYED_SOURCE)
        if item.origin_provider == "virustotal"
    ]
    assert virustotal
    assert virustotal[0].detail["direct_family_present"] is False


def test_a_lifecycle_state_can_never_be_read_as_safety() -> None:
    assert not [
        item
        for item in SourceLifecycleState
        if any(word in item.value for word in ("safe", "benign", "trust", "clean"))
    ]


def test_a_certificate_expiry_ahead_of_as_of_is_normal_and_unaged() -> None:
    """A ``not_after`` in the future is what a valid certificate looks like.

    Filing an issue against it would put ordinary correct data in front of an
    analyst as a defect, and would drown the two cases that mean the data is
    genuinely wrong. It is also not *aged* while it is still ahead: time
    remaining is a different quantity from elapsed time.
    """
    ahead = _fact(TemporalFactKind.VALID_UNTIL, AS_OF + timedelta(days=120))
    evaluated = qualify_facts([ahead], as_of=AS_OF)

    assert evaluated.issues == ()
    assert evaluated.qualifications[0].age_seconds is None
    assert evaluated.qualifications[0].fact.instant == AS_OF + timedelta(days=120)


def test_an_already_expired_certificate_ages_normally() -> None:
    """Once the instant has passed, the age means what it says: how long ago."""
    expired = _fact(TemporalFactKind.VALID_UNTIL, AS_OF - timedelta(days=30))
    evaluated = qualify_facts([expired], as_of=AS_OF)
    assert evaluated.qualifications[0].age_days == 30.0
    assert evaluated.issues == ()
