"""The live smoke suites must cost what they say they cost.

Offline and static: this file parses the live test modules and never runs them.

Four live suites are metered in some way — GreyNoise over a weekly lookup
allowance, Censys per asset read in credits, abuse.ch by a free service's
published fair-use limits, Hybrid Analysis at roughly five requests a minute on a
restricted key — and each documents a specific cost. The obvious way
to break that documentation is also the most natural thing to write: give each
assertion its own ``adapter.lookup(...)`` call. That bypasses the Task 6 cache
and quietly multiplies the bill by the number of tests, which is exactly what an
earlier version of the Censys file did.

So the claim is enforced here rather than trusted. Inside a ``test_*`` function,
no function may build a request for one of the module's metered observables, and
no test may drive the executor; all provider traffic goes through the single
shared helper, and the helper performs one request pair per platform, once.

A test that needs live enrichment data reads the shared outcome. A test that
genuinely needs a second physical request would have to change this file too,
which is the point.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import pytest

#: The live modules are read from disk rather than imported: a static check
#: should not execute the thing it is checking.
_LIVE_DIR: Final[Path] = Path(__file__).resolve().parents[1] / "live"
GREYNOISE_LIVE: Final[Path] = _LIVE_DIR / "test_greynoise_live.py"
CENSYS_LIVE: Final[Path] = _LIVE_DIR / "test_censys_live.py"
ABUSECH_LIVE: Final[Path] = _LIVE_DIR / "test_abusech_live.py"
HYBRID_ANALYSIS_LIVE: Final[Path] = _LIVE_DIR / "test_hybrid_analysis_live.py"

#: How a request for an observable is constructed in these modules.
_REQUEST_BUILDERS: Final[frozenset[str]] = frozenset({"request_for"})

#: The call that actually reaches a provider through the execution layer.
_EXECUTE: Final[frozenset[str]] = frozenset({"execute"})

#: The helper allowed to spend the run's requests. One name across all three
#: modules, so the rule reads the same wherever it is applied.
_PAYING_HELPER: Final[str] = "_perform_single_lookup"


@dataclass(frozen=True, slots=True)
class LiveSuite:
    """What one live module is allowed to cost, and how that is recognized.

    ``subjects`` names the module-level constants that identify a metered
    observable: building a request around one of them is the only way to spend
    anything, so those constants — not every mention of a value — are what has
    to stay inside the paying helper.

    ``expected_calls`` counts ``execute`` **call sites** in the paying helper,
    not requests: two, always — the one that pays and the one the cache must
    answer. A module covering several platforms loops over that pair rather than
    repeating it, so how many platforms the loop covers is bounded separately
    (see :func:`test_the_abusech_helper_covers_three_platforms_and_no_more`).

    ``platforms`` is how many times that pair runs, and therefore how many
    physical requests a full run makes.
    """

    path: Path
    subjects: frozenset[str]
    platforms: int
    expected_calls: int = 2
    #: The sentence the module must contain, stating what a run costs. Per-suite
    #: because the suites cost different things and each should say its own
    #: number rather than a shared form of words.
    cost_phrase: str = "exactly one physical"


SUITES: Final[dict[str, LiveSuite]] = {
    "greynoise": LiveSuite(GREYNOISE_LIVE, frozenset({"SMOKE_ADDRESS"}), platforms=1),
    "censys": LiveSuite(CENSYS_LIVE, frozenset({"SMOKE_ADDRESS"}), platforms=1),
    "abusech": LiveSuite(
        ABUSECH_LIVE,
        frozenset({"SMOKE_IOC", "SMOKE_URL", "SMOKE_HASH", "smoke_file"}),
        platforms=3,
    ),
    "hybrid_analysis": LiveSuite(
        HYBRID_ANALYSIS_LIVE,
        frozenset({"SMOKE_SHA256", "smoke_file"}),
        platforms=1,
        # Two: a search plus, at STANDARD depth, at most one report summary.
        cost_phrase="at most two physical requests",
    ),
}

LIVE_MODULES = pytest.mark.parametrize(
    "suite", [pytest.param(suite, id=name) for name, suite in SUITES.items()]
)


def _tree(module: Path) -> ast.Module:
    return ast.parse(module.read_text(encoding="utf-8"))


def _functions(tree: ast.Module) -> list[ast.AsyncFunctionDef | ast.FunctionDef]:
    return [
        node for node in ast.walk(tree) if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef)
    ]


def _calls_named(node: ast.AST, names: frozenset[str] | set[str]) -> list[ast.Call]:
    """Every call in ``node`` to an attribute or function with one of ``names``."""
    return [
        candidate
        for candidate in ast.walk(node)
        if isinstance(candidate, ast.Call) and _called_name(candidate.func) in names
    ]


def _called_name(function: ast.expr) -> str | None:
    """The bare name of whatever is being called, attribute or plain name."""
    if isinstance(function, ast.Attribute):
        return function.attr
    if isinstance(function, ast.Name):
        return function.id
    return None


def _builds_the_smoke_request(function: ast.AST, subjects: frozenset[str]) -> bool:
    """Whether this function constructs a request for a metered observable.

    Building one is the only way to spend a live request, so this — rather than
    every mention of the value — is what has to be confined to one place. A test
    asserting ``coverage["asset"] == SMOKE_ADDRESS`` costs nothing and is left
    alone.
    """
    return any(
        isinstance(inner, ast.Name) and inner.id in subjects
        for call in _calls_named(function, _REQUEST_BUILDERS)
        for argument in list(call.args) + [keyword.value for keyword in call.keywords]
        for inner in ast.walk(argument)
    )


@LIVE_MODULES
def test_no_test_function_builds_a_metered_request(suite: LiveSuite) -> None:
    """Every paid request goes through the shared helper, not through a test."""
    offenders = sorted(
        function.name
        for function in _functions(_tree(suite.path))
        if function.name.startswith("test_") and _builds_the_smoke_request(function, suite.subjects)
    )
    assert offenders == [], (
        f"these tests would each spend a live request: {offenders}. "
        f"Read the shared outcome instead."
    )


@LIVE_MODULES
def test_only_the_shared_helper_builds_a_metered_request(suite: LiveSuite) -> None:
    """One place decides what a live run costs."""
    spenders = {
        function.name
        for function in _functions(_tree(suite.path))
        if _builds_the_smoke_request(function, suite.subjects)
    }
    assert spenders == {_PAYING_HELPER}


@LIVE_MODULES
def test_no_test_function_drives_the_executor_itself(suite: LiveSuite) -> None:
    """A second ``execute`` in a test is a second request, cache or no cache."""
    executors = {
        function.name
        for function in _functions(_tree(suite.path))
        if _calls_named(function, _EXECUTE)
    }
    assert executors == {_PAYING_HELPER}


@LIVE_MODULES
def test_the_shared_helper_pays_once_per_platform(suite: LiveSuite) -> None:
    """Two executions per platform: the one that costs, and the one that must not."""
    helper = next(
        function for function in _functions(_tree(suite.path)) if function.name == _PAYING_HELPER
    )
    assert len(_calls_named(helper, _EXECUTE)) == suite.expected_calls


@LIVE_MODULES
def test_the_shared_outcome_is_computed_at_most_once(suite: LiveSuite) -> None:
    """A module-level slot, so fixture scope and test ordering cannot multiply it."""
    tree = _tree(suite.path)
    slots = [
        node.target.id
        for node in ast.walk(tree)
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    ]
    assert "_LOOKUP" in slots

    accessor = next(function for function in _functions(tree) if function.name == "live_lookup")
    assert any(isinstance(node, ast.Global) for node in ast.walk(accessor))


@LIVE_MODULES
def test_the_live_module_documents_what_a_run_costs(suite: LiveSuite) -> None:
    """The prose and the structure have to agree, so both are checked."""
    docstring = ast.get_docstring(_tree(suite.path)) or ""
    assert suite.cost_phrase in docstring


def test_the_censys_suite_performs_no_search_at_any_depth() -> None:
    """Search is deferred; a live file must not be where it creeps back in."""
    tree = _tree(CENSYS_LIVE)
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    for forbidden in ("search", "query", "rescan", "get_web_property", "get_host"):
        assert forbidden not in called


def test_the_greynoise_suite_validates_without_an_intelligence_lookup() -> None:
    """Credential and health checks must not touch an IP endpoint."""
    tree = _tree(GREYNOISE_LIVE)
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "get_ip_context" not in called
    assert "get_community" not in called


#: abuse.ch query names that write, transfer or bulk-export. None may be called
#: from a live module, and none may be drafted as a query value there.
_ABUSECH_WRITE_QUERIES: Final[frozenset[str]] = frozenset(
    {
        "submit_ioc",
        "get_file",
        "upload",
        "update",
        "add_comment",
        "get_recent",
        "get_iocs",
    }
)

#: Read helpers that exist but are not part of the three-request budget.
_ABUSECH_UNBUDGETED_READS: Final[frozenset[str]] = frozenset(
    {"lookup_payload", "lookup_host", "search_hash"}
)


def _query_values(tree: ast.Module) -> set[str]:
    """Every string a call passes as a ``query``, by keyword or in a form dict.

    Precise on purpose. An earlier version scanned the whole file for the write
    names as literals, which flagged the tests that assert those names are
    *absent* — a guard that fires on the assertion proving its own point is a
    guard nobody will keep. What actually issues a write is a query value, so
    that is what this reads.
    """
    values: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.keyword)
            and node.arg == "query"
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            values.add(node.value.value)
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "query"
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    values.add(value.value)
    return values


def test_the_abusech_suite_performs_no_write_query() -> None:
    """Every abuse.ch write lives one string away from a read; not in a live file."""
    tree = _tree(ABUSECH_LIVE)
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not (called & _ABUSECH_WRITE_QUERIES)
    # Nor a read outside the budget: three requests means three client methods.
    assert not (called & _ABUSECH_UNBUDGETED_READS)
    # And none of them drafted as a query value, which is what would send one.
    assert not (_query_values(tree) & _ABUSECH_WRITE_QUERIES)


def test_the_abusech_suite_validates_no_credential_separately() -> None:
    """None of these APIs has a zero-cost status endpoint, so a probe costs a query."""
    tree = ast.parse(ABUSECH_LIVE.read_text(encoding="utf-8"))
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "validate_credentials" not in called
    assert "health" not in called


def test_the_abusech_helper_covers_three_platforms_and_no_more() -> None:
    """The loop's length is what a full run costs, so it is bounded here too.

    The helper issues one execute pair inside a loop over its ``plan``. Three
    entries, three platforms, three physical requests. A fourth entry — a second
    URLhaus endpoint, a hash search alongside the IOC search — would change what
    a live run costs, so it has to change this test as well.
    """
    tree = _tree(ABUSECH_LIVE)
    helper = next(function for function in _functions(tree) if function.name == _PAYING_HELPER)
    plan = next(
        node.value
        for node in ast.walk(helper)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "plan" for target in node.targets)
    )
    assert isinstance(plan, ast.Tuple)
    assert len(plan.elts) == SUITES["abusech"].platforms


#: Hybrid Analysis routes that submit, detonate or transfer. None may appear in a
#: live module, and none may be reachable from one.
_HYBRID_ANALYSIS_FORBIDDEN_ROUTES: Final[frozenset[str]] = frozenset(
    {
        "submit",
        "quick-scan",
        "refresh",
        "pcap",
        "memory-dumps",
        "screenshots",
        "dropped-file",
        "report/json",
    }
)


def test_the_hybrid_analysis_suite_requests_no_transfer_route() -> None:
    """The routes this provider must never touch, checked in the live file too.

    A live suite is where a "just fetch the PCAP to check" would be most
    tempting and least visible.
    """
    tree = _tree(HYBRID_ANALYSIS_LIVE)
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    for forbidden in ("search_hash", "report_summary", "key_current"):
        # Direct client use bypasses the executor and the shared helper.
        assert forbidden not in called, f"live suite calls the client directly: {forbidden}"

    # Route-shaped literals only. The module docstring names the absent routes
    # in prose precisely to explain that they are absent, and a scan that flagged
    # that would fire on its own explanation.
    routes = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and ("api/v2" in node.value or node.value.startswith("/"))
    }
    for route in routes:
        for forbidden in _HYBRID_ANALYSIS_FORBIDDEN_ROUTES:
            assert forbidden not in route, f"live suite names route {forbidden}"


def test_the_hybrid_analysis_suite_validates_no_credential_separately() -> None:
    """A successful search already proves the key is accepted.

    ``/key/current`` would be 20% of a minute's allowance on a restricted key.
    """
    tree = _tree(HYBRID_ANALYSIS_LIVE)
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "validate_credentials" not in called
    assert "health" not in called


def test_the_hybrid_analysis_suite_stays_at_standard_depth() -> None:
    """DEEP would add a third request for no additional coverage of the path."""
    source = HYBRID_ANALYSIS_LIVE.read_text(encoding="utf-8")
    assert "InvestigationDepth.DEEP" not in source
