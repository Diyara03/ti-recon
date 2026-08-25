"""The live smoke suites must cost what they say they cost.

Offline and static: this file parses the live test modules and never runs them.

Three live suites are metered in some way — GreyNoise over a weekly lookup
allowance, Censys per asset read in credits, abuse.ch by a free service's
published fair-use limits — and each documents a specific cost. The obvious way
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


SUITES: Final[dict[str, LiveSuite]] = {
    "greynoise": LiveSuite(GREYNOISE_LIVE, frozenset({"SMOKE_ADDRESS"}), platforms=1),
    "censys": LiveSuite(CENSYS_LIVE, frozenset({"SMOKE_ADDRESS"}), platforms=1),
    "abusech": LiveSuite(
        ABUSECH_LIVE,
        frozenset({"SMOKE_ADDRESS", "SMOKE_URL", "SMOKE_HASH", "smoke_file"}),
        platforms=3,
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
    assert "exactly one physical" in docstring


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


def test_the_abusech_suite_performs_no_write_query() -> None:
    """Every abuse.ch write lives one string away from a read; not in a live file."""
    source = ABUSECH_LIVE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    called = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    for forbidden in (
        "submit_ioc",
        "get_file",
        "upload",
        "update",
        "add_comment",
        "lookup_payload",
        "search_hash",
    ):
        assert forbidden not in called
    for forbidden in ("submit_ioc", "get_file", "add_comment", "upload"):
        # Not even as a literal: a live file is not where a write query is drafted.
        assert f'"{forbidden}"' not in source


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
