"""The live smoke suites must cost what they say they cost.

Offline and static: this file parses the live test modules and never runs them.

Both GreyNoise and Censys meter what a live run spends — GreyNoise over a weekly
lookup allowance, Censys per asset read in credits — and both live modules
document a specific cost. The obvious way to break that documentation is also the
most natural thing to write: give each assertion its own ``adapter.lookup(...)``
call. That bypasses the Task 6 cache and quietly multiplies the bill by the
number of tests, which is exactly what an earlier version of the Censys file did.

So the claim is enforced here rather than trusted. Inside a ``test_*`` function,
no function may build a request for the module's metered observable, and no test
may drive the executor; all provider traffic goes through the single shared
helper, and the helper performs the request pair exactly once.

A test that needs live enrichment data reads the shared outcome. A test that
genuinely needs a second physical request would have to change this file too,
which is the point.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

import pytest

#: The live modules are read from disk rather than imported: a static check
#: should not execute the thing it is checking.
_LIVE_DIR: Final[Path] = Path(__file__).resolve().parents[1] / "live"
GREYNOISE_LIVE: Final[Path] = _LIVE_DIR / "test_greynoise_live.py"
CENSYS_LIVE: Final[Path] = _LIVE_DIR / "test_censys_live.py"

#: How a request for an observable is constructed in these modules.
_REQUEST_BUILDERS: Final[frozenset[str]] = frozenset({"request_for"})

#: The call that actually reaches a provider through the execution layer.
_EXECUTE: Final[frozenset[str]] = frozenset({"execute"})

#: The helper allowed to spend the run's one request, and how many provider
#: calls it may make: one that pays, and one that must be served from cache.
_PAYING_HELPER: Final[str] = "_perform_single_lookup"
_EXPECTED_CALLS: Final[int] = 2

LIVE_MODULES = pytest.mark.parametrize(
    "module",
    [
        pytest.param(GREYNOISE_LIVE, id="greynoise"),
        pytest.param(CENSYS_LIVE, id="censys"),
    ],
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


def _builds_the_smoke_request(function: ast.AST) -> bool:
    """Whether this function constructs a request for the metered observable.

    Building one is the only way to spend a live request, so this — rather than
    every mention of the address — is what has to be confined to one place. A
    test asserting ``coverage["asset"] == SMOKE_ADDRESS`` costs nothing and is
    left alone.
    """
    return any(
        isinstance(inner, ast.Name) and inner.id == "SMOKE_ADDRESS"
        for call in _calls_named(function, _REQUEST_BUILDERS)
        for argument in list(call.args) + [keyword.value for keyword in call.keywords]
        for inner in ast.walk(argument)
    )


@LIVE_MODULES
def test_no_test_function_builds_a_metered_request(module: Path) -> None:
    """Every paid request goes through the shared helper, not through a test."""
    offenders = sorted(
        function.name
        for function in _functions(_tree(module))
        if function.name.startswith("test_") and _builds_the_smoke_request(function)
    )
    assert offenders == [], (
        f"these tests would each spend a live request: {offenders}. "
        f"Read the shared outcome instead."
    )


@LIVE_MODULES
def test_only_the_shared_helper_builds_a_metered_request(module: Path) -> None:
    """One place decides what a live run costs."""
    spenders = {
        function.name
        for function in _functions(_tree(module))
        if _builds_the_smoke_request(function)
    }
    assert spenders == {_PAYING_HELPER}


@LIVE_MODULES
def test_no_test_function_drives_the_executor_itself(module: Path) -> None:
    """A second ``execute`` in a test is a second request, cache or no cache."""
    executors = {
        function.name for function in _functions(_tree(module)) if _calls_named(function, _EXECUTE)
    }
    assert executors == {_PAYING_HELPER}


@LIVE_MODULES
def test_the_shared_helper_pays_once_and_proves_the_cache(module: Path) -> None:
    """Two executions: the one that costs, and the one that must not."""
    helper = next(
        function for function in _functions(_tree(module)) if function.name == _PAYING_HELPER
    )
    calls = _calls_named(helper, _EXECUTE)
    assert len(calls) == _EXPECTED_CALLS


@LIVE_MODULES
def test_the_shared_outcome_is_computed_at_most_once(module: Path) -> None:
    """A module-level slot, so fixture scope and test ordering cannot multiply it."""
    tree = _tree(module)
    slots = [
        node.target.id
        for node in ast.walk(tree)
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    ]
    assert "_LOOKUP" in slots

    accessor = next(function for function in _functions(tree) if function.name == "live_lookup")
    assert any(isinstance(node, ast.Global) for node in ast.walk(accessor))


@LIVE_MODULES
def test_the_live_module_documents_what_a_run_costs(module: Path) -> None:
    """The prose and the structure have to agree, so both are checked."""
    docstring = ast.get_docstring(_tree(module)) or ""
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
