"""The local/remote dependency boundary (Task 23, Phase 3).

TI Recon's core requires what the local stdio server imports. The remote HTTP
surface additionally imports PyJWT with its crypto extra, uvicorn and
Starlette, and those live in the ``remote`` extra. What the split must never
do is weaken the remote surface: an environment installed without the extra
must be refused at startup, explicitly, rather than served with a verifier
whose security floor is not met.

One fact is recorded here because it is easy to assume the opposite: the MCP
SDK itself requires ``pyjwt[crypto]``, ``uvicorn`` and ``starlette``, and
imports ``cryptography`` when ``mcp.server`` is imported. So the split changes
what TI Recon declares and enforces, not what a local environment contains.
"""

from __future__ import annotations

import logging
import sys
import tomllib
import types
from pathlib import Path

import pytest

from ti_recon.mcp_server import http_main

ROOT = Path(__file__).resolve().parents[3]
REMOTE_ONLY = ("pyjwt", "uvicorn", "starlette")


def _pyproject() -> dict[str, object]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def _names(specifiers: list[str]) -> set[str]:
    return {
        spec.split("[")[0].split(">")[0].split("<")[0].split("=")[0].strip() for spec in specifiers
    }


# --------------------------------------------------------------------------- #
# Declarations
# --------------------------------------------------------------------------- #


def test_the_core_declares_nothing_only_the_remote_surface_imports() -> None:
    project = _pyproject()["project"]
    core = _names(project["dependencies"])  # type: ignore[index]
    for name in REMOTE_ONLY:
        assert name not in core, name


def test_the_remote_extra_declares_exactly_the_remote_imports_with_their_floors() -> None:
    project = _pyproject()["project"]
    remote = project["optional-dependencies"]["remote"]  # type: ignore[index]
    assert _names(remote) == set(REMOTE_ONLY)
    jwt = next(spec for spec in remote if spec.startswith("pyjwt"))
    assert "[crypto]" in jwt, "asymmetric verification needs the crypto extra"
    assert ">=2.13" in jwt, "the security floor the verifier's tests assume"


def test_the_metadata_floor_and_the_runtime_floor_are_the_same_number() -> None:
    project = _pyproject()["project"]
    remote = project["optional-dependencies"]["remote"]  # type: ignore[index]
    jwt = next(spec for spec in remote if spec.startswith("pyjwt"))
    major, minor = http_main.MINIMUM_PYJWT
    assert f">={major}.{minor}" in jwt


def test_no_local_module_imports_a_remote_only_package() -> None:
    """The stdio path never touches PyJWT, uvicorn or Starlette itself."""
    local = ("main.py", "server.py", "tools.py", "runtime.py", "models.py", "limits.py")
    for name in local:
        text = (ROOT / "src" / "ti_recon" / "mcp_server" / name).read_text(encoding="utf-8")
        for package in (
            "import jwt",
            "from jwt",
            "import uvicorn",
            "from starlette",
            "import starlette",
        ):
            assert package not in text, f"{name}: {package}"


# --------------------------------------------------------------------------- #
# Enforcement at remote startup
# --------------------------------------------------------------------------- #


def test_the_development_environment_satisfies_the_remote_floor() -> None:
    """The suite runs with the extra installed; the check must pass here."""
    http_main.require_remote_dependencies()


def _fake_jwt(version: str, *, has_crypto: bool) -> types.ModuleType:
    module = types.ModuleType("jwt")
    module.__version__ = version  # type: ignore[attr-defined]
    algorithms = types.ModuleType("jwt.algorithms")
    algorithms.has_crypto = has_crypto  # type: ignore[attr-defined]
    module.algorithms = algorithms  # type: ignore[attr-defined]
    return module


def test_a_pyjwt_below_the_floor_is_refused_by_name(monkeypatch) -> None:
    fake = _fake_jwt("2.10.1", has_crypto=True)
    monkeypatch.setitem(sys.modules, "jwt", fake)
    monkeypatch.setitem(sys.modules, "jwt.algorithms", fake.algorithms)  # type: ignore[attr-defined]
    with pytest.raises(http_main.RemoteDependencyError, match=r"2\.10\.1.*floor.*remote"):
        http_main.require_remote_dependencies()


def test_pyjwt_without_its_crypto_extra_is_refused(monkeypatch) -> None:
    """HMAC-only PyJWT cannot verify against a JWKS; it must not be served."""
    fake = _fake_jwt("2.13.0", has_crypto=False)
    monkeypatch.setitem(sys.modules, "jwt", fake)
    monkeypatch.setitem(sys.modules, "jwt.algorithms", fake.algorithms)  # type: ignore[attr-defined]
    with pytest.raises(http_main.RemoteDependencyError, match="crypto"):
        http_main.require_remote_dependencies()


def test_a_missing_pyjwt_is_refused_not_worked_around(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "jwt", None)  # makes `import jwt` raise ImportError
    with pytest.raises(http_main.RemoteDependencyError, match="PyJWT is not installed"):
        http_main.require_remote_dependencies()


def test_a_missing_uvicorn_is_refused(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "uvicorn", None)
    with pytest.raises(http_main.RemoteDependencyError, match="uvicorn"):
        http_main.require_remote_dependencies()


def test_the_remote_process_exits_before_reading_configuration(monkeypatch, capsys) -> None:
    """Nothing listens, no configuration is read, and the error names no value.

    The entry point owns logging and attaches its own stderr handler, so the
    message is read from the captured stderr rather than from ``caplog``.
    """
    monkeypatch.setitem(sys.modules, "jwt", None)
    monkeypatch.setenv("TI_RECON_TENANT_KEY_B64", "SHOULD_NOT_BE_ECHOED_ANYWHERE")
    called: list[str] = []
    monkeypatch.setattr(http_main, "load_deployment", lambda: called.append("read") or None)
    saved = {
        name: (list(logging.getLogger(name).handlers), logging.getLogger(name).propagate)
        for name in ("ti_recon", "mcp", "ti_recon.mcp_server")
    }
    try:
        assert http_main.main([]) == 2
        captured = capsys.readouterr()
    finally:
        for name, (handlers, propagate) in saved.items():
            logging.getLogger(name).handlers = handlers
            logging.getLogger(name).propagate = propagate

    assert called == []
    assert captured.out == ""
    assert "dependency error" in captured.err
    assert "SHOULD_NOT_BE_ECHOED_ANYWHERE" not in captured.err
