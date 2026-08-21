"""Smoke test for the package skeleton."""

import ti_recon


def test_version_is_exposed() -> None:
    assert ti_recon.__version__ == "0.1.0"
