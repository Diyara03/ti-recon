"""The stopping objective reaches the request from the command line (Task 24 Phase 2)."""

from __future__ import annotations

from ti_recon.cli.main import _request_from
from ti_recon.cli.parser import build_parser
from ti_recon.investigation import InvestigationObjective


def test_the_objective_defaults_to_triage() -> None:
    args = build_parser().parse_args(["investigate", "203.0.113.5"])
    assert _request_from(args).objective is InvestigationObjective.TRIAGE


def test_corroborate_is_an_explicit_choice() -> None:
    args = build_parser().parse_args(["investigate", "203.0.113.5", "--objective", "corroborate"])
    assert _request_from(args).objective is InvestigationObjective.CORROBORATE
