"""Provider-neutral sandbox semantics (Task 12).

The framework's job is to make two mistakes impossible: reading a sandbox
non-detection as evidence of safety, and reading one provider's several runs as
several sources. Everything here defends one of those.
"""

from __future__ import annotations

import pytest

from ti_recon.enums import EvidenceEffect, InvestigationDepth
from ti_recon.sandbox import (
    HARD_CEILINGS,
    SANDBOX_VERDICT_EFFECT,
    SandboxAnalysisQuality,
    SandboxEnvironment,
    SandboxExtractedFile,
    SandboxReportRef,
    SandboxReportState,
    SandboxReportSummary,
    SandboxSampleView,
    SandboxVerdict,
    bounds_for_depth,
    verdict_rank,
)


def ref(
    report_id: str,
    *,
    verdict: SandboxVerdict = SandboxVerdict.MALICIOUS,
    state: SandboxReportState = SandboxReportState.SUCCESS,
    environment: str = "140",
) -> SandboxReportRef:
    return SandboxReportRef(
        report_id=report_id,
        environment=SandboxEnvironment(
            environment_id=environment, description=f"env {environment}"
        ),
        state=state,
        verdict=verdict,
    )


# --------------------------------------------------------------------------- #
# No sandbox result is ever benign
# --------------------------------------------------------------------------- #


def test_no_verdict_maps_to_benign() -> None:
    """The invariant the whole framework exists for.

    A sandbox failing to observe malice is a fact about one execution in one
    environment. If any verdict could produce SUPPORTS_BENIGN, an evasive sample
    would earn exoneration by being good at hiding.
    """
    assert EvidenceEffect.SUPPORTS_BENIGN not in set(SANDBOX_VERDICT_EFFECT.values())


@pytest.mark.parametrize(
    ("verdict", "expected"),
    [
        (SandboxVerdict.MALICIOUS, EvidenceEffect.SUPPORTS_MALICIOUS),
        (SandboxVerdict.SUSPICIOUS, EvidenceEffect.SUPPORTS_MALICIOUS),
        (SandboxVerdict.NO_SPECIFIC_THREAT, EvidenceEffect.CONTEXT_ONLY),
        (SandboxVerdict.NO_VERDICT, EvidenceEffect.CONTEXT_ONLY),
        (SandboxVerdict.ALLOWLISTED, EvidenceEffect.CONTEXT_ONLY),
        (SandboxVerdict.UNKNOWN, EvidenceEffect.CONTEXT_ONLY),
    ],
)
def test_verdict_effects(verdict: SandboxVerdict, expected: EvidenceEffect) -> None:
    assert SANDBOX_VERDICT_EFFECT[verdict] is expected


def test_every_verdict_has_an_effect() -> None:
    """A new verdict must not silently default to pointing somewhere."""
    assert set(SANDBOX_VERDICT_EFFECT) == set(SandboxVerdict)


def test_suspicious_points_at_malicious_without_becoming_malicious() -> None:
    """Direction and strength are separate concerns in the Task 3 model."""
    view = SandboxSampleView(reports=(ref("r1", verdict=SandboxVerdict.SUSPICIOUS),))
    assert view.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert view.strongest_verdict is SandboxVerdict.SUSPICIOUS
    assert view.strongest_verdict is not SandboxVerdict.MALICIOUS


def test_an_allowlist_hit_is_not_benign() -> None:
    """It says the provider does not analyse this file, not that it is safe."""
    view = SandboxSampleView(reports=(ref("r1", verdict=SandboxVerdict.ALLOWLISTED),))
    assert view.effect is EvidenceEffect.CONTEXT_ONLY


def test_an_empty_view_points_nowhere() -> None:
    view = SandboxSampleView()
    assert view.strongest_verdict is SandboxVerdict.UNKNOWN
    assert view.effect is EvidenceEffect.CONTEXT_ONLY


# --------------------------------------------------------------------------- #
# State is not verdict
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("state", "complete"),
    [
        (SandboxReportState.SUCCESS, True),
        (SandboxReportState.PARTIAL_SUCCESS, True),
        (SandboxReportState.ERROR, False),
        (SandboxReportState.IN_QUEUE, False),
        (SandboxReportState.IN_PROGRESS, False),
        (SandboxReportState.UNKNOWN, False),
    ],
)
def test_only_finished_runs_count_as_complete(state: SandboxReportState, complete: bool) -> None:
    assert state.is_complete is complete
    assert ref("r", state=state).is_selectable is complete


def test_a_failed_run_never_contributes_a_verdict() -> None:
    """Otherwise an infrastructure failure becomes an opinion.

    The ERROR report here carries `malicious`, which providers do emit. It must
    not reach `strongest_verdict`.
    """
    view = SandboxSampleView(
        reports=(
            ref("r1", verdict=SandboxVerdict.MALICIOUS, state=SandboxReportState.ERROR),
            ref("r2", verdict=SandboxVerdict.NO_VERDICT, state=SandboxReportState.SUCCESS),
        )
    )
    assert view.strongest_verdict is SandboxVerdict.NO_VERDICT
    assert view.effect is EvidenceEffect.CONTEXT_ONLY


def test_reports_that_all_failed_are_a_coverage_fact() -> None:
    view = SandboxSampleView(
        reports=(
            ref("r1", state=SandboxReportState.ERROR),
            ref("r2", state=SandboxReportState.IN_QUEUE),
        )
    )
    assert view.has_only_failed_reports is True
    assert view.completed_reports == ()
    assert view.effect is EvidenceEffect.CONTEXT_ONLY


def test_no_reports_at_all_is_not_the_same_as_all_failed() -> None:
    assert SandboxSampleView().has_only_failed_reports is False


# --------------------------------------------------------------------------- #
# Divergence is preserved
# --------------------------------------------------------------------------- #


def test_one_sample_can_have_many_reports_in_many_environments() -> None:
    view = SandboxSampleView(
        reports=(
            ref("r1", environment="120"),
            ref("r2", environment="140"),
            ref("r3", environment="110"),
        )
    )
    assert view.report_count == 3
    assert set(view.verdicts_by_environment) == {"120", "140", "110"}


def test_disagreeing_environments_are_recorded_rather_than_resolved() -> None:
    """Environment-dependent behaviour is how targeted malware works."""
    view = SandboxSampleView(
        reports=(
            ref("r1", verdict=SandboxVerdict.MALICIOUS, environment="140"),
            ref("r2", verdict=SandboxVerdict.NO_SPECIFIC_THREAT, environment="120"),
        )
    )
    assert view.divergent_verdicts is True
    assert view.verdicts_by_environment == {"140": "malicious", "120": "no_specific_threat"}
    # The strongest completed verdict still leads, without erasing the other.
    assert view.strongest_verdict is SandboxVerdict.MALICIOUS


def test_agreeing_reports_are_not_divergent() -> None:
    view = SandboxSampleView(reports=(ref("r1", environment="140"), ref("r2", environment="120")))
    assert view.divergent_verdicts is False


def test_divergence_ignores_failed_runs() -> None:
    """A run that never happened cannot disagree with one that did."""
    view = SandboxSampleView(
        reports=(
            ref("r1", verdict=SandboxVerdict.MALICIOUS),
            ref("r2", verdict=SandboxVerdict.NO_VERDICT, state=SandboxReportState.ERROR),
        )
    )
    assert view.divergent_verdicts is False


def test_verdict_ranking_orders_by_selection_strength() -> None:
    assert verdict_rank(SandboxVerdict.MALICIOUS) > verdict_rank(SandboxVerdict.SUSPICIOUS)
    assert verdict_rank(SandboxVerdict.SUSPICIOUS) > verdict_rank(SandboxVerdict.NO_SPECIFIC_THREAT)
    assert verdict_rank(SandboxVerdict.NO_SPECIFIC_THREAT) > verdict_rank(SandboxVerdict.NO_VERDICT)


# --------------------------------------------------------------------------- #
# Quality: nothing happened vs nothing could have happened
# --------------------------------------------------------------------------- #


def test_a_run_that_executed_nothing_is_visible_as_such() -> None:
    """The distinction a later false-positive layer depends on."""
    empty = SandboxAnalysisQuality(
        state=SandboxReportState.SUCCESS, total_processes=0, total_network_connections=0
    )
    busy = SandboxAnalysisQuality(
        state=SandboxReportState.SUCCESS, total_processes=11, total_network_connections=40
    )
    assert empty.observed_any_execution is False
    assert busy.observed_any_execution is True


def test_quality_keeps_the_execution_context() -> None:
    quality = SandboxAnalysisQuality(
        state=SandboxReportState.SUCCESS,
        runtime_seconds=30,
        network_mode="simulated",
        action_script="default",
        anti_evasion=False,
        warnings=("Sample did not reach its command and control server",),
    )
    assert quality.runtime_seconds == 30
    assert quality.network_mode == "simulated"
    assert quality.warnings
    # None of it is a verdict.
    assert not hasattr(quality, "verdict")


def test_an_unknown_execution_knob_stays_unknown() -> None:
    """`None` is not `False`: not knowing whether anti-evasion ran matters."""
    quality = SandboxAnalysisQuality()
    assert quality.anti_evasion is None
    assert quality.script_logging is None
    assert quality.sample_tampering_allowed is None


# --------------------------------------------------------------------------- #
# Bounds
# --------------------------------------------------------------------------- #


def test_quick_normalizes_no_detail_because_it_fetches_no_report() -> None:
    bounds = bounds_for_depth(InvestigationDepth.QUICK)
    assert bounds.processes == 0
    assert bounds.network == 0
    assert bounds.signatures == 0


def test_deeper_depths_keep_more() -> None:
    quick = bounds_for_depth(InvestigationDepth.QUICK)
    standard = bounds_for_depth(InvestigationDepth.STANDARD)
    deep = bounds_for_depth(InvestigationDepth.DEEP)
    for name in ("processes", "network", "signatures", "extracted_files"):
        assert getattr(quick, name) <= getattr(standard, name) <= getattr(deep, name)


def test_no_depth_exceeds_the_hard_ceilings() -> None:
    for depth in InvestigationDepth:
        bounds = bounds_for_depth(depth)
        for name, ceiling in HARD_CEILINGS.items():
            assert getattr(bounds, name) <= ceiling


def test_a_configured_bound_is_still_capped() -> None:
    """A configuration cannot raise a ceiling."""
    from ti_recon.sandbox.bounds import SandboxBounds

    absurd = SandboxBounds(
        signatures=10_000,
        techniques=10_000,
        processes=10_000,
        network=10_000,
        extracted_files=10_000,
        certificates=10_000,
        tags=10_000,
        warnings=10_000,
    ).capped()
    for name, ceiling in HARD_CEILINGS.items():
        assert getattr(absurd, name) == ceiling


def test_an_unknown_depth_falls_back_to_standard_not_the_largest() -> None:
    """A new depth value must not silently authorise the most expensive path."""
    assert bounds_for_depth(InvestigationDepth.STANDARD, {}) == bounds_for_depth(
        InvestigationDepth.STANDARD
    )


# --------------------------------------------------------------------------- #
# Structural integrity
# --------------------------------------------------------------------------- #


def test_a_summary_must_belong_to_an_indexed_report() -> None:
    """Otherwise the two halves came from different lookups and divergence is fiction."""
    with pytest.raises(ValueError, match="correspond to indexed reports"):
        SandboxSampleView(
            reports=(ref("r1"),),
            summaries=(SandboxReportSummary(report_id="somewhere-else"),),
        )


def test_an_extracted_file_reports_its_strongest_digest() -> None:
    assert SandboxExtractedFile(sha256="a" * 64, md5="b" * 32).strongest_hash == (
        "SHA-256",
        "a" * 64,
    )
    assert SandboxExtractedFile(md5="b" * 32).strongest_hash == ("MD5", "b" * 32)
    assert SandboxExtractedFile(name="no-hashes").strongest_hash is None


def test_the_framework_depends_on_no_provider() -> None:
    """A model shaped around one sandbox's JSON is not a framework.

    Checked on the AST rather than on the text: the docstrings deliberately
    *name* future providers as examples, and a prose scan that flagged them would
    fire on its own explanation. What matters is that no code here imports or
    references provider-specific machinery.
    """
    import ast
    import inspect
    from pathlib import Path

    from ti_recon.sandbox import bounds, models, selection

    for module in (models, selection, bounds):
        tree = ast.parse(Path(inspect.getfile(module)).read_text(encoding="utf-8"))
        imported: set[str] = set()
        identifiers: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Name):
                identifiers.add(node.id.lower())
            elif isinstance(node, ast.Attribute):
                identifiers.add(node.attr.lower())
        assert not any(name.startswith("ti_recon.providers") for name in imported), (
            f"{module.__name__} imports provider code"
        )
        # Whole tokens, not substrings: `capec_id` is the MITRE CAPEC catalogue
        # and has nothing to do with the CAPE sandbox, and a check that
        # conflated them would forbid a correct field name.
        tokens = {part for identifier in identifiers for part in identifier.split("_")}
        for name in ("hybrid", "falcon", "vx", "attck", "cape", "anyrun", "triage"):
            assert name not in tokens, f"{module.__name__} references {name}"
