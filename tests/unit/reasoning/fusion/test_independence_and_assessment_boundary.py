"""Independence closure, confidence scoping, and the authoritative model (Task 17).

Three boundaries, each of which fails silently rather than loudly when it breaks
-- which is why every one of them is pinned here rather than left to review.

* **Dependence composes.** Provenance says two claims are one source in three
  different ways, and a partition on any single one of them loses the other two.
  A relay that crosses a source-family boundary is the case that exposes it.
* **A cap must be about the decision.** Task 16 fixed one run-level qualification
  leaking onto every finding in the run; the same shape can reappear for any
  other condition, so the scoping is asserted per condition rather than once.
* **``FusionAssessment`` is the assessment.** The legacy Task 3 ``Assessment``
  requires a ``risk_score`` fusion refuses to invent, so an import of it from
  here would not be a style problem -- it would be a number nobody measured
  re-entering by the back door.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from fixtures.fusion import envelope, evidence, fuse, fuse_with_semantics, observable, scenario
from fixtures.fusion.builders import caution
from ti_recon.enums import EvidenceEffect, Verdict
from ti_recon.reasoning.false_positive.models import (
    ReasonCode,
    ReasoningDimension,
    ReasoningRole,
)
from ti_recon.reasoning.fusion.independence import independence_groups
from ti_recon.reasoning.fusion.models import AssessmentConfidence, SupportBreadth
from ti_recon.reasoning.fusion.policy import CONFIDENCE_CAPS, CONFIDENCE_RULES, VERDICT_RULES

TARGET = "198.51.100.44"


def _run(evidence_records, semantic: str | None = None, root=None):
    """Fuse a set of evidence records about one address.

    The root must be the same ``IntelObject`` the records were built from: a
    claim naming an object this run cannot place is unresolved and excluded from
    the assessment, rather than being credited to the root.
    """
    root = observable(TARGET) if root is None else root
    scene = scenario(root)
    for record in evidence_records:
        scene = scene.with_envelope(
            envelope(record, provider=record.transport_provider, objects=(root,))
        )
    if semantic is None:
        return fuse(scene)
    return fuse_with_semantics(scene, {record.id: semantic for record in evidence_records})


# --------------------------------------------------------------------------- #
# Independence is a connected component, not a partition on one key
# --------------------------------------------------------------------------- #


def test_cross_family_relay_is_one_independent_origin() -> None:
    """One origin reported directly and relayed through another family is one source.

    The relayed record carries a different ``source_family`` -- Task 10 gives a
    relay the transport's family in this shape -- while naming the same
    ``origin_provider``. A family-keyed partition calls that two independent
    confirmations, which is exactly the inflation the lineage rules exist to
    prevent, arrived at from the other direction.
    """
    root = observable(TARGET)
    direct = evidence(root, provider="prov_x", source_family="family_a")
    relayed = evidence(root, provider="relay_y", origin_provider="prov_x", source_family="family_b")

    result = _run([direct, relayed], semantic="c2_association", root=root)
    groups = independence_groups(result.normalized_claims)

    assert len(groups) == 1
    assert groups[0].origin_providers == ("prov_x",)
    # Both claims survive: collapsing independence is not deduplication.
    assert len(result.normalized_claims) == 2


def test_cross_family_relay_does_not_reach_independent_corroboration() -> None:
    """The verdict must not escalate on a source that reported once."""
    root = observable(TARGET)
    direct = evidence(root, provider="prov_x", source_family="family_a")
    relayed = evidence(root, provider="relay_y", origin_provider="prov_x", source_family="family_b")

    result = _run([direct, relayed], semantic="c2_association", root=root)

    assert result.assessment.verdict is not Verdict.MALICIOUS
    assert result.assessment.verdict_rule_id != VERDICT_RULES["malicious_corroborated"]


def test_same_family_different_providers_is_one_origin() -> None:
    """Two datasets run by one organisation are one origin, lineage notwithstanding.

    Task 3 *defaults* ``lineage_group_id`` to ``"{family}:{origin}"``, so keying
    on lineage alone would split this family in two and read it as independent
    corroboration.
    """
    root = observable(TARGET)
    first = evidence(root, provider="p1", source_family="fam", lineage_group_id="fam:p1")
    second = evidence(root, provider="p2", source_family="fam", lineage_group_id="fam:p2")

    groups = independence_groups(
        _run([first, second], semantic="c2_association", root=root).normalized_claims
    )

    assert len(groups) == 1
    assert groups[0].origin_providers == ("p1", "p2")


def test_dependence_is_transitive() -> None:
    """A shares a family with B, B shares an origin with C: all three are one source.

    A and C have no key in common at all. Any scheme that chooses one key in a
    precedence order rather than closing over every dependence edge reports two
    independent origins here, and the middle claim -- the one that proves they
    are the same source -- is the one it ignores.
    """
    root = observable(TARGET)
    first = evidence(root, provider="p_a", source_family="fam_a")
    middle = evidence(root, provider="origin_z", source_family="fam_a")
    last = evidence(root, provider="p_c", origin_provider="origin_z", source_family="fam_b")

    result = _run([first, middle, last], semantic="c2_association", root=root)
    groups = independence_groups(result.normalized_claims)

    assert len(groups) == 1
    assert len(result.normalized_claims) == 3


def test_genuinely_independent_families_still_corroborate() -> None:
    """The closure must not swallow real independence.

    A fix for over-counting that quietly stopped anything from ever corroborating
    would pass every test above and be worse than the bug.
    """
    root = observable(TARGET)
    alpha = evidence(root, provider="alpha", source_family="fam_alpha")
    beta = evidence(root, provider="beta", source_family="fam_beta")

    result = _run([alpha, beta], semantic="c2_association", root=root)
    groups = independence_groups(result.normalized_claims)

    assert len(groups) == 2
    assert result.assessment.verdict is Verdict.MALICIOUS
    assert result.assessment.verdict_rule_id == VERDICT_RULES["malicious_corroborated"]
    assert any(
        group.breadth is SupportBreadth.MULTIPLE_INDEPENDENT_SOURCES
        for group in result.corroboration_groups
    )


def test_grouping_is_independent_of_input_order() -> None:
    """The component representative cannot depend on which claim arrived first."""
    root = observable(TARGET)
    first = evidence(root, provider="p_a", source_family="fam_a")
    middle = evidence(root, provider="origin_z", source_family="fam_a")
    last = evidence(root, provider="p_c", origin_provider="origin_z", source_family="fam_b")

    forward = _run([first, middle, last], semantic="c2_association", root=root)
    backward = _run([last, middle, first], semantic="c2_association", root=root)

    assert [group.group_key for group in independence_groups(forward.normalized_claims)] == [
        group.group_key for group in independence_groups(backward.normalized_claims)
    ]


# --------------------------------------------------------------------------- #
# Confidence is about the decision, and does not count sources
# --------------------------------------------------------------------------- #


def _unrelated_sandbox_divergence(root, unrelated_evidence):
    """A divergence finding about an object the verdict never used."""
    return caution(
        root,
        unrelated_evidence,
        role=ReasoningRole.ANALYSIS_QUALITY_LIMITATION,
        reason=ReasonCode.SANDBOX_RESULT_ENVIRONMENT_DEPENDENT,
        dimension=ReasoningDimension.ANALYSIS_QUALITY,
        rule_key="sandbox_divergence",
    )


def test_unrelated_sandbox_divergence_does_not_cap_confidence() -> None:
    """A divergent detonation of some other object says nothing about this verdict.

    The same scoping bug Task 16 fixed for stale datasets: an ``any()`` over the
    run's findings attaches a caveat to evidence the condition never touched.
    """
    root = observable(TARGET)
    supporting = evidence(root, provider="alpha", source_family="fam_alpha")
    elsewhere = observable("203.0.113.9")
    unrelated = evidence(elsewhere, provider="beta", source_family="fam_beta")

    scene = (
        scenario(root)
        .with_envelope(envelope(supporting, provider="alpha", objects=(root,)))
        .with_finding(_unrelated_sandbox_divergence(root, unrelated))
    )
    result = fuse_with_semantics(scene, {supporting.id: "malware_sample_identity"})

    assert CONFIDENCE_CAPS["sandbox_divergence"] not in result.assessment.confidence_caps


def test_sandbox_divergence_on_the_basis_does_cap_confidence() -> None:
    """Scoping the cap must not disable it: divergence on the basis still counts."""
    root = observable(TARGET)
    supporting = evidence(root, provider="alpha", source_family="fam_alpha")

    scene = (
        scenario(root)
        .with_envelope(envelope(supporting, provider="alpha", objects=(root,)))
        .with_finding(_unrelated_sandbox_divergence(root, supporting))
    )
    result = fuse_with_semantics(scene, {supporting.id: "malware_sample_identity"})

    assert CONFIDENCE_CAPS["sandbox_divergence"] in result.assessment.confidence_caps


def test_conflict_driven_inconclusive_names_the_conflict() -> None:
    """INCONCLUSIVE from disagreement is not INCONCLUSIVE from silence.

    Both land on UNSPECIFIED, and reporting the second rule for the first case
    tells an analyst there was no directional support when in fact there was
    plenty of it, pointing in incompatible directions.
    """
    root = observable(TARGET)
    accusing = evidence(root, provider="alpha", source_family="fam_alpha")
    clearing = evidence(
        root,
        provider="beta",
        source_family="fam_beta",
        effect=EvidenceEffect.SUPPORTS_BENIGN,
    )

    # Weak semantics on both sides, so no malicious residual survives the conflict
    # and the run genuinely reaches INCONCLUSIVE rather than SUSPICIOUS.
    result = _run([accusing, clearing], semantic="aggregated_reputation", root=root)

    assert result.assessment.verdict is Verdict.INCONCLUSIVE
    assert result.assessment.verdict_rule_id == VERDICT_RULES["inconclusive_conflict"]
    assert result.assessment.confidence is AssessmentConfidence.UNSPECIFIED
    assert result.assessment.confidence_rule_id == CONFIDENCE_RULES["unspecified_conflicted"]
    assert result.assessment.confidence_rule_id != CONFIDENCE_RULES["unspecified_no_support"]


def test_same_verdict_can_carry_different_confidence() -> None:
    """Confidence is not a restatement of the verdict.

    One decisive source alone and two independent ones both reach MALICIOUS; if
    confidence were derived from the verdict's severity they would be
    indistinguishable, and the analyst would lose the only signal that says how
    much the conclusion rests on.
    """
    root = observable(TARGET)
    alone = _run(
        [evidence(root, provider="alpha", source_family="fam_alpha")],
        "malware_sample_identity",
        root=root,
    )
    together = _run(
        [
            evidence(root, provider="alpha", source_family="fam_alpha"),
            evidence(root, provider="beta", source_family="fam_beta"),
        ],
        "malware_sample_identity",
        root=root,
    )

    assert alone.assessment.verdict is together.assessment.verdict is Verdict.MALICIOUS
    assert alone.assessment.confidence is not together.assessment.confidence


# --------------------------------------------------------------------------- #
# FusionAssessment is the authoritative model
# --------------------------------------------------------------------------- #

_PACKAGES = ("src/ti_recon/reasoning/claims", "src/ti_recon/reasoning/fusion")
_LEGACY_NAMES = frozenset({"Assessment", "AssessmentContribution"})


@pytest.mark.parametrize("package", _PACKAGES)
def test_task_17_never_imports_the_legacy_assessment(package: str) -> None:
    """The legacy Task 3 model may not re-enter Task 17.

    It requires a numeric ``risk_score`` and a 0-100 ``confidence``, and its
    contribution model multiplies four factors together. Task 17 emits named
    bands and rule ids precisely because no such number is measurable here, so
    importing that model would not be a tidiness issue -- it would be the
    weighted score returning through a type.
    """
    offenders: list[str] = []
    for path in sorted(Path(package).rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module.endswith("models.assessment"):
                    offenders.append(f"{path}: from {module}")
                for alias in node.names:
                    if alias.name in _LEGACY_NAMES:
                        offenders.append(f"{path}: {alias.name} from {module}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.endswith("models.assessment"):
                        offenders.append(f"{path}: import {alias.name}")

    assert offenders == []


def test_fusion_assessment_carries_no_score_shaped_field() -> None:
    """The authoritative assessment exposes no number a caller could mistake for one."""
    from ti_recon.reasoning.fusion.models import FusionAssessment

    banned = ("score", "weight", "probability", "risk", "factor", "percent")
    offenders = [
        name
        for name in FusionAssessment.model_fields
        if any(token in name.lower() for token in banned)
    ]

    assert offenders == []
