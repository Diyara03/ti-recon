"""Two boundaries that only fail quietly (Task 17).

**Task 16's source-dependence link.** Task 16 can say a finding is relayed, and
Task 17 must not count a relay as a second source. The two layers agree today
without Task 17 reading the finding, and the tests below pin *why* rather than
asserting the happy answer: the link is unary, and the dependence it describes is
made of the same provenance fields the union-find already keys on. If Task 16
ever gains a genuinely binary dependence relation -- one naming two records whose
provenance does not already connect them -- these tests are where that shows up
as a failure, which is the point.

**Basis relevance.** Confidence answers "is *this assessment* correct?". A
limitation somewhere in the investigation is a fact about the investigation, and
what it is worth operationally is Task 18's question. Every cap is therefore
scoped to the claims the verdict actually rested on, and the table below proves
it by comparing a root assessment against the same assessment with an unrelated
limitation added: verdict, confidence and both rule ids must be untouched.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from fixtures.fusion import (
    AS_OF,
    caution,
    envelope,
    evidence,
    fuse_with_semantics,
    observable,
    scenario,
)
from ti_recon.enums import EvidenceEffect
from ti_recon.providers.result import ProviderResultEnvelope, ProviderRunStatus
from ti_recon.reasoning.engine import TemporalContextEngine
from ti_recon.reasoning.false_positive.engine import FalsePositiveReasoningEngine
from ti_recon.reasoning.false_positive.models import (
    FindingLimitation,
    LinkRelation,
    LinkTarget,
    ReasonCode,
    ReasoningDimension,
    ReasoningFinding,
    ReasoningRole,
)
from ti_recon.reasoning.fusion import EvidenceFusionEngine
from ti_recon.reasoning.fusion.independence import independence_groups
from ti_recon.reasoning.fusion.policy import CONFIDENCE_CAPS

ROOT = "198.51.100.5"
ELSEWHERE = "203.0.113.200"


# --------------------------------------------------------------------------- #
# 1. Task 16 source dependence
# --------------------------------------------------------------------------- #


def _relayed_investigation():
    """One origin answering directly and again through another transport."""
    root = observable(ROOT)
    direct = evidence(root, provider="prov_x", source_family="fam_x")
    relayed = evidence(root, provider="relay_y", origin_provider="prov_x", source_family="fam_x")
    envelopes = [
        envelope(direct, provider="prov_x", objects=(root,)),
        envelope(relayed, provider="relay_y", objects=(root,)),
    ]
    qualification = TemporalContextEngine().evaluate(as_of=AS_OF, results=envelopes, root=root)
    reasoning = FalsePositiveReasoningEngine().evaluate(
        qualification=qualification, results=envelopes, root=root
    )
    return root, direct, relayed, envelopes, qualification, reasoning


def test_task_16_dependence_link_is_unary_and_provenance_derived() -> None:
    """``DEPENDENT_WITH`` marks one record; it never names a second one.

    This is the fact that decides whether Task 17 has anything to consume. The
    link points at the relayed evidence alone, and the dependence the finding
    describes is carried in ``origin_provider`` and ``source_family`` -- copied
    verbatim from that same record, and already two of the three edges the
    union-find groups on. There is no pair here that provenance does not connect,
    so consuming the link would add no edge.
    """
    _, _, relayed, _, _, reasoning = _relayed_investigation()

    dependence = [
        finding for finding in reasoning.findings if finding.role is ReasoningRole.SOURCE_DEPENDENCE
    ]
    assert len(dependence) == 1
    finding = dependence[0]
    assert finding.reason_code is ReasonCode.RELAYED_FINDINGS_NOT_INDEPENDENT

    links = [link for link in finding.links if link.relation is LinkRelation.DEPENDENT_WITH]
    assert [link.ref for link in links] == [relayed.id]
    assert all(link.target is LinkTarget.EVIDENCE for link in links)

    # The dependence content is provenance the union-find already reads.
    assert finding.detail["origin_provider"] == relayed.origin_provider
    assert finding.detail["source_family"] == relayed.source_family


def test_relayed_finding_is_already_one_independent_origin() -> None:
    """The two layers agree, through the real Task 15 and Task 16 engines."""
    root, _, _, envelopes, qualification, reasoning = _relayed_investigation()

    result = EvidenceFusionEngine().evaluate(
        qualification=qualification, reasoning=reasoning, results=envelopes, root=root
    )
    groups = independence_groups(result.normalized_claims)

    assert len(groups) == 1
    assert len(result.normalized_claims) == 2


def test_relayed_dependence_composes_with_a_family_edge() -> None:
    """A ~ B by family, B ~ C by relay: one connected component.

    The composition the union-find exists for, with the second edge supplied by
    the same relay Task 16 files its dependence finding about.
    """
    root = observable(ROOT)
    first = evidence(root, provider="p_a", source_family="fam_a")
    middle = evidence(root, provider="origin_z", source_family="fam_a")
    relayed = evidence(
        root, provider="transport_c", origin_provider="origin_z", source_family="fam_b"
    )
    envelopes = [
        envelope(first, provider="p_a", objects=(root,)),
        envelope(middle, provider="origin_z", objects=(root,)),
        envelope(relayed, provider="transport_c", objects=(root,)),
    ]
    qualification = TemporalContextEngine().evaluate(as_of=AS_OF, results=envelopes, root=root)
    reasoning = FalsePositiveReasoningEngine().evaluate(
        qualification=qualification, results=envelopes, root=root
    )
    result = EvidenceFusionEngine().evaluate(
        qualification=qualification, reasoning=reasoning, results=envelopes, root=root
    )

    assert len(independence_groups(result.normalized_claims)) == 1
    assert len(result.normalized_claims) == 3


def test_dependent_claims_keep_distinct_semantics_and_provenance() -> None:
    """Grouping collapses corroboration, never the claims themselves.

    Two dependent sources can still assert two different propositions. Folding
    them together would delete a fact rather than decline to double-count one.
    """
    root = observable(ROOT)
    first = evidence(root, claim_type="a", provider="p1", source_family="shared")
    second = evidence(root, claim_type="b", provider="p2", source_family="shared")
    scene = (
        scenario(root)
        .with_envelope(envelope(first, provider="p1", objects=(root,)))
        .with_envelope(envelope(second, provider="p2", objects=(root,)))
    )
    result = fuse_with_semantics(
        scene, {first.id: "c2_association", second.id: "malware_distribution"}
    )

    assert len(independence_groups(result.normalized_claims)) == 1
    assert len(result.normalized_claims) == 2
    assert sorted(claim.semantic.value for claim in result.normalized_claims) == [
        "c2_association",
        "malware_distribution",
    ]
    assert len(result.proposition_groups) == 2
    assert sorted(claim.origin_provider for claim in result.normalized_claims) == ["p1", "p2"]
    # Every claim keeps a contribution, including the one that cannot corroborate.
    assert len(result.contributions) == 2


# --------------------------------------------------------------------------- #
# 2. Basis relevance
# --------------------------------------------------------------------------- #


def _assess(
    *,
    extra_envelopes: Sequence[ProviderResultEnvelope] = (),
    extra_findings: Sequence[ReasoningFinding] = (),
    extra_semantics: dict[str, str] | None = None,
):
    """A decisive, unopposed root assessment, plus whatever else is going on."""
    root = observable(ROOT)
    basis = evidence(root, provider="alpha", source_family="fam_alpha")
    scene = scenario(root).with_envelope(envelope(basis, provider="alpha", objects=(root,)))
    for item in extra_envelopes:
        scene = scene.with_envelope(item)
    for finding in extra_findings:
        scene = scene.with_finding(finding)
    semantics = {basis.id: "malware_sample_identity", **(extra_semantics or {})}
    return basis, fuse_with_semantics(scene, semantics)


def _elsewhere_finding(reason: ReasonCode, **kwargs) -> tuple[ReasoningFinding, ...]:
    """A Task 16 finding about evidence on another object entirely."""
    other = observable(ELSEWHERE)
    unrelated = evidence(other, provider="zeta", source_family="fam_zeta")
    return (caution(other, unrelated, reason=reason, **kwargs),)


def _unrelated_conflict() -> tuple[Sequence[ProviderResultEnvelope], dict[str, str]]:
    other = observable(ELSEWHERE)
    accusing = evidence(other, provider="gamma", source_family="fam_gamma")
    clearing = evidence(
        other, provider="delta", source_family="fam_delta", effect=EvidenceEffect.SUPPORTS_BENIGN
    )
    envelopes = [
        envelope(accusing, provider="gamma", objects=(other,)),
        envelope(clearing, provider="delta", objects=(other,)),
    ]
    return envelopes, {accusing.id: "c2_association", clearing.id: "c2_association"}


def _unrelated_partial() -> tuple[Sequence[ProviderResultEnvelope], dict[str, str]]:
    other = observable(ELSEWHERE)
    record = evidence(other, provider="zeta", source_family="fam_zeta")
    return (
        [envelope(record, provider="zeta", objects=(other,), status=ProviderRunStatus.PARTIAL)],
        {record.id: "c2_association"},
    )


def _unrelated_unclassified() -> tuple[Sequence[ProviderResultEnvelope], dict[str, str]]:
    other = observable(ELSEWHERE)
    record = evidence(other, provider="eps", source_family="fam_eps")
    return (
        [envelope(record, provider="eps", objects=(other,))],
        {record.id: "unclassified_directional"},
    )


def _empty(status: ProviderRunStatus) -> Sequence[ProviderResultEnvelope]:
    """A provider that answered without evidence -- coverage, not correctness."""
    return [envelope(provider="eta", objects=(observable(ELSEWHERE),), status=status)]


_UNRELATED_CASES = {
    "sandbox_divergence": lambda: (
        (),
        {},
        _elsewhere_finding(
            ReasonCode.SANDBOX_RESULT_ENVIRONMENT_DEPENDENT,
            role=ReasoningRole.ANALYSIS_QUALITY_LIMITATION,
            dimension=ReasoningDimension.ANALYSIS_QUALITY,
            rule_key="sandbox_divergence",
        ),
    ),
    "stale_context": lambda: (
        (),
        {},
        _elsewhere_finding(
            ReasonCode.SHARED_INFRASTRUCTURE_LIMITS_ATTRIBUTION,
            limitations=(FindingLimitation.SUPPORTING_CONTEXT_DATASET_STALE,),
        ),
    ),
    "conflict": lambda: (*_unrelated_conflict(), ()),
    "partial_result": lambda: (*_unrelated_partial(), ()),
    "unclassified_claim": lambda: (*_unrelated_unclassified(), ()),
    "no_data": lambda: (_empty(ProviderRunStatus.NO_DATA), {}, ()),
    "not_configured": lambda: (_empty(ProviderRunStatus.NOT_CONFIGURED), {}, ()),
    "not_supported": lambda: (_empty(ProviderRunStatus.NOT_SUPPORTED), {}, ()),
    "quota_exceeded": lambda: (_empty(ProviderRunStatus.QUOTA_EXCEEDED), {}, ()),
    "temporarily_unavailable": lambda: (
        _empty(ProviderRunStatus.TEMPORARILY_UNAVAILABLE),
        {},
        (),
    ),
    "plan_limited": lambda: (_empty(ProviderRunStatus.PLAN_LIMITED), {}, ()),
}


@pytest.mark.parametrize("case", sorted(_UNRELATED_CASES))
def test_an_unrelated_limitation_cannot_move_the_root_assessment(case: str) -> None:
    """Same verdict, same confidence, same two rule ids.

    Each of these is a real fact about the investigation and none of them is a
    fact about whether *this* assessment is right. An exact known-malware
    identification does not become less correct because an optional provider was
    unavailable, because a pivot object's reputation is disputed, or because a
    sandbox disagreed with itself about a different sample. Whether the
    investigation gathered enough to act on is Task 18's question, and answering
    it here by quietly lowering a band would put it beyond appeal.
    """
    envelopes, semantics, findings = _UNRELATED_CASES[case]()
    _, baseline = _assess()
    _, actual = _assess(
        extra_envelopes=envelopes, extra_semantics=semantics, extra_findings=findings
    )

    assert actual.assessment.verdict is baseline.assessment.verdict
    assert actual.assessment.confidence is baseline.assessment.confidence
    assert actual.assessment.verdict_rule_id == baseline.assessment.verdict_rule_id
    assert actual.assessment.confidence_rule_id == baseline.assessment.confidence_rule_id
    assert actual.assessment.confidence_caps == baseline.assessment.confidence_caps


def test_an_unrelated_conflict_is_still_reported() -> None:
    """Scoping a cap must not hide the fact from the trace.

    The disagreement happened and stays visible; what it does not do is decide
    how confident this assessment is.
    """
    envelopes, semantics = _unrelated_conflict()
    _, result = _assess(extra_envelopes=envelopes, extra_semantics=semantics)

    assert len(result.conflicts) == 1
    assert CONFIDENCE_CAPS["unresolved_conflict"] not in result.assessment.confidence_caps


def test_a_conflict_on_the_verdicts_own_proposition_still_caps() -> None:
    """Scoping must not disable the cap: a material conflict still counts."""
    root = observable(ROOT)
    accusing = evidence(root, provider="gamma", source_family="fam_gamma")
    clearing = evidence(
        root, provider="delta", source_family="fam_delta", effect=EvidenceEffect.SUPPORTS_BENIGN
    )
    scene = (
        scenario(root)
        .with_envelope(envelope(accusing, provider="gamma", objects=(root,)))
        .with_envelope(envelope(clearing, provider="delta", objects=(root,)))
    )
    result = fuse_with_semantics(
        scene, {accusing.id: "c2_association", clearing.id: "c2_association"}
    )

    assert CONFIDENCE_CAPS["unresolved_conflict"] in result.assessment.confidence_caps


def test_an_unrelated_non_weak_claim_cannot_suppress_the_weak_support_cap() -> None:
    """The mirror-image leak: a run-wide read can raise a band as well as lower one.

    The weak-support cap once read every surviving claim, so a non-weak claim
    about another object made the root's own thin support look better than it
    was. A cap that unrelated material can switch off is the same bug as one it
    can switch on.
    """
    root = observable(ROOT)
    other = observable(ELSEWHERE)
    first = evidence(root, provider="alpha", source_family="fam_alpha")
    second = evidence(root, provider="beta", source_family="fam_beta")
    unrelated = evidence(
        other, provider="gamma", source_family="fam_gamma", effect=EvidenceEffect.SUPPORTS_BENIGN
    )

    def assess(*extra):
        scene = (
            scenario(root)
            .with_envelope(envelope(first, provider="alpha", objects=(root,)))
            .with_envelope(envelope(second, provider="beta", objects=(root,)))
        )
        semantics = {first.id: "aggregated_reputation", second.id: "aggregated_reputation"}
        for record, semantic in extra:
            scene = scene.with_envelope(
                envelope(record, provider=record.transport_provider, objects=(other,))
            )
            semantics[record.id] = semantic
        return fuse_with_semantics(scene, semantics)

    baseline = assess()
    with_unrelated = assess((unrelated, "c2_association"))

    assert CONFIDENCE_CAPS["single_weak_support"] in baseline.assessment.confidence_caps
    assert CONFIDENCE_CAPS["single_weak_support"] in with_unrelated.assessment.confidence_caps
    assert with_unrelated.assessment.confidence is baseline.assessment.confidence
