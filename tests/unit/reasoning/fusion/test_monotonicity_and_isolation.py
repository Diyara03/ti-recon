"""What may and may not strengthen an assessment (Task 17).

The acceptance rule for the whole layer, stated as invariants rather than cases:
an assessment may change only for a semantic reason. Adding a genuinely
independent, compatible, unexplained, *root-relevant* claim may strengthen it.
Adding anything else — a duplicate, a relay, a same-family repeat, an unrelated
object's evidence, a provider failure, an absence — must not.

These are the tests that fail when a plausible-looking shortcut is taken, because
every shortcut in this layer shows up as an assessment that got stronger for a
reason nobody would defend out loud.
"""

from __future__ import annotations

import pytest

from fixtures.fusion import (
    caution,
    envelope,
    evidence,
    explanation,
    file_object,
    fuse_with_semantics,
    observable,
    scenario,
)
from ti_recon.enums import EvidenceEffect, MatchScope, Verdict
from ti_recon.providers.result import ProviderRunStatus
from ti_recon.reasoning.false_positive.models import ReasonCode
from ti_recon.reasoning.fusion.models import AssessmentConfidence

ROOT = "198.51.100.21"
ELSEWHERE = "203.0.113.77"

#: Least to most, so "stronger" is a comparison rather than a feeling.
VERDICT_ORDER = {
    Verdict.LIKELY_BENIGN: 0,
    Verdict.INCONCLUSIVE: 1,
    Verdict.SUSPICIOUS: 2,
    Verdict.MALICIOUS: 3,
}
CONFIDENCE_ORDER = {
    AssessmentConfidence.UNSPECIFIED: 0,
    AssessmentConfidence.LOW: 1,
    AssessmentConfidence.MEDIUM: 2,
    AssessmentConfidence.HIGH: 3,
}


#: One shared instance, deliberately. A claim whose subject object is absent from
#: every envelope and from the graph anchors to the run's root -- that is how the
#: shipped adapters attribute evidence to the requested observable -- so a pivot
#: built from a second, unlisted instance of the same value would be read as a
#: root claim and this file would test nothing.
PIVOT_OBJECT = observable(ELSEWHERE)


def _root_and_extra(extra=(), findings=()):
    """A fixed root claim, plus whatever else the case adds."""
    root = observable(ROOT)
    other = PIVOT_OBJECT
    basis = evidence(root, claim_type="root_claim", provider="alpha", source_family="fam_a")
    scene = scenario(root).with_envelope(envelope(basis, provider="alpha", objects=(root,)))
    semantics = {basis.id: "malicious_reputation"}
    for record, semantic, subject in extra:
        scene = scene.with_envelope(
            envelope(
                record,
                provider=record.transport_provider,
                objects=(root if subject == "root" else other,),
            )
        )
        semantics[record.id] = semantic
    for finding in findings:
        scene = scene.with_finding(finding)
    return basis, fuse_with_semantics(scene, semantics)


def _baseline():
    return _root_and_extra()[1]


def _elsewhere(provider: str, **kwargs):
    return evidence(PIVOT_OBJECT, provider=provider, source_family=f"fam_{provider}", **kwargs)


# --------------------------------------------------------------------------- #
# Root / pivot isolation
# --------------------------------------------------------------------------- #

PIVOT_CASES = {
    "decisive_malicious": lambda: ((_elsewhere("g1"), "malware_sample_identity", "other"),),
    "malware_distribution": lambda: ((_elsewhere("g2"), "malware_distribution", "other"),),
    "c2_association": lambda: ((_elsewhere("g3"), "c2_association", "other"),),
    "benign_reputation": lambda: (
        (
            _elsewhere("g4", effect=EvidenceEffect.SUPPORTS_BENIGN),
            "benign_reputation",
            "other",
        ),
    ),
    "unclassified": lambda: ((_elsewhere("g5"), "unclassified_directional", "other"),),
    "true_conflict": lambda: (
        (_elsewhere("g6"), "c2_association", "other"),
        (
            _elsewhere("g7", effect=EvidenceEffect.SUPPORTS_BENIGN),
            "c2_association",
            "other",
        ),
    ),
}


@pytest.mark.parametrize("case", sorted(PIVOT_CASES))
def test_an_unrelated_pivot_claim_cannot_move_the_root_assessment(case: str) -> None:
    """Zero effect on verdict, confidence and both rule ids.

    A decisive claim about an object two hops away is real knowledge about *that*
    object. Letting it decide this assessment would be the graph-derived
    promotion Task 14 deliberately deferred, arriving through claim indexing
    rather than through an edge — and it would attribute a pivot's verdict to
    whatever the analyst happened to type.
    """
    baseline = _baseline()
    _, actual = _root_and_extra(PIVOT_CASES[case]())

    assert actual.assessment.verdict is baseline.assessment.verdict
    assert actual.assessment.confidence is baseline.assessment.confidence
    assert actual.assessment.verdict_rule_id == baseline.assessment.verdict_rule_id
    assert actual.assessment.confidence_rule_id == baseline.assessment.confidence_rule_id
    assert actual.assessment.confidence_caps == baseline.assessment.confidence_caps


@pytest.mark.parametrize("case", sorted(PIVOT_CASES))
def test_pivot_evidence_stays_visible_even_though_it_does_not_vote(case: str) -> None:
    """Isolating the verdict is not discarding the knowledge."""
    baseline = _baseline()
    _, actual = _root_and_extra(PIVOT_CASES[case]())

    assert len(actual.normalized_claims) > len(baseline.normalized_claims)
    assert len(actual.proposition_groups) > len(baseline.proposition_groups)
    assert len(actual.contributions) > len(baseline.contributions)


# --------------------------------------------------------------------------- #
# Independence monotonicity
# --------------------------------------------------------------------------- #

NON_STRENGTHENING = {
    # The same family answering twice.
    "same_family_repeat": lambda: (
        (
            evidence(
                observable(ROOT), claim_type="again", provider="alpha2", source_family="fam_a"
            ),
            "malicious_reputation",
            "root",
        ),
    ),
    # A relay: a different family naming the same origin.
    "relayed_copy": lambda: (
        (
            evidence(
                observable(ROOT),
                claim_type="relayed",
                provider="transport",
                origin_provider="alpha",
                source_family="fam_relay",
            ),
            "malicious_reputation",
            "root",
        ),
    ),
    # An aggregate: one source relaying many opinions, compatible with nothing.
    "aggregate": lambda: (
        (
            evidence(observable(ROOT), claim_type="agg", provider="beta", source_family="fam_b"),
            "aggregated_reputation",
            "root",
        ),
    ),
    # Independent and directional, but about a different proposition.
    "incompatible_proposition": lambda: (
        (
            evidence(observable(ROOT), claim_type="scan", provider="gamma", source_family="fam_g"),
            "scanner_activity",
            "root",
        ),
    ),
    # Independent and compatible, but about the neighbourhood.
    "host_scope_claim": lambda: (
        (
            evidence(
                observable(ROOT),
                claim_type="host",
                provider="delta",
                source_family="fam_d",
                match_scope=MatchScope.SAME_HOST,
            ),
            "malicious_reputation",
            "root",
        ),
    ),
}


@pytest.mark.parametrize("case", sorted(NON_STRENGTHENING))
def test_dependent_or_incompatible_evidence_never_strengthens(case: str) -> None:
    """Neither the verdict nor the confidence may rise.

    Each row is a different way of looking like a second source without being
    one. A system that counted any of them would be confidently wrong exactly
    where an analyst most needs it not to be.
    """
    baseline = _baseline()
    _, actual = _root_and_extra(NON_STRENGTHENING[case]())

    assert VERDICT_ORDER[actual.assessment.verdict] <= VERDICT_ORDER[baseline.assessment.verdict]
    assert (
        CONFIDENCE_ORDER[actual.assessment.confidence]
        <= CONFIDENCE_ORDER[baseline.assessment.confidence]
    )


def test_genuinely_independent_compatible_evidence_may_strengthen() -> None:
    """The counterpart, without which every test above passes vacuously.

    A conservatism bug and a correctness bug look identical from the failing
    side; only this test tells them apart.
    """
    baseline = _baseline()
    _, actual = _root_and_extra(
        (
            (
                evidence(
                    observable(ROOT),
                    claim_type="sandbox",
                    provider="beta",
                    source_family="fam_b",
                ),
                "sandbox_classification",
                "root",
            ),
        )
    )

    assert VERDICT_ORDER[actual.assessment.verdict] > VERDICT_ORDER[baseline.assessment.verdict]
    assert actual.assessment.verdict is Verdict.MALICIOUS


ABSENT_STATUSES = [
    ProviderRunStatus.NO_DATA,
    ProviderRunStatus.NOT_SUPPORTED,
    ProviderRunStatus.NOT_CONFIGURED,
    ProviderRunStatus.QUOTA_EXCEEDED,
    ProviderRunStatus.TEMPORARILY_UNAVAILABLE,
    ProviderRunStatus.PARTIAL,
    ProviderRunStatus.PLAN_LIMITED,
]


@pytest.mark.parametrize("status", ABSENT_STATUSES, ids=[s.value for s in ABSENT_STATUSES])
def test_a_provider_that_answered_with_nothing_changes_nothing(
    status: ProviderRunStatus,
) -> None:
    """Absence is coverage. It is not support, and not doubt either."""
    root = observable(ROOT)
    basis = evidence(root, claim_type="root_claim", provider="alpha", source_family="fam_a")
    baseline = _baseline()

    scene = (
        scenario(root)
        .with_envelope(envelope(basis, provider="alpha", objects=(root,)))
        .with_envelope(envelope(provider="quiet", objects=(root,), status=status))
    )
    actual = fuse_with_semantics(scene, {basis.id: "malicious_reputation"})

    assert actual.assessment.verdict is baseline.assessment.verdict
    assert actual.assessment.confidence is baseline.assessment.confidence
    assert actual.assessment.confidence_rule_id == baseline.assessment.confidence_rule_id


# --------------------------------------------------------------------------- #
# Explanation monotonicity
# --------------------------------------------------------------------------- #


def test_an_explanation_never_makes_an_assessment_more_malicious() -> None:
    """Explaining evidence can only remove support, never add it."""
    root = observable(ROOT)
    basis = evidence(root, claim_type="root_claim", provider="alpha", source_family="fam_a")
    without = fuse_with_semantics(
        scenario(root).with_envelope(envelope(basis, provider="alpha", objects=(root,))),
        {basis.id: "malicious_reputation"},
    )
    with_explanation = fuse_with_semantics(
        scenario(root)
        .with_envelope(envelope(basis, provider="alpha", objects=(root,)))
        .with_finding(explanation(root, basis)),
        {basis.id: "malicious_reputation"},
    )

    assert (
        VERDICT_ORDER[with_explanation.assessment.verdict]
        <= VERDICT_ORDER[without.assessment.verdict]
    )
    assert basis.id in with_explanation.explained_evidence_ids


def test_a_qualifying_finding_is_not_an_explanation() -> None:
    """Only ALTERNATIVE_EXPLANATION with an EXPLAINS link removes support.

    An attribution caution says the owner may be a victim and a block has
    bystanders. Neither is a reason to doubt the activity happened, and filing
    one as an explanation would clear real evidence behind a verdict that looked
    thoroughly reasoned.
    """
    root = observable(ROOT)
    basis = evidence(root, claim_type="root_claim", provider="alpha", source_family="fam_a")
    result = fuse_with_semantics(
        scenario(root)
        .with_envelope(envelope(basis, provider="alpha", objects=(root,)))
        .with_finding(
            caution(root, basis, reason=ReasonCode.SHARED_INFRASTRUCTURE_LIMITS_ATTRIBUTION)
        ),
        {basis.id: "malicious_reputation"},
    )

    assert basis.id not in result.explained_evidence_ids
    assert basis.id in result.unexplained_directional_evidence_ids
    assert result.assessment.verdict is Verdict.SUSPICIOUS


def test_an_explanation_reaches_no_neighbouring_object() -> None:
    """Explaining a claim about one object leaves another object's claim alone."""
    sample = file_object(md5="44d88612fea8a8f36de82e1278abb02f")
    other = PIVOT_OBJECT
    explained = evidence(sample, claim_type="one", provider="alpha", source_family="fam_a")
    elsewhere = evidence(other, claim_type="two", provider="beta", source_family="fam_b")

    result = fuse_with_semantics(
        scenario(sample)
        .with_envelope(envelope(explained, provider="alpha", objects=(sample,)))
        .with_envelope(envelope(elsewhere, provider="beta", objects=(other,)))
        .with_finding(explanation(sample, explained)),
        {explained.id: "malicious_reputation", elsewhere.id: "malicious_reputation"},
    )

    assert explained.id in result.explained_evidence_ids
    assert elsewhere.id in result.unexplained_directional_evidence_ids
