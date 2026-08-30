"""A partial envelope is a coverage fact, not a correctness fact (Task 17).

Task 17 confidence answers **"is this assessment correct?"**. A provider result
carrying `PARTIAL` says something was missing from the *response*, and the
repository records that at envelope granularity only. It does not say whether the
directional claim the verdict rested on is itself incomplete.

Those are different statements with different owners:

| Signal | Means | Owned by |
|---|---|---|
| envelope `PARTIAL` | incomplete provider result | Task 17 coverage |
| a claim known incomplete | the fact itself is qualified | Task 17 confidence, if it existed |
| coverage insufficient to act | decision readiness | Task 18 |

A provider that returned its verdict-bearing fact in full while an optional
relationship lookup failed has told us nothing less correct. Capping on the
envelope status read the first row as if it were the second, and turned a
coverage gap into doubt about a fact that arrived intact.

The status is never hidden. It stays on the claim, on the contribution's reason
codes, and in coverage — all asserted below, because "stop capping on it" must
not quietly become "stop reporting it".
"""

from __future__ import annotations

import pytest

from fixtures.fusion import (
    envelope,
    evidence,
    file_object,
    fuse_with_semantics,
    observable,
    scenario,
)
from ti_recon.enums import Verdict
from ti_recon.providers.result import ProviderRunStatus
from ti_recon.reasoning.claims.models import NormalizedClaim
from ti_recon.reasoning.fusion.models import AssessmentConfidence
from ti_recon.reasoning.fusion.policy import CONFIDENCE_CAPS, REASON_CODES

#: The statuses fusion currently treats as partial.
PARTIAL_STATUSES = (ProviderRunStatus.PARTIAL, ProviderRunStatus.PLAN_LIMITED)


def _assess_root(status: ProviderRunStatus, *, corroborated: bool = False):
    """A decisive exact claim about a file, from an envelope with this status."""
    sample = file_object(sha256="a" * 64)
    first = evidence(sample, claim_type="alpha_sample", provider="alpha", source_family="fam_a")
    scene = scenario(sample).with_envelope(
        envelope(first, provider="alpha", objects=(sample,), status=status)
    )
    semantics = {first.id: "malware_sample_identity"}
    if corroborated:
        second = evidence(sample, claim_type="beta_sample", provider="beta", source_family="fam_b")
        scene = scene.with_envelope(envelope(second, provider="beta", objects=(sample,)))
        semantics[second.id] = "malware_sample_identity"
    return fuse_with_semantics(scene, semantics)


# --------------------------------------------------------------------------- #
# A. Optional data failed; the directional claim did not
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("status", PARTIAL_STATUSES)
@pytest.mark.parametrize("corroborated", [False, True])
def test_a_partial_envelope_matches_the_identical_success_case(
    status: ProviderRunStatus, corroborated: bool
) -> None:
    """Same verdict, same band, same rule — at both MEDIUM and HIGH.

    Parametrised over the corroborated case as well, because the cap used to bite
    hardest exactly where the evidence was strongest: a decisive claim with an
    independent origin agreeing earned HIGH and was knocked to MEDIUM by an
    optional lookup that failed somewhere in one of the two responses.
    """
    complete = _assess_root(ProviderRunStatus.SUCCESS, corroborated=corroborated)
    partial = _assess_root(status, corroborated=corroborated)

    assert complete.assessment.verdict is Verdict.MALICIOUS
    assert partial.assessment.verdict is complete.assessment.verdict
    assert partial.assessment.confidence is complete.assessment.confidence
    assert partial.assessment.confidence_rule_id == complete.assessment.confidence_rule_id
    assert partial.assessment.verdict_rule_id == complete.assessment.verdict_rule_id
    assert partial.assessment.confidence_caps == complete.assessment.confidence_caps


@pytest.mark.parametrize("status", PARTIAL_STATUSES)
def test_partial_status_stays_visible_everywhere_it_was(status: ProviderRunStatus) -> None:
    """Not capping is not concealing.

    Three independent surfaces keep it, so a reader — or Task 18 — can still see
    exactly which sources answered incompletely.
    """
    result = _assess_root(status)

    assert result.coverage.partial_sources == 1
    assert all(claim.source_partial for claim in result.normalized_claims)
    assert any(
        REASON_CODES["partial"] in contribution.reason_codes
        for contribution in result.contributions
    )


# --------------------------------------------------------------------------- #
# B. Partial on an unrelated pivot
# --------------------------------------------------------------------------- #


def test_a_partial_result_about_another_object_changes_nothing() -> None:
    """Pinned, and it passed before this change too — basis scoping already held."""
    sample = file_object(sha256="b" * 64)
    other = observable("203.0.113.200")
    basis = evidence(sample, claim_type="alpha_sample", provider="alpha", source_family="fam_a")
    unrelated = evidence(other, claim_type="zeta_finding", provider="zeta", source_family="fam_z")

    def assess(*extra):
        scene = scenario(sample).with_envelope(envelope(basis, provider="alpha", objects=(sample,)))
        semantics = {basis.id: "malware_sample_identity"}
        for record, status, semantic in extra:
            scene = scene.with_envelope(
                envelope(record, provider="zeta", objects=(other,), status=status)
            )
            semantics[record.id] = semantic
        return fuse_with_semantics(scene, semantics)

    baseline = assess()
    with_pivot = assess((unrelated, ProviderRunStatus.PARTIAL, "c2_association"))

    assert with_pivot.assessment.verdict is baseline.assessment.verdict
    assert with_pivot.assessment.confidence is baseline.assessment.confidence
    assert with_pivot.assessment.confidence_caps == baseline.assessment.confidence_caps


# --------------------------------------------------------------------------- #
# C. Partial has no direction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("status", PARTIAL_STATUSES)
def test_a_partial_result_carries_no_direction_of_its_own(status: ProviderRunStatus) -> None:
    """It is quality metadata, and quality metadata does not accuse or exonerate.

    An envelope that returned nothing directional produces no claim, so a partial
    response on its own leaves the engine with nothing to conclude — and
    INCONCLUSIVE here means "the engine cannot justify either direction", never
    a suspicion generated by absence.
    """
    target = observable("198.51.100.60")
    result = fuse_with_semantics(
        scenario(target).with_envelope(
            envelope(provider="alpha", objects=(target,), status=status)
        ),
        {},
    )

    assert result.assessment.verdict is Verdict.INCONCLUSIVE
    assert result.assessment.confidence is AssessmentConfidence.UNSPECIFIED
    assert result.assessment.confidence_caps == ()


# --------------------------------------------------------------------------- #
# D. The boundary itself
# --------------------------------------------------------------------------- #


def test_envelope_partiality_is_the_only_partiality_the_model_knows() -> None:
    """Provider-envelope partiality is not claim partiality.

    ``NormalizedClaim.source_partial`` is derived from the envelope's status and
    is the *only* completeness signal in the repository — it describes the
    response, not the proposition. This test exists to make that explicit, so
    that adding a genuine claim-level completeness field is a deliberate act with
    a visible consequence rather than something a confidence rule quietly starts
    reading.

    If this fails because such a field now exists: that field may legitimately
    inform confidence, after review, under a cap id of its own. Do not restore
    the envelope-status cap.
    """
    completeness_fields = {
        name
        for name in NormalizedClaim.model_fields
        if any(token in name for token in ("partial", "complete", "truncated"))
    }
    assert completeness_fields == {"source_partial"}

    # And no cap reads it, under any name.
    assert "partial_source" not in CONFIDENCE_CAPS
    assert not any("partial" in value for value in CONFIDENCE_CAPS.values())
