"""GTI's curated associations map on purpose, and corroborate nothing alone (Task 24).

A live DEEP lookup returned five ``gti.threat_association.*`` claims that no
translator entry knew, so every one became ``UNCLASSIFIED_DIRECTIONAL`` and the
assessment carried a cap for a claim nobody could read. Each relationship the
normalizer emits now has an exact entry: a family, actor or campaign attribution
is asserted; a report mention and a plain collection membership are hedged.
None of them is decisive, and none is compatible with a sandbox verdict, so a
same-origin association changes no verdict on its own.
"""

from __future__ import annotations

from fixtures.fusion import envelope, evidence, file_object, fuse, scenario
from fixtures.reasoning import gti_file_deep_envelope
from ti_recon.enums import Verdict
from ti_recon.providers.gti.claim_semantics import ASSOCIATION_STRENGTHS, CLAIM_SEMANTICS
from ti_recon.providers.gti.relationships import RELATIONSHIP_SPECS, TargetKind
from ti_recon.reasoning.claims import (
    CLAIM_SEMANTICS_POLICY_VERSION,
    ClaimAssertionStrength,
    ClaimSemantic,
    ClaimTranslationContext,
    translate_envelope,
)
from ti_recon.reasoning.fusion.models import ContributionRole
from ti_recon.reasoning.fusion.policy import VERDICT_RULES

SHA = "d" * 64


def _association_claims():
    result = gti_file_deep_envelope()
    context = ClaimTranslationContext.build(
        objects=result.objects, policy_version=CLAIM_SEMANTICS_POLICY_VERSION
    )
    by_id = {item.id: item for item in result.evidence}
    return {
        by_id[claim.evidence_id].claim_type: claim
        for claim in translate_envelope(result, context)
        if by_id[claim.evidence_id].claim_type.startswith("gti.threat_association.")
    }


def test_every_association_relationship_the_normalizer_can_emit_is_mapped() -> None:
    """One exact entry per threat-object relationship in the spec table.

    Derived from the specs rather than restated, so a relationship added to the
    table fails here until somebody decides what its claim means.
    """
    expected = {
        f"gti.threat_association.{name.replace('_', '-')}"
        for name, spec in RELATIONSHIP_SPECS.items()
        if spec.target_kind is TargetKind.THREAT_OBJECT
    }
    assert expected == set(ASSOCIATION_STRENGTHS)
    assert expected <= set(CLAIM_SEMANTICS)


def test_the_associations_a_deep_file_lookup_reaches_translate_on_purpose() -> None:
    claims = _association_claims()
    # The file DEEP plan lists eleven relationships and fetches ten, so
    # ``campaigns`` is never reached for a file; the other four are.
    assert set(claims) == set(ASSOCIATION_STRENGTHS) - {"gti.threat_association.campaigns"}
    for claim_type, claim in claims.items():
        assert CLAIM_SEMANTICS[claim_type] is ClaimSemantic.THREAT_ACTOR_ASSOCIATION
        assert claim.semantic is ClaimSemantic.THREAT_ACTOR_ASSOCIATION, claim_type
        assert claim.strength is ASSOCIATION_STRENGTHS[claim_type], claim_type


def test_attribution_is_asserted_and_a_mention_is_hedged() -> None:
    asserted = {
        "gti.threat_association.malware-families",
        "gti.threat_association.related-threat-actors",
        "gti.threat_association.campaigns",
    }
    for claim_type, strength in ASSOCIATION_STRENGTHS.items():
        expected = (
            ClaimAssertionStrength.ASSERTED
            if claim_type in asserted
            else ClaimAssertionStrength.SUSPECTED
        )
        assert strength is expected, claim_type


def test_an_association_claim_says_what_it_associates_with() -> None:
    claims = _association_claims()
    family = claims["gti.threat_association.malware-families"]
    assert family.highlights == (
        "relationship: malware_families",
        "gti_collection_type: malware-family",
        "name: SyntheticRAT",
    )


def test_a_same_origin_association_does_not_complete_a_malicious_verdict() -> None:
    """An attribution beside a sandbox verdict from one origin stays concern.

    The two are not compatible propositions, so the single-origin rule does not
    fire; and the claim is mapped, so no unclassified cap is charged either.
    """
    sample = file_object(sha256=SHA)
    family = evidence(
        sample,
        claim_type="gti.threat_association.malware-families",
        provider="gti",
        source_family="google_ti",
        lineage_group_id="google_ti:gti",
        attributes={"relationship": "malware_families", "name": "SyntheticRAT"},
    )
    sandboxes = evidence(
        sample,
        claim_type="gti.sandbox_verdicts",
        provider="gti",
        source_family="google_ti",
        lineage_group_id="google_ti:gti",
        attributes={"verdict": "malicious", "sandbox_count": 3},
    )
    scene = scenario(sample).with_envelope(
        envelope(family, sandboxes, provider="gti", objects=(sample,))
    )

    result = fuse(scene)

    assert result.assessment.verdict is Verdict.SUSPICIOUS
    assert result.assessment.verdict_rule_id != VERDICT_RULES["malicious_single_origin"]
    assert "cap.unclassified_directional_claim.v1" not in result.assessment.confidence_caps
    basis = {
        item.evidence_id
        for item in result.contributions_with_role(ContributionRole.SUPPORTS_VERDICT)
    }
    assert {family.id, sandboxes.id} <= basis
