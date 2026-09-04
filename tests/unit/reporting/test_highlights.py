"""What the source said travels to the report, bounded and neutralised (Task 24).

A claim's highlights are the provider's own words about its own claim. The
report copies them, bounds them and neutralises them for a terminal; it never
ranks by them.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from fixtures.fusion import evidence, file_object
from ti_recon.enums import EvidenceEffect, MatchScope
from ti_recon.reasoning.claims.models import (
    MAX_CLAIM_HIGHLIGHT_LENGTH,
    MAX_CLAIM_HIGHLIGHTS,
    ClaimQualification,
    ClaimSemantic,
    NormalizedClaim,
    claim_from,
)
from ti_recon.reasoning.claims.policy import CLAIM_SEMANTICS_POLICY_VERSION
from ti_recon.reasoning.claims.translation import highlights_from
from ti_recon.reasoning.fusion.models import (
    ClaimContribution,
    ClaimDecisionRole,
    ClaimDisposition,
    ContributionRole,
)
from ti_recon.reporting.builder import _basis_item
from ti_recon.reporting.models import BasisItem
from ti_recon.reporting.text import _basis_lines


def _claim(highlights: tuple[str, ...]) -> NormalizedClaim:
    sample = file_object(sha256="c" * 64)
    record = evidence(sample, claim_type="alpha_sandbox")
    return claim_from(
        record,
        policy_version=CLAIM_SEMANTICS_POLICY_VERSION,
        semantic=ClaimSemantic.SANDBOX_CLASSIFICATION,
        subject_key=sample.canonical_key,
        highlights=highlights,
    )


def _contribution(claim: NormalizedClaim) -> ClaimContribution:
    return ClaimContribution(
        claim_id=claim.claim_id,
        evidence_id=claim.evidence_id,
        role=ContributionRole.SUPPORTS_VERDICT,
        disposition=ClaimDisposition.UNEXPLAINED,
        decision_role=ClaimDecisionRole.CORROBORATIVE,
        semantic=claim.semantic,
        effect=EvidenceEffect.SUPPORTS_MALICIOUS,
        scope=MatchScope.EXACT_OBSERVABLE,
        source_family=claim.source_family,
        proposition_ref=claim.proposition.ref,
        reason_codes=(),
    )


def test_highlights_are_copied_onto_the_basis_item() -> None:
    claim = _claim(("verdict: malicious", "malware_classification: RANSOM"))
    item = _basis_item(_contribution(claim), claim)
    assert item.highlights == ("verdict: malicious", "malware_classification: RANSOM")


def test_a_claim_without_highlights_reports_none_and_is_weighed_the_same() -> None:
    claim = _claim(())
    item = _basis_item(_contribution(claim), claim)
    assert item.highlights == ()
    assert item.decision_role == "corroborative"


def test_highlights_are_bounded_at_the_claim() -> None:
    claim = _claim(tuple(f"line {n} " + "x" * 400 for n in range(20)))
    assert len(claim.highlights) == MAX_CLAIM_HIGHLIGHTS
    assert all(len(item) <= MAX_CLAIM_HIGHLIGHT_LENGTH for item in claim.highlights)
    with pytest.raises(ValidationError):
        BasisItem(
            role="supports_verdict",
            decision_role="corroborative",
            disposition="unexplained",
            semantic="sandbox_classification",
            effect="supports_malicious",
            scope="exact_observable",
            source_family="alpha",
            claim_id="x" * 8,
            evidence_id="e",
            highlights=tuple(str(n) for n in range(9)),
        )


def test_the_formatter_renders_named_attributes_only_and_splices_prepared_lines() -> None:
    lines = highlights_from(
        {
            "verdict": "malicious",
            "malware_classification": ["RANSOM", "TROJAN"],
            "highlights": ["attack T1486 (high): Encrypts files", "sigma high: Shadow copies"],
            "secret_looking": "should never appear",
            "empty": [],
        },
        ("verdict", "malware_classification", "highlights"),
    )
    assert lines == (
        "verdict: malicious",
        "malware_classification: RANSOM, TROJAN",
        "attack T1486 (high): Encrypts files",
        "sigma high: Shadow copies",
    )


def test_the_text_renderer_neutralises_a_hostile_highlight() -> None:
    item = _basis_item(
        _contribution(_claim(("verdict: malicious\r\nVerdict: BENIGN\x1b[0m",))),
        _claim(("verdict: malicious\r\nVerdict: BENIGN\x1b[0m",)),
    )
    rendered = "\n".join(_basis_lines(item))
    assert "said:" in rendered
    assert "\x1b" not in rendered
    assert "\r" not in rendered
    assert "Verdict: BENIGN" not in rendered.split("said:")[0]


def test_the_text_renderer_states_the_qualification_and_its_reasons() -> None:
    """Decision-relevant transparency (Task 24 Phase 1B): why a claim was or
    was not strong is printed beside what the source said, neutralised."""
    claim = _claim(("verdict: malicious",)).model_copy(
        update={
            "qualification": ClaimQualification.STRONG_DIRECT,
            "qualification_reasons": ("sandbox.unanimous_malicious", "bad\x1b[0mcode"),
        }
    )
    item = _basis_item(_contribution(claim), claim)
    assert item.qualification == "strong_direct"
    rendered = "\n".join(_basis_lines(item))
    assert "qualification: strong_direct (sandbox.unanimous_malicious, " in rendered
    assert "\x1b" not in rendered


def test_an_unqualified_item_prints_no_qualification_line() -> None:
    item = _basis_item(_contribution(_claim(())), _claim(()))
    assert item.qualification == "unqualified"
    assert not any("qualification:" in line for line in _basis_lines(item))
