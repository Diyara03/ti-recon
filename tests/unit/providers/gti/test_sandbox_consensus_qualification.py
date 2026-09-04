"""The consensus test behind a strong GTI sandbox classification (Task 24 Phase 1B).

Source independence and evidence strength are different concepts. Seven of
GTI's sandboxes classifying one sample malicious with stated confidence are
one origin -- and strong direct evidence. One malicious verdict beside three
suspicious and two harmless is the same origin and is not. The test that tells
them apart reads only the fields GTI documents for ``sandbox_verdicts``:
``category`` and ``confidence`` per sandbox, as the normalizer counts them.
GTI exposes no execution-quality field for these verdicts, so none is
modelled.
"""

from __future__ import annotations

import pytest

from fixtures.gti import payloads
from ti_recon.providers.gti.claim_semantics import (
    MIN_CONFIDENT_MALICIOUS,
    MIN_CONSENSUS_SANDBOXES,
    SANDBOX_QUALIFICATION_REASONS,
    qualify_sandbox_consensus,
)
from ti_recon.providers.gti.normalizer import SANDBOX_CONFIDENCE_FLOOR, normalize_sandbox_verdicts
from ti_recon.reasoning.claims import ClaimQualification

from .test_normalizer import context, gti_object

REASONS = SANDBOX_QUALIFICATION_REASONS


def _record(block: dict[str, object]):
    payload = payloads.file_object(
        with_assessment=False, extra_attributes={"sandbox_verdicts": block}
    )
    return normalize_sandbox_verdicts(context(), gti_object(payload)).evidence[0]


def _attributes(block: dict[str, object]) -> dict[str, object]:
    return dict(_record(block).attributes)


def _unanimous(count: int, confidence: int | None = 90) -> dict[str, object]:
    return payloads.sandbox_verdicts(
        *[(f"Sandbox {n}", "malicious", confidence, ("RANSOM",)) for n in range(count)]
    )


# --------------------------------------------------------------------------- #
# The normalizer counts what the test reads
# --------------------------------------------------------------------------- #


def test_the_normalizer_counts_confident_malicious_verdicts_over_the_whole_block() -> None:
    block = payloads.sandbox_verdicts(
        ("A", "malicious", 100, ()),
        ("B", "malicious", SANDBOX_CONFIDENCE_FLOOR, ()),
        ("C", "malicious", SANDBOX_CONFIDENCE_FLOOR - 1, ()),
        ("D", "malicious", None, ()),
        ("E", "suspicious", 95, ()),
    )
    attributes = _attributes(block)
    assert attributes["confidence_floor"] == SANDBOX_CONFIDENCE_FLOOR
    assert attributes["confident_malicious_count"] == 2
    assert attributes["malicious_without_confidence_count"] == 1
    assert attributes["malicious_confidence_min"] == SANDBOX_CONFIDENCE_FLOOR - 1
    assert attributes["malicious_confidence_max"] == 100


def test_counts_cover_entries_the_bounded_list_omits() -> None:
    attributes = _attributes(_unanimous(14))
    assert attributes["sandboxes_omitted"] == 4
    assert attributes["confident_malicious_count"] == 14


# --------------------------------------------------------------------------- #
# The qualification policy
# --------------------------------------------------------------------------- #


def test_a_unanimous_confident_malicious_consensus_is_strong() -> None:
    """Case A: 7 evaluated, 7 malicious, confidence stated, no harmless."""
    qualification, reasons = qualify_sandbox_consensus(_attributes(_unanimous(7)))
    assert qualification is ClaimQualification.STRONG_DIRECT
    assert reasons == (REASONS["unanimous"], REASONS["no_harmless"], REASONS["confident"])


def test_a_confident_majority_with_undetected_peers_is_strong_but_not_unanimous() -> None:
    block = payloads.sandbox_verdicts(
        ("A", "malicious", 95, ("TROJAN",)),
        ("B", "malicious", 80, ("TROJAN",)),
        ("C", "malicious", 70, ()),
        ("D", "undetected", None, ()),
        ("E", "suspicious", 40, ()),
    )
    qualification, reasons = qualify_sandbox_consensus(_attributes(block))
    assert qualification is ClaimQualification.STRONG_DIRECT
    assert reasons[0] == REASONS["majority"]


def test_one_weak_malicious_verdict_among_disagreeing_sandboxes_is_not_strong() -> None:
    """Case C: one malicious with no confidence, the rest disagree."""
    block = payloads.sandbox_verdicts(
        ("A", "malicious", None, ()),
        ("B", "suspicious", 60, ()),
        ("C", "undetected", None, ()),
        ("D", "harmless", 90, ()),
    )
    qualification, reasons = qualify_sandbox_consensus(_attributes(block))
    assert qualification is ClaimQualification.NOT_STRONG
    assert REASONS["harmless"] in reasons
    assert REASONS["confidence"] in reasons


def test_the_worked_counter_example_fails_on_three_counts() -> None:
    """1 malicious / 3 suspicious / 2 harmless, as the policy documents it."""
    block = payloads.sandbox_verdicts(
        ("A", "malicious", 100, ()),
        ("B", "suspicious", 90, ()),
        ("C", "suspicious", 90, ()),
        ("D", "suspicious", 90, ()),
        ("E", "harmless", 90, ()),
        ("F", "harmless", 90, ()),
    )
    qualification, reasons = qualify_sandbox_consensus(_attributes(block))
    assert qualification is ClaimQualification.NOT_STRONG
    assert set(reasons) == {REASONS["harmless"], REASONS["not_majority"], REASONS["confidence"]}


def test_suspicious_only_categories_are_hedged_never_strong() -> None:
    """Case D."""
    block = payloads.sandbox_verdicts(
        ("A", "suspicious", 100, ()),
        ("B", "suspicious", 100, ()),
        ("C", "suspicious", 100, ()),
    )
    qualification, reasons = qualify_sandbox_consensus(_attributes(block))
    assert qualification is ClaimQualification.NOT_STRONG
    assert REASONS["hedged"] in reasons


def test_a_single_sandbox_is_one_opinion_not_a_consensus() -> None:
    qualification, reasons = qualify_sandbox_consensus(_attributes(_unanimous(1, 100)))
    assert qualification is ClaimQualification.NOT_STRONG
    assert REASONS["too_few"] in reasons
    assert MIN_CONSENSUS_SANDBOXES == 2


def test_malicious_verdicts_without_stated_confidence_are_asserted_but_not_strong() -> None:
    """Nobody said how sure they were, so nothing counts toward consensus."""
    qualification, reasons = qualify_sandbox_consensus(_attributes(_unanimous(3, None)))
    assert qualification is ClaimQualification.NOT_STRONG
    assert reasons == (REASONS["confidence"],)


def test_a_harmless_verdict_beside_a_malicious_consensus_is_a_contradiction() -> None:
    """Case G: the contradiction is represented and defeats the qualification."""
    block = payloads.sandbox_verdicts(
        ("A", "malicious", 100, ("RANSOM",)),
        ("B", "malicious", 100, ("RANSOM",)),
        ("C", "malicious", 100, ("RANSOM",)),
        ("D", "harmless", 100, ()),
    )
    attributes = _attributes(block)
    assert attributes["divergent"] is True
    qualification, reasons = qualify_sandbox_consensus(attributes)
    assert qualification is ClaimQualification.NOT_STRONG
    assert reasons == (REASONS["harmless"],)


@pytest.mark.parametrize("confidence", [SANDBOX_CONFIDENCE_FLOOR, 75, 100])
def test_confidence_at_or_above_the_floor_counts_and_below_does_not(confidence: int) -> None:
    strong, _ = qualify_sandbox_consensus(_attributes(_unanimous(2, confidence)))
    weak, reasons = qualify_sandbox_consensus(
        _attributes(_unanimous(2, SANDBOX_CONFIDENCE_FLOOR - 1))
    )
    assert strong is ClaimQualification.STRONG_DIRECT
    assert weak is ClaimQualification.NOT_STRONG
    assert reasons == (REASONS["confidence"],)
    assert MIN_CONFIDENT_MALICIOUS == 2


def test_malicious_verdicts_must_be_a_strict_majority_of_everything_evaluated() -> None:
    block = payloads.sandbox_verdicts(
        ("A", "malicious", 100, ()),
        ("B", "malicious", 100, ()),
        ("C", "undetected", None, ()),
        ("D", "undetected", None, ()),
    )
    qualification, reasons = qualify_sandbox_consensus(_attributes(block))
    assert qualification is ClaimQualification.NOT_STRONG
    assert reasons == (REASONS["not_majority"],)


def test_unstated_confidence_counts_neither_for_nor_against() -> None:
    """The live shape: every sandbox said malicious, two backed it with a
    stated confidence, the rest stated none. Strong -- nobody undercut it."""
    block = payloads.sandbox_verdicts(
        ("A", "malicious", 100, ("RANSOM",)),
        ("B", "malicious", 90, ("RANSOM",)),
        *[(f"S{n}", "malicious", None, ("RANSOM",)) for n in range(5)],
    )
    qualification, reasons = qualify_sandbox_consensus(_attributes(block))
    assert qualification is ClaimQualification.STRONG_DIRECT
    assert reasons[0] == REASONS["unanimous"]


def test_a_stated_low_confidence_counts_against() -> None:
    """Two confident verdicts beside three that stated a confidence below the
    floor: the sandboxes that spoke to confidence mostly were not confident."""
    block = payloads.sandbox_verdicts(
        ("A", "malicious", 100, ()),
        ("B", "malicious", 90, ()),
        ("C", "malicious", 30, ()),
        ("D", "malicious", 20, ()),
        ("E", "malicious", 10, ()),
    )
    qualification, reasons = qualify_sandbox_consensus(_attributes(block))
    assert qualification is ClaimQualification.NOT_STRONG
    assert reasons == (REASONS["confidence"],)


def test_the_qualification_never_changes_direction_or_strength() -> None:
    """Confidence is a counting floor, not a weight: below it the record still
    supports malicious and is still asserted -- it simply does not decide."""
    from ti_recon.enums import EvidenceEffect

    record = _record(_unanimous(3, SANDBOX_CONFIDENCE_FLOOR - 10))
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert record.attributes["verdict"] == "malicious"


def test_the_claim_carries_one_bounded_confidence_summary_line() -> None:
    """The report can say how the verdicts were backed without a sandbox dump."""
    from fixtures.reasoning import gti_file_envelope
    from ti_recon.providers.gti.claim_semantics import translate
    from ti_recon.reasoning.claims import CLAIM_SEMANTICS_POLICY_VERSION, ClaimTranslationContext

    block = payloads.sandbox_verdicts(
        ("A", "malicious", 100, ("RANSOM",)),
        ("B", "malicious", 60, ("RANSOM",)),
        ("C", "malicious", None, ()),
    )
    envelope = gti_file_envelope(
        with_assessment=False, extra_attributes={"sandbox_verdicts": block}
    )
    context = ClaimTranslationContext.build(
        objects=envelope.objects, policy_version=CLAIM_SEMANTICS_POLICY_VERSION
    )
    record = next(item for item in envelope.evidence if item.claim_type == "gti.sandbox_verdicts")
    claim = next(item for item in translate(envelope, context) if item.evidence_id == record.id)
    assert (
        "confidence: 2 of 3 malicious verdicts stated >= 50, 1 stated none (stated range 60-100)"
        in claim.highlights
    )
    assert claim.qualification is ClaimQualification.STRONG_DIRECT
    assert len(claim.highlights) <= 8
