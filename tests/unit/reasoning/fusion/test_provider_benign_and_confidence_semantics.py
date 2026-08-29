"""Two provider distinctions the fusion layer must not blur (Task 17A/D).

**Benign is not undetected.** Google Threat Intelligence says `VERDICT_BENIGN`
when it has assessed something as benign, and `VERDICT_UNDETECTED` when nothing
flagged it. The second is also true of every threat nobody has caught yet, so
only the first is an affirmative determination. Nothing derived from counting
engines — zero malicious, forty harmless, `SEVERITY_NONE`, a zero threat score —
is an assertion either; those are statistics about who looked.

**Contributor confidence is not engine confidence.** ThreatFox carries a per-IOC
`confidence_level` from 0 to 100, defaulting to 50. TI Recon keeps it as the
submitter's number and reasons on none of it: there is no calibration mapping 75
onto MEDIUM, so a threshold would manufacture precision from a self-report.

Both are driven through the real normalizers and the real payload fixtures.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from fixtures.abusech import payloads as abusech_payloads
from fixtures.fusion import fuse, scenario
from fixtures.gti import payloads as gti_payloads
from fixtures.reasoning import file_object, observable, threatfox_compromised_envelope
from fixtures.reasoning.envelopes import _from_normalized, request_for
from ti_recon.enums import EvidenceEffect, Verdict
from ti_recon.providers.gti.adapter import GTIAdapter
from ti_recon.providers.gti.normalizer import VERDICT_EFFECTS
from ti_recon.reasoning.claims.models import ClaimSemantic
from ti_recon.reasoning.fusion.models import AssessmentConfidence
from ti_recon.reasoning.fusion.policy import VERDICT_RULES

#: Statistics with nothing flagged: many harmless, many undetected, zero malicious.
CLEAN_STATS: dict[str, int] = {
    "malicious": 0,
    "suspicious": 0,
    "harmless": 40,
    "undetected": 30,
    "timeout": 0,
    "failure": 0,
    "type-unsupported": 0,
}


def _gti(assessment: dict[str, Any] | None, stats: dict[str, int] | None = None):
    """One GTI file object through the real Task 7 normalizer and Task 17 fusion."""
    payload = gti_payloads.file_object()
    if assessment is None:
        payload["attributes"].pop("gti_assessment", None)
    else:
        payload["attributes"]["gti_assessment"] = assessment
    if stats is not None:
        payload["attributes"]["last_analysis_stats"] = stats
    subject = file_object(sha256=str(payload["id"]))
    result_envelope = _from_normalized(GTIAdapter(), request_for(subject), payload)
    return result_envelope, fuse(scenario(subject).with_envelope(result_envelope))


def _benign_claims(result) -> list[str]:
    return [
        claim.semantic.value
        for claim in result.normalized_claims
        if claim.semantic is ClaimSemantic.BENIGN_REPUTATION
    ]


def _benign_evidence(result_envelope) -> list[str]:
    return [
        record.claim_type
        for record in result_envelope.evidence
        if record.effect is EvidenceEffect.SUPPORTS_BENIGN
    ]


# --------------------------------------------------------------------------- #
# GTI: benign vs undetected
# --------------------------------------------------------------------------- #


def test_the_verdict_table_keeps_benign_and_undetected_apart() -> None:
    """The distinction at its source, before any of it reaches fusion."""
    assert VERDICT_EFFECTS["VERDICT_BENIGN"] is EvidenceEffect.SUPPORTS_BENIGN
    assert VERDICT_EFFECTS["VERDICT_UNDETECTED"] is EvidenceEffect.CONTEXT_ONLY
    assert VERDICT_EFFECTS["VERDICT_UNKNOWN"] is EvidenceEffect.CONTEXT_ONLY


def test_an_explicit_benign_verdict_is_a_benign_claim() -> None:
    """Case A, and the documented policy for case E.

    `VERDICT_BENIGN` is GTI stating a determination, so it becomes
    ``BENIGN_REPUTATION`` at exact scope — a genuine directional benign
    assertion, the only kind that can be a benign basis. Unopposed, it reaches
    LIKELY_BENIGN under `likely_benign.unopposed_benign_claim.v1`.

    **This is the reviewed v1 policy**: one provider's explicit benign
    determination about the exact object, with nothing malicious left standing,
    is enough. It rests on the provider having made an affirmative statement —
    never on how few engines flagged it.
    """
    result_envelope, result = _gti(
        {
            "verdict": {"value": "VERDICT_BENIGN"},
            "severity": {"value": "SEVERITY_NONE"},
            "threat_score": {"value": 0},
        },
        CLEAN_STATS,
    )

    assert _benign_evidence(result_envelope) == ["gti_assessment"]
    assert _benign_claims(result) == ["benign_reputation"]
    assert result.assessment.verdict is Verdict.LIKELY_BENIGN
    assert result.assessment.verdict_rule_id == VERDICT_RULES["likely_benign_directional"]


NON_ASSERTIONS = {
    # Case B: nothing flagged it, which is also true of every fresh threat.
    "undetected": (
        {
            "verdict": {"value": "VERDICT_UNDETECTED"},
            "severity": {"value": "SEVERITY_NONE"},
            "threat_score": {"value": 0},
        },
        CLEAN_STATS,
    ),
    # Case C: undetected plus zero malicious plus forty harmless engines.
    "undetected_with_clean_engine_counts": (
        {"verdict": {"value": "VERDICT_UNDETECTED"}},
        CLEAN_STATS,
    ),
    # Case D: a severity band, which grades a threat rather than denying one.
    "severity_none_only": ({"severity": {"value": "SEVERITY_NONE"}}, CLEAN_STATS),
    "zero_threat_score_only": ({"threat_score": {"value": 0}}, CLEAN_STATS),
    "unknown_verdict": ({"verdict": {"value": "VERDICT_UNKNOWN"}}, CLEAN_STATS),
    # No assessment at all: an absence of opinion is not an opinion.
    "no_assessment": (None, CLEAN_STATS),
}


@pytest.mark.parametrize("case", sorted(NON_ASSERTIONS))
def test_nothing_short_of_a_stated_verdict_creates_benign_support(case: str) -> None:
    """Cases B, C and D: no benign evidence, no benign claim, no LIKELY_BENIGN.

    Each row is a fact GTI reports and none of them is a determination. Reading
    any as one would be vendor-count arithmetic wearing a verdict's clothes, and
    it is precisely how a sample nobody has caught yet gets waved through.
    """
    assessment, stats = NON_ASSERTIONS[case]
    result_envelope, result = _gti(assessment, stats)

    assert _benign_evidence(result_envelope) == []
    assert _benign_claims(result) == []
    assert result.assessment.verdict is not Verdict.LIKELY_BENIGN


@pytest.mark.parametrize("case", ["undetected", "severity_none_only", "no_assessment"])
def test_a_clean_looking_gti_answer_is_inconclusive_not_benign(case: str) -> None:
    """Where nothing else is said, the honest answer is "cannot tell"."""
    assessment, stats = NON_ASSERTIONS[case]
    _, result = _gti(assessment, stats)

    if result.assessment.verdict is Verdict.INCONCLUSIVE:
        assert result.assessment.confidence is AssessmentConfidence.UNSPECIFIED
    # Whatever else it is, it is never a finding of safety.
    assert result.assessment.verdict is not Verdict.LIKELY_BENIGN


# --------------------------------------------------------------------------- #
# ThreatFox: contributor confidence stays the contributor's
# --------------------------------------------------------------------------- #


def _threatfox(confidence_level: int):
    payload = abusech_payloads.threatfox_domain_result()
    entry = copy.deepcopy(payload["data"][0])
    entry["confidence_level"] = confidence_level
    subject = observable(abusech_payloads.MALICIOUS_DOMAIN)
    result_envelope = threatfox_compromised_envelope(subject=subject, data=[entry])
    return result_envelope, fuse(scenario(subject).with_envelope(result_envelope))


@pytest.mark.parametrize("level", [0, 50, 75, 100])
def test_source_confidence_changes_nothing_about_the_assessment(level: int) -> None:
    """No threshold, documented or otherwise.

    Only the contributor's number changes across these runs. Verdict, confidence,
    both rule ids and the semantic must be identical, or an undocumented
    threshold has appeared somewhere.
    """
    _, baseline = _threatfox(50)
    _, actual = _threatfox(level)

    assert actual.assessment.verdict is baseline.assessment.verdict
    assert actual.assessment.confidence is baseline.assessment.confidence
    assert actual.assessment.verdict_rule_id == baseline.assessment.verdict_rule_id
    assert actual.assessment.confidence_rule_id == baseline.assessment.confidence_rule_id


@pytest.mark.parametrize("level", [0, 50, 100])
def test_source_confidence_is_preserved_verbatim_as_provider_data(level: int) -> None:
    """Kept for an analyst to read, and read by no rule."""
    result_envelope, result = _threatfox(level)

    preserved = [
        record.attributes["confidence_level"]
        for record in result_envelope.evidence
        if "confidence_level" in record.attributes
    ]
    assert preserved == [float(level)]
    # It reaches no claim, so no policy can key on it even by accident.
    for claim in result.normalized_claims:
        assert "confidence" not in claim.model_dump_json()


def test_an_exact_payload_delivery_ioc_is_malware_distribution() -> None:
    """The v1 policy decision, stated so it can be argued with.

    ThreatFox accepts confirmed and vetted IOC submissions, so an exact,
    unexpired `payload_delivery` record about the observable is treated as
    sufficient malicious evidence on its own — the same footing as any other
    curated repository making a specific claim about the exact object. The
    contributor's own confidence stays beside it and is never folded into TI
    Recon's, because the two answer different questions.
    """
    _, result = _threatfox(50)

    assert [claim.semantic for claim in result.normalized_claims] == [
        ClaimSemantic.MALWARE_DISTRIBUTION
    ]
    assert result.assessment.verdict is Verdict.MALICIOUS
    assert result.assessment.verdict_rule_id == VERDICT_RULES["malicious_decisive"]
