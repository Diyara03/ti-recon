"""Every directional provider claim has an intentional semantic (Task 17A).

The regression that keeps the claim layer honest. It drives the **real
adapters** over the real payload fixtures, collects every piece of directional
evidence the nine providers actually emit, and asserts each one either maps to a
deliberate semantic or is explicitly unclassified.

Without it the failure is silent and expensive: a provider adds a directional
claim type, nothing maps it, it becomes ``UNCLASSIFIED_DIRECTIONAL``, and a real
finding quietly stops being able to support anything. This test turns that into a
red build and a decision somebody has to make on purpose.
"""

from __future__ import annotations

import pytest

from fixtures.hybrid_analysis import payloads as sandbox_payloads
from fixtures.reasoning import (
    censys_host_envelope,
    greynoise_envelope,
    gti_file_envelope,
    malwarebazaar_envelope,
    sandbox_envelope,
    threatfox_compromised_envelope,
    threatfox_ip_envelope,
    urlhaus_payload_envelope,
    urlhaus_url_envelope,
    urlscan_scan_envelope,
)
from ti_recon.enums import EvidenceEffect
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.claims import (
    CLAIM_SEMANTICS_POLICY_VERSION,
    ClaimSemantic,
    ClaimTranslationContext,
    translate_envelope,
    translated_provider_ids,
)

#: Every shipped provider result these tests can obtain, including the shapes a
#: single happy-path fixture would not reach.
REAL_ENVELOPES = (
    ("gti", gti_file_envelope),
    ("urlscan", urlscan_scan_envelope),
    ("greynoise", greynoise_envelope),
    ("censys", censys_host_envelope),
    ("threatfox_ip", threatfox_ip_envelope),
    ("threatfox_domain", threatfox_compromised_envelope),
    ("urlhaus_url", urlhaus_url_envelope),
    ("urlhaus_payload", urlhaus_payload_envelope),
    ("malwarebazaar", malwarebazaar_envelope),
    ("sandbox", sandbox_envelope),
    (
        "sandbox_divergent",
        lambda: sandbox_envelope(search=sandbox_payloads.search_hash_divergent()),
    ),
)


def claims_for(envelope: ProviderResultEnvelope) -> tuple[object, ...]:
    context = ClaimTranslationContext.build(
        objects=envelope.objects, policy_version=CLAIM_SEMANTICS_POLICY_VERSION
    )
    return translate_envelope(envelope, context)


@pytest.mark.parametrize("name,builder", REAL_ENVELOPES, ids=[item[0] for item in REAL_ENVELOPES])
def test_every_directional_claim_is_translated(name: str, builder: object) -> None:
    """No directional finding disappears between the provider and fusion.

    One claim out, one claim in. A translator that dropped evidence would remove
    a real provider finding from the assessment without anybody seeing it go.
    """
    envelope = builder()  # type: ignore[operator]
    directional = [
        item for item in envelope.evidence if item.effect is not EvidenceEffect.CONTEXT_ONLY
    ]
    claims = claims_for(envelope)
    assert len(claims) == len(directional), name
    assert {item.evidence_id for item in claims} == {item.id for item in directional}  # type: ignore[attr-defined]


@pytest.mark.parametrize("name,builder", REAL_ENVELOPES, ids=[item[0] for item in REAL_ENVELOPES])
def test_no_shipped_directional_claim_is_unclassified(name: str, builder: object) -> None:
    """Every claim the nine providers currently emit maps on purpose.

    An unclassified claim is not a bug in itself -- it is the honest fallback --
    but none of the shipped providers should be hitting it today. If one does,
    the right response is a translator entry, not a silently weakened finding.
    """
    unmapped = [
        item
        for item in claims_for(builder())  # type: ignore[operator]
        if item.semantic is ClaimSemantic.UNCLASSIFIED_DIRECTIONAL  # type: ignore[attr-defined]
    ]
    assert unmapped == [], (
        f"{name}: unmapped directional claim(s) "
        f"{[getattr(item, 'evidence_id', '?') for item in unmapped]}"
    )


def test_context_only_evidence_never_becomes_a_claim() -> None:
    """A warninglist hit, a coverage record and a "nothing found" note all say
    something worth keeping, and none of them asserts a proposition."""
    for _, builder in REAL_ENVELOPES:
        envelope = builder()  # type: ignore[operator]
        context_ids = {
            item.id for item in envelope.evidence if item.effect is EvidenceEffect.CONTEXT_ONLY
        }
        produced = {item.evidence_id for item in claims_for(envelope)}  # type: ignore[attr-defined]
        assert not (context_ids & produced)


def test_providers_without_directional_evidence_produce_no_claims() -> None:
    """Censys says what is exposed; exposure is not an accusation. MISP hits are
    context. Neither has a translator, and neither needs one."""
    assert claims_for(censys_host_envelope()) == ()
    assert "censys" not in translated_provider_ids()
    assert "misp_warninglists" not in translated_provider_ids()


def test_a_provider_with_no_translator_falls_back_conservatively() -> None:
    """The behaviour that makes adding a provider safe.

    Its findings survive and are visible; none can be decisive, because nothing
    knows what they assert. Dropping them would hide a real claim and guessing a
    semantic would be worse than either.
    """
    from fixtures.fusion import envelope as build_envelope
    from fixtures.fusion import evidence as build_evidence
    from fixtures.fusion import observable

    target = observable("198.51.100.7")
    record = build_evidence(target, claim_type="newprovider_finding", provider="newprovider")
    produced = claims_for(build_envelope(record, provider="newprovider", objects=(target,)))
    assert len(produced) == 1
    assert produced[0].semantic is ClaimSemantic.UNCLASSIFIED_DIRECTIONAL  # type: ignore[attr-defined]


def test_the_scanner_and_c2_distinction_now_exists() -> None:
    """The Task 16 limitation, resolved at the semantic layer.

    GreyNoise classifies scanning behaviour; ThreatFox's structured
    ``botnet_cc`` says command and control. Task 16 could not tell them apart --
    both are ``CURATED_THREAT_ASSERTION`` with ``SUPPORTS_MALICIOUS`` -- so it
    deferred rather than guessed. They are now different propositions.
    """
    scanner = {item.semantic for item in claims_for(greynoise_envelope())}  # type: ignore[attr-defined]
    c2 = {item.semantic for item in claims_for(threatfox_ip_envelope())}  # type: ignore[attr-defined]

    assert ClaimSemantic.SCANNER_ACTIVITY in scanner
    assert ClaimSemantic.C2_ASSOCIATION in c2
    assert not (scanner & c2)


def test_threatfox_structured_threat_type_selects_the_semantic() -> None:
    """The mapping is from a documented platform value, never from prose."""
    c2 = {item.semantic for item in claims_for(threatfox_ip_envelope())}  # type: ignore[attr-defined]
    delivery = {item.semantic for item in claims_for(threatfox_compromised_envelope())}  # type: ignore[attr-defined]
    assert ClaimSemantic.C2_ASSOCIATION in c2
    assert ClaimSemantic.MALWARE_DISTRIBUTION in delivery


def test_aggregates_are_marked_as_aggregates() -> None:
    """A roll-up of other people's opinions is one source reporting many.

    Marking it as such is what stops forty vendor detections becoming forty
    corroborations later.
    """
    gti = {item.semantic for item in claims_for(gti_file_envelope())}  # type: ignore[attr-defined]
    urlscan = {item.semantic for item in claims_for(urlscan_scan_envelope())}  # type: ignore[attr-defined]
    assert ClaimSemantic.AGGREGATED_REPUTATION in gti
    assert ClaimSemantic.AGGREGATED_REPUTATION in urlscan


def test_the_strongest_object_claims_come_from_exact_identity_sources() -> None:
    """MalwareBazaar holds the sample; URLhaus tracked the delivery."""
    sample = {item.semantic for item in claims_for(malwarebazaar_envelope())}  # type: ignore[attr-defined]
    delivery = {item.semantic for item in claims_for(urlhaus_url_envelope())}  # type: ignore[attr-defined]
    assert ClaimSemantic.MALWARE_SAMPLE_IDENTITY in sample
    assert ClaimSemantic.MALWARE_DISTRIBUTION in delivery
