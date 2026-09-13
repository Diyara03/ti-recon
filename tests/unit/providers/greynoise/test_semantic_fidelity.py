"""GreyNoise's own distinctions survive to the claim (Task 24, GreyNoise validation).

A Community document says five separate things -- ``noise``, ``classification``,
``riot``, ``name`` and ``last_seen`` -- and a live run reduced them to
``scanner_activity -> supports_malicious`` by the time an analyst saw them
(GN-FINDING-01). These tests drive the real adapter over every Community shape
that matters and assert each distinction is preserved where it belongs:

* the **direction** comes from ``classification`` alone -- ``noise: true`` with
  an ``unknown`` classification is context and produces no claim (GN-FINDING-04);
* ``riot: false`` is the absence of business-service context, never malicious
  evidence, and ``riot: true`` is context, never proof of benignness (§13);
* the classification claim quotes the provider's word, whether scanning was
  observed, the RIOT state, the actor, the last sighting and the access path
  as bounded highlights, so the report can say them without reconstructing
  them from provider internals (§12);
* nothing quoted is raw JSON, and no credential reaches any of it (§17 O).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from fixtures.greynoise import payloads
from fixtures.greynoise.fake_client import FakeGreyNoiseClient, FakeGreyNoiseClientFactory
from ti_recon.credentials.enums import AuthType
from ti_recon.credentials.models import CredentialMaterial
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    ProviderCapability,
    ProviderErrorCategory,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.execution.clock import ManualClock
from ti_recon.normalization import normalize_observable
from ti_recon.providers import ProviderRequest
from ti_recon.providers.errors import provider_error_for
from ti_recon.providers.greynoise import (
    GreyNoiseAccessMode,
    GreyNoiseAdapter,
    GreyNoiseLookupPolicy,
)
from ti_recon.providers.greynoise.claim_semantics import (
    ACCESS_PATH_HIGHLIGHT,
    HIGHLIGHT_ATTRIBUTES,
    LAST_SEEN_HIGHLIGHT,
)
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.claims import (
    CLAIM_SEMANTICS_POLICY_VERSION,
    ClaimAssertionStrength,
    ClaimSemantic,
    ClaimTranslationContext,
    NormalizedClaim,
    translate_envelope,
)
from ti_recon.reasoning.claims.models import MAX_CLAIM_HIGHLIGHTS

FAKE_KEY = "greynoise-key-SHOULD-NOT-LEAK-fidelity-0001"
CLASSIFICATION = "greynoise_classification"
COMMUNITY = FakeGreyNoiseClient.COMMUNITY
FULL = FakeGreyNoiseClient.FULL


def _credential() -> CredentialMaterial:
    from pydantic import SecretStr

    return CredentialMaterial(
        connection_id="conn-1",
        user_id="analyst-a",
        provider_id="greynoise",
        credential_group="greynoise",
        auth_type=AuthType.API_KEY,
        secret=SecretStr(FAKE_KEY),
    )


def _request() -> ProviderRequest:
    return ProviderRequest(
        investigation_id="inv-1",
        intel_object=normalize_observable(payloads.SCANNER_IP).intel_object,
        operation=ProviderOperation.LOOKUP,
        requested_capabilities=frozenset(
            {ProviderCapability.REPUTATION, ProviderCapability.SCANNER_CONTEXT}
        ),
    )


async def community_envelope(**overrides: Any) -> ProviderResultEnvelope:
    """One lookup through a pinned Community door, over one Community document."""
    client = FakeGreyNoiseClient(community_payload=payloads.community_payload(**overrides))
    adapter = GreyNoiseAdapter(
        client_factory=FakeGreyNoiseClientFactory(client),  # type: ignore[arg-type]
        lookup_policy=GreyNoiseLookupPolicy(access_mode=GreyNoiseAccessMode.COMMUNITY),
        clock=ManualClock(),
    )
    return await adapter.lookup(_request(), _credential())


async def community_absent_envelope() -> ProviderResultEnvelope:
    """Community answering 404: "IP not observed scanning the internet"."""
    client = FakeGreyNoiseClient()
    client.fail(COMMUNITY, provider_error_for(ProviderErrorCategory.NOT_FOUND, "greynoise"))
    adapter = GreyNoiseAdapter(
        client_factory=FakeGreyNoiseClientFactory(client),  # type: ignore[arg-type]
        lookup_policy=GreyNoiseLookupPolicy(access_mode=GreyNoiseAccessMode.COMMUNITY),
        clock=ManualClock(),
    )
    return await adapter.lookup(_request(), _credential())


def claims_of(envelope: ProviderResultEnvelope) -> tuple[NormalizedClaim, ...]:
    context = ClaimTranslationContext.build(
        objects=envelope.objects, policy_version=CLAIM_SEMANTICS_POLICY_VERSION
    )
    return translate_envelope(envelope, context)


def classification_of(envelope: ProviderResultEnvelope) -> Any:
    return next(item for item in envelope.evidence if item.claim_type == CLASSIFICATION)


def directional(envelope: ProviderResultEnvelope) -> list[Any]:
    return [item for item in envelope.evidence if item.effect is not EvidenceEffect.CONTEXT_ONLY]


# --------------------------------------------------------------------------- #
# A / B / C -- the classification is the direction; scanning is not
# --------------------------------------------------------------------------- #


async def test_a_community_malicious_classification_is_one_asserted_scanner_claim() -> None:
    envelope = await community_envelope(classification="malicious")
    record = classification_of(envelope)
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert record.evidence_class is EvidenceClass.CURATED_THREAT_ASSERTION
    assert record.attributes["raw_classification"] == "malicious"
    assert record.attributes["observed_scanning"] is True

    (claim,) = claims_of(envelope)
    assert claim.semantic is ClaimSemantic.SCANNER_ACTIVITY
    assert claim.strength is ClaimAssertionStrength.ASSERTED
    assert claim.effect is EvidenceEffect.SUPPORTS_MALICIOUS


async def test_noise_with_an_unknown_classification_is_context_and_no_claim() -> None:
    """GN-FINDING-04 / §13 rule 1: scanning is not malicious by itself.

    GreyNoise saw the address scanning and declined to classify it. That is
    a fact about observation and points nowhere: no directional evidence, no
    claim of any semantic, and the observation itself is still on record.
    """
    envelope = await community_envelope(noise=True, classification="unknown")
    record = classification_of(envelope)
    assert record.effect is EvidenceEffect.CONTEXT_ONLY
    assert record.attributes["observed_scanning"] is True
    assert record.attributes["raw_classification"] == "unknown"
    assert directional(envelope) == []
    assert claims_of(envelope) == ()


async def test_a_benign_classification_points_toward_benign_and_stays_a_scanner_claim() -> None:
    envelope = await community_envelope(noise=True, classification="benign")
    record = classification_of(envelope)
    assert record.effect is EvidenceEffect.SUPPORTS_BENIGN
    assert record.attributes["observed_scanning"] is True
    (claim,) = claims_of(envelope)
    # A benign-classified scanner is still a claim about scanning, pointing
    # the way GreyNoise pointed it.
    assert claim.semantic is ClaimSemantic.SCANNER_ACTIVITY
    assert claim.effect is EvidenceEffect.SUPPORTS_BENIGN
    assert "raw_classification: benign" in claim.highlights


async def test_a_suspicious_classification_is_a_suspected_claim_and_says_the_word() -> None:
    envelope = await community_envelope(classification="suspicious")
    (claim,) = claims_of(envelope)
    assert claim.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert claim.strength is ClaimAssertionStrength.SUSPECTED
    assert "raw_classification: suspicious" in claim.highlights


@pytest.mark.parametrize("classification", ["malicious", "suspicious", "benign", "unknown"])
async def test_the_direction_is_read_from_the_classification_never_from_noise(
    classification: str,
) -> None:
    """The same ``noise: true`` beside four classifications gives four directions.

    If scanning were the direction, all four would point the same way.
    """
    expected = {
        "malicious": EvidenceEffect.SUPPORTS_MALICIOUS,
        "suspicious": EvidenceEffect.SUPPORTS_MALICIOUS,
        "benign": EvidenceEffect.SUPPORTS_BENIGN,
        "unknown": EvidenceEffect.CONTEXT_ONLY,
    }[classification]
    envelope = await community_envelope(noise=True, classification=classification)
    assert classification_of(envelope).effect is expected


# --------------------------------------------------------------------------- #
# D / E -- RIOT is context in one direction and absence in the other
# --------------------------------------------------------------------------- #


async def test_riot_true_is_business_service_context_and_never_proof_of_benignness() -> None:
    """§13 rule 3."""
    envelope = await community_envelope(riot=True, classification="malicious")
    record = classification_of(envelope)
    assert record.attributes["known_business_service"] is True
    # The malicious classification is untouched by the RIOT entry ...
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    # ... and the RIOT entry itself is context-class, so the model refuses it
    # a direction: nothing in the envelope points toward benign.
    business = next(
        item for item in envelope.evidence if item.claim_type == "greynoise_business_service"
    )
    assert business.evidence_class is EvidenceClass.CONTEXT
    assert business.effect is EvidenceEffect.CONTEXT_ONLY
    assert business.attributes["found"] is True
    assert not any(item.effect is EvidenceEffect.SUPPORTS_BENIGN for item in envelope.evidence)
    (claim,) = claims_of(envelope)
    assert "known_business_service: True" in claim.highlights


async def test_riot_false_is_the_absence_of_context_and_never_malicious_evidence() -> None:
    """§13 rule 4: an address with no RIOT entry has not thereby done anything."""
    envelope = await community_envelope(riot=False, noise=True, classification="unknown")
    record = classification_of(envelope)
    assert record.attributes["known_business_service"] is False
    assert directional(envelope) == []
    assert claims_of(envelope) == ()
    # And where the classification does point, RIOT's absence is quoted as an
    # absence rather than left unreported.
    envelope = await community_envelope(riot=False, classification="malicious")
    (claim,) = claims_of(envelope)
    assert "known_business_service: False" in claim.highlights
    assert not any(item.claim_type == "greynoise_business_service" for item in envelope.evidence), (
        "no business-service record exists for an address GreyNoise lists none for"
    )


async def test_the_community_name_is_the_actor_when_the_address_is_scanning() -> None:
    """Community spells the actor ``name``; the full context spells it ``actor``."""
    envelope = await community_envelope(name="Example Scanner Co")
    assert classification_of(envelope).attributes["actor"] == "Example Scanner Co"
    (claim,) = claims_of(envelope)
    assert "actor: Example Scanner Co" in claim.highlights


async def test_the_community_name_is_the_service_when_only_riot_matched() -> None:
    """The same field names the business service for a RIOT-only address.

    Filing it as a scanner actor would attribute scanning to a public DNS
    resolver GreyNoise explicitly said was not scanning.
    """
    envelope = await community_envelope(
        noise=False, riot=True, classification="benign", name="Example Public DNS"
    )
    assert "actor" not in classification_of(envelope).attributes
    business = next(
        item for item in envelope.evidence if item.claim_type == "greynoise_business_service"
    )
    assert business.attributes["name"] == "Example Public DNS"


# --------------------------------------------------------------------------- #
# F -- Community 404 is NO_DATA and nothing else
# --------------------------------------------------------------------------- #


async def test_a_community_404_is_no_data_with_no_direction_and_no_claim() -> None:
    """§11 / §13 rule 5: not benign, not safe, not an auth failure, not opposition."""
    envelope = await community_absent_envelope()
    assert envelope.status is ProviderRunStatus.NO_DATA
    assert envelope.error_message is None
    assert directional(envelope) == []
    assert claims_of(envelope) == ()
    kinds = {item.claim_type for item in envelope.evidence}
    # What *is* recorded is the coverage fact -- which door answered -- and
    # the not-observed record, which is why ``produced_evidence`` is true for
    # a NO_DATA check: the source wrote down what it did not find.
    assert kinds == {"greynoise_coverage", "greynoise_not_observed"}
    absent = next(item for item in envelope.evidence if item.claim_type == "greynoise_not_observed")
    assert absent.evidence_class is EvidenceClass.CONTEXT
    assert absent.attributes["observed_scanning"] is False
    coverage = next(item for item in envelope.evidence if item.claim_type == "greynoise_coverage")
    assert coverage.attributes["access_level"] == "community"


# --------------------------------------------------------------------------- #
# §12 -- the bounded representation the report can quote
# --------------------------------------------------------------------------- #


async def test_the_claim_quotes_every_distinction_the_community_document_drew() -> None:
    envelope = await community_envelope()
    (claim,) = claims_of(envelope)
    assert claim.highlights == (
        "raw_classification: malicious",
        "observed_scanning: True",
        "known_business_service: False",
        "actor: unknown",
        f"{LAST_SEEN_HIGHLIGHT}: 2026-08-20T00:00:00Z",
        f"{ACCESS_PATH_HIGHLIGHT}: community",
    )
    assert len(claim.highlights) <= MAX_CLAIM_HIGHLIGHTS


async def test_the_access_path_is_quoted_from_the_same_answers_coverage_record() -> None:
    """Full-tier answer, full-tier access path -- read from the envelope, never assumed."""
    client = FakeGreyNoiseClient()
    adapter = GreyNoiseAdapter(
        client_factory=FakeGreyNoiseClientFactory(client),  # type: ignore[arg-type]
        clock=ManualClock(),
    )
    envelope = await adapter.lookup(_request(), _credential())
    assert client.called(FULL)
    (claim,) = claims_of(envelope)
    assert f"{ACCESS_PATH_HIGHLIGHT}: full" in claim.highlights
    assert "raw_classification: malicious" in claim.highlights
    # The full document carries no ``noise`` flag by that name; ``found`` is
    # the same fact and reads through the same accessor.
    assert "observed_scanning: True" in claim.highlights


async def test_a_missing_coverage_record_writes_no_access_path_line() -> None:
    """Nothing is inferred: without the record, the line is simply absent."""
    envelope = await community_envelope()
    stripped = envelope.model_copy(
        update={
            "evidence": tuple(
                item for item in envelope.evidence if item.claim_type != "greynoise_coverage"
            )
        }
    )
    (claim,) = claims_of(stripped)
    assert not any(line.startswith(ACCESS_PATH_HIGHLIGHT) for line in claim.highlights)


def test_the_highlighted_attributes_are_bounded_scalars_the_normalizer_already_keeps() -> None:
    """The classification is quoted first, because it is the only field the
    effect was read from; the others are facts beside it, never weights."""
    assert HIGHLIGHT_ATTRIBUTES[0] == "raw_classification"
    assert set(HIGHLIGHT_ATTRIBUTES) == {
        "raw_classification",
        "observed_scanning",
        "known_business_service",
        "actor",
    }
    assert "reference" not in HIGHLIGHT_ATTRIBUTES, "a permalink is not something the source said"


# --------------------------------------------------------------------------- #
# O -- no raw JSON, no credential
# --------------------------------------------------------------------------- #


async def test_no_highlight_is_raw_json_and_none_carries_the_credential() -> None:
    envelope = await community_envelope()
    serialized = envelope.model_dump_json()
    assert FAKE_KEY not in serialized
    assert "SHOULD-NOT-LEAK" not in serialized
    for claim in claims_of(envelope):
        for line in claim.highlights:
            assert "{" not in line and "}" not in line, line
            assert FAKE_KEY not in line
            assert len(line) <= 160
        assert FAKE_KEY not in json.dumps(claim.model_dump(mode="json"))
