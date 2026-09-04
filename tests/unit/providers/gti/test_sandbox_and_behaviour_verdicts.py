"""What GTI's sandboxes said about a file, and what the sample merely did (Task 24).

Two blocks carry a sandbox's *classification* of a file: the file-level
``sandbox_verdicts`` map, which every VirusTotal-keyed account receives, and
the DEEP behaviour summary's own ``verdicts``. Each becomes one directional
record -- a curated assertion, because a verdict is the sandbox's judgement
rather than the watching itself -- and the two share one proposition from one
origin, so fusion sees one claim however many sandboxes agreed.

Everything else in a detonation -- techniques, processes, registry keys,
signatures -- is what the sample *did*. It travels as bounded highlights beside
the verdict and never becomes evidence on its own, because legitimate software
does those things too.
"""

from __future__ import annotations

from fixtures.gti import payloads
from fixtures.gti.fake_client import FakeGTIClient
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    InvestigationDepth,
    MatchScope,
    ProviderCapability,
    ProviderRunStatus,
)
from ti_recon.providers.gti.adapter import GTI_BEHAVIOR_NEEDS_DEEP
from ti_recon.providers.gti.claim_semantics import translate
from ti_recon.providers.gti.normalizer import (
    BEHAVIOR_VERDICT_STRENGTH,
    GTI_LINEAGE_GROUP,
    GTI_SANDBOX_VERDICTS_UNREADABLE,
    GTI_SOURCE_FAMILY,
    SANDBOX_VERDICT_EFFECTS,
    normalize_sandbox_verdicts,
)
from ti_recon.reasoning.claims.models import ClaimAssertionStrength, ClaimSemantic
from ti_recon.reasoning.claims.policy import CLAIM_SEMANTICS_POLICY_VERSION
from ti_recon.reasoning.claims.translation import ClaimTranslationContext
from ti_recon.reasoning.fusion.models import ClaimDecisionRole
from ti_recon.reasoning.fusion.policy import decision_role_for

from .test_normalizer import context, gti_object
from .test_threat_context import credential, file_subject, make_adapter, request_for


def _object(block: dict | None):
    """A file object carrying (or not carrying) a ``sandbox_verdicts`` block."""
    extra = {"sandbox_verdicts": block} if block is not None else None
    return gti_object(payloads.file_object(with_assessment=False, extra_attributes=extra))


MALICIOUS_SANDBOXES = payloads.sandbox_verdicts(
    ("Zenbox", "malicious", 100, ("RANSOM", "TROJAN")),
    ("CAPE Sandbox", "malicious", 84, ("RANSOM",)),
    ("Yomi Hunter", "suspicious", 40, ()),
)


def _claims(envelope):
    context = ClaimTranslationContext.build(
        objects=tuple(envelope.objects),
        root=envelope.objects[0] if envelope.objects else None,
        source_partial=False,
        policy_version=CLAIM_SEMANTICS_POLICY_VERSION,
    )
    return translate(envelope, context)


# --------------------------------------------------------------------------- #
# A/B: sandbox_verdicts becomes one assessable record
# --------------------------------------------------------------------------- #


def test_malicious_sandbox_verdicts_become_one_curated_malicious_record() -> None:
    """The strongest category any sandbox stated, as one record, with every
    sandbox listed beside it."""
    result = normalize_sandbox_verdicts(context(), _object(MALICIOUS_SANDBOXES))

    assert [e.claim_type for e in result.evidence] == ["gti.sandbox_verdicts"]
    record = result.evidence[0]
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert record.evidence_class is EvidenceClass.CURATED_THREAT_ASSERTION
    assert record.match_scope is MatchScope.EXACT_OBSERVABLE
    assert record.attributes["verdict"] == "malicious"
    assert record.attributes["malicious_count"] == 2
    assert record.attributes["suspicious_count"] == 1
    assert record.attributes["sandbox_count"] == 3
    assert record.attributes["divergent"] is False
    assert record.attributes["malware_classification"] == ["RANSOM", "TROJAN"]
    # The highest confidence among the sandboxes that stated the chosen category.
    assert record.provider_confidence == 100
    assert {item["sandbox_name"] for item in record.attributes["sandboxes"]} == {
        "Zenbox",
        "CAPE Sandbox",
        "Yomi Hunter",
    }
    # No instant is manufactured: a sandbox verdict carries no timestamp.
    assert record.last_seen is None


def test_a_suspicious_only_sandbox_set_is_a_hedged_claim_and_stays_weak() -> None:
    block = payloads.sandbox_verdicts(("Zenbox", "suspicious", 30, ()))
    result = normalize_sandbox_verdicts(context(), _object(block))

    record = result.evidence[0]
    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert record.attributes["verdict"] == "suspicious"


def test_harmless_and_undetected_are_context_never_benign() -> None:
    """A sandbox that saw nothing did not see safety."""
    block = payloads.sandbox_verdicts(
        ("Zenbox", "harmless", 90, ()), ("CAPE Sandbox", "undetected", None, ())
    )
    result = normalize_sandbox_verdicts(context(), _object(block))

    record = result.evidence[0]
    assert record.effect is EvidenceEffect.CONTEXT_ONLY
    assert record.evidence_class is EvidenceClass.CONTEXT
    assert record.attributes["verdict"] == "harmless"
    assert SANDBOX_VERDICT_EFFECTS["harmless"] is EvidenceEffect.CONTEXT_ONLY
    assert SANDBOX_VERDICT_EFFECTS["undetected"] is EvidenceEffect.CONTEXT_ONLY
    assert EvidenceEffect.SUPPORTS_BENIGN not in SANDBOX_VERDICT_EFFECTS.values()


def test_divergence_is_preserved_beside_the_malicious_direction() -> None:
    block = payloads.sandbox_verdicts(
        ("Zenbox", "malicious", 100, ("RANSOM",)), ("Yomi Hunter", "harmless", 60, ())
    )
    record = normalize_sandbox_verdicts(context(), _object(block)).evidence[0]

    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert record.attributes["divergent"] is True
    assert record.attributes["harmless_count"] == 1


def test_an_unreadable_block_degrades_rather_than_inventing_a_verdict() -> None:
    block = {"Zenbox": {"category": "weird-new-value"}, "Other": "not a mapping"}
    result = normalize_sandbox_verdicts(context(), _object(block))

    assert result.evidence == ()
    assert result.degraded is True
    assert GTI_SANDBOX_VERDICTS_UNREADABLE in result.warnings


def test_an_absent_block_is_silent() -> None:
    assert normalize_sandbox_verdicts(context(), _object(None)).evidence == ()


def test_the_sandbox_list_and_its_labels_are_bounded() -> None:
    many = payloads.sandbox_verdicts(
        *[
            (f"sandbox-{index:02d}", "malicious", 50, tuple(f"L{n}" for n in range(9)))
            for index in range(14)
        ]
    )
    record = normalize_sandbox_verdicts(context(), _object(many)).evidence[0]

    assert len(record.attributes["sandboxes"]) == 10
    assert record.attributes["sandboxes_omitted"] == 4
    assert record.attributes["sandbox_count"] == 14
    assert len(record.attributes["malware_classification"]) <= 5
    assert all(len(item["malware_classification"]) <= 5 for item in record.attributes["sandboxes"])


# --------------------------------------------------------------------------- #
# Translation: strength follows the stated category; one proposition, one origin
# --------------------------------------------------------------------------- #


def _fake(primary: dict, *, behaviour: dict | None = None) -> FakeGTIClient:
    fake = FakeGTIClient(behaviour_payload=behaviour or {})
    fake.register_primary("files", primary)
    return fake


async def _lookup(primary: dict, *, depth=InvestigationDepth.STANDARD, behaviour=None):
    adapter = make_adapter(_fake(primary, behaviour=behaviour))
    return await adapter.lookup(request_for(file_subject(), depth=depth), credential())


async def test_a_malicious_sandbox_record_is_a_firm_sandbox_classification() -> None:
    envelope = await _lookup(
        payloads.file_object(
            with_assessment=False, extra_attributes={"sandbox_verdicts": MALICIOUS_SANDBOXES}
        )
    )
    claims = {c.evidence_id: c for c in _claims(envelope)}
    record = next(e for e in envelope.evidence if e.claim_type == "gti.sandbox_verdicts")

    claim = claims[record.id]
    assert claim.semantic is ClaimSemantic.SANDBOX_CLASSIFICATION
    assert claim.strength is ClaimAssertionStrength.ASSERTED
    assert decision_role_for(claim) is ClaimDecisionRole.CORROBORATIVE
    assert claim.source_family == GTI_SOURCE_FAMILY
    assert claim.lineage_group_id == GTI_LINEAGE_GROUP
    assert any(item.startswith("verdict: malicious") for item in claim.highlights)
    assert any("RANSOM" in item for item in claim.highlights)


async def test_a_suspicious_sandbox_record_is_hedged_and_therefore_weak() -> None:
    block = payloads.sandbox_verdicts(("Zenbox", "suspicious", 30, ()))
    envelope = await _lookup(
        payloads.file_object(with_assessment=False, extra_attributes={"sandbox_verdicts": block})
    )
    claim = next(c for c in _claims(envelope) if c.semantic is ClaimSemantic.SANDBOX_CLASSIFICATION)

    assert claim.strength is ClaimAssertionStrength.SUSPECTED
    assert decision_role_for(claim) is ClaimDecisionRole.WEAK


# --------------------------------------------------------------------------- #
# The behaviour summary's verdict (DEEP)
# --------------------------------------------------------------------------- #


async def test_the_behaviour_verdict_is_a_firm_classification_with_bounded_highlights() -> None:
    envelope = await _lookup(
        payloads.file_object(with_assessment=False),
        depth=InvestigationDepth.DEEP,
        behaviour=payloads.behaviour_summary_payload(
            verdicts=("MALWARE", "RANSOM"), verdict_confidence=97, with_findings=True
        ),
    )
    record = next(e for e in envelope.evidence if e.claim_type == "gti.behavior.verdict")

    assert record.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    assert record.evidence_class is EvidenceClass.CURATED_THREAT_ASSERTION
    assert record.attributes["verdict"] == "asserted"
    assert record.attributes["verdicts"] == ["MALWARE", "RANSOM"]
    assert record.provider_confidence == 97
    highlights = record.attributes["highlights"]
    assert any(item.startswith("sigma high: Shadow Copies") for item in highlights)
    assert not any("Whoami" in item for item in highlights), "low-level sigma stays out"
    assert any(item.startswith("attack T1486 (high)") for item in highlights)
    assert any(item.startswith("signature: ransomware_file_encryption") for item in highlights)
    assert len(highlights) <= 8

    claim = next(c for c in _claims(envelope) if c.evidence_id == record.id)
    assert claim.semantic is ClaimSemantic.SANDBOX_CLASSIFICATION
    assert claim.strength is ClaimAssertionStrength.ASSERTED
    assert any("T1486" in item for item in claim.highlights)


async def test_a_hedged_behaviour_verdict_stays_weak() -> None:
    envelope = await _lookup(
        payloads.file_object(with_assessment=False),
        depth=InvestigationDepth.DEEP,
        behaviour=payloads.behaviour_summary_payload(verdicts=("SUSPICIOUS",)),
    )
    claim = next(c for c in _claims(envelope) if c.semantic is ClaimSemantic.SANDBOX_CLASSIFICATION)
    assert claim.strength is ClaimAssertionStrength.SUSPECTED
    assert BEHAVIOR_VERDICT_STRENGTH["SUSPICIOUS"] == "suspected"


async def test_an_unrecognised_verdict_word_is_recorded_without_a_direction() -> None:
    envelope = await _lookup(
        payloads.file_object(with_assessment=False),
        depth=InvestigationDepth.DEEP,
        behaviour=payloads.behaviour_summary_payload(verdicts=("BENIGN", "NEWWORD")),
    )
    record = next(e for e in envelope.evidence if e.claim_type == "gti.behavior.verdict")
    assert record.effect is EvidenceEffect.CONTEXT_ONLY
    assert record.attributes["verdict"] == "unclassified"
    assert record.attributes["unmapped_verdicts"] == ["BENIGN", "NEWWORD"]
    assert "BENIGN" not in BEHAVIOR_VERDICT_STRENGTH, (
        "a sandbox that saw nothing did not see safety"
    )


# --------------------------------------------------------------------------- #
# C: raw behaviour never points anywhere on its own
# --------------------------------------------------------------------------- #


async def test_techniques_processes_and_contacts_without_a_verdict_are_context_only() -> None:
    envelope = await _lookup(
        payloads.file_object(with_assessment=False, with_stats=False, with_threat_severity=False),
        depth=InvestigationDepth.DEEP,
        behaviour=payloads.behaviour_summary_payload(verdicts=None, with_findings=True),
    )
    behaviour = [e for e in envelope.evidence if e.claim_type.startswith("gti.behavior.")]
    assert behaviour, "the observed behaviour is still recorded"
    assert all(e.effect is EvidenceEffect.CONTEXT_ONLY for e in behaviour)
    assert not any(e.claim_type == "gti.behavior.verdict" for e in behaviour)
    assert _claims(envelope) == ()


# --------------------------------------------------------------------------- #
# The adapter answers a behaviour-only request honestly below DEEP
# --------------------------------------------------------------------------- #


async def test_a_behaviour_only_request_below_deep_is_not_supported_and_contacts_nothing() -> None:
    """Refused before any request is built: the file is not re-queried for a
    summary this depth never fetches, and no reputation record is re-issued to
    be credited as behaviour coverage."""
    fake = _fake(payloads.file_object(), behaviour=payloads.behaviour_summary_payload())
    adapter = make_adapter(fake)

    envelope = await adapter.lookup(
        request_for(
            file_subject(),
            capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
            depth=InvestigationDepth.STANDARD,
        ),
        credential(),
    )

    assert envelope.status is ProviderRunStatus.NOT_SUPPORTED
    assert envelope.evidence == ()
    assert GTI_BEHAVIOR_NEEDS_DEEP in envelope.warnings
    assert fake.call_count == 0


async def test_a_behaviour_only_request_at_deep_fetches_the_summary() -> None:
    fake = _fake(payloads.file_object(), behaviour=payloads.behaviour_summary_payload())
    adapter = make_adapter(fake)

    envelope = await adapter.lookup(
        request_for(
            file_subject(),
            capabilities=frozenset({ProviderCapability.FILE_BEHAVIOR}),
            depth=InvestigationDepth.DEEP,
        ),
        credential(),
    )

    assert envelope.status is ProviderRunStatus.SUCCESS
    assert fake.operations("behaviour")
    assert any(e.claim_type == "gti.behavior.verdict" for e in envelope.evidence)


async def test_a_bundled_request_below_deep_is_still_answered_for_the_rest() -> None:
    fake = _fake(payloads.file_object())
    adapter = make_adapter(fake)

    envelope = await adapter.lookup(
        request_for(
            file_subject(),
            capabilities=frozenset(
                {ProviderCapability.REPUTATION, ProviderCapability.FILE_BEHAVIOR}
            ),
            depth=InvestigationDepth.STANDARD,
        ),
        credential(),
    )

    assert envelope.status is ProviderRunStatus.SUCCESS
    assert not fake.operations("behaviour")
