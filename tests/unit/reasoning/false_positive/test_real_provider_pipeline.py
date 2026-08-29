"""Task 16 over the real pipeline, end to end.

Every other test in this package is written in Task 15's generic vocabulary,
which is the right way to assert the invariants: they must hold for any provider
producing those semantics, including ones that do not exist yet.

These two are the counterweight. They drive the **real adapters**, the **real
Task 15 engine** and the **real shipped warninglist snapshot**, so the generic
vocabulary the rest of the suite assumes is provably the vocabulary the shipped
providers actually emit. Without them, a claim type renamed in Task 10 or a
signal Task 15 stopped producing would leave the whole package passing against
semantics nobody generates any more.

No provider is named in an assertion about *reasoning* -- only in building the
inputs, which is where a provider legitimately belongs.
"""

from __future__ import annotations

import asyncio

import pytest

from fixtures.reasoning import AS_OF, file_object, observable, urlhaus_url_envelope
from ti_recon.enums import (
    EvidenceEffect,
    ProviderCapability,
    ProviderOperation,
)
from ti_recon.models.intel_object import IntelObject
from ti_recon.providers import ProviderRequest
from ti_recon.providers.misp_warninglists import (
    DEFAULT_SNAPSHOT_ROOT,
    MispWarningListsAdapter,
)
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning import TemporalContextEngine
from ti_recon.reasoning.false_positive import (
    DoesNotEstablish,
    FalsePositiveReasoningEngine,
    ReasonCode,
    ReasoningRole,
)

pytestmark = pytest.mark.skipif(
    not (DEFAULT_SNAPSHOT_ROOT / "manifest.json").is_file(),
    reason="no shipped warninglist snapshot in this checkout",
)

#: The real EICAR MD5, present in the shipped snapshot's ``eicar.com`` list.
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


@pytest.fixture(scope="module")
def warninglists() -> MispWarningListsAdapter:
    """One adapter for the module: the shipped dataset loads once."""
    return MispWarningListsAdapter()


def warninglist_envelope(
    adapter: MispWarningListsAdapter, subject: IntelObject
) -> ProviderResultEnvelope:
    return asyncio.run(
        adapter.lookup(
            ProviderRequest(
                investigation_id="inv-1",
                intel_object=subject,
                operation=ProviderOperation.LOOKUP,
                requested_capabilities=frozenset({ProviderCapability.FALSE_POSITIVE_CONTEXT}),
            ),
            None,
        )
    )


def test_a_real_test_artifact_lookup_produces_a_real_explanation(
    warninglists: MispWarningListsAdapter,
) -> None:
    """The full chain: a real warninglist match, real Task 15 qualification, and
    a Task 16 explanation that names the real evidence it accounts for.

    The file is EICAR. A malicious classification of it is what a scanner is
    supposed to produce, and that is what the explanation says -- while still
    denying that the object is benign, because a test artifact is not an ordinary
    benign file.
    """
    from fixtures.false_positive import envelope as build_envelope
    from fixtures.false_positive import evidence as build_evidence

    sample = file_object(md5=EICAR_MD5)
    context = warninglist_envelope(warninglists, sample)
    # A directional claim for the context to explain. Generic on purpose: what is
    # under test is that a *real* Task 15 signal reaches a Task 16 rule.
    classification = build_evidence(sample, claim_type="alpha_reputation")
    claim = build_envelope(classification, objects=(sample,))

    qualification = TemporalContextEngine().evaluate(
        as_of=AS_OF, results=[context, claim], root=sample
    )
    assert qualification.context_signals, "Task 15 produced no signals from the real snapshot"

    result = FalsePositiveReasoningEngine().evaluate(
        qualification=qualification, results=[context, claim], root=sample
    )

    found = result.of_reason(ReasonCode.EXPECTED_TEST_ARTIFACT_DETECTION)
    assert found
    assert found[0].role is ReasoningRole.ALTERNATIVE_EXPLANATION
    assert found[0].explained_evidence_ids == (classification.id,)
    assert found[0].does_not_establish == (DoesNotEstablish.OBJECT_BENIGN,)
    # The versions travel together, from two different policies.
    assert result.qualification_policy_version == qualification.context_policy_version
    assert result.as_of == AS_OF


def test_a_real_offline_malicious_url_is_temporal_not_explained() -> None:
    """The canonical example, through the real Task 10 normalizer and Task 15.

    URLhaus reports this exact URL as a malware-distribution URL and reports it
    offline. Both are true. Task 16 records the current-state distinction and
    leaves the historical finding explicitly unaccounted for -- which is the
    single most important thing this layer gets right.
    """
    from fixtures.abusech import payloads

    envelope = urlhaus_url_envelope()
    malicious = next(
        item for item in envelope.evidence if item.effect is EvidenceEffect.SUPPORTS_MALICIOUS
    )
    assert malicious.attributes["url_status"] == "offline"
    root = observable(payloads.MALICIOUS_URL)

    qualification = TemporalContextEngine().evaluate(as_of=AS_OF, results=[envelope], root=root)
    result = FalsePositiveReasoningEngine().evaluate(
        qualification=qualification, results=[envelope], root=root
    )

    temporal = result.of_reason(
        ReasonCode.CURRENT_INACTIVITY_DOES_NOT_ERASE_HISTORICAL_MALICIOUSNESS
    )
    assert temporal
    assert temporal[0].role is ReasoningRole.TEMPORAL_RELEVANCE
    assert DoesNotEstablish.HISTORICAL_EVIDENCE_FALSE in temporal[0].does_not_establish

    # Offline never becomes an explanation, and the finding stays unexplained.
    assert result.of_role(ReasoningRole.ALTERNATIVE_EXPLANATION) == ()
    assert malicious.id not in result.explained_evidence_ids
    assert result.coverage.directional_evidence_without_explanations >= 1
    # And the provider's own record is untouched by any of it.
    assert malicious.effect is EvidenceEffect.SUPPORTS_MALICIOUS
