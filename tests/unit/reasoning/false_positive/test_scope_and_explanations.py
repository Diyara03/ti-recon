"""What context may and may not explain (Task 16).

Every test here guards a boundary that, crossed, turns a caution into a verdict.
They are written in Task 15's generic vocabulary rather than in any provider's,
because the invariant is that Task 16 works for whatever produces those semantics
-- including providers that do not exist yet.

The recurring shape is a pair: one assertion that the right finding appeared, and
one that the *wrong* one did not. The second is usually the load-bearing half.
"""

from __future__ import annotations

import pytest

from fixtures.false_positive import (
    contact_envelope,
    envelope,
    evidence,
    file_object,
    observable,
    scenario,
    signal,
)
from ti_recon.enums import EvidenceClass, EvidenceEffect, MatchScope
from ti_recon.reasoning.false_positive import (
    DoesNotEstablish,
    FalsePositiveReasoningEngine,
    FalsePositiveReasoningResult,
    LinkRelation,
    ReasonCode,
    ReasoningDimension,
    ReasoningRole,
)
from ti_recon.reasoning.models import ContextSignalType


def reason(scene: object) -> FalsePositiveReasoningResult:
    """Run Task 16 over a scenario, with a graph when the scenario built one."""
    return FalsePositiveReasoningEngine().evaluate(
        qualification=scene.qualification(),  # type: ignore[attr-defined]
        results=scene.envelopes,  # type: ignore[attr-defined]
        graph=scene.graph,  # type: ignore[attr-defined]
        root=scene.root,  # type: ignore[attr-defined]
    )


def explanations(result: FalsePositiveReasoningResult) -> tuple[object, ...]:
    return result.of_role(ReasoningRole.ALTERNATIVE_EXPLANATION)


# --------------------------------------------------------------------------- #
# Context alone explains nothing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "signal_type",
    [
        ContextSignalType.KNOWN_SCANNER,
        ContextSignalType.SHARED_CLOUD_OR_CDN,
        ContextSignalType.POPULAR_OR_COMMON_SERVICE,
        ContextSignalType.BUSINESS_SERVICE,
        ContextSignalType.TEST_ARTIFACT,
        ContextSignalType.EMPTY_ARTIFACT,
        ContextSignalType.WARNINGLIST_MATCH,
    ],
)
def test_context_without_a_detection_explains_nothing(
    signal_type: ContextSignalType,
) -> None:
    """The invariant the whole package turns on.

    A warninglist hit on an address nobody has accused of anything is context.
    There is no detection to explain, so manufacturing an explanation would be
    inventing doubt about a finding that was never made -- and every one of these
    signal types is a plausible candidate for exactly that mistake.
    """
    target = observable("198.51.100.7")
    scene = scenario(target).with_signal(signal(target, signal_type))

    result = reason(scene)

    assert explanations(result) == ()
    assert result.coverage.alternative_explanations == 0


# --------------------------------------------------------------------------- #
# Host scope never clears an exact artifact
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "signal_type",
    [ContextSignalType.POPULAR_OR_COMMON_SERVICE, ContextSignalType.SHARED_CLOUD_OR_CDN],
)
def test_common_host_context_never_explains_the_exact_url(
    signal_type: ContextSignalType,
) -> None:
    """``https://common.example/bad/payload.exe`` on a popular host.

    The context is a fact about the host. Letting it speak for the URL is how
    every living-off-trusted-sites payload gets waved through, so the finding is
    a limitation and the malicious evidence stays explicitly unexplained.
    """
    url = observable("https://common.example/bad/payload.exe")
    malicious = evidence(url, claim_type="alpha_exact_url")
    scene = (
        scenario(url)
        .with_envelope(envelope(malicious, objects=(url,)))
        .with_signal(
            signal(
                url,
                signal_type,
                match_scope=MatchScope.SAME_HOST,
                host_component_only=True,
                source_key="common-hosts",
            )
        )
    )

    result = reason(scene)

    limitation = result.of_reason(ReasonCode.HOST_CONTEXT_DOES_NOT_EXPLAIN_EXACT_URL)
    assert limitation
    assert limitation[0].role is ReasoningRole.INTERPRETATION_LIMITATION
    assert limitation[0].match_scope is MatchScope.SAME_HOST
    # It names the evidence it bounds, and bounds rather than accounts for it.
    assert {
        link.ref for link in limitation[0].links if link.relation is LinkRelation.QUALIFIES
    } == {malicious.id}

    # The load-bearing half: nothing explained the exact URL.
    assert explanations(result) == ()
    assert malicious.id not in result.explained_evidence_ids
    assert result.coverage.directional_evidence_without_explanations == 1
    assert DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE in limitation[0].does_not_establish


def test_host_context_still_limits_attribution_without_explaining() -> None:
    """Shared hosting is an attribution question, and gets an attribution answer.

    Both findings coexist: one says the host context does not reach the artifact,
    the other says the host's operator is not necessarily the actor. Neither
    suggests the detection was wrong.
    """
    ip = observable("203.0.113.7")
    malicious = evidence(ip)
    scene = (
        scenario(ip)
        .with_envelope(envelope(malicious, objects=(ip,)))
        .with_signal(signal(ip, ContextSignalType.SHARED_CLOUD_OR_CDN, source_key="a-cloud"))
    )

    result = reason(scene)

    caution = result.of_reason(ReasonCode.SHARED_INFRASTRUCTURE_LIMITS_ATTRIBUTION)
    assert caution
    assert caution[0].role is ReasoningRole.ATTRIBUTION_CAUTION
    assert caution[0].dimension is ReasoningDimension.ATTRIBUTION
    assert DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE in caution[0].does_not_establish
    assert DoesNotEstablish.INFRASTRUCTURE_SAFE in caution[0].does_not_establish

    assert explanations(result) == ()
    assert malicious.id not in result.explained_evidence_ids


# --------------------------------------------------------------------------- #
# Compromised infrastructure
# --------------------------------------------------------------------------- #


def test_compromised_infrastructure_moves_attribution_not_the_finding() -> None:
    """Malicious activity on somebody else's hacked host is malicious activity.

    What changes is that the owner is a victim rather than the actor, and that
    blocking has a cost. Filing this as a potential false positive would be the
    most consequential mistake this package could make.
    """
    ip = observable("203.0.113.9")
    malicious = evidence(ip)
    scene = (
        scenario(ip)
        .with_envelope(envelope(malicious, objects=(ip,)))
        .with_signal(
            signal(
                ip,
                ContextSignalType.COMPROMISED_INFRASTRUCTURE,
                source_key="is_compromised",
            )
        )
    )

    result = reason(scene)

    caution = result.of_reason(ReasonCode.COMPROMISED_INFRASTRUCTURE_SEPARATES_OWNER_FROM_ACTOR)
    assert caution
    assert caution[0].role is ReasoningRole.ATTRIBUTION_CAUTION
    assert explanations(result) == ()
    # The evidence is neither explained nor suppressed.
    assert malicious.id not in result.explained_evidence_ids
    assert result.findings_for_evidence(malicious.id)


# --------------------------------------------------------------------------- #
# Relationship-scoped explanations
# --------------------------------------------------------------------------- #


def test_a_public_resolver_explains_the_contact_and_not_the_file() -> None:
    """A sample that resolved a name contacted a resolver. That is what programs
    do -- and it says nothing whatever about the sample.

    Both halves are asserted, because the failure mode here is not the missing
    explanation but the over-reaching one.
    """
    sample = file_object(sha256="a" * 64)
    resolver = observable("8.8.8.8")
    reputation = evidence(sample, claim_type="alpha_reputation")

    scene = (
        scenario(sample)
        .with_envelope(envelope(reputation, objects=(sample,)))
        .with_envelope(contact_envelope(sample, resolver))
        .with_signal(signal(resolver, ContextSignalType.PUBLIC_RESOLVER, source_key="public-dns"))
        .with_graph()
    )

    result = reason(scene)

    found = result.of_reason(ReasonCode.PUBLIC_RESOLVER_MAY_EXPLAIN_CONTACT)
    assert found
    explanation = found[0]
    assert explanation.role is ReasoningRole.ALTERNATIVE_EXPLANATION
    assert explanation.dimension is ReasoningDimension.RELATIONSHIP_INTERPRETATION

    # Scoped to the edge, and it says so in its subject.
    assert explanation.subject.kind.value == "relationship"
    assert explanation.subject.key == f"{sample.canonical_key}|contacts|{resolver.canonical_key}"

    # It explains a relationship, never a piece of evidence about the file.
    assert explanation.explained_evidence_ids == ()
    assert reputation.id not in result.explained_evidence_ids
    assert result.coverage.directional_evidence_without_explanations == 1
    assert DoesNotEstablish.OBJECT_BENIGN in explanation.does_not_establish


def test_the_observed_relationship_survives_being_explained() -> None:
    """Task 16 interprets observations; it does not rewrite them."""
    sample = file_object(sha256="b" * 64)
    resolver = observable("8.8.8.8")
    scene = (
        scenario(sample)
        .with_envelope(contact_envelope(sample, resolver))
        .with_signal(signal(resolver, ContextSignalType.PUBLIC_RESOLVER))
        .with_graph()
    )
    assert scene.graph is not None
    before = scene.graph.edges

    reason(scene)

    assert scene.graph.edges == before
    assert scene.graph.edge_count == 1
    assert any(item.basis.value == "provider_observed" for item in scene.graph.edges[0].assertions)


def test_business_service_explains_a_connection_without_certifying_it() -> None:
    ip = observable("203.0.113.20")
    sample = file_object(sha256="c" * 64)
    scene = (
        scenario(sample)
        .with_envelope(contact_envelope(sample, ip))
        .with_signal(signal(ip, ContextSignalType.BUSINESS_SERVICE, source_key="bsi"))
        .with_graph()
    )

    result = reason(scene)

    found = result.of_reason(ReasonCode.KNOWN_BUSINESS_SERVICE_MAY_EXPLAIN_CONNECTION)
    assert found
    assert found[0].subject.kind.value == "relationship"
    assert DoesNotEstablish.INFRASTRUCTURE_SAFE in found[0].does_not_establish
    assert DoesNotEstablish.OBJECT_BENIGN in found[0].does_not_establish


def test_common_service_context_does_not_explain_a_contact_with_an_accused_endpoint() -> None:
    """ "It is a common service" does not account for a specific accusation.

    If somebody has said this endpoint is malicious, the ordinariness of talking
    to it explains nothing -- and explaining the contact anyway would use
    ordinariness to wave past a real finding about the thing being contacted.
    """
    sample = file_object(sha256="d" * 64)
    endpoint = observable("203.0.113.30")
    accusation = evidence(endpoint, claim_type="alpha_c2", provider="beta")

    scene = (
        scenario(sample)
        .with_envelope(contact_envelope(sample, endpoint))
        .with_envelope(envelope(accusation, provider="beta", objects=(endpoint,)))
        .with_signal(signal(endpoint, ContextSignalType.BUSINESS_SERVICE))
        .with_graph()
    )

    result = reason(scene)

    assert result.of_reason(ReasonCode.KNOWN_BUSINESS_SERVICE_MAY_EXPLAIN_CONNECTION) == ()
    assert accusation.id not in result.explained_evidence_ids


def test_context_does_not_travel_from_a_pivot_to_the_root() -> None:
    """A sample that contacted a CDN does not acquire CDN context.

    The context belongs to the address and, at most, to that one edge. Nothing
    attaches it to the root object, which is the transitive-propagation failure
    in its most tempting form.
    """
    sample = file_object(sha256="e" * 64)
    cdn = observable("203.0.113.40")
    malicious = evidence(sample, claim_type="alpha_reputation")

    scene = (
        scenario(sample)
        .with_envelope(envelope(malicious, objects=(sample,)))
        .with_envelope(contact_envelope(sample, cdn))
        .with_signal(signal(cdn, ContextSignalType.SHARED_CLOUD_OR_CDN))
        .with_graph()
    )

    result = reason(scene)

    root_subject = f"observable:{sample.canonical_key}"
    for finding in result.findings:
        if finding.subject.ref == root_subject:
            assert finding.reason_code is not ReasonCode.SHARED_INFRASTRUCTURE_LIMITS_ATTRIBUTION
    assert malicious.id not in result.explained_evidence_ids


# --------------------------------------------------------------------------- #
# Object-nature explanations
# --------------------------------------------------------------------------- #


def test_a_test_artifact_explains_the_classification_of_itself() -> None:
    """The strongest explanation available, and still not a verdict.

    Detecting EICAR is what a scanner is supposed to do. That accounts for the
    classification without saying anything about whether the object is benign --
    a test artifact is not an ordinary benign file.
    """
    sample = file_object(md5="44d88612fea8a8f36de82e1278abb02f")
    classification = evidence(sample, claim_type="alpha_reputation")
    scene = (
        scenario(sample)
        .with_envelope(envelope(classification, objects=(sample,)))
        .with_signal(signal(sample, ContextSignalType.TEST_ARTIFACT, source_key="eicar.com"))
    )

    result = reason(scene)

    found = result.of_reason(ReasonCode.EXPECTED_TEST_ARTIFACT_DETECTION)
    assert found
    assert found[0].role is ReasoningRole.ALTERNATIVE_EXPLANATION
    assert found[0].dimension is ReasoningDimension.OBJECT_NATURE
    assert found[0].explained_evidence_ids == (classification.id,)
    assert result.coverage.directional_evidence_with_explanations == 1
    assert result.coverage.directional_evidence_without_explanations == 0
    assert found[0].does_not_establish == (DoesNotEstablish.OBJECT_BENIGN,)


def test_a_test_artifact_does_not_explain_what_a_sandbox_watched_it_do() -> None:
    """If the same file genuinely did something, "it is a test artifact" does not
    account for that.

    The behaviour is carried as opposing rather than folded into the explanation,
    so Task 17 can see that one claim was accounted for and another was not.
    """
    sample = file_object(md5="44d88612fea8a8f36de82e1278abb02f")
    classification = evidence(sample, claim_type="alpha_reputation")
    behaviour = evidence(
        sample,
        claim_type="alpha_observed_behaviour",
        evidence_class=EvidenceClass.DIRECT_OBSERVATION,
        provider="sandbox_alpha",
    )
    scene = (
        scenario(sample)
        .with_envelope(envelope(classification, objects=(sample,)))
        .with_envelope(envelope(behaviour, provider="sandbox_alpha", objects=(sample,)))
        .with_signal(signal(sample, ContextSignalType.TEST_ARTIFACT, source_key="eicar.com"))
    )

    result = reason(scene)

    found = result.of_reason(ReasonCode.EXPECTED_TEST_ARTIFACT_DETECTION)[0]
    assert found.explained_evidence_ids == (classification.id,)
    assert found.opposing_evidence_ids == (behaviour.id,)
    # The watched behaviour stays visible as unaccounted for.
    assert behaviour.id not in result.explained_evidence_ids
    assert result.coverage.directional_evidence_without_explanations == 1


def test_an_empty_artifact_explains_a_reputation_detection() -> None:
    sample = file_object(md5="d41d8cd98f00b204e9800998ecf8427e")
    classification = evidence(sample, claim_type="alpha_reputation")
    scene = (
        scenario(sample)
        .with_envelope(envelope(classification, objects=(sample,)))
        .with_signal(signal(sample, ContextSignalType.EMPTY_ARTIFACT, source_key="empty-hashes"))
    )

    result = reason(scene)

    found = result.of_reason(ReasonCode.EMPTY_ARTIFACT_MAY_EXPLAIN_REPUTATION_DETECTION)
    assert found
    assert found[0].explained_evidence_ids == (classification.id,)
    assert found[0].does_not_establish == (DoesNotEstablish.OBJECT_BENIGN,)


def test_host_scoped_object_context_cannot_explain_the_object() -> None:
    """Even a normally-explaining signal must arrive at exact scope.

    A test-artifact match against a URL's *host* would be nonsense, and the scope
    check refuses it rather than trusting that it cannot happen.
    """
    url = observable("https://common.example/bad/payload.exe")
    malicious = evidence(url)
    scene = (
        scenario(url)
        .with_envelope(envelope(malicious, objects=(url,)))
        .with_signal(
            signal(
                url,
                ContextSignalType.TEST_ARTIFACT,
                match_scope=MatchScope.SAME_HOST,
                host_component_only=True,
            )
        )
    )

    assert reason(scene).of_reason(ReasonCode.EXPECTED_TEST_ARTIFACT_DETECTION) == ()


# --------------------------------------------------------------------------- #
# Scanner alignment
# --------------------------------------------------------------------------- #


def test_scanner_context_never_explains_a_directional_claim() -> None:
    """Scanner context could explain a scanning-reputation claim. It must never
    explain a C2 claim merely because both concern one address.

    Telling those apart needs to know what a claim asserts, and the generic
    evidence model does not carry that -- a scanner classification and a C2
    indicator are both ``CURATED_THREAT_ASSERTION`` with ``SUPPORTS_MALICIOUS``.
    So the honest output is a limitation naming the unknown alignment, and the
    explanation is deferred rather than guessed.
    """
    ip = observable("162.142.125.1")
    c2_claim = evidence(ip, claim_type="beta_botnet_c2", provider="beta")
    scene = (
        scenario(ip)
        .with_envelope(envelope(c2_claim, provider="beta", objects=(ip,)))
        .with_signal(signal(ip, ContextSignalType.KNOWN_SCANNER, source_key="a-scanning-list"))
    )

    result = reason(scene)

    limitation = result.of_reason(ReasonCode.SCANNER_CONTEXT_ALIGNMENT_NOT_ESTABLISHED)
    assert limitation
    assert limitation[0].role is ReasoningRole.INTERPRETATION_LIMITATION
    assert explanations(result) == ()
    assert c2_claim.id not in result.explained_evidence_ids
    assert DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE in limitation[0].does_not_establish


def test_a_scanner_claim_and_a_c2_claim_are_treated_identically() -> None:
    """The same limitation for both, because nothing generic separates them.

    Asserted rather than assumed: if a future claim-kind seam lets these diverge,
    this test is where that shows up.
    """
    ip = observable("162.142.125.1")
    results = []
    for claim in ("beta_scanner_reputation", "beta_botnet_c2"):
        record = evidence(ip, claim_type=claim, provider="beta")
        scene = (
            scenario(ip)
            .with_envelope(envelope(record, provider="beta", objects=(ip,)))
            .with_signal(signal(ip, ContextSignalType.KNOWN_SCANNER))
        )
        outcome = reason(scene)
        results.append(
            (
                tuple(item.reason_code for item in outcome.findings),
                outcome.coverage.alternative_explanations,
            )
        )
    assert results[0] == results[1]


# --------------------------------------------------------------------------- #
# Private / special-use addressing
# --------------------------------------------------------------------------- #


def test_public_intelligence_does_not_identify_a_private_asset() -> None:
    """Reputation for ``10.0.0.5`` describes somebody else's ``10.0.0.5``."""
    ip = observable("10.0.0.5")
    claim = evidence(ip)
    scene = (
        scenario(ip)
        .with_envelope(envelope(claim, objects=(ip,)))
        .with_signal(signal(ip, ContextSignalType.PRIVATE_OR_SPECIAL_USE, source_key="rfc1918"))
    )

    result = reason(scene)

    found = result.of_reason(ReasonCode.PUBLIC_INTELLIGENCE_SCOPE_MISMATCH)
    assert found
    assert found[0].role is ReasoningRole.INTERPRETATION_LIMITATION
    assert explanations(result) == ()
    assert DoesNotEstablish.OBJECT_BENIGN in found[0].does_not_establish


# --------------------------------------------------------------------------- #
# The rules TI Recon deliberately does not have
# --------------------------------------------------------------------------- #


def test_a_low_detection_count_alone_explains_nothing() -> None:
    """One engine out of sixty is not a false-positive rule.

    TI Recon does not count vendor votes, and a ratio that looks reassuring is
    exactly how a genuinely novel sample gets dismissed. The counts sit in the
    evidence attributes and no rule reads them.
    """
    sample = file_object(sha256="f" * 64)
    aggregate = evidence(
        sample,
        claim_type="alpha_reputation_aggregate",
        evidence_class=EvidenceClass.AGGREGATED_REPUTATION,
        attributes={"malicious": 1, "undetected": 60, "engines_total": 61},
    )
    scene = scenario(sample).with_envelope(envelope(aggregate, objects=(sample,)))

    result = reason(scene)

    assert explanations(result) == ()
    assert aggregate.id not in result.explained_evidence_ids
    assert result.coverage.directional_evidence_without_explanations == 1


def test_a_code_signature_alone_explains_nothing() -> None:
    """A valid signature establishes a publisher, not benign behaviour.

    Signing keys get stolen and abused, and "signed" has never meant "safe to
    run". The signing metadata is present on the evidence and no rule consults
    it.
    """
    sample = file_object(sha256="1" * 64)
    malicious = evidence(sample, claim_type="alpha_reputation")
    signing = evidence(
        sample,
        claim_type="alpha_code_signing",
        effect=EvidenceEffect.CONTEXT_ONLY,
        evidence_class=EvidenceClass.CONTEXT,
        attributes={"signed": True, "signature_valid": True, "subject_cn": "Example Ltd"},
    )
    scene = scenario(sample).with_envelope(envelope(malicious, signing, objects=(sample,)))

    result = reason(scene)

    assert explanations(result) == ()
    assert malicious.id not in result.explained_evidence_ids


def test_popularity_alone_explains_nothing_about_an_exact_artifact() -> None:
    url = observable("https://common.example/bad/payload.exe")
    malicious = evidence(url)
    scene = (
        scenario(url)
        .with_envelope(envelope(malicious, objects=(url,)))
        .with_signal(
            signal(
                url,
                ContextSignalType.POPULAR_OR_COMMON_SERVICE,
                match_scope=MatchScope.SAME_HOST,
                host_component_only=True,
            )
        )
    )
    assert explanations(reason(scene)) == ()
