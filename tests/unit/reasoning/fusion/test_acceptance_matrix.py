"""Task 17 acceptance: is the policy analytically defensible? (Tasks 17A-D)

The other suites ask whether the engine does what the code says. This one asks
whether what the code says is *right* — driven, wherever it can be, by the real
adapters over the real shipped payload fixtures rather than by hand-built claims.

Three questions organise it:

* **What can decide alone?** A decisive claim reaches MALICIOUS with no second
  source, so the decisive inventory is the shortest list in the system and every
  member has to earn its place from the provider's actual data semantics — not
  from the provider being reputable.
* **What can reach benign?** Reviewed harder than the malicious side, because a
  wrong MALICIOUS produces an argument and a wrong LIKELY_BENIGN produces
  silence.
* **What must never strengthen an assessment?** Duplicate, dependent, unrelated,
  context-only and absent information, in every combination.
"""

from __future__ import annotations

from itertools import combinations

import pytest

from fixtures.fusion import (
    envelope,
    evidence,
    explanation,
    file_object,
    fuse,
    fuse_with_semantics,
    observable,
    scenario,
)
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
from ti_recon.enums import EvidenceClass, EvidenceEffect, MatchScope, Verdict
from ti_recon.providers.result import ProviderRunStatus
from ti_recon.reasoning.claims import CLAIM_SEMANTICS_POLICY_VERSION, ClaimTranslationContext
from ti_recon.reasoning.claims.models import ClaimSemantic, NormalizedClaim, claim_from
from ti_recon.reasoning.claims.policy import compatible
from ti_recon.reasoning.claims.registry import translate_envelope
from ti_recon.reasoning.fusion.models import AssessmentConfidence, ClaimDecisionRole
from ti_recon.reasoning.fusion.policy import (
    DECISIVE_SEMANTICS,
    REASON_CODES,
    VERDICT_RULES,
    decision_role_for,
    is_benign_basis,
)


def _assess(builder):
    """Fuse one real provider envelope about its own subject."""
    result_envelope = builder()
    return fuse(scenario(result_envelope.objects[0]).with_envelope(result_envelope))


def _claims(result_envelope) -> tuple[NormalizedClaim, ...]:
    context = ClaimTranslationContext.build(
        objects=result_envelope.objects, policy_version=CLAIM_SEMANTICS_POLICY_VERSION
    )
    return translate_envelope(result_envelope, context)


# --------------------------------------------------------------------------- #
# The decisive inventory
# --------------------------------------------------------------------------- #


def test_only_two_semantics_can_decide_a_verdict_alone() -> None:
    """The shortest list in the system, and deliberately about identity.

    ``MALWARE_SAMPLE_IDENTITY`` — a curated repository holds *this* sample —
    and ``MALWARE_DISTRIBUTION`` — this exact URL or host serves malware. Both
    are specific claims about the exact object, of a kind a repository publishes
    after vetting. Neither is "a provider said malicious", which is what
    ``MALICIOUS_REPUTATION`` is, and that reaches SUSPICIOUS instead.
    """
    assert DECISIVE_SEMANTICS == frozenset(
        {ClaimSemantic.MALWARE_SAMPLE_IDENTITY, ClaimSemantic.MALWARE_DISTRIBUTION}
    )


@pytest.mark.parametrize(
    "evidence_class",
    # Every class a directional claim may carry. EvidenceClass.CONTEXT is excluded
    # because the model refuses it a direction at all, so it cannot reach here.
    [item for item in EvidenceClass if item is not EvidenceClass.CONTEXT],
)
def test_a_sandbox_classification_never_decides_alone(evidence_class: EvidenceClass) -> None:
    """Whatever its evidence class — the regression for a real bug.

    ``SANDBOX_CLASSIFICATION`` used to be promoted to decisive when its evidence
    class was ``DIRECT_OBSERVATION``, meaning "a sandbox watched the sample act
    rather than a report of one". Nothing in a claim can tell those apart, and
    the only shipped claim the rule promoted was a *boolean contributing factor*
    on one provider's assessment — ``{"factor": ..., "value": True}``, with no
    report, environment, runtime or execution quality behind it. The integration
    that does carry a full report and Task 12's ``observed_execution`` was only
    corroborative, so the promotion inverted the hierarchy: the claim with less
    behind it outranked the claim with more, and one boolean reached MALICIOUS.
    """
    sample = file_object(sha256="e" * 64)
    record = evidence(sample, provider="alpha", evidence_class=evidence_class)
    claim = claim_from(
        record,
        policy_version=CLAIM_SEMANTICS_POLICY_VERSION,
        semantic=ClaimSemantic.SANDBOX_CLASSIFICATION,
        subject_key=sample.canonical_key,
    )

    assert decision_role_for(claim) is not ClaimDecisionRole.DECISIVE


def test_a_direct_observation_sandbox_claim_reaches_suspicious_not_malicious() -> None:
    """End to end, through the engine, at the verdict."""
    sample = file_object(sha256="e" * 64)
    record = evidence(sample, provider="alpha", evidence_class=EvidenceClass.DIRECT_OBSERVATION)
    result = fuse_with_semantics(
        scenario(sample).with_envelope(envelope(record, provider="alpha", objects=(sample,))),
        {record.id: "sandbox_classification"},
    )

    assert result.assessment.verdict is Verdict.SUSPICIOUS


# --------------------------------------------------------------------------- #
# Golden matrix over the real fixtures
# --------------------------------------------------------------------------- #

GOLDEN = (
    # A curated repository holding this exact vetted sample. Decides alone.
    ("malwarebazaar", malwarebazaar_envelope, Verdict.MALICIOUS),
    # This exact URL is tracked as distributing malware. Decides alone.
    ("urlhaus_url", urlhaus_url_envelope, Verdict.MALICIOUS),
    # An exact-scope payload-delivery IOC. Decides alone.
    ("threatfox_domain", threatfox_compromised_envelope, Verdict.MALICIOUS),
    # A C2 association at same_ip scope: about the address, not the observable.
    ("threatfox_ip", threatfox_ip_envelope, Verdict.SUSPICIOUS),
    # One vendor's judgement about the object, however well resourced.
    ("gti_file", gti_file_envelope, Verdict.SUSPICIOUS),
    ("urlscan", urlscan_scan_envelope, Verdict.SUSPICIOUS),
    # Malicious *scanning*, which is a different accusation from C2.
    ("greynoise", greynoise_envelope, Verdict.SUSPICIOUS),
    # A sandbox classification corroborates and never decides.
    ("sandbox", sandbox_envelope, Verdict.SUSPICIOUS),
    (
        "sandbox_divergent",
        lambda: sandbox_envelope(search=sandbox_payloads.search_hash_divergent()),
        Verdict.SUSPICIOUS,
    ),
    # Exposure is not an accusation; a payload record is provenance.
    ("censys", censys_host_envelope, Verdict.INCONCLUSIVE),
    ("urlhaus_payload", urlhaus_payload_envelope, Verdict.INCONCLUSIVE),
)


@pytest.mark.parametrize("name,builder,expected", GOLDEN, ids=[case[0] for case in GOLDEN])
def test_one_provider_alone_reaches_the_verdict_its_semantics_justify(
    name: str, builder, expected: Verdict
) -> None:
    """The whole policy in one table, driven by real adapter output.

    Read down the `MALICIOUS` rows: every one is a specific claim about the exact
    object from a repository that vetted it. Read down the `SUSPICIOUS` rows:
    every one is a judgement, an aggregate, or a claim about the neighbourhood.
    That line — specificity, not vendor reputation — is the policy.
    """
    assert _assess(builder).assessment.verdict is expected


def test_urlhaus_payload_presence_is_not_malware_identity() -> None:
    """URLhaus says a tracked URL served this file; that is provenance.

    URLhaus is explicit that not every payload collected from a malicious URL is
    itself malicious — a cleaned URL later serves an installer or an error page.
    So the payload record produces no directional claim at all, and identity is
    left to a platform that vets samples.
    """
    payload = urlhaus_payload_envelope()
    claims = _claims(payload)

    assert all(claim.semantic is not ClaimSemantic.MALWARE_SAMPLE_IDENTITY for claim in claims)
    assert _assess(urlhaus_payload_envelope).assessment.verdict is Verdict.INCONCLUSIVE


def test_a_vetted_repository_supplies_the_identity_urlhaus_declines_to() -> None:
    """Payload provenance plus a curated sample record: the second one decides."""
    payload = urlhaus_payload_envelope()
    bazaar = malwarebazaar_envelope()
    scene = scenario(bazaar.objects[0]).with_envelope(bazaar).with_envelope(payload)

    result = fuse(scene)

    assert result.assessment.verdict is Verdict.MALICIOUS
    assert result.assessment.verdict_rule_id == VERDICT_RULES["malicious_decisive"]


def test_threatfox_source_confidence_never_becomes_engine_confidence() -> None:
    """A contributor's 0-100 number stays the contributor's.

    ThreatFox carries a per-IOC ``confidence_level`` that defaults to 50. It is
    preserved verbatim as a provider attribute and read by nothing in the
    reasoning layers: there is no calibration mapping 75 onto MEDIUM, so
    inventing one would manufacture precision from a submitter's self-report.
    """
    threatfox = threatfox_ip_envelope()
    levels = [
        record.attributes["confidence_level"]
        for record in threatfox.evidence
        if "confidence_level" in record.attributes
    ]

    assert levels, "fixture should carry a source confidence level"
    # Present in provider evidence, absent from every claim the engine reasons on.
    for claim in _claims(threatfox):
        assert "confidence" not in claim.model_dump_json()


def test_scanner_activity_and_c2_stay_different_propositions() -> None:
    """Both point malicious about one address, and they are not the same claim.

    Malicious *scanning* observed by a sensor fleet and a *command-and-control*
    association are different accusations. Letting them corroborate would be the
    confusion Task 16 refused to guess at, and would let scanner context explain
    away a C2 finding.
    """
    assert not compatible(ClaimSemantic.SCANNER_ACTIVITY, ClaimSemantic.C2_ASSOCIATION)

    target = observable("198.51.100.11")
    scanning = evidence(target, provider="alpha", source_family="fam_a")
    command = evidence(target, provider="beta", source_family="fam_b")
    result = fuse_with_semantics(
        scenario(target)
        .with_envelope(envelope(scanning, provider="alpha", objects=(target,)))
        .with_envelope(envelope(command, provider="beta", objects=(target,))),
        {scanning.id: "scanner_activity", command.id: "c2_association"},
    )

    assert len(result.proposition_groups) == 2
    assert result.assessment.verdict_rule_id != VERDICT_RULES["malicious_corroborated"]


# --------------------------------------------------------------------------- #
# The benign inventory — reviewed harder than the malicious one
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("semantic", list(ClaimSemantic))
def test_only_a_stated_benign_reputation_can_be_a_benign_basis(
    semantic: ClaimSemantic,
) -> None:
    """One semantic, and it has to be a provider actually asserting benignness.

    Everything else that *feels* reassuring is excluded by construction: a
    known-scanner classification is ``SCANNER_ACTIVITY``, business-service
    membership and warninglist hits are context and never become claims at all,
    and an absence of detections is not a claim either.
    """
    target = observable("198.51.100.12")
    record = evidence(target, provider="alpha", effect=EvidenceEffect.SUPPORTS_BENIGN)
    claim = claim_from(
        record,
        policy_version=CLAIM_SEMANTICS_POLICY_VERSION,
        semantic=semantic,
        subject_key=target.canonical_key,
    )

    assert is_benign_basis(claim) is (semantic is ClaimSemantic.BENIGN_REPUTATION)


def test_a_benign_classified_scanner_is_still_a_claim_about_scanning() -> None:
    """GreyNoise's benign class names a trusted scanning actor, not a safe host.

    GreyNoise itself says benign actors can be compromised and recommends
    de-prioritising rather than closing. Mapping it to ``SCANNER_ACTIVITY``
    keeps the assertion exactly as wide as GreyNoise made it: it can never reach
    ``is_benign_basis``, so it can never certify the address.
    """
    target = observable("198.51.100.13")
    record = evidence(
        target,
        claim_type="greynoise_classification",
        provider="greynoise",
        effect=EvidenceEffect.SUPPORTS_BENIGN,
        attributes={"raw_classification": "benign"},
    )
    result = fuse(
        scenario(target).with_envelope(envelope(record, provider="greynoise", objects=(target,)))
    )
    claim = result.normalized_claims[0]

    assert claim.semantic is ClaimSemantic.SCANNER_ACTIVITY
    assert is_benign_basis(claim) is False
    assert result.assessment.verdict is not Verdict.LIKELY_BENIGN


def test_a_benign_scanner_classification_does_not_refute_a_c2_claim() -> None:
    """Different propositions, so no conflict and no cancellation."""
    target = observable("198.51.100.14")
    scanner = evidence(
        target,
        claim_type="greynoise_classification",
        provider="greynoise",
        source_family="greynoise",
        effect=EvidenceEffect.SUPPORTS_BENIGN,
        attributes={"raw_classification": "benign"},
    )
    command = evidence(target, provider="beta", source_family="fam_b")
    result = fuse_with_semantics(
        scenario(target)
        .with_envelope(envelope(scanner, provider="greynoise", objects=(target,)))
        .with_envelope(envelope(command, provider="beta", objects=(target,))),
        {scanner.id: "scanner_activity", command.id: "c2_association"},
    )

    assert result.conflicts == ()
    assert result.assessment.verdict is Verdict.SUSPICIOUS


CONTEXT_ONLY_BUILDERS = (
    ("censys", censys_host_envelope),
    ("urlhaus_payload", urlhaus_payload_envelope),
)


@pytest.mark.parametrize(
    "name,builder", CONTEXT_ONLY_BUILDERS, ids=[case[0] for case in CONTEXT_ONLY_BUILDERS]
)
def test_context_and_absence_never_reach_likely_benign(name: str, builder) -> None:
    """Nothing said is INCONCLUSIVE, which is not a finding of safety."""
    result = _assess(builder)

    assert result.assessment.verdict is Verdict.INCONCLUSIVE
    assert result.assessment.confidence is AssessmentConfidence.UNSPECIFIED


@pytest.mark.parametrize(
    "status",
    [
        ProviderRunStatus.NO_DATA,
        ProviderRunStatus.NOT_SUPPORTED,
        ProviderRunStatus.NOT_CONFIGURED,
        ProviderRunStatus.QUOTA_EXCEEDED,
        ProviderRunStatus.TEMPORARILY_UNAVAILABLE,
        ProviderRunStatus.PLAN_LIMITED,
        ProviderRunStatus.PARTIAL,
    ],
)
def test_a_provider_status_alone_supports_no_direction(status: ProviderRunStatus) -> None:
    """Coverage facts, and coverage is Task 18's material, not a verdict input."""
    target = observable("198.51.100.15")
    result = fuse(
        scenario(target).with_envelope(envelope(provider="alpha", objects=(target,), status=status))
    )

    assert result.assessment.verdict is Verdict.INCONCLUSIVE
    assert result.assessment.confidence is AssessmentConfidence.UNSPECIFIED
    assert result.assessment.confidence_caps == ()


def test_a_sandbox_that_saw_no_threat_supports_nothing_benign() -> None:
    """A quiet detonation is not an acquittal, driven by the real payload.

    The real adapter emits only ``CONTEXT_ONLY`` records here — a "no report"
    note and a coverage record — so there is nothing directional for fusion to
    read, and the assessment says exactly that rather than reporting reassurance.
    """
    quiet = sandbox_envelope(search=sandbox_payloads.search_hash_no_reports())
    assert quiet.evidence, "fixture should still describe what was looked for"
    assert all(record.effect is EvidenceEffect.CONTEXT_ONLY for record in quiet.evidence)

    sample = file_object(sha256="f" * 64)
    result = fuse(scenario(sample).with_envelope(quiet))

    assert result.normalized_claims == ()
    assert result.assessment.verdict is Verdict.INCONCLUSIVE
    assert result.assessment.verdict is not Verdict.LIKELY_BENIGN


# --------------------------------------------------------------------------- #
# Explanation scoping and the two LIKELY_BENIGN paths
# --------------------------------------------------------------------------- #


def test_an_exact_explanation_of_every_claim_reaches_likely_benign() -> None:
    """The complete-account path, and it requires the account to be complete."""
    sample = file_object(md5="44d88612fea8a8f36de82e1278abb02f")
    classification = evidence(sample, provider="alpha")
    scene = (
        scenario(sample)
        .with_envelope(envelope(classification, provider="alpha", objects=(sample,)))
        .with_finding(explanation(sample, classification))
    )

    result = fuse_with_semantics(scene, {classification.id: "malicious_reputation"})

    assert result.assessment.verdict is Verdict.LIKELY_BENIGN
    assert result.assessment.verdict_rule_id == VERDICT_RULES["likely_benign_explained"]


def test_an_explanation_reaches_only_the_evidence_it_names() -> None:
    """No spread by subject, proposition or family.

    Two claims about one object from one provider; one is explained. The other
    must survive, or an explanation of a single scanner hit would quietly clear
    everything anybody had ever said about the file.
    """
    sample = file_object(md5="44d88612fea8a8f36de82e1278abb02f")
    explained = evidence(sample, claim_type="alpha_one", provider="alpha")
    untouched = evidence(sample, claim_type="alpha_two", provider="alpha")
    scene = (
        scenario(sample)
        .with_envelope(envelope(explained, provider="alpha", objects=(sample,)))
        .with_envelope(envelope(untouched, provider="alpha", objects=(sample,)))
        .with_finding(explanation(sample, explained))
    )

    result = fuse_with_semantics(
        scene,
        {explained.id: "malicious_reputation", untouched.id: "malicious_reputation"},
    )

    assert explained.id in result.explained_evidence_ids
    assert untouched.id in result.unexplained_directional_evidence_ids
    assert result.assessment.verdict is not Verdict.LIKELY_BENIGN


def test_host_context_cannot_clear_an_exact_malicious_url() -> None:
    """A popular host does not vouch for a path on it."""
    url = observable("http://cdn.example.com/payload.bin")
    exact = evidence(url, provider="alpha", match_scope=MatchScope.EXACT_OBSERVABLE)
    host_level = evidence(
        url,
        provider="beta",
        source_family="fam_b",
        effect=EvidenceEffect.SUPPORTS_BENIGN,
        match_scope=MatchScope.SAME_HOST,
    )
    result = fuse_with_semantics(
        scenario(url)
        .with_envelope(envelope(exact, provider="alpha", objects=(url,)))
        .with_envelope(envelope(host_level, provider="beta", objects=(url,))),
        {exact.id: "malware_distribution", host_level.id: "benign_reputation"},
    )

    # Different scope, so not the same proposition and not a conflict.
    assert result.conflicts == ()
    assert result.assessment.verdict is Verdict.MALICIOUS


# --------------------------------------------------------------------------- #
# Corroboration algebra
# --------------------------------------------------------------------------- #


def test_compatibility_is_symmetric_for_every_pair() -> None:
    """Every ordered pair, not a sample."""
    for first in ClaimSemantic:
        for second in ClaimSemantic:
            assert compatible(first, second) == compatible(second, first)


def test_compatibility_is_not_transitive_and_is_not_closed_over() -> None:
    """The high-risk one: C must not corroborate A because both meet B.

    The shipped table really does contain such a triple —
    ``MALWARE_SAMPLE_IDENTITY`` ↔ ``SANDBOX_CLASSIFICATION`` ↔
    ``MALICIOUS_REPUTATION``, with the ends incompatible — so this is a live
    hazard rather than a hypothetical. Independence is a connected component on
    purpose; compatibility must stay pairwise, and a corroborating basis must be
    mutually compatible throughout.
    """
    a, b, c = (
        ClaimSemantic.MALWARE_SAMPLE_IDENTITY,
        ClaimSemantic.SANDBOX_CLASSIFICATION,
        ClaimSemantic.MALICIOUS_REPUTATION,
    )
    assert compatible(a, b) and compatible(b, c) and not compatible(a, c)

    target = observable("198.51.100.16")
    # A at host scope so it corroborates rather than deciding, forcing the
    # cross-proposition path to run with all three claims present.
    first = evidence(target, provider="pa", source_family="fam_a", match_scope=MatchScope.SAME_HOST)
    middle = evidence(target, provider="pb", source_family="fam_b")
    last = evidence(target, provider="pc", source_family="fam_c")

    def assess(*records):
        scene = scenario(target)
        semantics = {}
        for record, semantic in records:
            scene = scene.with_envelope(
                envelope(record, provider=record.transport_provider, objects=(target,))
            )
            semantics[record.id] = semantic
        return fuse_with_semantics(scene, semantics)

    ends_only = assess((first, a.value), (last, c.value))
    assert ends_only.assessment.verdict_rule_id != VERDICT_RULES["malicious_corroborated"]

    all_three = assess((first, a.value), (middle, b.value), (last, c.value))
    by_id = {claim.claim_id: claim for claim in all_three.normalized_claims}
    basis = [
        by_id[contribution.claim_id].semantic
        for contribution in all_three.contributions
        if REASON_CODES["corroborates"] in contribution.reason_codes
    ]
    assert all(compatible(x, y) for x, y in combinations(basis, 2))
    assert not ({a, c} <= set(basis))


# --------------------------------------------------------------------------- #
# Corroboration needs the same subject and the same scope
# --------------------------------------------------------------------------- #


def _two_claims(first_scope: MatchScope, second_scope: MatchScope, *, same_subject: bool):
    target = observable("http://cdn.example.com/payload.bin")
    other = observable("http://cdn.example.com/other.bin")
    first = evidence(target, provider="alpha", source_family="fam_a", match_scope=first_scope)
    second = evidence(
        target if same_subject else other,
        provider="beta",
        source_family="fam_b",
        match_scope=second_scope,
    )
    scene = (
        scenario(target)
        .with_envelope(envelope(first, provider="alpha", objects=(target,)))
        .with_envelope(
            envelope(second, provider="beta", objects=(target,) if same_subject else (other,))
        )
    )
    return fuse_with_semantics(
        scene, {first.id: "malicious_reputation", second.id: "malicious_reputation"}
    )


def test_a_host_scope_claim_cannot_corroborate_an_exact_claim() -> None:
    """Same subject, different scope: not the same thing being claimed.

    Scope is part of the proposition key, so two claims at different scopes are
    already different propositions. The cross-proposition path exists for a
    repository holding a sample beside a sandbox watching *that* sample — both
    exact — and it used to ignore scope, so a host-level reputation could
    complete a MALICIOUS verdict about an exact URL out of a statement nobody had
    made about the URL. That is the mirror of the rule that host context never
    clears an exact URL, and it has to hold in both directions.
    """
    mixed = _two_claims(MatchScope.EXACT_OBSERVABLE, MatchScope.SAME_HOST, same_subject=True)

    assert mixed.assessment.verdict is Verdict.SUSPICIOUS
    assert mixed.assessment.verdict_rule_id != VERDICT_RULES["malicious_corroborated"]


def test_two_independent_exact_claims_still_corroborate() -> None:
    """The counterpart: matching scope, independent origins, compatible semantics."""
    matched = _two_claims(
        MatchScope.EXACT_OBSERVABLE, MatchScope.EXACT_OBSERVABLE, same_subject=True
    )

    assert matched.assessment.verdict is Verdict.MALICIOUS
    assert matched.assessment.verdict_rule_id == VERDICT_RULES["malicious_corroborated"]


def test_claims_about_two_different_objects_never_corroborate() -> None:
    """Two malicious files are two findings, not agreement about either."""
    separate = _two_claims(
        MatchScope.EXACT_OBSERVABLE, MatchScope.EXACT_OBSERVABLE, same_subject=False
    )

    assert separate.assessment.verdict is Verdict.SUSPICIOUS
    assert separate.assessment.verdict_rule_id != VERDICT_RULES["malicious_corroborated"]


# --------------------------------------------------------------------------- #
# What "deterministic" actually means here
# --------------------------------------------------------------------------- #


def _identical_inputs():
    sample = file_object(sha256="9" * 64)
    record = evidence(sample, claim_type="alpha_sample", provider="alpha")
    scene = scenario(sample).with_envelope(envelope(record, provider="alpha", objects=(sample,)))
    return scene, record


def test_ids_are_stable_for_one_set_of_inputs() -> None:
    """Re-running fusion over the same evidence re-derives the same identities.

    This is what the ids are for: a stored assessment can be recomputed and
    compared rather than merely trusted, and discovery order cannot mint two
    identities for one conclusion.
    """
    scene, record = _identical_inputs()
    first = fuse_with_semantics(scene, {record.id: "malware_sample_identity"})
    second = fuse_with_semantics(scene, {record.id: "malware_sample_identity"})

    assert first.assessment.assessment_id == second.assessment.assessment_id
    assert [claim.claim_id for claim in first.normalized_claims] == [
        claim.claim_id for claim in second.normalized_claims
    ]


def test_claim_and_assessment_ids_are_run_scoped_not_cross_run_semantic() -> None:
    """Stated plainly, because the honest limit is easy to overclaim.

    ``claim_id`` and ``assessment_id`` incorporate ``Evidence.id``, a UUID minted
    per collection. Two investigations that gather semantically identical
    intelligence therefore produce **different** claim and assessment ids. What
    survives across runs is the *proposition* — subject, semantic and scope — and
    that is the identity to compare on when asking "is this the same claim about
    the same thing?".

    Calling the ids content-derived is true of the content they hash, and would
    be misleading if it were read as semantic identity across collections.
    """
    first_scene, first_record = _identical_inputs()
    second_scene, second_record = _identical_inputs()
    assert first_record.id != second_record.id  # fresh UUIDs, same meaning

    first = fuse_with_semantics(first_scene, {first_record.id: "malware_sample_identity"})
    second = fuse_with_semantics(second_scene, {second_record.id: "malware_sample_identity"})

    assert first.assessment.assessment_id != second.assessment.assessment_id
    # The semantic layer is stable across runs, and is what may be compared.
    assert [group.proposition.ref for group in first.proposition_groups] == [
        group.proposition.ref for group in second.proposition_groups
    ]
    assert first.assessment.verdict is second.assessment.verdict
    assert first.assessment.target_key == second.assessment.target_key


def test_a_result_survives_a_serialization_round_trip_unchanged() -> None:
    """No in-memory identity anywhere in the assessment."""
    scene, record = _identical_inputs()
    original = fuse_with_semantics(scene, {record.id: "malware_sample_identity"})

    restored = type(original).model_validate_json(original.model_dump_json())

    assert restored.model_dump_json() == original.model_dump_json()
    assert restored.assessment.assessment_id == original.assessment.assessment_id
    assert restored.assessment.verdict is original.assessment.verdict
    assert restored.assessment.confidence is original.assessment.confidence
    assert len(restored.normalized_claims) == len(original.normalized_claims)
    assert len(restored.proposition_groups) == len(original.proposition_groups)
    assert len(restored.contributions) == len(original.contributions)


def test_every_policy_version_travels_with_the_assessment() -> None:
    """Four versions, so a stored verdict can always be traced to the rules that made it."""
    scene, record = _identical_inputs()
    assessment = fuse_with_semantics(scene, {record.id: "malware_sample_identity"}).assessment

    assert assessment.fusion_policy_version
    assert assessment.claim_semantics_policy_version == CLAIM_SEMANTICS_POLICY_VERSION
    assert assessment.qualification_policy_version
    assert assessment.false_positive_policy_version
