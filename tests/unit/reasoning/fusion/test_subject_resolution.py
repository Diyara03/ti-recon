"""Unknown is not root (Task 17A/D).

A claim names its subject by ``Evidence.subject_object_id``, a per-run UUID that
has to be resolved onto the canonical key every other layer uses. There are three
honest outcomes and the third is the one that matters:

* the id is the root object's — the claim is about the root;
* the id is some other object this run saw — the claim is about that object;
* the id resolves to nothing — the claim is **unresolved**, and stays that way.

The third case used to fall through to the root, on the reading that an adapter
anchoring evidence to the requested observable would arrive that way. It does
not: :meth:`ClaimTranslationContext.build` indexes the root object's own id, so a
legitimate root claim resolves explicitly. The fallback therefore only ever fired
on an id nothing could account for — and handed that record the root's identity,
letting a malformed or misrouted claim vote on the assessment of whatever the
analyst had typed.

These tests drive the real ThreatFox, URLhaus and Hybrid Analysis adapters,
because those three list only the objects they *discovered* in
``envelope.objects`` and so depend entirely on root-id resolution working.
"""

from __future__ import annotations

import uuid

import pytest

from fixtures.abusech import payloads as abusech_payloads
from fixtures.fusion import envelope, evidence, file_object, fuse, fuse_with_semantics, observable
from fixtures.fusion import scenario as fusion_scenario
from fixtures.hybrid_analysis import payloads as sandbox_payloads
from fixtures.reasoning import (
    file_object as reasoning_file_object,
)
from fixtures.reasoning import (
    observable as reasoning_observable,
)
from fixtures.reasoning import (
    sandbox_envelope,
    threatfox_compromised_envelope,
    urlhaus_url_envelope,
)
from ti_recon.enums import EvidenceEffect, Verdict
from ti_recon.reasoning.claims.translation import (
    UNRESOLVED_SUBJECT_PREFIX,
    ClaimTranslationContext,
    is_unresolved_subject,
)
from ti_recon.reasoning.fusion.models import AssessmentConfidence, FusionIssueType

# --------------------------------------------------------------------------- #
# A / B / C — the resolution algorithm itself
# --------------------------------------------------------------------------- #


def test_the_root_objects_own_id_resolves_to_the_root() -> None:
    """Case A: explicitly, through the index — not through a fallback.

    The root is indexed by id even when no envelope lists it, which is exactly
    the shape several adapters produce: they report the objects they discovered
    and leave the requested observable implicit.
    """
    root = observable("198.51.100.30")
    context = ClaimTranslationContext.build(objects=(), root=root)

    assert context.subject_key_for(root.id) == root.canonical_key
    assert not is_unresolved_subject(context.subject_key_for(root.id))


def test_a_known_non_root_id_resolves_to_that_object() -> None:
    """Case B: a pivot is the pivot, never the root."""
    root = observable("198.51.100.30")
    pivot = observable("203.0.113.30")
    context = ClaimTranslationContext.build(objects=(pivot,), root=root)

    assert context.subject_key_for(pivot.id) == pivot.canonical_key
    assert context.subject_key_for(pivot.id) != root.canonical_key


def test_an_unknown_id_resolves_to_neither() -> None:
    """Case C: the invariant, stated as directly as it can be."""
    root = observable("198.51.100.30")
    context = ClaimTranslationContext.build(objects=(), root=root)
    stray = str(uuid.uuid4())

    resolved = context.subject_key_for(stray)

    assert resolved != root.canonical_key
    assert is_unresolved_subject(resolved)
    assert resolved.startswith(UNRESOLVED_SUBJECT_PREFIX)


def test_a_missing_id_is_unresolved_rather_than_root() -> None:
    """``subject_object_id`` is required, so this is belt and braces."""
    root = observable("198.51.100.30")
    context = ClaimTranslationContext.build(objects=(), root=root)

    assert is_unresolved_subject(context.subject_key_for(None))


# --------------------------------------------------------------------------- #
# D / E — an orphan claim cannot decide anything
# --------------------------------------------------------------------------- #


def _root_with_orphan(semantic: str, effect: EvidenceEffect):
    """A root nobody has said anything about, plus one unplaceable claim."""
    root = observable("198.51.100.31")
    stray_object = observable("203.0.113.31")
    orphan = evidence(stray_object, provider="alpha", source_family="fam_a", effect=effect)
    # Deliberately omitted from `objects`, so nothing in the run can place it.
    scene = fusion_scenario(root).with_envelope(envelope(orphan, provider="alpha", objects=()))
    return fuse_with_semantics(scene, {orphan.id: semantic})


def test_an_orphan_decisive_malicious_claim_cannot_condemn_the_root() -> None:
    """Case D: the failure this fix exists to prevent.

    A decisive malicious claim naming an object nothing can place would, under
    the old fallback, have been read as a claim about the root and taken an
    otherwise silent investigation to MALICIOUS.
    """
    result = _root_with_orphan("malware_sample_identity", EvidenceEffect.SUPPORTS_MALICIOUS)

    assert result.assessment.verdict is Verdict.INCONCLUSIVE
    assert result.assessment.confidence is AssessmentConfidence.UNSPECIFIED


def test_an_orphan_benign_claim_cannot_clear_the_root() -> None:
    """Case E: and the same in the direction that fails quietly."""
    result = _root_with_orphan("benign_reputation", EvidenceEffect.SUPPORTS_BENIGN)

    assert result.assessment.verdict is not Verdict.LIKELY_BENIGN
    assert result.assessment.verdict is Verdict.INCONCLUSIVE


def test_an_orphan_claim_is_retained_and_reported() -> None:
    """Excluded from the assessment, never dropped from the record.

    Silently discarding it would hide a plumbing fault; silently crediting it to
    the root would hide a correctness one. It is kept, named, and does not vote.
    """
    result = _root_with_orphan("malware_sample_identity", EvidenceEffect.SUPPORTS_MALICIOUS)

    assert len(result.normalized_claims) == 1
    claim = result.normalized_claims[0]
    assert is_unresolved_subject(claim.subject_key)

    issues = [
        issue
        for issue in result.issues
        if issue.issue_type is FusionIssueType.UNRESOLVED_CLAIM_SUBJECT
    ]
    assert len(issues) == 1
    assert issues[0].refs == (claim.claim_id,)
    assert len(result.contributions) == 1


# --------------------------------------------------------------------------- #
# F / G / H — the real adapters still resolve to the root
# --------------------------------------------------------------------------- #

REAL_ROOT_CASES = (
    (
        "threatfox",
        threatfox_compromised_envelope,
        lambda: reasoning_observable(abusech_payloads.MALICIOUS_DOMAIN),
        Verdict.MALICIOUS,
    ),
    (
        "urlhaus",
        urlhaus_url_envelope,
        lambda: reasoning_observable(str(abusech_payloads.urlhaus_url_result()["url"])),
        Verdict.MALICIOUS,
    ),
    (
        "hybrid_analysis",
        sandbox_envelope,
        lambda: reasoning_file_object(
            sha256=str(sandbox_payloads.search_hash_malicious()[0]["sha256"])
        ),
        Verdict.SUSPICIOUS,
    ),
)


@pytest.mark.parametrize(
    "name,builder,subject_factory,expected",
    REAL_ROOT_CASES,
    ids=[case[0] for case in REAL_ROOT_CASES],
)
def test_a_real_adapters_root_evidence_still_resolves(
    name: str, builder, subject_factory, expected: Verdict
) -> None:
    """Cases F, G and H, through the real adapters.

    These three list only discovered objects in ``envelope.objects``, so every
    one of their claims about the requested observable depends on the root being
    indexed by id. If that ever stops working they do not fail loudly — they go
    quiet, because their claims become unresolved and stop voting.
    """
    subject = subject_factory()
    result = fuse(fusion_scenario(subject).with_envelope(builder(subject=subject)))

    assert result.assessment.verdict is expected
    assert result.assessment.target_key == subject.canonical_key
    assert result.normalized_claims, f"{name} produced no claims"
    assert not any(is_unresolved_subject(claim.subject_key) for claim in result.normalized_claims)
    assert not any(
        issue.issue_type is FusionIssueType.UNRESOLVED_CLAIM_SUBJECT for issue in result.issues
    )


def test_a_real_adapters_evidence_becomes_unresolved_without_its_subject() -> None:
    """The counterpart, so the tests above cannot pass by accident.

    Root the run on some *other* object and ThreatFox's claims stop resolving —
    which is precisely what used to be papered over, since the fallback made
    every one of them look like a claim about whatever the run was rooted on.
    """
    answered_about = reasoning_observable(abusech_payloads.MALICIOUS_DOMAIN)
    unrelated_root = file_object(sha256="c" * 64)
    result = fuse(
        fusion_scenario(unrelated_root).with_envelope(
            threatfox_compromised_envelope(subject=answered_about)
        )
    )

    assert all(is_unresolved_subject(claim.subject_key) for claim in result.normalized_claims)
    assert result.assessment.verdict is Verdict.INCONCLUSIVE
    assert any(
        issue.issue_type is FusionIssueType.UNRESOLVED_CLAIM_SUBJECT for issue in result.issues
    )
