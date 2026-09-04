"""A sandbox's *verdict* is explainable; what it *watched* is not (Task 24).

The test-artifact rule accounts for detections about the object's nature. A
sandbox classifying a test artifact as malicious is such a detection -- every
sandbox flags EICAR -- and it arrives as a curated assertion, so the rule
explains it. A directly observed behaviour record about the same file is
different knowledge and stays opposing, exactly as before.
"""

from __future__ import annotations

from fixtures.false_positive import envelope, evidence, file_object, scenario, signal
from ti_recon.enums import EvidenceClass
from ti_recon.reasoning.false_positive import FalsePositiveReasoningEngine
from ti_recon.reasoning.false_positive.models import LinkRelation, ReasoningRole
from ti_recon.reasoning.models import ContextSignalType


def _reason(scene):
    return FalsePositiveReasoningEngine().evaluate(
        qualification=scene.qualification(),
        results=scene.envelopes,
        graph=scene.graph,
        root=scene.root,
    )


def test_a_curated_sandbox_verdict_about_a_test_artifact_is_explained() -> None:
    sample = file_object(sha256="d" * 64)
    verdict = evidence(sample, claim_type="alpha_verdict")
    sandbox = evidence(
        sample,
        claim_type="alpha_sandbox_verdicts",
        evidence_class=EvidenceClass.CURATED_THREAT_ASSERTION,
    )
    watched = evidence(
        sample, claim_type="alpha_behaviour_record", evidence_class=EvidenceClass.DIRECT_OBSERVATION
    )
    scene = (
        scenario(sample)
        .with_envelope(envelope(verdict, sandbox, watched, objects=(sample,)))
        .with_signal(signal(sample, ContextSignalType.TEST_ARTIFACT, source_key="eicar.com"))
    )

    result = _reason(scene)

    finding = next(f for f in result.findings if f.role is ReasoningRole.ALTERNATIVE_EXPLANATION)
    explained = {link.ref for link in finding.links if link.relation is LinkRelation.EXPLAINS}
    opposed = {link.ref for link in finding.links if link.relation is LinkRelation.OPPOSES}
    assert explained == {verdict.id, sandbox.id}
    assert opposed == {watched.id}
