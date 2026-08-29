"""Building fusion scenarios in generic vocabulary.

Task 17 reasons over propositions, not providers, so its tests are written that
way: synthetic families like ``alpha`` and ``beta``, claims described by semantic,
scope and direction. A test that reached for URLhaus to express "an exact
malware-distribution claim" would be asserting that fusion works for URLhaus,
when the invariant is that it works for anything producing those semantics.

A separate module drives the real adapters end to end, so the generic vocabulary
these tests assume is provably the one the shipped providers emit.

Nothing here touches a network, a clock or a credential.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ti_recon.correlation.engine import CorrelationEngine
from ti_recon.correlation.graph import InvestigationGraph
from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    MatchScope,
    ObjectClass,
    ProviderOperation,
    ProviderRunStatus,
)
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.normalization import normalize_observable
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.claims.models import (
    ClaimAssertionStrength,
    ClaimSemantic,
    NormalizedClaim,
    claim_from,
)
from ti_recon.reasoning.claims.policy import CLAIM_SEMANTICS_POLICY_VERSION
from ti_recon.reasoning.false_positive.models import (
    DoesNotEstablish,
    FindingLimitation,
    FindingLink,
    LinkRelation,
    LinkTarget,
    ReasonCode,
    ReasoningDimension,
    ReasoningFinding,
    ReasoningRole,
    finding_id_for,
)
from ti_recon.reasoning.false_positive.policy import (
    FALSE_POSITIVE_REASONING_POLICY_VERSION,
    RULE_IDS,
)
from ti_recon.reasoning.false_positive.results import (
    FalsePositiveReasoningResult,
    ReasoningCoverage,
)
from ti_recon.reasoning.models import observable_subject
from ti_recon.reasoning.results import QualificationCoverage, TemporalContextResult

#: The instant every Task 15 result in these tests was evaluated at. Task 17
#: carries it through and never reads a clock of its own.
AS_OF = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def observable(value: str) -> IntelObject:
    return normalize_observable(value).intel_object


def file_object(**hashes: str) -> IntelObject:
    named = {
        {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}[key]: value
        for key, value in hashes.items()
    }
    strongest = named.get("SHA-256") or named.get("SHA-1") or next(iter(named.values()))
    return IntelObject(
        object_class=ObjectClass.OBSERVABLE,
        object_type=IntelObjectType.FILE,
        canonical_value=strongest,
        display_value=strongest,
        properties={"hashes": named},
    )


def evidence(
    subject: IntelObject,
    *,
    claim_type: str = "alpha_finding",
    effect: EvidenceEffect = EvidenceEffect.SUPPORTS_MALICIOUS,
    evidence_class: EvidenceClass = EvidenceClass.CURATED_THREAT_ASSERTION,
    match_scope: MatchScope = MatchScope.EXACT_OBSERVABLE,
    provider: str = "alpha",
    origin_provider: str | None = None,
    source_family: str | None = None,
    lineage_group_id: str = "",
    attributes: dict[str, Any] | None = None,
) -> Evidence:
    """One provider claim, described only in generic terms."""
    return Evidence(
        investigation_id="inv-1",
        subject_object_id=subject.id,
        evidence_class=evidence_class,
        claim_type=claim_type,
        effect=effect,
        transport_provider=provider,
        origin_provider=origin_provider or provider,
        source_family=source_family or provider,
        lineage_group_id=lineage_group_id,
        match_scope=match_scope,
        attributes=attributes or {},
    )


def envelope(
    *records: Evidence,
    provider: str = "alpha",
    objects: tuple[IntelObject, ...] = (),
    status: ProviderRunStatus = ProviderRunStatus.SUCCESS,
) -> ProviderResultEnvelope:
    return ProviderResultEnvelope(
        provider=provider,
        operation=ProviderOperation.LOOKUP,
        status=status,
        adapter_version="1.0.0",
        api_version="v1",
        evidence=records,
        objects=objects,
    )


def claim(
    subject: IntelObject,
    record: Evidence,
    semantic: ClaimSemantic,
    *,
    strength: ClaimAssertionStrength = ClaimAssertionStrength.ASSERTED,
) -> NormalizedClaim:
    """A claim built directly, for tests about fusion rather than translation."""
    return claim_from(
        record,
        policy_version=CLAIM_SEMANTICS_POLICY_VERSION,
        semantic=semantic,
        strength=strength,
        subject_key=subject.canonical_key,
    )


def explanation(
    subject: IntelObject,
    explained: Evidence,
    *,
    reason: ReasonCode = ReasonCode.EXPECTED_TEST_ARTIFACT_DETECTION,
    opposing: tuple[Evidence, ...] = (),
    limitations: tuple[FindingLimitation, ...] = (),
) -> ReasoningFinding:
    """A Task 16 alternative explanation that specifically explains evidence.

    The only finding shape that removes support, built the way Task 16 builds it
    -- an ``ALTERNATIVE_EXPLANATION`` role with an ``EXPLAINS`` link to evidence.
    """
    links = (
        FindingLink(relation=LinkRelation.EXPLAINS, target=LinkTarget.EVIDENCE, ref=explained.id),
        *(
            FindingLink(relation=LinkRelation.OPPOSES, target=LinkTarget.EVIDENCE, ref=item.id)
            for item in opposing
        ),
    )
    return _finding(
        subject,
        rule_key="test_artifact",
        reason=reason,
        role=ReasoningRole.ALTERNATIVE_EXPLANATION,
        dimension=ReasoningDimension.OBJECT_NATURE,
        links=links,
        boundaries=(DoesNotEstablish.OBJECT_BENIGN,),
        limitations=limitations,
    )


def caution(
    subject: IntelObject,
    qualified: Evidence,
    *,
    role: ReasoningRole = ReasoningRole.ATTRIBUTION_CAUTION,
    reason: ReasonCode = ReasonCode.SHARED_INFRASTRUCTURE_LIMITS_ATTRIBUTION,
    dimension: ReasoningDimension = ReasoningDimension.ATTRIBUTION,
    rule_key: str = "shared_infrastructure",
    limitations: tuple[FindingLimitation, ...] = (),
) -> ReasoningFinding:
    """A Task 16 finding that qualifies evidence without explaining it.

    Every non-explanation role goes through here, because the invariant under
    test is that none of them removes support however cautionary it sounds.
    """
    return _finding(
        subject,
        rule_key=rule_key,
        reason=reason,
        role=role,
        dimension=dimension,
        links=(
            FindingLink(
                relation=LinkRelation.QUALIFIES, target=LinkTarget.EVIDENCE, ref=qualified.id
            ),
        ),
        boundaries=(DoesNotEstablish.MALICIOUS_EVIDENCE_FALSE,),
        limitations=limitations,
    )


def _finding(
    subject: IntelObject,
    *,
    rule_key: str,
    reason: ReasonCode,
    role: ReasoningRole,
    dimension: ReasoningDimension,
    links: tuple[FindingLink, ...],
    boundaries: tuple[DoesNotEstablish, ...],
    limitations: tuple[FindingLimitation, ...] = (),
) -> ReasoningFinding:
    subject_ref = observable_subject(subject.canonical_key)
    return ReasoningFinding(
        finding_id=finding_id_for(
            policy_version=FALSE_POSITIVE_REASONING_POLICY_VERSION,
            rule_id=RULE_IDS[rule_key],
            subject=subject_ref,
            match_scope=MatchScope.EXACT_OBSERVABLE,
            link_refs=tuple(item.ref for item in links),
        ),
        rule_id=RULE_IDS[rule_key],
        policy_version=FALSE_POSITIVE_REASONING_POLICY_VERSION,
        role=role,
        dimension=dimension,
        reason_code=reason,
        subject=subject_ref,
        match_scope=MatchScope.EXACT_OBSERVABLE,
        links=links,
        does_not_establish=boundaries,
        limitations=limitations,
    )


def qualification(*, stale_context_datasets: int = 0) -> TemporalContextResult:
    """A minimal Task 15 result. Fusion reads its ``as_of`` and its version."""
    return TemporalContextResult(
        evaluated_at=AS_OF,
        engine_version="0.1.0",
        context_policy_version="1.0.0",
        warninglist_map_version="1.0.0",
        coverage=QualificationCoverage(stale_context_datasets=stale_context_datasets),
    )


def reasoning(*findings: ReasoningFinding) -> FalsePositiveReasoningResult:
    return FalsePositiveReasoningResult(
        policy_version=FALSE_POSITIVE_REASONING_POLICY_VERSION,
        qualification_policy_version="1.0.0",
        engine_version="0.1.0",
        as_of=AS_OF,
        findings=tuple(findings),
        coverage=ReasoningCoverage(),
    )


@dataclass
class Scenario:
    """One investigation's inputs, ready for the fusion engine."""

    root: IntelObject
    envelopes: list[ProviderResultEnvelope] = field(default_factory=list)
    findings: list[ReasoningFinding] = field(default_factory=list)
    stale_context_datasets: int = 0
    graph: InvestigationGraph | None = None

    def with_envelope(self, item: ProviderResultEnvelope) -> Scenario:
        self.envelopes.append(item)
        return self

    def with_finding(self, item: ReasoningFinding) -> Scenario:
        self.findings.append(item)
        return self

    def with_graph(self) -> Scenario:
        graph = InvestigationGraph(investigation_id="inv-1", authenticated_user_id="analyst-a")
        engine = CorrelationEngine(graph=graph)
        engine.add_root(self.root)
        for item in self.envelopes:
            engine.ingest(item)
        self.graph = graph
        return self

    def qualification(self) -> TemporalContextResult:
        return qualification(stale_context_datasets=self.stale_context_datasets)

    def reasoning(self) -> FalsePositiveReasoningResult:
        return reasoning(*self.findings)


def scenario(root: IntelObject) -> Scenario:
    return Scenario(root=root)


# --------------------------------------------------------------------------- #
# Running fusion
# --------------------------------------------------------------------------- #


def _semantic_translator(semantics: dict[str, str]) -> Any:
    """A translator that assigns a semantic per evidence id.

    Lets a test state exactly which proposition each claim asserts without
    routing through a provider. That is the right level for a test about fusion:
    translation has its own suite, driven by the real adapters.
    """

    def translate(item_envelope: Any, context: Any) -> tuple[NormalizedClaim, ...]:
        from ti_recon.reasoning.claims.translation import directional_evidence

        return tuple(
            claim_from(
                record,
                policy_version=context.policy_version,
                semantic=ClaimSemantic(semantics[record.id]),
                subject_key=context.subject_key_for(record.subject_object_id),
                source_partial=context.source_partial,
            )
            for record in directional_evidence(item_envelope)
        )

    return translate


def fuse(scene: Scenario) -> Any:
    """Run fusion with the real provider translators."""
    from ti_recon.reasoning.fusion import EvidenceFusionEngine

    return EvidenceFusionEngine().evaluate(
        qualification=scene.qualification(),
        reasoning=scene.reasoning(),
        results=scene.envelopes,
        graph=scene.graph,
        root=scene.root,
    )


def fuse_with_semantics(scene: Scenario, semantics: dict[str, str]) -> Any:
    """Run fusion with each evidence item assigned a stated semantic."""
    from ti_recon.reasoning.fusion import EvidenceFusionEngine

    providers = {item.provider for item in scene.envelopes}
    engine = EvidenceFusionEngine(
        translators={name: _semantic_translator(semantics) for name in providers}
    )
    return engine.evaluate(
        qualification=scene.qualification(),
        reasoning=scene.reasoning(),
        results=scene.envelopes,
        graph=scene.graph,
        root=scene.root,
    )


def fuse_as(scene: Scenario, semantic: str) -> Any:
    """Run fusion treating every directional claim as one semantic."""
    semantics = {
        record.id: semantic
        for item in scene.envelopes
        for record in item.evidence
        if record.effect is not EvidenceEffect.CONTEXT_ONLY
    }
    return fuse_with_semantics(scene, semantics)
