"""Turning sandbox observations into evidence (Task 12).

One principal finding per sample, and one coverage record. Not one per report,
and emphatically not one per signature.

Why one finding
---------------

A hash with three malicious detonations has been *run three times by one
sandbox*. Emitting three pieces of directional evidence would let a
thoroughly-analysed sample look independently corroborated, so a fusion layer
would count a single provider's diligence as agreement between sources. The same
applies inside a report: one detonation can trip four hundred signatures and
twenty ATT&CK techniques, and each is a description of the same execution.

So there is one ``hybrid_analysis_sandbox_assessment`` carrying bounded
per-report detail, plus context records for behaviour, and everything shares a
sample-level lineage group.

Why a quiet sandbox is not a benign sandbox
-------------------------------------------

The direction of the principal finding comes from
:data:`~ti_recon.sandbox.models.SANDBOX_VERDICT_EFFECT`, in which **no verdict
maps to ``SUPPORTS_BENIGN``**. A sample that did nothing may have been run on the
wrong OS, wanted a command line, wanted a click, found its C2 offline, been
geofenced, been waiting, or noticed it was being watched. The evidence that
matters in that case is the *quality* record — runtime, process count,
connection count, warnings — which lets a later layer distinguish "nothing
happened" from "nothing could have happened".
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from ti_recon.enums import (
    EvidenceClass,
    EvidenceEffect,
    IntelObjectType,
    MatchScope,
    ObjectClass,
    RelationshipType,
)
from ti_recon.models.base import FrozenTiReconModel, utc_now
from ti_recon.models.evidence import Evidence
from ti_recon.models.intel_object import IntelObject
from ti_recon.models.relationship import Relationship
from ti_recon.providers.hybrid_analysis.descriptor import (
    HYBRID_ANALYSIS_ORIGIN_PROVIDER,
    HYBRID_ANALYSIS_PROVIDER_ID,
    HYBRID_ANALYSIS_SOURCE_FAMILY,
    lineage_group_for_sample,
)
from ti_recon.sandbox.models import SandboxReportSummary, SandboxSampleView
from ti_recon.sandbox.selection import ReportSelection

__all__ = [
    "ASSESSMENT_CLAIM_TYPE",
    "BEHAVIOUR_CLAIM_TYPE",
    "COVERAGE_CLAIM_TYPE",
    "NO_REPORT_CLAIM_TYPE",
    "NormalizationContext",
    "ObjectRegistry",
    "SandboxNormalization",
    "normalize_behaviour",
    "normalize_coverage",
    "normalize_no_report",
    "normalize_sample_assessment",
]

ASSESSMENT_CLAIM_TYPE = "hybrid_analysis_sandbox_assessment"
BEHAVIOUR_CLAIM_TYPE = "hybrid_analysis_sandbox_behaviour"
COVERAGE_CLAIM_TYPE = "hybrid_analysis_sandbox_coverage"
NO_REPORT_CLAIM_TYPE = "hybrid_analysis_no_sandbox_report"


class NormalizationContext(FrozenTiReconModel):
    """What every record from one lookup shares."""

    investigation_id: str = Field(min_length=1, max_length=200)
    subject_object_id: str = Field(min_length=1, max_length=200)
    sample_sha256: str | None = Field(default=None, max_length=64)

    @property
    def lineage_group_id(self) -> str:
        return lineage_group_for_sample(self.sample_sha256)


class SandboxNormalization(FrozenTiReconModel):
    """Evidence, objects and relationships from one lookup."""

    evidence: tuple[Evidence, ...] = ()
    objects: tuple[IntelObject, ...] = ()
    relationships: tuple[Relationship, ...] = ()

    def merge(self, other: SandboxNormalization) -> SandboxNormalization:
        return SandboxNormalization(
            evidence=self.evidence + other.evidence,
            objects=self.objects + other.objects,
            relationships=self.relationships + other.relationships,
        )


class ObjectRegistry:
    """One :class:`IntelObject` per identity, across every report in a lookup.

    Two reports of the same sample routinely observe the same C2 domain, and
    creating an object per report would fracture one host into several — a graph
    where ``c2.example`` appears three times is a graph nothing can correlate on.
    So objects are interned by ``(type, canonical value)`` while each report still
    contributes its own relationship, which is what keeps "both runs contacted
    it" visible without duplicating the thing contacted.
    """

    def __init__(self) -> None:
        self._objects: dict[tuple[str, str], IntelObject] = {}

    def intern(self, candidate: IntelObject) -> tuple[IntelObject, bool]:
        """``(object, is_new)`` for this identity."""
        key = (candidate.object_type.value, candidate.canonical_value)
        existing = self._objects.get(key)
        if existing is not None:
            return existing, False
        self._objects[key] = candidate
        return candidate, True


def _evidence(
    context: NormalizationContext,
    *,
    evidence_class: EvidenceClass,
    claim_type: str,
    effect: EvidenceEffect,
    attributes: dict[str, Any],
) -> Evidence:
    """Build one record with mandatory sample-level provenance.

    No Admiralty grading and no ``provider_confidence``: how much a sandbox run
    is worth is TI Recon policy, and an adapter asserting it would smuggle in a
    judgement it is not allowed to make.
    """
    return Evidence(
        investigation_id=context.investigation_id,
        subject_object_id=context.subject_object_id,
        evidence_class=evidence_class,
        claim_type=claim_type,
        effect=effect,
        transport_provider=HYBRID_ANALYSIS_PROVIDER_ID,
        origin_provider=HYBRID_ANALYSIS_ORIGIN_PROVIDER,
        source_family=HYBRID_ANALYSIS_SOURCE_FAMILY,
        match_scope=MatchScope.EXACT_OBSERVABLE,
        lineage_group_id=context.lineage_group_id,
        attributes=attributes,
        observed_at=utc_now(),
    )


def _report_record(summary: SandboxReportSummary) -> dict[str, Any]:
    """One report's headline, for the assessment record.

    Report id and environment travel with every entry: a verdict without the
    machine it came from is unusable, because the whole point of keeping several
    is that they may legitimately differ.
    """
    record: dict[str, Any] = {
        "report_id": summary.report_id,
        "environment_id": summary.environment.environment_id,
        "environment": summary.environment.description,
        "verdict": summary.verdict.value,
        "raw_verdict": summary.raw_verdict,
        "state": summary.quality.state.value,
    }
    if summary.threat_score is not None:
        record["threat_score"] = summary.threat_score
    if summary.threat_level is not None:
        record["threat_level"] = summary.threat_level
    if summary.family_label is not None:
        record["family_label"] = summary.family_label
    return record


def normalize_sample_assessment(
    context: NormalizationContext, view: SandboxSampleView
) -> SandboxNormalization:
    """The one directional finding, if the runs point anywhere at all.

    ``effect`` comes from the strongest **completed** verdict, so a failed run
    never becomes an opinion — and it can never be ``SUPPORTS_BENIGN``.

    ``divergent_verdicts`` and ``verdicts_by_environment`` are the reason this is
    one record rather than a summary. A sample that detonates on Windows 11 and
    sits still on Windows 7 is not a contradiction to resolve; it is
    environment-dependent malware describing itself, and collapsing it into a
    single answer would delete the finding.
    """
    verdict = view.strongest_verdict
    attributes: dict[str, Any] = {
        "sandbox_verdict": verdict.value,
        "report_count": view.report_count,
        "completed_report_count": len(view.completed_reports),
        "summarized_report_count": len(view.summaries),
        "verdicts_by_environment": view.verdicts_by_environment,
        "divergent_verdicts": view.divergent_verdicts,
        # Stated rather than implied: the one inference this provider must never
        # let anything downstream make.
        "means_benign": False,
    }
    if view.canonical_sha256 is not None:
        attributes["sample_sha256"] = view.canonical_sha256
    if view.summaries:
        attributes["reports"] = [_report_record(item) for item in view.summaries]
    raw = [item.raw_verdict for item in view.completed_reports if item.raw_verdict]
    if raw:
        attributes["raw_verdicts"] = sorted(set(raw))
    families = sorted(
        {item.family_label for item in view.summaries if item.family_label is not None}
    )
    if families:
        # One provider's naming, not resolved attribution. Alias reconciliation
        # against MalwareBazaar, ThreatFox and GTI is a later concern, and this
        # must not overwrite theirs.
        attributes["provider_family_labels"] = families

    # A positive verdict is the provider's own curated conclusion about a run it
    # performed; anything else is context, and the model then forbids a
    # direction outright.
    evidence_class = (
        EvidenceClass.CURATED_THREAT_ASSERTION if verdict.is_positive else EvidenceClass.CONTEXT
    )
    return SandboxNormalization(
        evidence=(
            _evidence(
                context,
                evidence_class=evidence_class,
                claim_type=ASSESSMENT_CLAIM_TYPE,
                effect=view.effect,
                attributes=attributes,
            ),
        )
    )


def normalize_behaviour(
    context: NormalizationContext,
    summary: SandboxReportSummary,
    registry: ObjectRegistry | None = None,
) -> SandboxNormalization:
    """What one detonation was observed doing.

    Always ``CONTEXT_ONLY``, including when it is full of malicious signatures.
    The direction was already stated once by the assessment record; repeating it
    here would be the same sandbox voting twice.

    Related objects are created for contacted infrastructure and dropped files,
    linked by ``contacts`` and ``drops`` — the sandbox observed the sample doing
    those things, which is exactly what those relationships mean. Nothing is
    enriched further: whether to pivot on them is the future planner's decision.
    """
    quality = summary.quality
    attributes: dict[str, Any] = {
        "report_id": summary.report_id,
        "environment_id": summary.environment.environment_id,
        "environment": summary.environment.description,
        "state": quality.state.value,
        # Kept even when detail is truncated: "600 connections, 25 normalized" is
        # honest, "25 connections" is not.
        "total_processes": quality.total_processes,
        "total_network_connections": quality.total_network_connections,
        "total_signatures": quality.total_signatures,
        "normalized_processes": len(summary.processes),
        "normalized_network": len(summary.network),
        "normalized_signatures": len(summary.signatures),
        "normalized_techniques": len(summary.techniques),
        "normalized_extracted_files": len(summary.extracted_files),
        "truncated": {name: flag for name, flag in summary.truncated.items() if flag},
        # The quality question, answered explicitly: did anything run at all?
        "observed_execution": quality.observed_any_execution,
    }
    if quality.analysis_started_at is not None:
        attributes["analysis_started_at"] = quality.analysis_started_at.isoformat()
    for name in ("runtime_seconds", "network_mode", "action_script"):
        value = getattr(quality, name)
        if value is not None:
            attributes[name] = value
    for name in ("anti_evasion", "script_logging", "sample_tampering_allowed"):
        value = getattr(quality, name)
        if value is not None:
            attributes[name] = value
    if quality.warnings:
        attributes["warnings"] = list(quality.warnings)
    if summary.tags:
        attributes["tags"] = list(summary.tags)

    if summary.signatures:
        attributes["signatures"] = [
            {
                key: value
                for key, value in (
                    ("name", item.name),
                    ("category", item.category),
                    ("threat_level", item.threat_level),
                    ("threat_level_label", item.threat_level_label),
                    ("relevance", item.relevance),
                    ("attack_id", item.attack_id),
                    ("capec_id", item.capec_id),
                    ("description", item.description),
                )
                if value is not None
            }
            for item in summary.signatures
        ]
    if summary.techniques:
        attributes["mitre_techniques"] = [
            {
                key: value
                for key, value in (
                    ("attack_id", item.attack_id),
                    ("technique", item.technique),
                    ("tactic", item.tactic),
                    ("parent_attack_id", item.parent_attack_id),
                    ("malicious_identifiers", item.malicious_identifiers),
                    ("suspicious_identifiers", item.suspicious_identifiers),
                    ("informative_identifiers", item.informative_identifiers),
                )
                if value is not None
            }
            for item in summary.techniques
        ]
    if summary.processes:
        attributes["processes"] = [
            {
                key: value
                for key, value in (
                    ("name", item.name),
                    ("normalized_path", item.normalized_path),
                    # Observed, bounded, control-character-free, and never
                    # executed or interpolated anywhere.
                    ("command_line", item.command_line),
                    ("sha256", item.sha256),
                    ("process_id", item.process_id),
                    ("parent_process_id", item.parent_process_id),
                )
                if value is not None
            }
            for item in summary.processes
        ]
    if summary.certificates:
        attributes["certificates"] = [
            {
                key: value
                for key, value in (
                    ("owner", item.owner),
                    ("issuer", item.issuer),
                    ("serial_number", item.serial_number),
                    ("sha1_fingerprint", item.sha1_fingerprint),
                    ("md5_fingerprint", item.md5_fingerprint),
                    (
                        "valid_from",
                        item.valid_from.isoformat() if item.valid_from else None,
                    ),
                    (
                        "valid_until",
                        item.valid_until.isoformat() if item.valid_until else None,
                    ),
                )
                if value is not None
            }
            for item in summary.certificates
        ]

    evidence = _evidence(
        context,
        evidence_class=EvidenceClass.CONTEXT,
        claim_type=BEHAVIOUR_CLAIM_TYPE,
        effect=EvidenceEffect.CONTEXT_ONLY,
        attributes=attributes,
    )
    result = SandboxNormalization(evidence=(evidence,))
    return result.merge(
        _related_objects(
            context, summary, evidence.id, registry if registry is not None else ObjectRegistry()
        )
    )


def _related_objects(
    context: NormalizationContext,
    summary: SandboxReportSummary,
    evidence_id: str,
    registry: ObjectRegistry,
) -> SandboxNormalization:
    """Objects for what the sample touched and wrote.

    A contacted host is not accused of anything. A detonating sample also reaches
    certificate revocation lists, CDNs, time servers and telemetry endpoints, and
    the sandbox cannot tell those from a C2 either — so these are observations
    with a relationship, and significance is the correlation layer's to decide.
    """
    objects: list[IntelObject] = []
    relationships: list[Relationship] = []

    for observation in summary.network:
        object_type = {
            "domain": IntelObjectType.DOMAIN_NAME,
            "ipv4": IntelObjectType.IPV4_ADDR,
            "ipv6": IntelObjectType.IPV6_ADDR,
        }.get(observation.kind)
        if object_type is None:  # pragma: no cover - kinds are closed
            continue
        node, is_new = registry.intern(
            IntelObject(
                object_class=ObjectClass.INFRASTRUCTURE,
                object_type=object_type,
                canonical_value=observation.value,
                display_value=observation.value,
                properties={"sandbox_role": observation.role.value},
            )
        )
        if is_new:
            objects.append(node)
        relationships.append(
            Relationship(
                source_object_id=context.subject_object_id,
                relationship_type=RelationshipType.CONTACTS,
                target_object_id=node.id,
                evidence_refs=(evidence_id,),
            )
        )

    for extracted in summary.extracted_files:
        strongest = extracted.strongest_hash
        if strongest is None:
            continue
        _, digest = strongest
        hashes = {
            name: value
            for name, value in (
                ("MD5", extracted.md5),
                ("SHA-1", extracted.sha1),
                ("SHA-256", extracted.sha256),
            )
            if value is not None
        }
        node, is_new = registry.intern(
            IntelObject(
                object_class=ObjectClass.OBSERVABLE,
                object_type=IntelObjectType.FILE,
                canonical_value=digest,
                display_value=extracted.name or digest,
                properties={"hashes": hashes},
            )
        )
        if is_new:
            objects.append(node)
        relationships.append(
            Relationship(
                source_object_id=context.subject_object_id,
                relationship_type=RelationshipType.DROPS,
                target_object_id=node.id,
                evidence_refs=(evidence_id,),
            )
        )
    return SandboxNormalization(objects=tuple(objects), relationships=tuple(relationships))


def normalize_no_report(context: NormalizationContext) -> SandboxNormalization:
    """Record that the provider has no accessible report for this sample.

    Says exactly one thing: nobody has run this file here, or the run is not
    accessible to this key. Not benign, not safe, not "never malicious", not
    "cannot execute" — an absence of detonations is the normal state of a
    freshly-built implant, and reading it as reassurance would invert its
    meaning.
    """
    return SandboxNormalization(
        evidence=(
            _evidence(
                context,
                evidence_class=EvidenceClass.CONTEXT,
                claim_type=NO_REPORT_CLAIM_TYPE,
                effect=EvidenceEffect.CONTEXT_ONLY,
                attributes={"sandbox_report_available": False, "means_benign": False},
            ),
        )
    )


def normalize_coverage(
    context: NormalizationContext,
    *,
    view: SandboxSampleView,
    selection: ReportSelection,
    depth: str,
    queried_hash_algorithm: str,
    requests_made: int,
    partial_reason: str | None,
    container_reports: tuple[str, ...] = (),
    unavailable_reports: tuple[str, ...] = (),
) -> SandboxNormalization:
    """What was looked at, what was skipped, and how the choice was made.

    The record that makes a thin result interpretable. "One report of forty was
    read, chosen by strongest completed verdict" and "the provider has one
    report" are entirely different situations that look the same without it.
    """
    states: dict[str, int] = {}
    for ref in view.reports:
        states[ref.state.value] = states.get(ref.state.value, 0) + 1
    verdicts: dict[str, int] = {}
    for ref in view.reports:
        verdicts[ref.verdict.value] = verdicts.get(ref.verdict.value, 0) + 1

    attributes: dict[str, Any] = {
        "depth": depth,
        "queried_hash_algorithm": queried_hash_algorithm,
        "provider_requests": requests_made,
        "report_count": view.report_count,
        "completed_report_count": len(view.completed_reports),
        "report_states": states,
        "report_verdicts": verdicts,
        "environments": sorted(
            {ref.environment.identity for ref in view.reports if ref.environment.identity}
        ),
        "summary_budget": selection.budget,
        "summaries_requested": selection.selected_count,
        "summaries_retrieved": len(view.summaries),
        "selection_strategy": selection.strategy,
        "contrasting_selection": selection.contrasting,
        "skipped_incomplete_reports": selection.skipped_incomplete,
        "skipped_over_budget_reports": selection.skipped_over_budget,
        # Every depth reads at most two of possibly many runs, so this is false
        # whenever anything was left unread. Never implied.
        "all_reports_summarized": (bool(view.reports) and len(view.summaries) == len(view.reports)),
        "only_failed_reports": view.has_only_failed_reports,
    }
    if view.canonical_sha256 is not None:
        attributes["sample_sha256"] = view.canonical_sha256
    if container_reports:
        # A container is a real answer about a real report. Its children are
        # named and deliberately not fetched.
        attributes["container_reports"] = list(container_reports)
    if unavailable_reports:
        attributes["unavailable_reports"] = list(unavailable_reports)
    if partial_reason is not None:
        attributes["partial_reason"] = partial_reason

    return SandboxNormalization(
        evidence=(
            _evidence(
                context,
                evidence_class=EvidenceClass.CONTEXT,
                claim_type=COVERAGE_CLAIM_TYPE,
                effect=EvidenceEffect.CONTEXT_ONLY,
                attributes=attributes,
            ),
        )
    )
