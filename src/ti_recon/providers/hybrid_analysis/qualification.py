"""What a sandbox run's time and quality mean (Task 15).

Hybrid Analysis is where "the scan found nothing" has to stop meaning "the file
is fine", and this module is where that distinction is made structural.

Time
----

``analysis_start_time`` is **when somebody detonated the sample**, so it becomes
``ANALYZED_AT`` on the report, at report scope. It is not a first-seen, not a
last-seen and not a "malware active at": a sample uploaded by a stranger in 2021
and run once produces exactly this instant and nothing else. Reports from
different environments carry different analysis times and stay separate facts —
one per run, each carrying its report id and environment.

Certificates observed during a run carry real validity windows, and those become
``VALID_FROM`` / ``VALID_UNTIL`` on the report. They describe the certificate,
not the sample.

Quality
-------

Task 12 already answers the only question that matters here:
``SandboxAnalysisQuality.observed_any_execution``. Task 15 treats it as
authoritative and invents no threshold of its own — no "more than three processes
counts as meaningful". Process and network totals travel on the signal as
explanation, never as a redefinition.

The three signals this produces:

* a **completed** run with a non-directional verdict and no observed execution is
  ``SANDBOX_LOW_EXECUTION`` — a negative worth very little, because the sample may
  simply have wanted a click, the wrong OS, a live C2, or have noticed it was
  being watched;
* the same run *with* observed execution is ``SANDBOX_MEANINGFUL_EXECUTION``,
  which is a more informative negative and still not a benign verdict;
* completed runs that disagreed are ``SANDBOX_DIVERGENCE``, preserved rather than
  resolved: malicious on Windows 11 and quiet on Windows 7 is targeted malware
  describing itself.

A run that errored, queued or never finished produces **none** of them. It has no
behavioural content, and letting an infrastructure failure look like a quiet run
is exactly the error Task 12's state/verdict split exists to prevent.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final

from ti_recon.models.evidence import Evidence
from ti_recon.providers.hybrid_analysis.normalizer import (
    ASSESSMENT_CLAIM_TYPE,
    BEHAVIOUR_CLAIM_TYPE,
)
from ti_recon.providers.result import ProviderResultEnvelope
from ti_recon.reasoning.extraction import ProviderQualification, QualificationContext
from ti_recon.reasoning.models import (
    ContextSignal,
    ContextSignalType,
    EvidenceRef,
    SignalOrigin,
    SubjectRef,
    TemporalFact,
    TemporalFactKind,
    report_subject,
)
from ti_recon.sandbox.models import SandboxReportState, SandboxVerdict

__all__ = ["NON_DIRECTIONAL_VERDICTS", "qualify"]

#: Verdicts that assert nothing about maliciousness.
#:
#: ``allowlisted`` is here because Task 12 already refuses to let it mean benign:
#: it is somebody's list membership, not an observation of harmlessness. It is
#: treated as a negative whose informational value depends on execution quality,
#: exactly like ``no specific threat``.
NON_DIRECTIONAL_VERDICTS: Final[frozenset[str]] = frozenset(
    {
        SandboxVerdict.NO_SPECIFIC_THREAT.value,
        SandboxVerdict.NO_VERDICT.value,
        SandboxVerdict.ALLOWLISTED.value,
        SandboxVerdict.UNKNOWN.value,
    }
)


def qualify(
    envelope: ProviderResultEnvelope, context: QualificationContext
) -> ProviderQualification:
    verdicts = _verdicts_by_report(envelope)
    facts: list[TemporalFact] = []
    signals: list[ContextSignal] = []
    for evidence in envelope.evidence:
        if evidence.claim_type == ASSESSMENT_CLAIM_TYPE:
            signals.extend(_divergence_signal(evidence, context))
        elif evidence.claim_type == BEHAVIOUR_CLAIM_TYPE:
            facts.extend(_report_facts(evidence, context))
            signals.extend(_execution_signal(evidence, verdicts, context))
    return ProviderQualification(temporal_facts=tuple(facts), context_signals=tuple(signals))


def _verdicts_by_report(envelope: ProviderResultEnvelope) -> dict[str, str]:
    """Report id -> verdict, from the one record that carries verdicts.

    The behaviour record knows how a run went; only the assessment record knows
    what the provider concluded from it. Joining them here — inside the provider's
    own module — is what lets the generic layer never learn either shape.
    """
    found: dict[str, str] = {}
    for evidence in envelope.evidence:
        if evidence.claim_type != ASSESSMENT_CLAIM_TYPE:
            continue
        reports = evidence.attributes.get("reports")
        if not isinstance(reports, list):
            continue
        for entry in reports:
            if not isinstance(entry, dict):
                continue
            report_id, verdict = entry.get("report_id"), entry.get("verdict")
            if isinstance(report_id, str) and isinstance(verdict, str):
                found[report_id] = verdict
    return found


def _report_facts(evidence: Evidence, context: QualificationContext) -> list[TemporalFact]:
    subject = _report_subject(evidence, context)
    reference = EvidenceRef.of(evidence)
    environment = evidence.attributes.get("environment_id")
    detail = f"environment={environment}"[:200] if isinstance(environment, str) else None

    found: list[TemporalFact] = []
    started = _instant(evidence.attributes.get("analysis_started_at"))
    if started is not None:
        found.append(
            TemporalFact(
                subject=subject,
                kind=TemporalFactKind.ANALYZED_AT,
                instant=started,
                transport_provider=evidence.transport_provider,
                origin_provider=evidence.origin_provider,
                source_family=evidence.source_family,
                lineage_group_id=evidence.lineage_group_id,
                raw_field="analysis_start_time",
                source_partial=context.source_partial,
                evidence=reference,
                detail=detail,
            )
        )

    certificates = evidence.attributes.get("certificates")
    if isinstance(certificates, list):
        for index, entry in enumerate(certificates):
            if not isinstance(entry, dict):
                continue
            fingerprint = entry.get("sha1_fingerprint")
            marker = fingerprint if isinstance(fingerprint, str) else f"index={index}"
            for kind, name in (
                (TemporalFactKind.VALID_FROM, "valid_from"),
                (TemporalFactKind.VALID_UNTIL, "valid_until"),
            ):
                instant = _instant(entry.get(name))
                if instant is None:
                    continue
                found.append(
                    TemporalFact(
                        subject=subject,
                        kind=kind,
                        instant=instant,
                        transport_provider=evidence.transport_provider,
                        origin_provider=evidence.origin_provider,
                        source_family=evidence.source_family,
                        lineage_group_id=evidence.lineage_group_id,
                        raw_field=f"certificates.{name}",
                        source_partial=context.source_partial,
                        evidence=reference,
                        detail=f"certificate={marker}"[:200],
                    )
                )
    return found


def _execution_signal(
    evidence: Evidence,
    verdicts: dict[str, str],
    context: QualificationContext,
) -> list[ContextSignal]:
    """How much this run's silence is worth — only for a run that finished."""
    state = evidence.attributes.get("state")
    if not isinstance(state, str) or not _is_complete(state):
        return []

    report_id = evidence.attributes.get("report_id")
    verdict = verdicts.get(report_id) if isinstance(report_id, str) else None
    if verdict is None or verdict not in NON_DIRECTIONAL_VERDICTS:
        # A malicious or suspicious run is not a negative and needs no
        # qualification of its silence.
        return []

    observed = evidence.attributes.get("observed_execution") is True
    signal_type = (
        ContextSignalType.SANDBOX_MEANINGFUL_EXECUTION
        if observed
        else ContextSignalType.SANDBOX_LOW_EXECUTION
    )
    detail: dict[str, Any] = {"state": state[:200], "sandbox_outcome": verdict[:200]}
    for name in ("total_processes", "total_network_connections", "environment_id"):
        value = evidence.attributes.get(name)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            detail[name] = value
        elif isinstance(value, str) and value:
            detail[name] = value[:200]

    return [
        ContextSignal(
            signal_type=signal_type,
            subject=_report_subject(evidence, context),
            origin=SignalOrigin.PROVIDER_REPORTED,
            match_scope=evidence.match_scope,
            transport_provider=evidence.transport_provider,
            origin_provider=evidence.origin_provider,
            source_family=evidence.source_family,
            lineage_group_id=evidence.lineage_group_id,
            evidence=EvidenceRef.of(evidence),
            source_key=report_id if isinstance(report_id, str) else None,
            source_partial=context.source_partial,
            detail=detail,
        )
    ]


def _divergence_signal(evidence: Evidence, context: QualificationContext) -> list[ContextSignal]:
    """Completed runs that disagreed, recorded rather than reconciled."""
    if evidence.attributes.get("divergent_verdicts") is not True:
        return []
    by_environment = evidence.attributes.get("verdicts_by_environment")
    detail: dict[str, Any] = {}
    if isinstance(by_environment, dict):
        detail["environments"] = len(by_environment)
        detail["distinct_outcomes"] = len(
            {value for value in by_environment.values() if isinstance(value, str)}
        )
    return [
        ContextSignal(
            signal_type=ContextSignalType.SANDBOX_DIVERGENCE,
            subject=context.subject_for(evidence.subject_object_id),
            origin=SignalOrigin.PROVIDER_REPORTED,
            match_scope=evidence.match_scope,
            transport_provider=evidence.transport_provider,
            origin_provider=evidence.origin_provider,
            source_family=evidence.source_family,
            lineage_group_id=evidence.lineage_group_id,
            evidence=EvidenceRef.of(evidence),
            source_key="verdicts_by_environment",
            source_partial=context.source_partial,
            detail=detail,
        )
    ]


def _report_subject(evidence: Evidence, context: QualificationContext) -> SubjectRef:
    """A report-scoped subject, falling back to the sample it is about.

    Report scope matters: several runs of one sample are several observations,
    and attaching all of them to the file would merge findings that Task 12 went
    to some trouble to keep apart.
    """
    report_id = evidence.attributes.get("report_id")
    if isinstance(report_id, str) and report_id:
        return report_subject(evidence.transport_provider, report_id)
    return context.subject_for(evidence.subject_object_id)


def _is_complete(state: str) -> bool:
    try:
        return SandboxReportState(state).is_complete
    except ValueError:
        return False


def _instant(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None
