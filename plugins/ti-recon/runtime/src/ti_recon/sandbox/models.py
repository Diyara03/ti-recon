"""Provider-neutral dynamic-analysis models (Task 12).

The vocabulary TI Recon uses to talk about *what a sample did when somebody ran
it*, independent of which sandbox ran it. Hybrid Analysis is the first provider
to populate these; CAPE, Triage or ANY.RUN would populate the same shapes
without touching this file.

Nothing here carries a provider's field names. A model shaped around one
sandbox's JSON is not a framework, it is that sandbox with extra steps — and the
first thing a second provider would have to do is fight it.

The distinction the whole module exists for
-------------------------------------------

**A sandbox report is an observation of a sample in one environment. It is not
the sample, and it is not a verdict about the sample.**

The same SHA-256 routinely has a Windows 11 report that says malicious, a
Windows 7 report that says nothing specific, a report from last year, and one
that failed to execute at all. Flattening file, report and environment into one
identity throws away the only information that makes a negative result
interpretable — so they are three separate things here, and
:class:`SandboxSampleView` keeps the disagreement rather than resolving it.

**And a sandbox that saw nothing is not a sandbox that saw safety.** A sample can
fail to misbehave because the OS was wrong, the C2 was down, it wanted a command
line, it wanted a click, it was geofenced, it was waiting, or it noticed it was
being watched. :class:`SandboxAnalysisQuality` exists so a future
false-positive layer can tell "nothing happened" from "nothing could have
happened", and no model in this file can express "benign".
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from pydantic import Field, model_validator

from ti_recon.enums import EvidenceEffect
from ti_recon.models.base import FrozenTiReconModel, UtcDatetime

__all__ = [
    "MAX_COMMAND_LINE",
    "MAX_LABEL",
    "MAX_TEXT",
    "SANDBOX_VERDICT_EFFECT",
    "SandboxAnalysisQuality",
    "SandboxCertificate",
    "SandboxEnvironment",
    "SandboxExtractedFile",
    "SandboxNetworkObservation",
    "SandboxNetworkRole",
    "SandboxProcess",
    "SandboxReportRef",
    "SandboxReportState",
    "SandboxReportSummary",
    "SandboxSampleView",
    "SandboxSignature",
    "SandboxTechnique",
    "SandboxVerdict",
]

#: Bounds on provider-supplied text. A command line is allowed more room than a
#: label because it is genuinely long and genuinely useful; neither is unbounded.
MAX_LABEL: Final[int] = 200
MAX_TEXT: Final[int] = 1024
MAX_COMMAND_LINE: Final[int] = 2048


class SandboxVerdict(StrEnum):
    """What a sandbox concluded about one run, in neutral terms.

    Five values because that is the shape real sandboxes report: a positive
    finding, a weaker positive, an explicit "nothing stood out", an explicit "no
    opinion", and an explicit allow-list hit. Collapsing the last three would
    destroy the distinction between *examined and unremarkable* and *not
    examined*.

    ``ALLOWLISTED`` is deliberately not called benign. A sandbox allow-list means
    the provider recognised the file as something it does not analyse — which is
    a statement about the provider's list, not about the file's safety.
    """

    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    NO_SPECIFIC_THREAT = "no_specific_threat"
    NO_VERDICT = "no_verdict"
    ALLOWLISTED = "allowlisted"
    UNKNOWN = "unknown"

    @property
    def is_positive(self) -> bool:
        """Whether this verdict points at maliciousness at all."""
        return self in {SandboxVerdict.MALICIOUS, SandboxVerdict.SUSPICIOUS}


#: How each verdict maps onto evidence direction.
#:
#: The load-bearing asymmetry: two verdicts point at malicious and **none points
#: at benign**. ``NO_SPECIFIC_THREAT``, ``NO_VERDICT`` and ``ALLOWLISTED`` are
#: all ``CONTEXT_ONLY``, because a sandbox failing to observe malice is a fact
#: about one execution in one environment, not about the file. Emitting
#: ``SUPPORTS_BENIGN`` from a non-detection is the single most consequential
#: mistake this framework exists to prevent — it would let an evasive sample earn
#: exoneration by being good at hiding.
#:
#: ``SUSPICIOUS`` maps to ``SUPPORTS_MALICIOUS`` because direction and strength
#: are separate concerns in the Task 3 model: the effect records which way the
#: evidence points, and the provider's own weaker word travels alongside it.
SANDBOX_VERDICT_EFFECT: Final[dict[SandboxVerdict, EvidenceEffect]] = {
    SandboxVerdict.MALICIOUS: EvidenceEffect.SUPPORTS_MALICIOUS,
    SandboxVerdict.SUSPICIOUS: EvidenceEffect.SUPPORTS_MALICIOUS,
    SandboxVerdict.NO_SPECIFIC_THREAT: EvidenceEffect.CONTEXT_ONLY,
    SandboxVerdict.NO_VERDICT: EvidenceEffect.CONTEXT_ONLY,
    SandboxVerdict.ALLOWLISTED: EvidenceEffect.CONTEXT_ONLY,
    SandboxVerdict.UNKNOWN: EvidenceEffect.CONTEXT_ONLY,
}

#: Strength order for choosing a representative report. Not a scale of badness —
#: purely "which single report is most worth spending a request on".
_VERDICT_RANK: Final[dict[SandboxVerdict, int]] = {
    SandboxVerdict.MALICIOUS: 5,
    SandboxVerdict.SUSPICIOUS: 4,
    SandboxVerdict.NO_SPECIFIC_THREAT: 3,
    SandboxVerdict.ALLOWLISTED: 2,
    SandboxVerdict.NO_VERDICT: 1,
    SandboxVerdict.UNKNOWN: 0,
}


def verdict_rank(verdict: SandboxVerdict) -> int:
    """Selection strength of a verdict. See :data:`_VERDICT_RANK`."""
    return _VERDICT_RANK[verdict]


class SandboxReportState(StrEnum):
    """How far a run actually got.

    Kept apart from the verdict because "no verdict" and "never ran" are
    completely different facts that look identical once collapsed. A report that
    errored has no behavioural content to reason about, and treating its absence
    of findings as a finding is how a failed detonation becomes a clean bill of
    health.
    """

    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    ERROR = "error"
    IN_QUEUE = "in_queue"
    IN_PROGRESS = "in_progress"
    UNKNOWN = "unknown"

    @property
    def is_complete(self) -> bool:
        """Whether the run finished with behaviour worth reading."""
        return self in {SandboxReportState.SUCCESS, SandboxReportState.PARTIAL_SUCCESS}


class SandboxNetworkRole(StrEnum):
    """How a sandbox characterised a network peer it observed.

    ``COMPROMISED_HOST`` preserves a provider's own stronger claim without
    reinterpreting it: the provider said this host looked compromised, which is
    not the same as saying it is attacker-owned, and the difference matters when
    the host turns out to be a hijacked WordPress site.
    """

    CONTACTED = "contacted"
    COMPROMISED_HOST = "compromised_host"


class SandboxEnvironment(FrozenTiReconModel):
    """The machine a run happened on.

    Its own model because it is the axis along which sandbox results legitimately
    disagree. "Malicious on Windows 11" and "nothing on Windows 7" are both true,
    and neither can be understood without knowing which was which.
    """

    environment_id: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=MAX_LABEL)

    @property
    def identity(self) -> str:
        """A stable label for grouping and ordering."""
        return self.environment_id or self.description or "unknown"


class SandboxReportRef(FrozenTiReconModel):
    """A report that exists, before anything has been fetched about it.

    What a hash search returns: enough to *choose* between runs, and nothing
    more. Deliberately has no analysis timestamp — see
    :mod:`ti_recon.sandbox.selection` for why that absence is load-bearing.
    """

    report_id: str = Field(min_length=1, max_length=128)
    environment: SandboxEnvironment = SandboxEnvironment()
    state: SandboxReportState = SandboxReportState.UNKNOWN
    verdict: SandboxVerdict = SandboxVerdict.UNKNOWN
    #: The provider's own verdict word, kept because a normalized enum loses
    #: nuance an analyst may want back.
    raw_verdict: str | None = Field(default=None, max_length=64)
    error_type: str | None = Field(default=None, max_length=MAX_LABEL)
    error_origin: str | None = Field(default=None, max_length=MAX_LABEL)

    @property
    def is_selectable(self) -> bool:
        """Whether it is worth spending a request on this report.

        A failed or queued run has nothing to summarize, so fetching it would
        spend an allowance to learn what the index already said.
        """
        return self.state.is_complete


class SandboxAnalysisQuality(FrozenTiReconModel):
    """How much this run is worth believing.

    The most important model here for false-positive reasoning, and the reason
    "the sandbox found nothing" is never enough on its own. Two runs can both
    report no findings while meaning opposite things: one executed for two
    minutes, spawned eleven processes and made forty connections; the other
    errored after four seconds having started nothing.

    Task 12 does not diagnose *why* a run was uninformative — wrong OS, absent
    C2, anti-analysis, a missing click. It records enough for a later layer to
    ask that question at all.
    """

    state: SandboxReportState = SandboxReportState.UNKNOWN
    analysis_started_at: UtcDatetime | None = None
    #: Provider-reported totals, kept even when the detail is truncated: "600
    #: connections, 25 normalized" is honest, "25 connections" is not.
    total_processes: int | None = Field(default=None, ge=0)
    total_network_connections: int | None = Field(default=None, ge=0)
    total_signatures: int | None = Field(default=None, ge=0)
    #: Execution knobs. Safe fields only — see the provider normalizer for the
    #: submission metadata deliberately left out.
    runtime_seconds: int | None = Field(default=None, ge=0)
    network_mode: str | None = Field(default=None, max_length=64)
    action_script: str | None = Field(default=None, max_length=64)
    anti_evasion: bool | None = None
    script_logging: bool | None = None
    sample_tampering_allowed: bool | None = None
    #: Provider-generated warnings about the run itself, bounded.
    warnings: tuple[str, ...] = ()

    @property
    def observed_any_execution(self) -> bool:
        """Whether anything at all was observed running.

        ``False`` is not evidence of safety — it is evidence that this run cannot
        support a conclusion in either direction.
        """
        return bool(self.total_processes) or bool(self.total_network_connections)


class SandboxProcess(FrozenTiReconModel):
    """One process a sandbox observed.

    ``command_line`` is the field worth having and the field worth being careful
    with. It is attacker-authored text that ends up in an evidence record, so it
    is bounded and stripped of control characters at normalization — and it is
    never executed, interpolated into a shell, or treated as an instruction by
    anything downstream.
    """

    name: str | None = Field(default=None, max_length=MAX_LABEL)
    normalized_path: str | None = Field(default=None, max_length=MAX_TEXT)
    command_line: str | None = Field(default=None, max_length=MAX_COMMAND_LINE)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    process_id: str | None = Field(default=None, max_length=64)
    parent_process_id: str | None = Field(default=None, max_length=64)


class SandboxNetworkObservation(FrozenTiReconModel):
    """A host or domain the sample touched while running.

    Contact is not accusation. A sample reaching out during detonation may be
    calling its C2 or may be checking a certificate revocation list, resolving
    time, fetching a CDN asset or phoning Windows telemetry — and the sandbox
    cannot tell those apart either. So this records what was contacted and lets
    the correlation layer decide whether it matters.
    """

    value: str = Field(min_length=1, max_length=MAX_TEXT)
    #: ``"domain"``, ``"ipv4"`` or ``"ipv6"``, decided by parsing rather than by
    #: trusting which provider list the value arrived in.
    kind: str = Field(min_length=1, max_length=16)
    role: SandboxNetworkRole = SandboxNetworkRole.CONTACTED


class SandboxExtractedFile(FrozenTiReconModel):
    """A file the sample wrote, dropped or unpacked.

    Never downloaded. A dropped file is interesting as a pivot and as a
    relationship; retrieving it would put live malware on the machine running the
    investigation, and no code path in Task 12 can.

    ``threat_level`` and the AV counts are the provider's own reading, kept as
    context rather than turned into a finding per file: a dropper that writes
    forty files must not become forty malicious votes.
    """

    name: str | None = Field(default=None, max_length=MAX_LABEL)
    file_path: str | None = Field(default=None, max_length=MAX_TEXT)
    size_bytes: int | None = Field(default=None, ge=0)
    md5: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    sha1: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    type_tags: tuple[str, ...] = ()
    threat_level: int | None = Field(default=None, ge=0)
    av_label: str | None = Field(default=None, max_length=MAX_LABEL)
    av_matched: int | None = Field(default=None, ge=0)
    av_total: int | None = Field(default=None, ge=0)

    @property
    def strongest_hash(self) -> tuple[str, str] | None:
        """``(algorithm, digest)`` for the strongest digest present."""
        for algorithm, digest in (
            ("SHA-256", self.sha256),
            ("SHA-1", self.sha1),
            ("MD5", self.md5),
        ):
            if digest:
                return algorithm, digest
        return None


class SandboxCertificate(FrozenTiReconModel):
    """A code-signing certificate seen on the sample or its artifacts.

    Neither direction is inferred. A valid signature does not make a file safe —
    stolen and purpose-bought certificates are routine — and an expired or
    self-signed one does not make it malicious.
    """

    owner: str | None = Field(default=None, max_length=MAX_LABEL)
    issuer: str | None = Field(default=None, max_length=MAX_LABEL)
    serial_number: str | None = Field(default=None, max_length=128)
    #: Certificate fingerprints, which are *not* file hashes even though they
    #: share a shape. Modelled as what they identify.
    md5_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    sha1_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    valid_from: UtcDatetime | None = None
    valid_until: UtcDatetime | None = None


class SandboxSignature(FrozenTiReconModel):
    """One behavioural rule the sandbox matched.

    Bounded and never a finding of its own. A single detonation can trip hundreds
    of signatures, and one Evidence per signature would let a thorough sandbox
    outvote every other provider in the investigation by itself.
    """

    name: str | None = Field(default=None, max_length=MAX_LABEL)
    category: str | None = Field(default=None, max_length=MAX_LABEL)
    description: str | None = Field(default=None, max_length=MAX_TEXT)
    threat_level: int | None = Field(default=None, ge=0)
    threat_level_label: str | None = Field(default=None, max_length=64)
    relevance: int | None = Field(default=None, ge=0)
    attack_id: str | None = Field(default=None, max_length=32)
    capec_id: str | None = Field(default=None, max_length=32)


class SandboxTechnique(FrozenTiReconModel):
    """A MITRE ATT&CK technique the sandbox attributed to the run.

    Behavioural annotation on one analysis, not independent corroboration. Ten
    techniques from one report are ten descriptions of the same execution.
    """

    technique: str | None = Field(default=None, max_length=MAX_LABEL)
    tactic: str | None = Field(default=None, max_length=MAX_LABEL)
    attack_id: str | None = Field(default=None, max_length=32)
    parent_attack_id: str | None = Field(default=None, max_length=32)
    malicious_identifiers: int | None = Field(default=None, ge=0)
    suspicious_identifiers: int | None = Field(default=None, ge=0)
    informative_identifiers: int | None = Field(default=None, ge=0)


class SandboxReportSummary(FrozenTiReconModel):
    """Everything worth keeping from one detonation.

    Detail is bounded and totals are kept separately, so a truncated view never
    looks like a complete one: ``normalized_processes`` next to
    ``quality.total_processes`` is the difference between "the sample spawned
    twelve" and "we kept twelve of six hundred".
    """

    report_id: str = Field(min_length=1, max_length=128)
    environment: SandboxEnvironment = SandboxEnvironment()
    verdict: SandboxVerdict = SandboxVerdict.UNKNOWN
    raw_verdict: str | None = Field(default=None, max_length=64)
    quality: SandboxAnalysisQuality = SandboxAnalysisQuality()

    threat_score: int | None = Field(default=None, ge=0, le=100)
    threat_level: int | None = Field(default=None, ge=0)
    #: The provider's family label. One provider's naming, not resolved
    #: attribution — alias reconciliation across providers is a later concern.
    family_label: str | None = Field(default=None, max_length=MAX_LABEL)
    tags: tuple[str, ...] = ()

    signatures: tuple[SandboxSignature, ...] = ()
    techniques: tuple[SandboxTechnique, ...] = ()
    processes: tuple[SandboxProcess, ...] = ()
    network: tuple[SandboxNetworkObservation, ...] = ()
    extracted_files: tuple[SandboxExtractedFile, ...] = ()
    certificates: tuple[SandboxCertificate, ...] = ()

    #: Alternate digests for the analysed sample, so a lookup by MD5 can learn
    #: the SHA-256 the sandbox indexed it under.
    hashes: dict[str, str] = Field(default_factory=dict)
    #: Truncation record per collection, so bounds are visible in the result.
    truncated: dict[str, bool] = Field(default_factory=dict)

    @property
    def has_behaviour(self) -> bool:
        """Whether this summary contains any observed behaviour at all."""
        return bool(self.processes or self.network or self.signatures or self.techniques)


class SandboxSampleView(FrozenTiReconModel):
    """Every run a provider holds for one sample, and their disagreement.

    The top-level result of a passive sandbox lookup, and the model that refuses
    to answer the question everyone wants answered. It does not say whether the
    sample is malicious; it says what happened when it was run, where, how well,
    and whether the runs agree.

    ``divergent_verdicts`` is not a defect to resolve. Environment-dependent
    behaviour is *how targeted malware works*, so a sample that detonates on
    Windows 11 and sits still on Windows 7 is telling an analyst something
    valuable — and a model that averaged those into one verdict would delete it.
    """

    #: The identity the provider indexes runs under, when it exposes one.
    canonical_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    #: Every run the provider knows about, including failed ones.
    reports: tuple[SandboxReportRef, ...] = ()
    #: The runs actually fetched in detail. A bounded subset, by design.
    summaries: tuple[SandboxReportSummary, ...] = ()

    @property
    def report_count(self) -> int:
        return len(self.reports)

    @property
    def completed_reports(self) -> tuple[SandboxReportRef, ...]:
        return tuple(item for item in self.reports if item.state.is_complete)

    @property
    def verdicts_by_environment(self) -> dict[str, str]:
        """Which environment reported what, for completed runs.

        Deliberately keyed by environment rather than aggregated: this is the
        record that keeps a disagreement legible instead of averaging it away.
        """
        return {
            item.environment.identity: item.verdict.value
            for item in sorted(self.completed_reports, key=lambda ref: ref.environment.identity)
        }

    @property
    def divergent_verdicts(self) -> bool:
        """Whether completed runs disagreed about this sample."""
        return len({item.verdict for item in self.completed_reports}) > 1

    @property
    def strongest_verdict(self) -> SandboxVerdict:
        """The strongest verdict any *completed* run reached.

        Completed only. A failed run has no verdict to contribute, and letting
        one influence this would turn an infrastructure problem into an opinion.
        """
        completed = self.completed_reports
        if not completed:
            return SandboxVerdict.UNKNOWN
        return max((item.verdict for item in completed), key=verdict_rank)

    @property
    def effect(self) -> EvidenceEffect:
        """The direction this sample's runs point, if any.

        Never ``SUPPORTS_BENIGN``. There is no combination of sandbox results
        that produces it — see :data:`SANDBOX_VERDICT_EFFECT`.
        """
        return SANDBOX_VERDICT_EFFECT[self.strongest_verdict]

    @property
    def has_only_failed_reports(self) -> bool:
        """Reports exist, but none of them ran. A coverage fact, not a finding."""
        return bool(self.reports) and not self.completed_reports

    @model_validator(mode="after")
    def _validate_view(self) -> SandboxSampleView:
        known = {item.report_id for item in self.reports}
        unknown = {item.report_id for item in self.summaries} - known
        if unknown:
            # A summary for a report the index never mentioned means the two
            # halves came from different lookups, which would make the
            # divergence record fiction.
            msg = "sandbox summaries must correspond to indexed reports"
            raise ValueError(msg)
        return self
