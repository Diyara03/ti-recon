"""Provider-neutral dynamic-analysis (sandbox) framework (Task 12).

The vocabulary TI Recon uses for *what a sample did when somebody ran it*, and
the policy for how much of that to fetch and keep. Hybrid Analysis is the first
provider to populate these shapes; a second sandbox would populate the same ones
without changing anything here.

Three ideas hold the package together.

**A report is an observation, not a verdict.** One sample, many runs, many
environments, sometimes disagreeing — and the disagreement is the signal, because
environment-dependent behaviour is how targeted malware works.
:class:`SandboxSampleView` preserves it instead of averaging it away.

**A sandbox that saw nothing did not see safety.** No verdict in
:data:`SANDBOX_VERDICT_EFFECT` maps to ``SUPPORTS_BENIGN``, and none can: a
sample may sit still because the OS was wrong, the C2 was down, it wanted a
click, or it noticed it was being watched. :class:`SandboxAnalysisQuality` keeps
enough of the execution context for a later layer to tell "nothing happened" from
"nothing could have happened".

**Detail is bounded and totals are kept.** One detonation can produce hundreds of
signatures and thousands of connections. What is normalized is capped per depth
and every collection records what it truncated, so a partial view never reads as
a complete one.

Deliberately absent: anything active. There is no submission, detonation or
download model here, and none should be added speculatively — a future active
path needs explicit approval, privacy handling and entitlement checks that are
design work in their own right.
"""

from ti_recon.sandbox.bounds import (
    DEPTH_BOUNDS,
    HARD_CEILINGS,
    SandboxBounds,
    bounds_for_depth,
)
from ti_recon.sandbox.models import (
    SANDBOX_VERDICT_EFFECT,
    SandboxAnalysisQuality,
    SandboxCertificate,
    SandboxEnvironment,
    SandboxExtractedFile,
    SandboxNetworkObservation,
    SandboxNetworkRole,
    SandboxProcess,
    SandboxReportRef,
    SandboxReportState,
    SandboxReportSummary,
    SandboxSampleView,
    SandboxSignature,
    SandboxTechnique,
    SandboxVerdict,
    verdict_rank,
)
from ti_recon.sandbox.selection import (
    DEPTH_SUMMARY_BUDGET,
    MAX_SUMMARIES_PER_LOOKUP,
    SELECTION_STRATEGY,
    ReportSelection,
    select_reports,
)

__all__ = [
    "DEPTH_BOUNDS",
    "DEPTH_SUMMARY_BUDGET",
    "HARD_CEILINGS",
    "MAX_SUMMARIES_PER_LOOKUP",
    "SANDBOX_VERDICT_EFFECT",
    "SELECTION_STRATEGY",
    "ReportSelection",
    "SandboxAnalysisQuality",
    "SandboxBounds",
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
    "bounds_for_depth",
    "select_reports",
    "verdict_rank",
]
