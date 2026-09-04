"""The analyst-facing output contract (Task 20).

The supported public view of an investigation. Everything an interface needs to
show a result lives here; nothing that decides one does.
"""

from ti_recon.reporting.builder import build_analyst_report, report_id_for
from ti_recon.reporting.models import (
    ANALYST_REPORT_SCHEMA_VERSION,
    AnalystInvestigationReport,
    AssessmentSummary,
    BasisItem,
    ConflictItem,
    CoverageCheckItem,
    ExplanationItem,
    GapItem,
    InformationNeedItem,
    InvestigationSummary,
    IssueItem,
    LimitationItem,
    QualificationItem,
    ReadinessSummary,
    RelatedObservableItem,
    ReportSection,
    ReportVersions,
    RequestSummary,
    SourceCheckItem,
    TargetSummary,
    UnexplainedEvidenceItem,
)
from ti_recon.reporting.schema import (
    SCHEMA_DIALECT,
    report_json_schema,
    request_json_schema,
)
from ti_recon.reporting.text import render_text, safe_text

__all__ = [
    "ANALYST_REPORT_SCHEMA_VERSION",
    "SCHEMA_DIALECT",
    "AnalystInvestigationReport",
    "AssessmentSummary",
    "BasisItem",
    "ConflictItem",
    "CoverageCheckItem",
    "ExplanationItem",
    "GapItem",
    "InformationNeedItem",
    "InvestigationSummary",
    "IssueItem",
    "LimitationItem",
    "QualificationItem",
    "ReadinessSummary",
    "RelatedObservableItem",
    "ReportSection",
    "ReportVersions",
    "RequestSummary",
    "SourceCheckItem",
    "TargetSummary",
    "UnexplainedEvidenceItem",
    "build_analyst_report",
    "render_text",
    "report_id_for",
    "report_json_schema",
    "request_json_schema",
    "safe_text",
]
